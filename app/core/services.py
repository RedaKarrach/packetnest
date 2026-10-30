import hashlib
import logging
import uuid
from urllib.parse import unquote, urlparse

import requests
from django.conf import settings

from .analysis import analyse_pcap_bytes
from .models import Capture
from .storage import put_capture

logger = logging.getLogger("packetnest.captures")

ALLOWED_EXTENSIONS = (".pcap", ".pcapng")


class CaptureTooLarge(Exception):
    pass


def make_storage_key(organisation):
    return f"{organisation.id}/{uuid.uuid4()}.pcap"


def create_capture(organisation, user, name, data, source_url=None):
    """Store the raw capture, create the Capture row and analyse it synchronously."""
    key = make_storage_key(organisation)
    put_capture(key, data)
    capture = Capture.objects.create(
        organisation=organisation,
        uploaded_by=user,
        name=name[:200],
        storage_key=key,
        size_bytes=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
        source_url=source_url,
        status=Capture.STATUS_PENDING,
    )
    analyse_capture(capture, data)
    logger.info(
        "capture created id=%s org=%s user=%s status=%s size=%s source_url=%s",
        capture.id, organisation.slug, getattr(user, "username", "-"), capture.status, len(data), source_url or "-",
    )
    return capture


def analyse_capture(capture, data):
    try:
        capture.summary = analyse_pcap_bytes(data)
    except Exception as exc:
        capture.status = Capture.STATUS_FAILED
        capture.error = str(exc) or exc.__class__.__name__
        capture.summary = {}
    else:
        capture.status = Capture.STATUS_DONE
        capture.error = ""
    capture.save(update_fields=["summary", "status", "error"])
    return capture


def download_capture(url):
    """Download a capture over HTTP(S), refusing anything larger than MAX_CAPTURE_BYTES."""
    limit = settings.MAX_CAPTURE_BYTES
    response = requests.get(url, timeout=10, stream=True)
    try:
        response.raise_for_status()
        chunks = []
        total = 0
        for chunk in response.iter_content(chunk_size=64 * 1024):
            if not chunk:
                continue
            total += len(chunk)
            if total > limit:
                raise CaptureTooLarge(f"The file is larger than {limit // (1024 * 1024)} MB.")
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        response.close()


def name_from_url(url):
    path = unquote(urlparse(url).path)
    name = path.rstrip("/").rsplit("/", 1)[-1]
    return name or urlparse(url).netloc or "imported-capture"
