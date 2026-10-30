from unittest import mock

import requests
from django.urls import reverse

from core.models import Capture
from core.synthetic import synthetic_pcap_bytes

from .base import PacketNestTestCase


def fake_response(data, status=200, chunk=4096):
    response = mock.Mock()
    response.status_code = status
    if status >= 400:
        response.raise_for_status.side_effect = requests.HTTPError(f"{status} Client Error")
    else:
        response.raise_for_status.return_value = None
    response.iter_content.side_effect = lambda chunk_size=chunk: (
        data[i:i + chunk_size] for i in range(0, len(data), chunk_size)
    )
    return response


class UrlImportTests(PacketNestTestCase):
    def setUp(self):
        self.org = self.make_org("Org", "org")
        self.alice = self.make_user("alice", self.org)
        self.client.force_login(self.alice)

    @mock.patch("core.services.requests.get")
    def test_import_downloads_and_analyses(self, get):
        data = synthetic_pcap_bytes("web", seed=5)
        get.return_value = fake_response(data)
        url = "https://files.example/captures/branch-office.pcap"

        response = self.client.post(reverse("capture_import"), {"url": url})

        get.assert_called_once_with(url, timeout=10, stream=True)
        capture = Capture.objects.get()
        self.assertRedirects(response, reverse("capture_detail", args=[capture.pk]))
        self.assertEqual(capture.name, "branch-office.pcap")
        self.assertEqual(capture.source_url, url)
        self.assertEqual(capture.size_bytes, len(data))
        self.assertEqual(capture.status, Capture.STATUS_DONE)
        self.assertGreater(capture.summary["protocols"]["HTTP"], 0)

    @mock.patch("core.services.requests.get")
    def test_import_stops_beyond_10_mb(self, get):
        get.return_value = fake_response(b"\0" * (10 * 1024 * 1024 + 10), chunk=1024 * 1024)
        response = self.client.post(reverse("capture_import"), {"url": "http://files.example/big.pcap"})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "larger than 10 MB")
        self.assertFalse(Capture.objects.exists())

    @mock.patch("core.services.requests.get")
    def test_import_http_error(self, get):
        get.return_value = fake_response(b"", status=404)
        response = self.client.post(reverse("capture_import"), {"url": "http://files.example/missing.pcap"})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Could not download")
        self.assertFalse(Capture.objects.exists())

    @mock.patch("core.services.requests.get")
    def test_import_rejects_non_http_scheme(self, get):
        response = self.client.post(reverse("capture_import"), {"url": "ftp://files.example/a.pcap"})
        self.assertEqual(response.status_code, 200)
        get.assert_not_called()
        self.assertFalse(Capture.objects.exists())
