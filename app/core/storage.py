"""Capture file storage.

If CAPTURES_BUCKET is set, captures go to S3 using boto3's default credential chain
(on EC2 that is the instance role). Otherwise they are written under MEDIA_ROOT/captures/.
"""

from pathlib import Path

import boto3
from django.conf import settings


def _s3_client():
    return boto3.client("s3", region_name=settings.AWS_REGION or None)


def _local_path(key):
    return Path(settings.MEDIA_ROOT) / "captures" / key


def put_capture(key, data):
    if settings.CAPTURES_BUCKET:
        _s3_client().put_object(
            Bucket=settings.CAPTURES_BUCKET,
            Key=key,
            Body=data,
            ContentType="application/vnd.tcpdump.pcap",
        )
        return
    path = _local_path(key)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def get_capture(key):
    if settings.CAPTURES_BUCKET:
        response = _s3_client().get_object(Bucket=settings.CAPTURES_BUCKET, Key=key)
        return response["Body"].read()
    return _local_path(key).read_bytes()
