import tempfile
from pathlib import Path

from django.core.files.uploadedfile import SimpleUploadedFile
from django.urls import reverse
from scapy.utils import PcapNgWriter

from core.models import Capture
from core.storage import get_capture
from core.synthetic import FAKE_FTP_PASSWORD, build_packets, synthetic_pcap_bytes

from .base import PacketNestTestCase


class UploadTests(PacketNestTestCase):
    def setUp(self):
        self.org = self.make_org("Org", "org")
        self.user = self.make_user("alice", self.org)
        self.client.force_login(self.user)

    def upload(self, data, filename="lan.pcap", name=""):
        return self.client.post(reverse("capture_upload"), {
            "name": name,
            "file": SimpleUploadedFile(filename, data, content_type="application/octet-stream"),
        })

    def test_upload_produces_summary_with_protocols_and_ftp_finding(self):
        data = synthetic_pcap_bytes("mixed", seed=7)
        response = self.upload(data)

        capture = Capture.objects.get()
        self.assertRedirects(response, reverse("capture_detail", args=[capture.pk]))
        self.assertEqual(capture.status, Capture.STATUS_DONE)
        self.assertEqual(capture.organisation, self.org)
        self.assertEqual(capture.uploaded_by, self.user)
        self.assertEqual(capture.name, "lan.pcap")
        self.assertEqual(capture.size_bytes, len(data))
        self.assertRegex(capture.storage_key, rf"^{self.org.id}/[0-9a-f-]{{36}}\.pcap$")
        self.assertEqual(get_capture(capture.storage_key), data)

        summary = capture.summary
        self.assertEqual(summary["packet_count"], len(build_packets("mixed", seed=7)))
        self.assertGreater(summary["duration_seconds"], 0)
        for proto in ("TCP", "UDP", "ICMP", "ARP", "DNS", "HTTP", "TLS"):
            self.assertGreater(summary["protocols"][proto], 0, proto)
        self.assertEqual(sum(summary["protocols"].values()), summary["packet_count"])
        self.assertLessEqual(len(summary["top_sources"]), 10)
        self.assertLessEqual(len(summary["top_conversations"]), 10)
        self.assertTrue(all(name.endswith(".example") for name in summary["dns_queries"]))

        ftp = [f for f in summary["cleartext_findings"] if f["type"] == "ftp_credentials"]
        self.assertEqual(len(ftp), 1)
        self.assertEqual(ftp[0]["username"], "demo_user")
        self.assertTrue(ftp[0]["password_seen"])
        # The password value must never be stored.
        self.assertNotIn(FAKE_FTP_PASSWORD, str(capture.summary))

        page = self.client.get(reverse("capture_detail", args=[capture.pk]))
        self.assertContains(page, "FTP login sent in cleartext")
        self.assertNotContains(page, FAKE_FTP_PASSWORD)

    def test_telnet_and_basic_auth_findings(self):
        self.upload(synthetic_pcap_bytes("telnet", seed=1), filename="telnet.pcap")
        self.upload(synthetic_pcap_bytes("basic_auth", seed=1), filename="basic.pcap")
        telnet = Capture.objects.get(name="telnet.pcap").summary["cleartext_findings"]
        basic = Capture.objects.get(name="basic.pcap").summary["cleartext_findings"]
        self.assertEqual({f["type"] for f in telnet}, {"telnet"})
        self.assertEqual({f["type"] for f in basic}, {"http_basic_auth"})
        self.assertNotIn("ZGVtb191c2Vy", str(basic))  # base64 credentials are not stored

    def test_pcapng_upload(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "dns.pcapng"
            writer = PcapNgWriter(str(path))
            for pkt in build_packets("dns", seed=3):
                writer.write(pkt)
            writer.close()
            data = path.read_bytes()
        self.assertEqual(data[:4], b"\x0a\x0d\x0d\x0a")
        self.upload(data, filename="dns.pcapng")
        capture = Capture.objects.get()
        self.assertEqual(capture.status, Capture.STATUS_DONE)
        self.assertGreater(capture.summary["protocols"]["DNS"], 0)

    def test_invalid_file_marks_capture_failed(self):
        self.upload(b"this is not a capture file at all", filename="broken.pcap")
        capture = Capture.objects.get()
        self.assertEqual(capture.status, Capture.STATUS_FAILED)
        self.assertTrue(capture.error)
        self.assertEqual(capture.summary, {})

    def test_rejects_wrong_extension(self):
        response = self.upload(synthetic_pcap_bytes(), filename="notes.txt")
        self.assertEqual(response.status_code, 200)
        self.assertFalse(Capture.objects.exists())

    def test_rejects_files_over_10_mb(self):
        response = self.upload(b"\0" * (10 * 1024 * 1024 + 1), filename="huge.pcap")
        self.assertEqual(response.status_code, 200)
        self.assertFalse(Capture.objects.exists())

    def test_packet_cap(self):
        with self.settings(MAX_ANALYSED_PACKETS=10):
            self.upload(synthetic_pcap_bytes("mixed", seed=1))
        summary = Capture.objects.get().summary
        self.assertEqual(summary["packet_count"], 10)
        self.assertTrue(summary["truncated"])

    def test_dashboard_lists_org_captures(self):
        self.make_capture(self.org, self.user, name="mine.pcap")
        response = self.client.get(reverse("dashboard"))
        self.assertContains(response, "mine.pcap")

    def test_download(self):
        capture = self.make_capture(self.org, self.user)
        response = self.client.get(reverse("capture_download", args=[capture.pk]))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, get_capture(capture.storage_key))
