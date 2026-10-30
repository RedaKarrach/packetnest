from django.core.files.uploadedfile import SimpleUploadedFile
from django.urls import reverse
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

from core.models import Capture
from core.synthetic import synthetic_pcap_bytes

from .base import PacketNestTestCase


class ApiTests(PacketNestTestCase):
    def setUp(self):
        self.org = self.make_org("Org", "org")
        self.alice = self.make_user("alice", self.org)
        self.token = Token.objects.create(user=self.alice)
        self.api = APIClient()
        self.api.credentials(HTTP_AUTHORIZATION=f"Token {self.token.key}")

    def test_token_auth_can_list(self):
        capture = self.make_capture(self.org, self.alice, name="listed.pcap")
        response = self.api.get("/api/captures/")
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["count"], 1)
        self.assertEqual(body["results"][0]["id"], capture.pk)
        self.assertEqual(body["results"][0]["name"], "listed.pcap")
        self.assertEqual(body["results"][0]["uploaded_by"], "alice")
        self.assertNotIn("storage_key", body["results"][0])

    def test_token_auth_can_upload_and_fetch(self):
        upload = SimpleUploadedFile("api.pcap", synthetic_pcap_bytes("ftp", seed=2))
        response = self.api.post("/api/captures/", {"file": upload, "name": "from-api"}, format="multipart")
        self.assertEqual(response.status_code, 201, response.content)
        body = response.json()
        self.assertEqual(body["name"], "from-api")
        self.assertEqual(body["status"], "done")
        self.assertEqual(body["summary"]["cleartext_findings"][0]["type"], "ftp_credentials")

        capture = Capture.objects.get(pk=body["id"])
        self.assertEqual(capture.organisation, self.org)
        self.assertEqual(capture.uploaded_by, self.alice)

        detail = self.api.get(f"/api/captures/{capture.pk}/")
        self.assertEqual(detail.status_code, 200)
        self.assertEqual(detail.json()["summary"]["packet_count"], capture.summary["packet_count"])

    def test_upload_validation(self):
        upload = SimpleUploadedFile("notes.txt", b"hello")
        response = self.api.post("/api/captures/", {"file": upload}, format="multipart")
        self.assertEqual(response.status_code, 400)
        self.assertFalse(Capture.objects.exists())

    def test_bad_token_rejected(self):
        api = APIClient()
        api.credentials(HTTP_AUTHORIZATION="Token not-a-real-token")
        self.assertEqual(api.get("/api/captures/").status_code, 401)

    def test_session_auth_works(self):
        self.client.force_login(self.alice)
        self.assertEqual(self.client.get("/api/captures/").status_code, 200)

    def test_token_page_shows_and_regenerates(self):
        self.client.force_login(self.alice)
        response = self.client.get(reverse("api_token"))
        self.assertContains(response, self.token.key)

        self.client.post(reverse("api_token"))
        new_token = Token.objects.get(user=self.alice)
        self.assertNotEqual(new_token.key, self.token.key)
        self.assertEqual(self.api.get("/api/captures/").status_code, 401)
