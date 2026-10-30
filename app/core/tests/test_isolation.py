from django.urls import reverse
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

from core.models import ShareLink

from .base import PacketNestTestCase


class OrganisationIsolationTests(PacketNestTestCase):
    def setUp(self):
        self.org_a = self.make_org("Org A", "org-a")
        self.org_b = self.make_org("Org B", "org-b")
        self.alice = self.make_user("alice", self.org_a)
        self.bob = self.make_user("bob", self.org_b)
        self.capture_b = self.make_capture(self.org_b, self.bob, name="bob-secret.pcap")

    def test_web_pages_return_404_for_other_org_capture(self):
        self.client.force_login(self.alice)
        pk = self.capture_b.pk
        self.assertEqual(self.client.get(reverse("capture_detail", args=[pk])).status_code, 404)
        self.assertEqual(self.client.get(reverse("capture_download", args=[pk])).status_code, 404)
        self.assertEqual(self.client.post(reverse("share_create", args=[pk])).status_code, 404)
        self.assertFalse(ShareLink.objects.exists())
        self.assertNotContains(self.client.get(reverse("dashboard")), "bob-secret.pcap")

    def test_cannot_revoke_other_org_share_link(self):
        link = ShareLink.objects.create(capture=self.capture_b, created_by=self.bob)
        self.client.force_login(self.alice)
        response = self.client.post(reverse("share_revoke", args=[self.capture_b.pk, link.pk]))
        self.assertEqual(response.status_code, 404)
        link.refresh_from_db()
        self.assertFalse(link.revoked)

    def test_api_returns_404_for_other_org_capture(self):
        api = APIClient()
        token = Token.objects.create(user=self.alice)
        api.credentials(HTTP_AUTHORIZATION=f"Token {token.key}")
        self.assertEqual(api.get(f"/api/captures/{self.capture_b.pk}/").status_code, 404)
        listing = api.get("/api/captures/").json()
        self.assertEqual(listing["count"], 0)

    def test_owner_can_see_own_capture(self):
        self.client.force_login(self.bob)
        self.assertEqual(self.client.get(reverse("capture_detail", args=[self.capture_b.pk])).status_code, 200)

    def test_anonymous_is_redirected_to_login(self):
        response = self.client.get(reverse("capture_detail", args=[self.capture_b.pk]))
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("login"), response["Location"])
        self.assertEqual(APIClient().get("/api/captures/").status_code, 401)
