from django.urls import reverse

from core.models import Profile, ShareLink

from .base import PacketNestTestCase


class ShareLinkTests(PacketNestTestCase):
    def setUp(self):
        self.org = self.make_org("Org", "org")
        self.alice = self.make_user("alice", self.org)
        self.capture = self.make_capture(self.org, self.alice, name="shared.pcap")

    def test_share_link_works_until_revoked(self):
        self.client.force_login(self.alice)
        response = self.client.post(reverse("share_create", args=[self.capture.pk]))
        self.assertRedirects(response, reverse("capture_detail", args=[self.capture.pk]))
        link = ShareLink.objects.get()
        self.assertEqual(link.capture, self.capture)
        self.assertGreaterEqual(len(link.token), 20)

        public_url = reverse("share_public", args=[link.token])
        anonymous = self.client_class()
        response = anonymous.get(public_url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "shared.pcap")
        self.assertContains(response, "Protocol breakdown")
        self.assertNotContains(response, reverse("capture_download", args=[self.capture.pk]))

        response = self.client.post(reverse("share_revoke", args=[self.capture.pk, link.pk]))
        self.assertRedirects(response, reverse("capture_detail", args=[self.capture.pk]))
        link.refresh_from_db()
        self.assertTrue(link.revoked)
        self.assertEqual(anonymous.get(public_url).status_code, 404)

    def test_unknown_token_is_404(self):
        self.assertEqual(self.client.get(reverse("share_public", args=["does-not-exist"])).status_code, 404)

    def test_other_member_cannot_revoke_but_org_admin_can(self):
        link = ShareLink.objects.create(capture=self.capture, created_by=self.alice)
        bob = self.make_user("bob", self.org)
        boss = self.make_user("boss", self.org, role=Profile.ROLE_ORG_ADMIN)
        url = reverse("share_revoke", args=[self.capture.pk, link.pk])

        self.client.force_login(bob)
        self.assertEqual(self.client.post(url).status_code, 403)
        link.refresh_from_db()
        self.assertFalse(link.revoked)

        self.client.force_login(boss)
        self.client.post(url)
        link.refresh_from_db()
        self.assertTrue(link.revoked)

    def test_share_requires_post(self):
        self.client.force_login(self.alice)
        self.assertEqual(self.client.get(reverse("share_create", args=[self.capture.pk])).status_code, 405)
