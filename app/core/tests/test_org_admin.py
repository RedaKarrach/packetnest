import io

from django.contrib.auth.models import User
from django.core.management import call_command
from django.urls import reverse

from core.models import Capture, Invitation, Organisation, Profile

from .base import PASSWORD, PacketNestTestCase


class MemberRemovalTests(PacketNestTestCase):
    def setUp(self):
        self.org = self.make_org("Org", "org")
        self.other_org = self.make_org("Other", "other")
        self.admin = self.make_user("boss", self.org, role=Profile.ROLE_ORG_ADMIN)
        self.member = self.make_user("worker", self.org)
        self.member2 = self.make_user("worker2", self.org)
        self.outsider = self.make_user("outsider", self.other_org)

    def remove(self, user):
        return self.client.post(reverse("org_member_remove", args=[user.pk]))

    def test_member_cannot_see_or_use_admin_pages(self):
        self.client.force_login(self.member)
        self.assertEqual(self.client.get(reverse("org_members")).status_code, 403)
        self.assertEqual(self.remove(self.member2).status_code, 403)
        self.assertTrue(User.objects.filter(pk=self.member2.pk).exists())

    def test_org_admin_can_remove_member(self):
        self.client.force_login(self.admin)
        page = self.client.get(reverse("org_members"))
        self.assertContains(page, "worker2")
        self.assertNotContains(page, "outsider")
        response = self.remove(self.member)
        self.assertRedirects(response, reverse("org_members"))
        self.assertFalse(User.objects.filter(pk=self.member.pk).exists())

    def test_org_admin_cannot_remove_other_org_user_or_self(self):
        self.client.force_login(self.admin)
        self.assertEqual(self.remove(self.outsider).status_code, 404)
        self.assertTrue(User.objects.filter(pk=self.outsider.pk).exists())
        self.remove(self.admin)
        self.assertTrue(User.objects.filter(pk=self.admin.pk).exists())


class InvitationTests(PacketNestTestCase):
    def setUp(self):
        self.org = self.make_org("Org", "org")
        self.admin = self.make_user("boss", self.org, role=Profile.ROLE_ORG_ADMIN)
        self.member = self.make_user("worker", self.org)

    def test_invitation_flow(self):
        self.client.force_login(self.admin)
        response = self.client.post(reverse("org_members"), {"email": "new@org.example", "role": Profile.ROLE_MEMBER})
        self.assertRedirects(response, reverse("org_members"))
        invitation = Invitation.objects.get()
        self.assertEqual(invitation.organisation, self.org)
        link = reverse("invitation_accept", args=[invitation.token])
        self.assertContains(self.client.get(reverse("org_members")), link)

        invitee = self.client_class()
        self.assertContains(invitee.get(link), "Join Org")
        response = invitee.post(link, {"username": "newbie", "password1": PASSWORD, "password2": PASSWORD})
        self.assertRedirects(response, reverse("dashboard"))

        user = User.objects.get(username="newbie")
        self.assertEqual(user.email, "new@org.example")
        self.assertEqual(user.profile.organisation, self.org)
        self.assertEqual(user.profile.role, Profile.ROLE_MEMBER)
        invitation.refresh_from_db()
        self.assertTrue(invitation.accepted)

        # The link cannot be used twice.
        response = self.client_class().post(link, {"username": "again", "password1": PASSWORD, "password2": PASSWORD})
        self.assertEqual(response.status_code, 410)
        self.assertFalse(User.objects.filter(username="again").exists())

    def test_member_cannot_create_invitation(self):
        self.client.force_login(self.member)
        response = self.client.post(reverse("org_members"), {"email": "x@org.example", "role": Profile.ROLE_ORG_ADMIN})
        self.assertEqual(response.status_code, 403)
        self.assertFalse(Invitation.objects.exists())

    def test_unknown_invitation_is_404(self):
        self.assertEqual(self.client.get(reverse("invitation_accept", args=["nope"])).status_code, 404)


class SeedDemoTests(PacketNestTestCase):
    def test_seed_demo_is_idempotent(self):
        call_command("seed_demo", stdout=io.StringIO())
        call_command("seed_demo", stdout=io.StringIO())
        self.assertEqual(Organisation.objects.count(), 3)
        self.assertEqual(Profile.objects.count(), 9)
        self.assertEqual(Profile.objects.filter(role=Profile.ROLE_ORG_ADMIN).count(), 3)
        self.assertEqual(Capture.objects.count(), 24)
        for org in Organisation.objects.all():
            self.assertEqual(org.captures.count(), 8)
