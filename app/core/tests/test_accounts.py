from django.contrib.auth.models import User
from django.urls import reverse

from core.models import Organisation, Profile

from .base import PASSWORD, PacketNestTestCase


class SignUpTests(PacketNestTestCase):
    def test_signup_creates_organisation_and_org_admin(self):
        response = self.client.post(reverse("signup"), {
            "organisation_name": "Test Freight SARL",
            "username": "founder",
            "email": "founder@freight.example",
            "password1": PASSWORD,
            "password2": PASSWORD,
        })
        self.assertRedirects(response, reverse("dashboard"))

        org = Organisation.objects.get(name="Test Freight SARL")
        self.assertEqual(org.slug, "test-freight-sarl")
        user = User.objects.get(username="founder")
        self.assertEqual(user.email, "founder@freight.example")
        self.assertEqual(user.profile.organisation, org)
        self.assertEqual(user.profile.role, Profile.ROLE_ORG_ADMIN)
        # The new user is logged in.
        self.assertEqual(self.client.get(reverse("dashboard")).status_code, 200)

    def test_signup_with_same_company_name_gets_unique_slug(self):
        self.make_org("Acme", "acme")
        self.client.post(reverse("signup"), {
            "organisation_name": "Acme",
            "username": "acme2",
            "email": "x@acme.example",
            "password1": PASSWORD,
            "password2": PASSWORD,
        })
        self.assertTrue(Organisation.objects.filter(slug="acme-2").exists())

    def test_signup_rejects_weak_password(self):
        response = self.client.post(reverse("signup"), {
            "organisation_name": "Weak Co",
            "username": "weak",
            "email": "weak@weak.example",
            "password1": "123",
            "password2": "123",
        })
        self.assertEqual(response.status_code, 200)
        self.assertFalse(User.objects.filter(username="weak").exists())
        self.assertFalse(Organisation.objects.filter(name="Weak Co").exists())


class LoginTests(PacketNestTestCase):
    def setUp(self):
        self.org = self.make_org("Org", "org")
        self.user = self.make_user("alice", self.org)

    def test_login_and_logout(self):
        response = self.client.post(reverse("login"), {"username": "alice", "password": PASSWORD})
        self.assertRedirects(response, reverse("dashboard"))
        response = self.client.post(reverse("logout"))
        self.assertRedirects(response, reverse("login"))
        response = self.client.get(reverse("dashboard"))
        self.assertRedirects(response, f"{reverse('login')}?next={reverse('dashboard')}")

    def test_wrong_password(self):
        response = self.client.post(reverse("login"), {"username": "alice", "password": "nope"})
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("_auth_user_id", self.client.session)

    def test_change_password(self):
        self.client.force_login(self.user)
        new_password = "An0ther-Strong-Pass!"
        response = self.client.post(reverse("password_change"), {
            "old_password": PASSWORD,
            "new_password1": new_password,
            "new_password2": new_password,
        })
        self.assertRedirects(response, reverse("password_change_done"))
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password(new_password))

    def test_home_page_is_public(self):
        self.assertEqual(self.client.get(reverse("home")).status_code, 200)
