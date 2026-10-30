import shutil
import tempfile

from django.contrib.auth.models import User
from django.test import TestCase, override_settings

from core.models import Organisation, Profile
from core.services import create_capture
from core.synthetic import synthetic_pcap_bytes

PASSWORD = "Unit-test-Pa55word!"

# Tests don't run collectstatic, so skip the manifest storage used in production.
TEST_STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"},
}


class PacketNestTestCase(TestCase):
    """Uses a throw-away MEDIA_ROOT and local storage (no S3)."""

    @classmethod
    def setUpClass(cls):
        cls._media_dir = tempfile.mkdtemp(prefix="packetnest-tests-")
        cls._settings = override_settings(
            MEDIA_ROOT=cls._media_dir,
            CAPTURES_BUCKET="",
            STORAGES=TEST_STORAGES,
            PASSWORD_HASHERS=["django.contrib.auth.hashers.MD5PasswordHasher"],
        )
        cls._settings.enable()
        super().setUpClass()

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        cls._settings.disable()
        shutil.rmtree(cls._media_dir, ignore_errors=True)

    @staticmethod
    def make_org(name, slug):
        return Organisation.objects.create(name=name, slug=slug)

    @staticmethod
    def make_user(username, organisation, role=Profile.ROLE_MEMBER):
        user = User.objects.create_user(username=username, email=f"{username}@test.example", password=PASSWORD)
        Profile.objects.create(user=user, organisation=organisation, role=role)
        return user

    @staticmethod
    def make_capture(organisation, user, kind="mixed", name="sample.pcap"):
        return create_capture(organisation, user, name, synthetic_pcap_bytes(kind, seed=1))
