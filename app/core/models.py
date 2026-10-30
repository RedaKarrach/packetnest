import secrets

from django.conf import settings
from django.db import models


def generate_share_token():
    return secrets.token_urlsafe(16)


def generate_invitation_token():
    return secrets.token_urlsafe(24)


class Organisation(models.Model):
    name = models.CharField(max_length=150)
    slug = models.SlugField(max_length=160, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name


class Profile(models.Model):
    ROLE_MEMBER = "member"
    ROLE_ORG_ADMIN = "org_admin"
    ROLE_CHOICES = [
        (ROLE_MEMBER, "Member"),
        (ROLE_ORG_ADMIN, "Organisation admin"),
    ]

    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="profile")
    organisation = models.ForeignKey(Organisation, on_delete=models.CASCADE, related_name="profiles")
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default=ROLE_MEMBER)

    def __str__(self):
        return f"{self.user.username} ({self.organisation}, {self.role})"

    @property
    def is_org_admin(self):
        return self.role == self.ROLE_ORG_ADMIN


class Capture(models.Model):
    STATUS_PENDING = "pending"
    STATUS_DONE = "done"
    STATUS_FAILED = "failed"
    STATUS_CHOICES = [
        (STATUS_PENDING, "Pending"),
        (STATUS_DONE, "Done"),
        (STATUS_FAILED, "Failed"),
    ]

    organisation = models.ForeignKey(Organisation, on_delete=models.CASCADE, related_name="captures")
    uploaded_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="captures"
    )
    name = models.CharField(max_length=200)
    storage_key = models.CharField(max_length=255)
    size_bytes = models.PositiveBigIntegerField(default=0)
    sha256 = models.CharField(max_length=64, blank=True)
    source_url = models.URLField(max_length=2000, null=True, blank=True)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default=STATUS_PENDING)
    summary = models.JSONField(default=dict, blank=True)
    error = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at", "-id"]

    def __str__(self):
        return self.name


class ShareLink(models.Model):
    capture = models.ForeignKey(Capture, on_delete=models.CASCADE, related_name="share_links")
    token = models.CharField(max_length=64, unique=True, default=generate_share_token)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    revoked = models.BooleanField(default=False)

    class Meta:
        ordering = ["-created_at", "-id"]

    def __str__(self):
        return f"Share of {self.capture} ({'revoked' if self.revoked else 'active'})"


class Invitation(models.Model):
    organisation = models.ForeignKey(Organisation, on_delete=models.CASCADE, related_name="invitations")
    email = models.EmailField()
    role = models.CharField(max_length=20, choices=Profile.ROLE_CHOICES, default=Profile.ROLE_MEMBER)
    token = models.CharField(max_length=64, unique=True, default=generate_invitation_token)
    created_at = models.DateTimeField(auto_now_add=True)
    accepted = models.BooleanField(default=False)

    class Meta:
        ordering = ["-created_at", "-id"]

    def __str__(self):
        return f"Invitation for {self.email} to {self.organisation}"
