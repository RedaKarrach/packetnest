from django.contrib import admin

from .models import Capture, Invitation, Organisation, Profile, ShareLink


@admin.register(Organisation)
class OrganisationAdmin(admin.ModelAdmin):
    list_display = ("name", "slug", "created_at")
    search_fields = ("name", "slug")
    prepopulated_fields = {"slug": ("name",)}


@admin.register(Profile)
class ProfileAdmin(admin.ModelAdmin):
    list_display = ("user", "organisation", "role")
    list_filter = ("role", "organisation")
    search_fields = ("user__username", "user__email", "organisation__name")


@admin.register(Capture)
class CaptureAdmin(admin.ModelAdmin):
    list_display = ("name", "organisation", "uploaded_by", "status", "size_bytes", "created_at")
    list_filter = ("status", "organisation")
    search_fields = ("name", "sha256", "source_url")
    readonly_fields = ("storage_key", "sha256", "size_bytes", "created_at")


@admin.register(ShareLink)
class ShareLinkAdmin(admin.ModelAdmin):
    list_display = ("capture", "created_by", "created_at", "revoked")
    list_filter = ("revoked",)


@admin.register(Invitation)
class InvitationAdmin(admin.ModelAdmin):
    list_display = ("email", "organisation", "role", "created_at", "accepted")
    list_filter = ("accepted", "role", "organisation")
    search_fields = ("email",)
