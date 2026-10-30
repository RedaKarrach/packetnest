import logging
from functools import wraps

import requests
from django.contrib import messages
from django.contrib.auth import login
from django.contrib.auth.decorators import login_required
from django.db import transaction
from django.http import Http404, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils.text import slugify
from django.views.decorators.http import require_POST
from rest_framework.authtoken.models import Token

from .analysis import PROTOCOLS
from .forms import CaptureImportForm, CaptureUploadForm, InvitationForm, InvitationSignUpForm, SignUpForm
from .models import Capture, Invitation, Organisation, Profile, ShareLink
from .services import CaptureTooLarge, create_capture, download_capture, name_from_url
from .storage import get_capture

logger = logging.getLogger("packetnest.web")


# --- helpers -------------------------------------------------------------


def org_required(view):
    """Logged-in user attached to an organisation; sets request.organisation."""

    @wraps(view)
    @login_required
    def wrapper(request, *args, **kwargs):
        profile = getattr(request.user, "profile", None)
        if profile is None:
            return render(request, "core/no_organisation.html", status=403)
        request.profile = profile
        request.organisation = profile.organisation
        return view(request, *args, **kwargs)

    return wrapper


def org_admin_required(view):
    @wraps(view)
    @org_required
    def wrapper(request, *args, **kwargs):
        if not request.profile.is_org_admin:
            return render(request, "core/forbidden.html", status=403)
        return view(request, *args, **kwargs)

    return wrapper


def unique_org_slug(name):
    base = slugify(name)[:150] or "org"
    slug = base
    n = 2
    while Organisation.objects.filter(slug=slug).exists():
        slug = f"{base}-{n}"
        n += 1
    return slug


def build_report(summary):
    """Pre-compute bar widths (percentages) for the CSS charts."""
    protocols = summary.get("protocols", {})
    total = sum(protocols.values()) or 1
    # jsonb does not keep key order, so always list protocols in the same order.
    protocol_bars = [
        {"label": name, "count": protocols.get(name, 0), "pct": protocols.get(name, 0) * 100 / total}
        for name in PROTOCOLS
    ]
    sources = summary.get("top_sources", [])
    max_src = max((s["packets"] for s in sources), default=0) or 1
    source_bars = [{**s, "pct": s["packets"] * 100 / max_src} for s in sources]
    conversations = summary.get("top_conversations", [])
    max_conv = max((c["packets"] for c in conversations), default=0) or 1
    conversation_bars = [{**c, "pct": c["packets"] * 100 / max_conv} for c in conversations]
    return {
        "protocol_bars": protocol_bars,
        "source_bars": source_bars,
        "conversation_bars": conversation_bars,
        "dns_queries": summary.get("dns_queries", []),
        "findings": summary.get("cleartext_findings", []),
    }


def org_capture(request, pk):
    return get_object_or_404(Capture, pk=pk, organisation=request.organisation)


# --- public pages / accounts --------------------------------------------


def home(request):
    if request.user.is_authenticated:
        return redirect("dashboard")
    return render(request, "core/home.html")


def signup(request):
    if request.method == "POST":
        form = SignUpForm(request.POST)
        if form.is_valid():
            with transaction.atomic():
                name = form.cleaned_data["organisation_name"]
                organisation = Organisation.objects.create(name=name, slug=unique_org_slug(name))
                user = form.save(commit=False)
                user.email = form.cleaned_data["email"]
                user.save()
                Profile.objects.create(user=user, organisation=organisation, role=Profile.ROLE_ORG_ADMIN)
            logger.info("signup org=%s user=%s", organisation.slug, user.username)
            login(request, user, backend="django.contrib.auth.backends.ModelBackend")
            messages.success(request, f"Welcome to PacketNest, {organisation.name}!")
            return redirect("dashboard")
    else:
        form = SignUpForm()
    return render(request, "registration/signup.html", {"form": form})


def invitation_accept(request, token):
    invitation = get_object_or_404(Invitation, token=token)
    if invitation.accepted:
        return render(request, "core/invitation_used.html", {"invitation": invitation}, status=410)
    if request.method == "POST":
        form = InvitationSignUpForm(request.POST)
        if form.is_valid():
            with transaction.atomic():
                user = form.save(commit=False)
                user.email = invitation.email
                user.save()
                Profile.objects.create(user=user, organisation=invitation.organisation, role=invitation.role)
                invitation.accepted = True
                invitation.save(update_fields=["accepted"])
            logger.info("invitation accepted org=%s user=%s", invitation.organisation.slug, user.username)
            login(request, user, backend="django.contrib.auth.backends.ModelBackend")
            messages.success(request, f"You joined {invitation.organisation.name}.")
            return redirect("dashboard")
    else:
        form = InvitationSignUpForm()
    return render(request, "core/invitation_accept.html", {"form": form, "invitation": invitation})


# --- captures ------------------------------------------------------------


@org_required
def dashboard(request):
    captures = Capture.objects.filter(organisation=request.organisation).select_related("uploaded_by")
    stats = {
        "total": captures.count(),
        "done": captures.filter(status=Capture.STATUS_DONE).count(),
        "failed": captures.filter(status=Capture.STATUS_FAILED).count(),
        "with_findings": sum(1 for c in captures if c.summary.get("cleartext_findings")),
    }
    return render(request, "core/dashboard.html", {"captures": captures, "stats": stats})


@org_required
def capture_upload(request):
    if request.method == "POST":
        form = CaptureUploadForm(request.POST, request.FILES)
        if form.is_valid():
            upload = form.cleaned_data["file"]
            name = form.cleaned_data["name"] or upload.name
            capture = create_capture(request.organisation, request.user, name, upload.read())
            if capture.status == Capture.STATUS_DONE:
                messages.success(request, "Capture uploaded and analysed.")
            else:
                messages.error(request, "The capture was stored but could not be analysed.")
            return redirect("capture_detail", pk=capture.pk)
    else:
        form = CaptureUploadForm()
    return render(request, "core/capture_upload.html", {"form": form})


@org_required
def capture_import(request):
    if request.method == "POST":
        form = CaptureImportForm(request.POST)
        if form.is_valid():
            url = form.cleaned_data["url"]
            try:
                data = download_capture(url)
            except CaptureTooLarge as exc:
                form.add_error("url", str(exc))
            except requests.RequestException as exc:
                form.add_error("url", f"Could not download the capture: {exc}")
            else:
                name = form.cleaned_data["name"] or name_from_url(url)
                capture = create_capture(request.organisation, request.user, name, data, source_url=url)
                if capture.status == Capture.STATUS_DONE:
                    messages.success(request, "Capture imported and analysed.")
                else:
                    messages.error(request, "The file was downloaded but could not be analysed.")
                return redirect("capture_detail", pk=capture.pk)
    else:
        form = CaptureImportForm()
    return render(request, "core/capture_import.html", {"form": form})


@org_required
def capture_detail(request, pk):
    capture = org_capture(request, pk)
    share_links = capture.share_links.filter(revoked=False).select_related("created_by")
    context = {
        "capture": capture,
        "report": build_report(capture.summary),
        "share_links": share_links,
    }
    return render(request, "core/capture_detail.html", context)


@org_required
def capture_download(request, pk):
    capture = org_capture(request, pk)
    data = get_capture(capture.storage_key)
    response = HttpResponse(data, content_type="application/vnd.tcpdump.pcap")
    filename = slugify(capture.name.rsplit(".", 1)[0]) or f"capture-{capture.pk}"
    response["Content-Disposition"] = f'attachment; filename="{filename}.pcap"'
    return response


@require_POST
@org_required
def share_create(request, pk):
    capture = org_capture(request, pk)
    link = ShareLink.objects.create(capture=capture, created_by=request.user)
    logger.info("share link created capture=%s user=%s", capture.pk, request.user.username)
    messages.success(request, "Share link created: " + request.build_absolute_uri(reverse("share_public", args=[link.token])))
    return redirect("capture_detail", pk=capture.pk)


@require_POST
@org_required
def share_revoke(request, pk, link_id):
    capture = org_capture(request, pk)
    link = get_object_or_404(ShareLink, pk=link_id, capture=capture)
    if link.created_by_id != request.user.id and not request.profile.is_org_admin:
        return render(request, "core/forbidden.html", status=403)
    link.revoked = True
    link.save(update_fields=["revoked"])
    logger.info("share link revoked capture=%s link=%s user=%s", capture.pk, link.pk, request.user.username)
    messages.success(request, "Share link revoked.")
    return redirect("capture_detail", pk=capture.pk)


def share_public(request, token):
    link = get_object_or_404(ShareLink.objects.select_related("capture__organisation"), token=token)
    if link.revoked:
        raise Http404("This share link has been revoked.")
    capture = link.capture
    return render(request, "core/share_public.html", {"capture": capture, "report": build_report(capture.summary)})


# --- API token -----------------------------------------------------------


@org_required
def api_token(request):
    if request.method == "POST":
        Token.objects.filter(user=request.user).delete()
        Token.objects.create(user=request.user)
        logger.info("api token regenerated user=%s", request.user.username)
        messages.success(request, "A new API token was generated. The old one no longer works.")
        return redirect("api_token")
    token, _ = Token.objects.get_or_create(user=request.user)
    return render(request, "core/api_token.html", {"token": token})


# --- organisation admin --------------------------------------------------


@org_admin_required
def org_members(request):
    organisation = request.organisation
    if request.method == "POST":
        form = InvitationForm(request.POST)
        if form.is_valid():
            invitation = form.save(commit=False)
            invitation.organisation = organisation
            invitation.save()
            link = request.build_absolute_uri(reverse("invitation_accept", args=[invitation.token]))
            logger.info("invitation created org=%s email=%s by=%s", organisation.slug, invitation.email, request.user.username)
            messages.success(request, f"Invitation created. Send this link to {invitation.email}: {link}")
            return redirect("org_members")
    else:
        form = InvitationForm()
    members = Profile.objects.filter(organisation=organisation).select_related("user").order_by("user__username")
    invitations = [
        (inv, request.build_absolute_uri(reverse("invitation_accept", args=[inv.token])))
        for inv in organisation.invitations.filter(accepted=False)
    ]
    return render(
        request,
        "core/org_members.html",
        {"members": members, "invitations": invitations, "form": form, "organisation": organisation},
    )


@require_POST
@org_admin_required
def org_member_remove(request, user_id):
    profile = get_object_or_404(Profile, user_id=user_id, organisation=request.organisation)
    if profile.user_id == request.user.id:
        messages.error(request, "You cannot remove yourself.")
        return redirect("org_members")
    username = profile.user.username
    profile.user.delete()
    logger.info("member removed org=%s user=%s by=%s", request.organisation.slug, username, request.user.username)
    messages.success(request, f"{username} was removed from {request.organisation.name}.")
    return redirect("org_members")
