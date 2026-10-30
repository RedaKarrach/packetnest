from urllib.parse import urlparse

from django import forms
from django.conf import settings
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from django.utils.text import slugify

from .models import Invitation
from .services import ALLOWED_EXTENSIONS


def validate_capture_file(upload):
    name = upload.name or ""
    if not name.lower().endswith(ALLOWED_EXTENSIONS):
        raise forms.ValidationError("Only .pcap and .pcapng files are accepted.")
    if upload.size > settings.MAX_CAPTURE_BYTES:
        raise forms.ValidationError("Captures are limited to 10 MB.")
    return upload


class SignUpForm(UserCreationForm):
    organisation_name = forms.CharField(max_length=150, label="Company name")
    email = forms.EmailField()

    class Meta(UserCreationForm.Meta):
        model = User
        fields = ("organisation_name", "username", "email")

    def clean_organisation_name(self):
        name = self.cleaned_data["organisation_name"].strip()
        if not slugify(name):
            raise forms.ValidationError("Please use a company name with letters or digits.")
        return name


class InvitationSignUpForm(UserCreationForm):
    class Meta(UserCreationForm.Meta):
        model = User
        fields = ("username",)


class CaptureUploadForm(forms.Form):
    name = forms.CharField(max_length=200, required=False, help_text="Optional. Defaults to the file name.")
    file = forms.FileField(label="Capture file (.pcap / .pcapng, max 10 MB)")

    def clean_file(self):
        return validate_capture_file(self.cleaned_data["file"])


class CaptureImportForm(forms.Form):
    url = forms.URLField(max_length=2000, label="Capture URL", assume_scheme="https")
    name = forms.CharField(max_length=200, required=False, help_text="Optional. Defaults to the file name in the URL.")

    def clean_url(self):
        url = self.cleaned_data["url"]
        if urlparse(url).scheme not in ("http", "https"):
            raise forms.ValidationError("Only http:// and https:// links are supported.")
        return url


class InvitationForm(forms.ModelForm):
    class Meta:
        model = Invitation
        fields = ("email", "role")

