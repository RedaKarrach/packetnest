from django.conf import settings
from rest_framework import generics, permissions, serializers, status
from rest_framework.parsers import FormParser, JSONParser, MultiPartParser
from rest_framework.response import Response

from .models import Capture
from .services import ALLOWED_EXTENSIONS, create_capture


class HasOrganisation(permissions.BasePermission):
    message = "Your account is not attached to an organisation."

    def has_permission(self, request, view):
        return hasattr(request.user, "profile")


class CaptureListSerializer(serializers.ModelSerializer):
    uploaded_by = serializers.CharField(source="uploaded_by.username", read_only=True, default=None)

    class Meta:
        model = Capture
        fields = ["id", "name", "status", "size_bytes", "sha256", "source_url", "uploaded_by", "created_at"]


class CaptureDetailSerializer(CaptureListSerializer):
    class Meta(CaptureListSerializer.Meta):
        fields = CaptureListSerializer.Meta.fields + ["summary", "error"]


class CaptureUploadSerializer(serializers.Serializer):
    file = serializers.FileField()
    name = serializers.CharField(max_length=200, required=False, allow_blank=True)

    def validate_file(self, upload):
        if not (upload.name or "").lower().endswith(ALLOWED_EXTENSIONS):
            raise serializers.ValidationError("Only .pcap and .pcapng files are accepted.")
        if upload.size > settings.MAX_CAPTURE_BYTES:
            raise serializers.ValidationError("Captures are limited to 10 MB.")
        return upload


class OrganisationCaptureMixin:
    permission_classes = [permissions.IsAuthenticated, HasOrganisation]

    def get_queryset(self):
        return Capture.objects.filter(organisation=self.request.user.profile.organisation).select_related("uploaded_by")


class CaptureListCreateView(OrganisationCaptureMixin, generics.ListCreateAPIView):
    serializer_class = CaptureListSerializer
    parser_classes = [MultiPartParser, FormParser, JSONParser]

    def create(self, request, *args, **kwargs):
        upload_serializer = CaptureUploadSerializer(data=request.data)
        upload_serializer.is_valid(raise_exception=True)
        upload = upload_serializer.validated_data["file"]
        name = upload_serializer.validated_data.get("name") or upload.name
        capture = create_capture(request.user.profile.organisation, request.user, name, upload.read())
        return Response(CaptureDetailSerializer(capture).data, status=status.HTTP_201_CREATED)


class CaptureDetailView(OrganisationCaptureMixin, generics.RetrieveAPIView):
    serializer_class = CaptureDetailSerializer
