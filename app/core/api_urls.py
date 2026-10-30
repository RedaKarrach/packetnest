from django.urls import path

from . import api

urlpatterns = [
    path("captures/", api.CaptureListCreateView.as_view(), name="api_capture_list"),
    path("captures/<int:pk>/", api.CaptureDetailView.as_view(), name="api_capture_detail"),
]
