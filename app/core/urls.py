from django.contrib.auth import views as auth_views
from django.urls import path

from . import views

urlpatterns = [
    path("", views.home, name="home"),
    path("signup/", views.signup, name="signup"),
    path("login/", auth_views.LoginView.as_view(redirect_authenticated_user=True), name="login"),
    path("logout/", auth_views.LogoutView.as_view(), name="logout"),
    path("account/password/", auth_views.PasswordChangeView.as_view(), name="password_change"),
    path("account/password/done/", auth_views.PasswordChangeDoneView.as_view(), name="password_change_done"),
    path("account/api-token/", views.api_token, name="api_token"),
    path("captures/", views.dashboard, name="dashboard"),
    path("captures/upload/", views.capture_upload, name="capture_upload"),
    path("captures/import/", views.capture_import, name="capture_import"),
    path("captures/<int:pk>/", views.capture_detail, name="capture_detail"),
    path("captures/<int:pk>/download/", views.capture_download, name="capture_download"),
    path("captures/<int:pk>/share/", views.share_create, name="share_create"),
    path("captures/<int:pk>/share/<int:link_id>/revoke/", views.share_revoke, name="share_revoke"),
    path("s/<str:token>/", views.share_public, name="share_public"),
    path("org/members/", views.org_members, name="org_members"),
    path("org/members/<int:user_id>/remove/", views.org_member_remove, name="org_member_remove"),
    path("invite/<str:token>/", views.invitation_accept, name="invitation_accept"),
]
