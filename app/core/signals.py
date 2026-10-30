"""Log authentication events to stdout so they end up in the container logs."""

import logging

from django.contrib.auth.signals import user_logged_in, user_logged_out, user_login_failed
from django.dispatch import receiver

logger = logging.getLogger("packetnest.auth")


def client_ip(request):
    if request is None:
        return "-"
    forwarded = request.META.get("HTTP_X_FORWARDED_FOR")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR", "-")


@receiver(user_logged_in)
def log_login(sender, request, user, **kwargs):
    logger.info("login success user=%s ip=%s", user.username, client_ip(request))


@receiver(user_logged_out)
def log_logout(sender, request, user, **kwargs):
    logger.info("logout user=%s ip=%s", getattr(user, "username", "-"), client_ip(request))


@receiver(user_login_failed)
def log_login_failed(sender, credentials, request=None, **kwargs):
    logger.warning("login failed user=%s ip=%s", credentials.get("username", "-"), client_ip(request))
