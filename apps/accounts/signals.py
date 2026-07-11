"""Auth signals → activity log."""

from django.contrib.auth.signals import user_logged_in, user_logged_out
from django.dispatch import receiver

from apps.accounts.activity_log import record_user_activity
from apps.accounts.models import UserActivityLog


@receiver(user_logged_in)
def log_user_logged_in(sender, request, user, **kwargs):
    record_user_activity(
        user=user,
        event_type=UserActivityLog.EventType.USER_LOGIN,
        metadata={"email": getattr(user, "email", "") or None},
        request=request,
    )


@receiver(user_logged_out)
def log_user_logged_out(sender, request, user, **kwargs):
    if user is None or not getattr(user, "pk", None):
        return
    record_user_activity(
        user=user,
        organization=getattr(user, "organization", None),
        event_type=UserActivityLog.EventType.USER_LOGOUT,
        metadata={},
        request=request,
    )
