from django.db.models.signals import post_save
from django.dispatch import receiver
from django.utils import timezone
from .models import Secret, User
from django.db import models


@receiver(post_save, sender=Secret)
def update_user_secret_count(sender, instance, created, **kwargs):
    """Update total_secrets_created di User setiap kali secret baru dibuat."""
    if created and instance.creator_user:
        User.objects.filter(pk=instance.creator_user_id).update(
            total_secrets_created=models.F("total_secrets_created") + 1
        )


@receiver(post_save, sender=Secret)
def auto_expire_check(sender, instance, **kwargs):
    """
    Tandai secret sebagai expired jika sudah melewati expires_at.
    Ini backup — Celery beat task yang jadi primary mekanisme expire.
    """
    if (
        instance.status == Secret.Status.ACTIVE
        and instance.expires_at
        and timezone.now() > instance.expires_at
    ):
        # Hindari rekursi dengan update langsung ke DB
        Secret.objects.filter(pk=instance.pk).update(
            status=Secret.Status.EXPIRED,
            expired_at=timezone.now(),
        )
