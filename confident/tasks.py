import logging
from datetime import timedelta

from celery import shared_task
from django.db import transaction
from django.db.models import Q
from django.utils import timezone

logger = logging.getLogger(__name__)


# ===========================================================================
# 1. EXPIRE SECRETS
# Task utama — dijalankan setiap menit via Celery Beat.
# ===========================================================================

@shared_task(
    bind=True,
    name="secrets.expire_secrets",
    max_retries=3,
    default_retry_delay=60,
    acks_late=True,
)
def expire_secrets(self):
    """
    Tandai semua secret yang sudah melewati expires_at sebagai EXPIRED.
    Dijalankan setiap menit.

    Kenapa per-batch (500)?
    Menghindari lock tabel terlalu lama saat ada ribuan secret expired sekaligus.
    """
    from .models import Secret

    now = timezone.now()
    batch_size = 500
    total_expired = 0

    try:
        while True:
            with transaction.atomic():
                # Ambil ID dulu untuk hindari race condition
                ids = list(
                    Secret.objects.filter(
                        status=Secret.Status.ACTIVE,
                        expires_at__lte=now,
                    ).values_list("id", flat=True)[:batch_size]
                )

                if not ids:
                    break

                updated = Secret.objects.filter(id__in=ids).update(
                    status     = Secret.Status.EXPIRED,
                    expired_at = now,
                )

                # Non-aktifkan semua link dari secret yang expired
                from .models import SecretLink
                SecretLink.objects.filter(
                    secret_id__in=ids,
                    is_active=True,
                ).update(is_active=False)

                total_expired += updated
                logger.info(f"[expire_secrets] Batch: {updated} secret expired.")

                if len(ids) < batch_size:
                    break

        if total_expired:
            logger.info(f"[expire_secrets] Total: {total_expired} secret ditandai expired.")
        return {"expired": total_expired}

    except Exception as exc:
        logger.error(f"[expire_secrets] Error: {exc}", exc_info=True)
        raise self.retry(exc=exc)


# ===========================================================================
# 2. CLEANUP REVOKED SECRETS
# Hapus payload dari secret yang sudah di-revoke > N hari lalu.
# Ini safety net — seharusnya payload sudah dihapus saat revoke().
# Dijalankan setiap jam.
# ===========================================================================

@shared_task(
    bind=True,
    name="secrets.cleanup_revoked_secrets",
    max_retries=3,
    default_retry_delay=300,
    acks_late=True,
)
def cleanup_revoked_secrets(self, older_than_days=1):
    """
    Hapus encrypted_payload dari secret yang sudah di-revoke
    lebih dari older_than_days hari lalu.

    Ini safety net untuk kasus di mana revoke() gagal menghapus payload
    (misal: koneksi DB terputus saat revoke).
    """
    from .models import Secret

    cutoff = timezone.now() - timedelta(days=older_than_days)
    total_cleaned = 0

    try:
        # Cari secret revoked yang masih punya payload (seharusnya sudah kosong)
        qs = Secret.objects.filter(
            status     = Secret.Status.REVOKED,
            revoked_at__lte = cutoff,
        ).exclude(encrypted_payload="")

        count = qs.count()
        if count:
            logger.warning(
                f"[cleanup_revoked] Ditemukan {count} secret revoked yang masih punya payload. "
                f"Menghapus..."
            )
            with transaction.atomic():
                qs.update(
                    encrypted_payload = "",
                    encryption_iv     = "",
                    encryption_tag    = "",
                    encryption_salt   = "",
                )
            total_cleaned = count
            logger.info(f"[cleanup_revoked] {total_cleaned} payload dihapus.")

        return {"cleaned": total_cleaned}

    except Exception as exc:
        logger.error(f"[cleanup_revoked] Error: {exc}", exc_info=True)
        raise self.retry(exc=exc)


# ===========================================================================
# 3. CLEANUP OLD LOGS
# Hapus access log dan AI detection log yang sudah lama.
# Dijalankan setiap hari tengah malam.
# ===========================================================================

@shared_task(
    bind=True,
    name="secrets.cleanup_old_logs",
    max_retries=2,
    default_retry_delay=600,
    acks_late=True,
)
def cleanup_old_logs(self, access_log_days=90, ai_log_days=180):
    """
    Hapus log lama untuk menjaga ukuran DB tetap terkontrol.

    Default:
      - AccessLog    : hapus yang lebih dari 90 hari
      - AIDetectionLog: hapus yang sudah di-review dan lebih dari 180 hari
    """
    from .models import AccessLog, AIDetectionLog

    now = timezone.now()
    results = {}

    try:
        # Hapus access log lama
        access_cutoff = now - timedelta(days=access_log_days)
        deleted_access, _ = AccessLog.objects.filter(
            accessed_at__lte=access_cutoff
        ).delete()
        results["access_logs_deleted"] = deleted_access
        logger.info(f"[cleanup_logs] {deleted_access} access log dihapus (>{access_log_days} hari).")

        # Hapus AI detection log lama yang sudah di-review
        ai_cutoff = now - timedelta(days=ai_log_days)
        deleted_ai, _ = AIDetectionLog.objects.filter(
            created_at__lte = ai_cutoff,
            reviewed_at__isnull = False,  # hanya yang sudah di-review
        ).delete()
        results["ai_logs_deleted"] = deleted_ai
        logger.info(f"[cleanup_logs] {deleted_ai} AI log dihapus (>{ai_log_days} hari, sudah review).")

        return results

    except Exception as exc:
        logger.error(f"[cleanup_logs] Error: {exc}", exc_info=True)
        raise self.retry(exc=exc)


# ===========================================================================
# 4. RESET ANON COUNTERS
# Reset daily_count semua AnonymousSession yang belum di-reset hari ini.
# Dijalankan setiap tengah malam (00:00).
# ===========================================================================

@shared_task(
    bind=True,
    name="secrets.reset_anon_counters",
    max_retries=2,
    default_retry_delay=300,
    acks_late=True,
)
def reset_anon_counters(self):
    """
    Reset counter harian semua anonymous session.
    Dijalankan tepat tengah malam setiap hari.

    Kenapa ada task ini padahal AnonymousSession.reset_if_new_day() sudah ada?
    Karena reset_if_new_day() hanya berjalan saat ada request masuk.
    Sesi yang tidak aktif tidak pernah ter-reset lewat request,
    tapi kita tetap ingin datanya bersih.
    """
    from .models import AnonymousSession

    today = timezone.now().date()

    try:
        updated = AnonymousSession.objects.filter(
            last_reset_date__lt=today,
            daily_count__gt=0,
        ).update(
            daily_count     = 0,
            last_reset_date = today,
        )
        logger.info(f"[reset_anon] {updated} sesi anon di-reset.")
        return {"reset": updated}

    except Exception as exc:
        logger.error(f"[reset_anon] Error: {exc}", exc_info=True)
        raise self.retry(exc=exc)


# ===========================================================================
# 5. CLEANUP OLD ANON SESSIONS
# Hapus sesi anon yang sudah lama tidak aktif.
# Dijalankan setiap minggu.
# ===========================================================================

@shared_task(
    bind=True,
    name="secrets.cleanup_anon_sessions",
    max_retries=2,
    default_retry_delay=600,
    acks_late=True,
)
def cleanup_anon_sessions(self, inactive_days=30):
    """
    Hapus AnonymousSession yang tidak aktif lebih dari inactive_days hari.
    Sesi dianggap tidak aktif jika tidak ada secret aktif yang terkait.
    """
    from .models import AnonymousSession, Secret

    cutoff = timezone.now() - timedelta(days=inactive_days)

    try:
        # Cari ID sesi anon yang sudah lama
        old_sessions = AnonymousSession.objects.filter(
            updated_at__lte=cutoff
        )

        # Exclude sesi yang masih punya secret aktif
        active_session_ids = Secret.objects.filter(
            anon_session__isnull=False,
            status=Secret.Status.ACTIVE,
        ).values_list("anon_session_id", flat=True).distinct()

        to_delete = old_sessions.exclude(id__in=active_session_ids)
        count     = to_delete.count()

        if count:
            to_delete.delete()
            logger.info(f"[cleanup_anon] {count} sesi anon lama dihapus.")

        return {"deleted": count}

    except Exception as exc:
        logger.error(f"[cleanup_anon] Error: {exc}", exc_info=True)
        raise self.retry(exc=exc)


# ===========================================================================
# 6. GENERATE DAILY REPORT
# Buat ringkasan statistik harian dan simpan ke log.
# Dijalankan setiap hari jam 07:00.
# ===========================================================================

@shared_task(
    bind=True,
    name="secrets.generate_daily_report",
    max_retries=2,
    default_retry_delay=300,
)
def generate_daily_report(self):
    """
    Buat ringkasan statistik 24 jam terakhir.
    Hasilnya di-log — bisa diperluas untuk kirim email ke admin.
    """
    from .models import Secret, AccessLog, AIDetectionLog, User

    now       = timezone.now()
    yesterday = now - timedelta(hours=24)

    try:
        new_secrets     = Secret.objects.filter(created_at__gte=yesterday).count()
        expired_secrets = Secret.objects.filter(
            status=Secret.Status.EXPIRED,
            expired_at__gte=yesterday,
        ).count()
        revoked_secrets = Secret.objects.filter(
            status=Secret.Status.REVOKED,
            revoked_at__gte=yesterday,
        ).count()
        blocked_secrets = Secret.objects.filter(
            status=Secret.Status.BLOCKED,
            updated_at__gte=yesterday,
        ).count()

        total_access    = AccessLog.objects.filter(accessed_at__gte=yesterday).count()
        denied_access   = AccessLog.objects.filter(
            accessed_at__gte=yesterday
        ).exclude(result="success").count()

        flagged_count   = AIDetectionLog.objects.filter(
            action_taken="flagged",
            created_at__gte=yesterday,
        ).count()
        blocked_by_ai   = AIDetectionLog.objects.filter(
            action_taken="blocked",
            created_at__gte=yesterday,
        ).count()

        new_users       = User.objects.filter(created_at__gte=yesterday).count()
        active_secrets  = Secret.objects.filter(status=Secret.Status.ACTIVE).count()
        pending_review  = AIDetectionLog.objects.filter(reviewed_at__isnull=True).count()

        report = {
            "period":        "last_24h",
            "generated_at":  now.isoformat(),
            "secrets": {
                "new":     new_secrets,
                "expired": expired_secrets,
                "revoked": revoked_secrets,
                "blocked": blocked_secrets,
                "active_total": active_secrets,
            },
            "access": {
                "total":  total_access,
                "denied": denied_access,
                "success_rate": (
                    round((total_access - denied_access) / total_access * 100, 1)
                    if total_access else 100.0
                ),
            },
            "ai_detection": {
                "flagged":        flagged_count,
                "blocked":        blocked_by_ai,
                "pending_review": pending_review,
            },
            "users": {
                "new_registrations": new_users,
            },
        }

        logger.info(f"[daily_report] {report}")
        return report

    except Exception as exc:
        logger.error(f"[daily_report] Error: {exc}", exc_info=True)
        raise self.retry(exc=exc)


# ===========================================================================
# 7. EXPIRE EXHAUSTED SECRETS
# Secret yang sudah habis view count-nya tapi belum di-expire
# (edge case: kalau increment_view() gagal update status).
# Dijalankan setiap 15 menit sebagai safety net.
# ===========================================================================

@shared_task(
    bind=True,
    name="secrets.expire_exhausted_secrets",
    max_retries=3,
    default_retry_delay=60,
    acks_late=True,
)
def expire_exhausted_secrets(self):
    """
    Tandai expired semua secret aktif yang current_views >= max_views.
    Safety net untuk edge case di mana model.increment_view() tidak
    sempat mengupdate status (misal: crash antara dua operasi DB).
    """
    from .models import Secret, SecretLink
    from django.db.models import F

    now = timezone.now()
    total = 0

    try:
        with transaction.atomic():
            # Secret dengan max_views > 0 dan sudah habis views-nya
            ids = list(
                Secret.objects.filter(
                    status=Secret.Status.ACTIVE,
                    max_views__gt=0,
                    current_views__gte=F("max_views"),
                ).values_list("id", flat=True)[:500]
            )

            if ids:
                Secret.objects.filter(id__in=ids).update(
                    status     = Secret.Status.EXPIRED,
                    expired_at = now,
                )
                SecretLink.objects.filter(
                    secret_id__in=ids,
                    is_active=True,
                ).update(is_active=False)
                total = len(ids)
                logger.info(f"[expire_exhausted] {total} secret di-expire karena views habis.")

        return {"expired": total}

    except Exception as exc:
        logger.error(f"[expire_exhausted] Error: {exc}", exc_info=True)
        raise self.retry(exc=exc)