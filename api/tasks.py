import logging
from datetime import timedelta

from celery import shared_task
from django.db import transaction
from django.db.models import F, Q
from django.utils import timezone

logger = logging.getLogger(__name__)


# ===========================================================================
# 1. EXPIRE SECRETS
# Task utama — dijalankan setiap menit via Celery Beat.
# Perubahan dari versi awal: payload langsung dihapus saat expire,
# tidak menunggu 90 hari. Ini menghemat storage secara signifikan.
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
    Tandai semua secret yang sudah melewati expires_at sebagai EXPIRED
    dan langsung hapus payload terenkripsinya.

    Kenapa payload langsung dihapus?
    encrypted_payload adalah kolom terbesar (bisa puluhan KB–MB per row).
    Menunggu 90 hari berarti menyimpan data besar yang tidak terpakai.
    Server tidak bisa membacanya (ZKE) dan penerima sudah tidak bisa akses —
    tidak ada alasan mempertahankannya.

    Row secret tetap ada selama 7 hari untuk keperluan audit singkat,
    kemudian dihapus oleh cleanup_expired_rows.

    Kenapa per-batch (500)?
    Menghindari lock tabel terlalu lama saat ada ribuan secret expired sekaligus.
    """
    from .models import Secret, SecretLink

    now        = timezone.now()
    batch_size = 500
    total      = 0

    try:
        while True:
            with transaction.atomic():
                ids = list(
                    Secret.objects.filter(
                        status          = Secret.Status.ACTIVE,
                        expires_at__lte = now,
                    ).values_list("id", flat=True)[:batch_size]
                )

                if not ids:
                    break

                # Update status + hapus payload sekaligus dalam satu query
                Secret.objects.filter(id__in=ids).update(
                    status            = Secret.Status.EXPIRED,
                    expired_at        = now,
                    encrypted_payload = "",
                    encryption_iv     = "",
                    encryption_tag    = "",
                    encryption_salt   = "",
                )

                SecretLink.objects.filter(
                    secret_id__in=ids,
                    is_active=True,
                ).update(is_active=False)

                total += len(ids)
                logger.info(
                    f"[expire_secrets] Batch: {len(ids)} secret expired + payload dihapus."
                )

                if len(ids) < batch_size:
                    break

        if total:
            logger.info(f"[expire_secrets] Total: {total} secret expired.")
        return {"expired": total}

    except Exception as exc:
        logger.error(f"[expire_secrets] Error: {exc}", exc_info=True)
        raise self.retry(exc=exc)


# ===========================================================================
# 2. EXPIRE EXHAUSTED SECRETS
# Secret yang view count-nya habis tapi belum di-expire.
# Edge case: increment_view() crash sebelum update status.
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
    Tandai expired semua secret aktif yang current_views >= max_views,
    dan langsung hapus payload-nya (konsisten dengan expire_secrets).

    Safety net untuk edge case di mana model.increment_view() tidak
    sempat mengupdate status (misal: crash antara dua operasi DB).
    """
    from .models import Secret, SecretLink

    now   = timezone.now()
    total = 0

    try:
        with transaction.atomic():
            ids = list(
                Secret.objects.filter(
                    status              = Secret.Status.ACTIVE,
                    max_views__gt       = 0,
                    current_views__gte  = F("max_views"),
                ).values_list("id", flat=True)[:500]
            )

            if ids:
                Secret.objects.filter(id__in=ids).update(
                    status            = Secret.Status.EXPIRED,
                    expired_at        = now,
                    encrypted_payload = "",
                    encryption_iv     = "",
                    encryption_tag    = "",
                    encryption_salt   = "",
                )
                SecretLink.objects.filter(
                    secret_id__in=ids,
                    is_active=True,
                ).update(is_active=False)
                total = len(ids)
                logger.info(
                    f"[expire_exhausted] {total} secret di-expire "
                    f"karena views habis + payload dihapus."
                )

        return {"expired": total}

    except Exception as exc:
        logger.error(f"[expire_exhausted] Error: {exc}", exc_info=True)
        raise self.retry(exc=exc)


# ===========================================================================
# 3. CLEANUP REVOKED SECRETS
# Safety net — payload seharusnya sudah dihapus saat revoke().
# Cek ulang setiap jam kalau ada yang lolos (misal koneksi DB putus saat revoke).
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
    lebih dari older_than_days hari lalu, jika ternyata masih ada.

    Ini murni safety net — revoke() seharusnya sudah menghapus payload
    secara langsung. Task ini menangani edge case kegagalan operasi DB.
    """
    from .models import Secret

    cutoff        = timezone.now() - timedelta(days=older_than_days)
    total_cleaned = 0

    try:
        qs = Secret.objects.filter(
            status          = Secret.Status.REVOKED,
            revoked_at__lte = cutoff,
        ).exclude(encrypted_payload="")

        count = qs.count()
        if count:
            logger.warning(
                f"[cleanup_revoked] {count} secret revoked masih punya payload — menghapus..."
            )
            with transaction.atomic():
                qs.update(
                    encrypted_payload = "",
                    encryption_iv     = "",
                    encryption_tag    = "",
                    encryption_salt   = "",
                )
            total_cleaned = count
            logger.info(f"[cleanup_revoked] {total_cleaned} payload dibersihkan.")

        return {"cleaned": total_cleaned}

    except Exception as exc:
        logger.error(f"[cleanup_revoked] Error: {exc}", exc_info=True)
        raise self.retry(exc=exc)


# ===========================================================================
# 4. CLEANUP EXPIRED ROWS
# Hapus row secret yang sudah expired lebih dari 7 hari.
# Payload sudah kosong (dihapus saat expire) — yang dihapus hanya metadata.
# Dijalankan setiap hari jam 01:00 WIB.
# ===========================================================================

@shared_task(
    bind=True,
    name="secrets.cleanup_expired_rows",
    max_retries=2,
    default_retry_delay=300,
    acks_late=True,
)
def cleanup_expired_rows(self, expired_row_days=7):
    """
    Hapus row secret yang sudah expired lebih dari expired_row_days hari.

    Pada titik ini encrypted_payload sudah kosong (dihapus saat expire_secrets).
    Yang dihapus hanya metadata ringan: UUID, timestamps, status (~500 bytes/row).
    Cascade delete otomatis menghapus secret_links dan email_whitelist terkait.

    Kenapa 7 hari?
    Cukup untuk creator melihat riwayat singkat di dashboard,
    tapi tidak terlalu lama memenuhi tabel.
    """
    from .models import Secret

    cutoff = timezone.now() - timedelta(days=expired_row_days)
    total  = 0

    try:
        while True:
            with transaction.atomic():
                ids = list(
                    Secret.objects.filter(
                        status          = Secret.Status.EXPIRED,
                        expired_at__lte = cutoff,
                    ).values_list("id", flat=True)[:500]
                )

                if not ids:
                    break

                deleted, _ = Secret.objects.filter(id__in=ids).delete()
                total += deleted
                logger.info(f"[cleanup_expired_rows] Batch: {deleted} row dihapus.")

                if len(ids) < 500:
                    break

        if total:
            logger.info(
                f"[cleanup_expired_rows] Total: {total} row expired dihapus "
                f"(lebih dari {expired_row_days} hari)."
            )
        return {"deleted_rows": total}

    except Exception as exc:
        logger.error(f"[cleanup_expired_rows] Error: {exc}", exc_info=True)
        raise self.retry(exc=exc)


# ===========================================================================
# 5. CLEANUP OLD LOGS
# Hapus access log dan AI detection log yang sudah lama.
# Dijalankan setiap hari jam 02:00 WIB.
# ===========================================================================

@shared_task(
    bind=True,
    name="secrets.cleanup_old_logs",
    max_retries=2,
    default_retry_delay=600,
    acks_late=True,
)
def cleanup_old_logs(self, access_log_days=30, ai_log_days=90):
    """
    Hapus log lama untuk menjaga ukuran DB tetap terkontrol.

    Threshold:
      access_log_days = 30  — cukup untuk investigasi abuse 1 bulan terakhir
      ai_log_days     = 90  — cukup untuk audit trail moderasi per kuartal

    Catatan: AI log yang belum di-review TIDAK dihapus —
    admin harus review dulu sebelum bisa terhapus otomatis.
    """
    from .models import AccessLog, AIDetectionLog

    now     = timezone.now()
    results = {}

    try:
        # Hapus access log > 30 hari
        access_cutoff     = now - timedelta(days=access_log_days)
        deleted_access, _ = AccessLog.objects.filter(
            accessed_at__lte=access_cutoff
        ).delete()
        results["access_logs_deleted"] = deleted_access
        logger.info(
            f"[cleanup_logs] {deleted_access} access log dihapus "
            f"(>{access_log_days} hari)."
        )

        # Hapus AI detection log > 90 hari yang sudah di-review
        ai_cutoff     = now - timedelta(days=ai_log_days)
        deleted_ai, _ = AIDetectionLog.objects.filter(
            created_at__lte     = ai_cutoff,
            reviewed_at__isnull = False,
        ).delete()
        results["ai_logs_deleted"] = deleted_ai
        logger.info(
            f"[cleanup_logs] {deleted_ai} AI log dihapus "
            f"(>{ai_log_days} hari, sudah di-review)."
        )

        return results

    except Exception as exc:
        logger.error(f"[cleanup_logs] Error: {exc}", exc_info=True)
        raise self.retry(exc=exc)


# ===========================================================================
# 6. RESET ANON COUNTERS
# Reset daily_count semua AnonymousSession yang belum di-reset hari ini.
# Dijalankan setiap tengah malam (00:00 WIB).
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

    Melengkapi AnonymousSession.reset_if_new_day() yang hanya berjalan
    saat ada request masuk. Task ini memastikan sesi yang tidak aktif
    juga ter-reset tepat waktu.
    """
    from .models import AnonymousSession

    today = timezone.now().date()

    try:
        updated = AnonymousSession.objects.filter(
            last_reset_date__lt = today,
            daily_count__gt     = 0,
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
# 7. CLEANUP OLD ANON SESSIONS
# Hapus sesi anon yang sudah lama tidak aktif.
# Dijalankan setiap Minggu jam 03:00 WIB.
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
        old_sessions = AnonymousSession.objects.filter(updated_at__lte=cutoff)

        # Exclude sesi yang masih punya secret aktif
        active_session_ids = Secret.objects.filter(
            anon_session__isnull = False,
            status               = Secret.Status.ACTIVE,
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
# 8. GENERATE DAILY REPORT
# Ringkasan statistik harian — di-log dan bisa diperluas untuk kirim email.
# Dijalankan setiap hari jam 07:00 WIB.
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
            status=Secret.Status.EXPIRED, expired_at__gte=yesterday,
        ).count()
        revoked_secrets = Secret.objects.filter(
            status=Secret.Status.REVOKED, revoked_at__gte=yesterday,
        ).count()
        blocked_secrets = Secret.objects.filter(
            status=Secret.Status.BLOCKED, updated_at__gte=yesterday,
        ).count()

        total_access  = AccessLog.objects.filter(accessed_at__gte=yesterday).count()
        denied_access = AccessLog.objects.filter(
            accessed_at__gte=yesterday
        ).exclude(result="success").count()

        flagged_count = AIDetectionLog.objects.filter(
            action_taken="flagged", created_at__gte=yesterday,
        ).count()
        blocked_by_ai = AIDetectionLog.objects.filter(
            action_taken="blocked", created_at__gte=yesterday,
        ).count()

        new_users      = User.objects.filter(created_at__gte=yesterday).count()
        active_secrets = Secret.objects.filter(status=Secret.Status.ACTIVE).count()
        pending_review = AIDetectionLog.objects.filter(reviewed_at__isnull=True).count()

        report = {
            "period":       "last_24h",
            "generated_at": now.isoformat(),
            "secrets": {
                "new":          new_secrets,
                "expired":      expired_secrets,
                "revoked":      revoked_secrets,
                "blocked":      blocked_secrets,
                "active_total": active_secrets,
            },
            "access": {
                "total":        total_access,
                "denied":       denied_access,
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