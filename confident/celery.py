import os
from celery import Celery
from celery.schedules import crontab

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")

app = Celery("confidential_sharing")
app.config_from_object("django.conf:settings", namespace="CELERY")
app.autodiscover_tasks()


# ---------------------------------------------------------------------------
# Beat Schedule
# Semua waktu dalam UTC. WIB = UTC+7.
# ---------------------------------------------------------------------------

app.conf.beat_schedule = {

    # Expire secrets + hapus payload — setiap 1 menit
    "expire-secrets-every-minute": {
        "task":     "secrets.expire_secrets",
        "schedule": 60.0,
        "options":  {"expires": 50},
    },

    # Safety net view count habis — setiap 15 menit
    "expire-exhausted-every-15min": {
        "task":     "secrets.expire_exhausted_secrets",
        "schedule": 60.0 * 15,
        "options":  {"expires": 60 * 14},
    },

    # Safety net revoked payload — setiap jam
    "cleanup-revoked-every-hour": {
        "task":     "secrets.cleanup_revoked_secrets",
        "schedule": crontab(minute=0),
        "kwargs":   {"older_than_days": 1},
    },

    # Hapus row expired setelah 7 hari — setiap hari 01:00 WIB (18:00 UTC)
    "cleanup-expired-rows-daily": {
        "task":     "secrets.cleanup_expired_rows",
        "schedule": crontab(hour=18, minute=0),
        "kwargs":   {"expired_row_days": 7},
    },

    # Hapus log lama — setiap hari 02:00 WIB (19:00 UTC)
    "cleanup-old-logs-daily": {
        "task":     "secrets.cleanup_old_logs",
        "schedule": crontab(hour=19, minute=0),
        "kwargs":   {"access_log_days": 30, "ai_log_days": 90},
    },

    # Reset anon counter — setiap hari 00:00 WIB (17:00 UTC)
    "reset-anon-counters-midnight": {
        "task":     "secrets.reset_anon_counters",
        "schedule": crontab(hour=17, minute=0),
    },

    # Hapus sesi anon lama — setiap Minggu 03:00 WIB (20:00 UTC)
    "cleanup-anon-sessions-weekly": {
        "task":     "secrets.cleanup_anon_sessions",
        "schedule": crontab(hour=20, minute=0, day_of_week="sunday"),
        "kwargs":   {"inactive_days": 30},
    },

    # Daily report — setiap hari 07:00 WIB (00:00 UTC)
    "generate-daily-report": {
        "task":     "secrets.generate_daily_report",
        "schedule": crontab(hour=0, minute=0),
    },
}

app.conf.timezone          = "Asia/Jakarta"
app.conf.enable_utc        = True
app.conf.task_serializer   = "json"
app.conf.result_serializer = "json"
app.conf.accept_content    = ["json"]
app.conf.task_acks_late             = True
app.conf.worker_prefetch_multiplier = 1
app.conf.task_reject_on_worker_lost = True
app.conf.result_expires             = 60 * 60 * 24