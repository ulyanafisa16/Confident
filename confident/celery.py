

import os
from celery import Celery
from celery.schedules import crontab

# Ganti "config" dengan nama folder project Django kamu
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "confident.settings")

app = Celery("confident")

# Baca semua konfigurasi CELERY_* dari settings.py
app.config_from_object("django.conf:settings", namespace="CELERY")

# Auto-discover tasks dari semua app yang terdaftar di INSTALLED_APPS
app.autodiscover_tasks()


# ---------------------------------------------------------------------------
# Beat Schedule
# ---------------------------------------------------------------------------

app.conf.beat_schedule = {

    # ── Expire secrets setiap 1 menit ──────────────────────────────────────
    "expire-secrets-every-minute": {
        "task":     "secrets.expire_secrets",
        "schedule": 60.0,  # detik
        "options":  {"expires": 50},  # task kedaluwarsa jika tidak jalan dalam 50 detik
    },

    # ── Expire exhausted (view habis) setiap 15 menit ──────────────────────
    "expire-exhausted-every-15min": {
        "task":     "secrets.expire_exhausted_secrets",
        "schedule": 60.0 * 15,
        "options":  {"expires": 60 * 14},
    },

    # ── Cleanup revoked payload setiap 1 jam ───────────────────────────────
    "cleanup-revoked-every-hour": {
        "task":     "secrets.cleanup_revoked_secrets",
        "schedule": crontab(minute=0),  # setiap awal jam
        "kwargs":   {"older_than_days": 1},
    },

    # ── Reset anon counter setiap tengah malam (00:00 WIB = 17:00 UTC) ────
    "reset-anon-counters-midnight": {
        "task":     "secrets.reset_anon_counters",
        "schedule": crontab(hour=17, minute=0),  # 17:00 UTC = 00:00 WIB
    },

    # ── Cleanup log lama setiap hari jam 02:00 WIB (19:00 UTC) ────────────
    "cleanup-old-logs-daily": {
        "task":     "secrets.cleanup_old_logs",
        "schedule": crontab(hour=19, minute=0),
        "kwargs":   {
            "access_log_days": 90,
            "ai_log_days":     180,
        },
    },

    # ── Cleanup anon session setiap Minggu jam 03:00 WIB (20:00 UTC) ──────
    "cleanup-anon-sessions-weekly": {
        "task":     "secrets.cleanup_anon_sessions",
        "schedule": crontab(hour=20, minute=0, day_of_week="sunday"),
        "kwargs":   {"inactive_days": 30},
    },

    # ── Daily report setiap hari jam 07:00 WIB (00:00 UTC) ────────────────
    "generate-daily-report": {
        "task":     "secrets.generate_daily_report",
        "schedule": crontab(hour=0, minute=0),
    },
}

