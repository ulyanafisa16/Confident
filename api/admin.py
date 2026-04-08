from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.utils import timezone
from django.utils.html import format_html
from django.db.models import Count

from .models import (
    User, AnonymousSession, Secret, SecretLink,
    EmailWhitelist, AccessLog, AIDetectionLog, RateLimitConfig,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def badge(color, text):
    """Render badge berwarna di admin list."""
    colors = {
        "green":  "#d1fae5; color: #065f46",
        "red":    "#fee2e2; color: #991b1b",
        "amber":  "#fef3c7; color: #92400e",
        "blue":   "#dbeafe; color: #1e40af",
        "gray":   "#f3f4f6; color: #374151",
    }
    style = colors.get(color, colors["gray"])
    return format_html(
        '<span style="padding:2px 8px; border-radius:4px; font-size:11px; '
        'font-weight:600; background:{}">{}</span>',
        style, text
    )


# ---------------------------------------------------------------------------
# 1. USER ADMIN
# ---------------------------------------------------------------------------

@admin.register(User)
class UserAdmin(BaseUserAdmin):
    list_display    = ("email", "full_name", "role_badge", "is_banned_badge",
                       "total_secrets_created", "created_at")
    list_filter     = ("role", "is_banned", "is_active", "is_staff")
    search_fields   = ("email", "full_name")
    ordering        = ("-created_at",)
    readonly_fields = ("id", "created_at", "updated_at", "total_secrets_created")

    fieldsets = (
        ("Akun", {"fields": ("id", "email", "password")}),
        ("Profil", {"fields": ("full_name", "role")}),
        ("Status", {"fields": ("is_active", "is_banned", "is_staff", "is_superuser")}),
        ("Statistik", {"fields": ("total_secrets_created",)}),
        ("Timestamps", {"fields": ("created_at", "updated_at")}),
    )
    add_fieldsets = (
        (None, {
            "classes": ("wide",),
            "fields": ("email", "full_name", "role", "password1", "password2"),
        }),
    )

    actions = ["ban_users", "unban_users", "promote_to_admin"]

    @admin.display(description="Role")
    def role_badge(self, obj):
        color = "blue" if obj.is_admin else "gray"
        return badge(color, obj.get_role_display())

    @admin.display(description="Status")
    def is_banned_badge(self, obj):
        if obj.is_banned:
            return badge("red", "Banned")
        return badge("green", "Aktif")

    @admin.action(description="Ban user terpilih")
    def ban_users(self, request, queryset):
        queryset.update(is_banned=True, is_active=False)
        self.message_user(request, f"{queryset.count()} user dibanned.")

    @admin.action(description="Unban user terpilih")
    def unban_users(self, request, queryset):
        queryset.update(is_banned=False, is_active=True)
        self.message_user(request, f"{queryset.count()} user di-unban.")

    @admin.action(description="Jadikan admin")
    def promote_to_admin(self, request, queryset):
        queryset.update(role=User.Role.ADMIN, is_staff=True)
        self.message_user(request, f"{queryset.count()} user dijadikan admin.")


# ---------------------------------------------------------------------------
# 2. ANONYMOUS SESSION ADMIN
# ---------------------------------------------------------------------------

@admin.register(AnonymousSession)
class AnonymousSessionAdmin(admin.ModelAdmin):
    list_display  = ("ip_address", "fingerprint_hash", "daily_count", "last_reset_date", "created_at")
    list_filter   = ("last_reset_date",)
    search_fields = ("ip_address", "fingerprint_hash")
    readonly_fields = ("id", "created_at", "updated_at")


# ---------------------------------------------------------------------------
# 3. SECRET LINK INLINE (untuk SecretAdmin)
# ---------------------------------------------------------------------------

class SecretLinkInline(admin.TabularInline):
    model         = SecretLink
    extra         = 0
    readonly_fields = ("token", "is_active", "accessed_count", "last_accessed",
                       "created_at", "revoked_at")
    fields        = ("token", "label", "is_active", "accessed_count",
                     "last_accessed", "revoked_at")
    can_delete    = False
    show_change_link = True


class EmailWhitelistInline(admin.TabularInline):
    model         = EmailWhitelist
    extra         = 1
    fields        = ("email", "access_count", "accessed_at")
    readonly_fields = ("access_count", "accessed_at")


# ---------------------------------------------------------------------------
# 4. SECRET ADMIN
# ---------------------------------------------------------------------------

@admin.register(Secret)
class SecretAdmin(admin.ModelAdmin):
    list_display  = ("short_id", "secret_type", "creator_display", "status_badge",
                     "ai_score_badge", "ai_flagged", "current_views", "max_views",
                     "expires_at", "created_at")
    list_filter   = ("status", "secret_type", "ai_flagged", "creator_user__role")
    search_fields = ("id", "creator_user__email", "mime_type")
    ordering      = ("-created_at",)
    readonly_fields = (
        "id", "creator_user", "anon_session", "secret_type",
        "encrypted_payload", "encryption_iv", "encryption_tag", "encryption_salt",
        "current_views", "ai_risk_score", "revoke_token",
        "created_at", "updated_at", "revoked_at", "expired_at",
        "file_size_bytes", "mime_type", "original_filename",
    )
    inlines       = [SecretLinkInline, EmailWhitelistInline]
    actions       = ["block_secrets", "approve_flagged", "force_revoke"]

    fieldsets = (
        ("Identitas", {
            "fields": ("id", "creator_user", "anon_session", "secret_type",
                       "original_filename", "mime_type", "file_size_bytes")
        }),
        ("Payload terenkripsi (ZKE)", {
            "fields": ("encrypted_payload", "encryption_iv", "encryption_tag", "encryption_salt"),
            "classes": ("collapse",),
            "description": "Server tidak bisa mendekripsi ini. Hanya tampil untuk audit.",
        }),
        ("Akses & expiry", {
            "fields": ("max_views", "current_views", "expires_at", "access_password_hash"),
        }),
        ("Status & AI", {
            "fields": ("status", "ai_risk_score", "ai_flagged"),
        }),
        ("Revoke", {
            "fields": ("revoke_token", "revoked_at", "expired_at"),
        }),
        ("Timestamps", {
            "fields": ("created_at", "updated_at"),
        }),
    )

    @admin.display(description="ID")
    def short_id(self, obj):
        return str(obj.id)[:8] + "..."

    @admin.display(description="Pembuat")
    def creator_display(self, obj):
        if obj.creator_user:
            return obj.creator_user.email
        return format_html('<span style="color:#6b7280">anon</span>')

    @admin.display(description="Status")
    def status_badge(self, obj):
        color_map = {
            "active":  "green",
            "revoked": "gray",
            "expired": "amber",
            "blocked": "red",
        }
        return badge(color_map.get(obj.status, "gray"), obj.get_status_display())

    @admin.display(description="AI Score")
    def ai_score_badge(self, obj):
        score = obj.ai_risk_score
        if score >= 70:
            color = "red"
        elif score >= 40:
            color = "amber"
        else:
            color = "green"
        return badge(color, str(score))

    @admin.action(description="Blokir secret terpilih")
    def block_secrets(self, request, queryset):
        queryset.update(status=Secret.Status.BLOCKED)
        self.message_user(request, f"{queryset.count()} secret diblokir.")

    @admin.action(description="Approve flagged secret (izinkan)")
    def approve_flagged(self, request, queryset):
        queryset.update(ai_flagged=False)
        self.message_user(request, f"{queryset.count()} secret di-approve.")

    @admin.action(description="Force revoke + hapus payload")
    def force_revoke(self, request, queryset):
        for secret in queryset:
            secret.revoke(hard_delete_payload=True)
        self.message_user(request, f"{queryset.count()} secret di-revoke dan payload dihapus.")


# ---------------------------------------------------------------------------
# 5. SECRET LINK ADMIN
# ---------------------------------------------------------------------------

@admin.register(SecretLink)
class SecretLinkAdmin(admin.ModelAdmin):
    list_display  = ("token", "secret_short", "label", "is_active",
                     "accessed_count", "last_accessed", "created_at")
    list_filter   = ("is_active",)
    search_fields = ("token", "label", "secret__id")
    readonly_fields = ("id", "secret", "token", "accessed_count",
                       "last_accessed", "created_at", "revoked_at")
    actions = ["revoke_links"]

    @admin.display(description="Secret")
    def secret_short(self, obj):
        return str(obj.secret_id)[:8] + "..."

    @admin.action(description="Revoke link terpilih")
    def revoke_links(self, request, queryset):
        for link in queryset:
            link.revoke()
        self.message_user(request, f"{queryset.count()} link di-revoke.")


# ---------------------------------------------------------------------------
# 6. EMAIL WHITELIST ADMIN
# ---------------------------------------------------------------------------

@admin.register(EmailWhitelist)
class EmailWhitelistAdmin(admin.ModelAdmin):
    list_display  = ("email", "secret_short", "access_count", "accessed_at", "created_at")
    search_fields = ("email", "secret__id")
    readonly_fields = ("id", "accessed_at", "access_count", "created_at")

    @admin.display(description="Secret")
    def secret_short(self, obj):
        return str(obj.secret_id)[:8] + "..."


# ---------------------------------------------------------------------------
# 7. ACCESS LOG ADMIN (read-only)
# ---------------------------------------------------------------------------

@admin.register(AccessLog)
class AccessLogAdmin(admin.ModelAdmin):
    list_display  = ("accessed_at", "secret_link_token", "result_badge",
                     "accessed_by_email", "ip_address")
    list_filter   = ("result", "accessed_at")
    search_fields = ("accessed_by_email", "ip_address", "secret_link__token")
    readonly_fields = ("id", "secret_link", "accessed_by_email", "ip_address",
                       "user_agent", "referer", "result", "accessed_at")
    ordering      = ("-accessed_at",)

    # Tidak ada yang boleh diedit — ini pure audit log
    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    @admin.display(description="Link token")
    def secret_link_token(self, obj):
        return obj.secret_link.token

    @admin.display(description="Hasil")
    def result_badge(self, obj):
        color = "green" if obj.result == "success" else "red"
        return badge(color, obj.get_result_display())


# ---------------------------------------------------------------------------
# 8. AI DETECTION LOG ADMIN
# ---------------------------------------------------------------------------

@admin.register(AIDetectionLog)
class AIDetectionLogAdmin(admin.ModelAdmin):
    list_display  = ("created_at", "source_badge", "ai_score_badge",
                     "action_badge", "rules_summary", "reviewed_badge")
    list_filter   = ("action_taken", "source", "reviewed_at")
    search_fields = ("ip_address", "secret__id")
    readonly_fields = ("id", "secret", "source", "rules_triggered", "risk_score",
                       "action_taken", "ip_address", "file_size_bytes",
                       "secret_type", "created_at")
    ordering      = ("-created_at",)
    actions       = ["mark_as_reviewed_safe", "mark_as_reviewed_block"]

    fieldsets = (
        ("Detection", {
            "fields": ("id", "secret", "source", "rules_triggered",
                       "risk_score", "action_taken")
        }),
        ("Metadata", {
            "fields": ("ip_address", "file_size_bytes", "secret_type"),
        }),
        ("Review admin", {
            "fields": ("admin_note", "reviewed_by", "reviewed_at"),
        }),
        ("Timestamps", {
            "fields": ("created_at",),
        }),
    )

    @admin.display(description="Source")
    def source_badge(self, obj):
        color = "blue" if obj.source == "client" else "purple" if obj.source == "server" else "gray"
        return badge(color, obj.get_source_display())

    @admin.display(description="Score")
    def ai_score_badge(self, obj):
        score = obj.risk_score
        if score >= 70:
            return badge("red", str(score))
        elif score >= 40:
            return badge("amber", str(score))
        return badge("green", str(score))

    @admin.display(description="Action")
    def action_badge(self, obj):
        color_map = {"allowed": "green", "flagged": "amber", "blocked": "red"}
        return badge(color_map.get(obj.action_taken, "gray"), obj.get_action_taken_display())

    @admin.display(description="Rules")
    def rules_summary(self, obj):
        rules = obj.rules_triggered or []
        if not rules:
            return "-"
        return ", ".join(rules[:2]) + (f" +{len(rules)-2}" if len(rules) > 2 else "")

    @admin.display(description="Reviewed")
    def reviewed_badge(self, obj):
        if obj.reviewed_at:
            return badge("green", "Sudah review")
        return badge("amber", "Belum review")

    @admin.action(description="Tandai sudah review — aman")
    def mark_as_reviewed_safe(self, request, queryset):
        for log in queryset:
            log.mark_reviewed(request.user, note="Marked safe via admin action.")
            if log.secret:
                log.secret.ai_flagged = False
                log.secret.save(update_fields=["ai_flagged"])
        self.message_user(request, f"{queryset.count()} log ditandai aman.")

    @admin.action(description="Tandai sudah review — blokir secret")
    def mark_as_reviewed_block(self, request, queryset):
        for log in queryset:
            log.mark_reviewed(request.user, note="Blocked via admin review.")
            if log.secret:
                log.secret.status = Secret.Status.BLOCKED
                log.secret.save(update_fields=["status"])
        self.message_user(request, f"{queryset.count()} secret diblokir setelah review.")


# ---------------------------------------------------------------------------
# 9. RATE LIMIT CONFIG ADMIN
# ---------------------------------------------------------------------------

@admin.register(RateLimitConfig)
class RateLimitConfigAdmin(admin.ModelAdmin):
    list_display  = ("user_type", "max_secrets_per_day", "max_file_size_mb",
                     "max_recipients", "max_expiry_days", "is_active", "updated_at")
    readonly_fields = ("id", "created_at", "updated_at")

    fieldsets = (
        ("Konfigurasi", {
            "fields": ("user_type", "is_active"),
        }),
        ("Batas", {
            "fields": ("max_secrets_per_day", "max_file_size_mb",
                       "max_recipients", "max_expiry_days"),
        }),
        ("Timestamps", {
            "fields": ("created_at", "updated_at"),
        }),
    )