from django.shortcuts import render
from django.utils import timezone
from django.db.models import Count, Q
from django.db import transaction
from django.core.cache import cache

import logging
import secrets
import hashlib

from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny, BasePermission
from rest_framework_simplejwt.views import TokenRefreshView as BaseTokenRefreshView
from .aidetection import run_server_detection
from rest_framework import serializers
from .models import (
    User, Secret, SecretLink,
    AccessLog, AIDetectionLog,
)
from .serializers import (
    UserRegisterSerializer,
    UserLoginSerializer,
    UserProfileSerializer,
    SecretCreateSerializer,
    SecretCreateResponseSerializer,
    SecretDetailSerializer,
    SecretRevokeSerializer,
    SecretAccessRequestSerializer,
    SecretAccessResponseSerializer,
    SecretLinkSerializer,
    SecretLinkRevokeSerializer,
    AdminSecretListSerializer,
    AdminAIDetectionSerializer,
    AdminReviewActionSerializer,
    AccessLogSerializer,
)

logger = logging.getLogger(__name__)



def get_client_ip(request):
        x_forwarded = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded:
            return x_forwarded.split(",")[0].strip()
        return request.META.get("REMOTE_ADDR", "")

class QuotaStatusView(APIView):
    permission_classes = [AllowAny]
 
    def get(self, request):
        # Coba autentikasi JWT dulu — kalau ada token valid, user login
        user = self._try_get_authenticated_user(request)
 
        if user and user.is_authenticated:
            return self._quota_for_registered(request, user)
        return self._quota_for_anonymous(request)
 
    def _try_get_authenticated_user(self, request):
        """
        Coba autentikasi JWT tanpa raise exception.
        Return user jika token valid, None jika tidak ada atau invalid.
        """
        try:
            auth = JWTAuthentication()
            result = auth.authenticate(request)
            if result:
                return result[0]
        except Exception:
            pass
        return None
 
    def _quota_for_registered(self, request, user):
        from .models import Secret, RateLimitConfig
 
        config    = RateLimitConfig.get_for_registered()
        today_start = timezone.now().replace(hour=0, minute=0, second=0, microsecond=0)
        used_today  = Secret.objects.filter(
            creator_user=user,
            created_at__gte=today_start,
        ).count()
 
        return Response({
            "user_type":       "registered",
            "max_per_day":     None,   # unlimited
            "used_today":      used_today,
            "remaining":       None,   # unlimited
            "resets_at":       None,
            "max_file_size_mb": config.max_file_size_mb,
            "max_recipients":  config.max_recipients,
            "max_expiry_days": config.max_expiry_days,
        })
 
    def _quota_for_anonymous(self, request):
        from .models import AnonymousSession, RateLimitConfig
 
        config           = RateLimitConfig.get_for_anonymous()
        ip               = get_client_ip(request)
        fingerprint_hash = request.META.get("HTTP_X_FINGERPRINT_HASH", "").strip()
 
        # Cari atau buat AnonymousSession
        session = None
        if ip and fingerprint_hash:
            session, _ = AnonymousSession.objects.get_or_create(
                ip_address       = ip,
                fingerprint_hash = fingerprint_hash,
            )
            session.reset_if_new_day()
        elif ip:
            # Fallback — hanya IP, tanpa fingerprint
            session = AnonymousSession.objects.filter(
                ip_address=ip
            ).order_by("-created_at").first()
            if session:
                session.reset_if_new_day()
 
        used_today = session.daily_count if session else 0
        max_per_day = config.max_secrets_per_day
        remaining   = max(0, max_per_day - used_today)
 
        # Waktu reset — tengah malam WIB (UTC+7)
        now         = timezone.now()
        tomorrow    = (now + timezone.timedelta(days=1)).replace(
            hour=0, minute=0, second=0, microsecond=0
        )
 
        return Response({
            "user_type":        "anonymous",
            "max_per_day":      max_per_day,
            "used_today":       used_today,
            "remaining":        remaining,
            "resets_at":        tomorrow.isoformat(),
            "max_file_size_mb": config.max_file_size_mb,
            "max_recipients":   config.max_recipients,
            "max_expiry_days":  config.max_expiry_days,
        })

class RateLimitConfigView(APIView):

    permission_classes = [AllowAny]
 
    def get(self, request):
        from .models import RateLimitConfig
 
        anon = RateLimitConfig.get_for_anonymous()
        reg  = RateLimitConfig.get_for_registered()
 
        return Response({
            "anonymous": {
                "max_secrets_per_day": anon.max_secrets_per_day,
                "max_file_size_mb":    anon.max_file_size_mb,
                "max_recipients":      anon.max_recipients,
                "max_expiry_days":     anon.max_expiry_days,
            },
            "registered": {
                "max_secrets_per_day": reg.max_secrets_per_day,
                "max_file_size_mb":    reg.max_file_size_mb,
                "max_recipients":      reg.max_recipients,
                "max_expiry_days":     reg.max_expiry_days,
            },
        })

# ===========================================================================
# PERMISSIONS
# ===========================================================================

class IsAdminUser(BasePermission):
    """Hanya user dengan role admin yang bisa akses."""
    message = "Akses ditolak. Diperlukan role admin."

    def has_permission(self, request, view):
        return (
            request.user
            and request.user.is_authenticated
            and request.user.is_admin
        )


class IsOwnerOrAdmin(BasePermission):
    """Hanya creator secret atau admin yang bisa akses."""
    message = "Akses ditolak. Anda bukan pemilik resource ini."

    def has_object_permission(self, request, view, obj):
        if request.user.is_admin:
            return True
        if isinstance(obj, Secret):
            return obj.creator_user == request.user
        if isinstance(obj, SecretLink):
            return obj.secret.creator_user == request.user
        return False


# ===========================================================================
# HELPERS
# ===========================================================================

def get_client_ip(request):
    x_forwarded = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded:
        return x_forwarded.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR")


def success_response(data=None, message="", status_code=status.HTTP_200_OK):
    return Response({
        "success": True,
        "message": message,
        "data": data or {},
    }, status=status_code)


def error_response(message="", errors=None, status_code=status.HTTP_400_BAD_REQUEST):
    return Response({
        "success": False,
        "message": message,
        "errors": errors or {},
    }, status=status_code)


# ===========================================================================
# AUTH VIEWS
# ===========================================================================

class RegisterView(APIView):
    """
    POST /api/auth/register
    Registrasi user baru. Tidak perlu autentikasi.
    """
    permission_classes = [AllowAny]
    throttle_scope = "register"

    def post(self, request):
        serializer = UserRegisterSerializer(data=request.data)
        if not serializer.is_valid():
            return error_response(
                message="Registrasi gagal.",
                errors=serializer.errors,
                status_code=status.HTTP_400_BAD_REQUEST,
            )
        user = serializer.save()
        return success_response(
            data={"email": user.email, "id": str(user.id)},
            message="Registrasi berhasil. Silakan login.",
            status_code=status.HTTP_201_CREATED,
        )


class LoginView(APIView):
    """
    POST /api/auth/login
    Login dengan email + password. Mengembalikan JWT.
    """
    permission_classes = [AllowAny]
    throttle_scope = "login"

    def post(self, request):
        serializer = UserLoginSerializer(
            data=request.data,
            context={"request": request},
        )
        if not serializer.is_valid():
            return error_response(
                message="Login gagal.",
                errors=serializer.errors,
                status_code=status.HTTP_401_UNAUTHORIZED,
            )
        data = serializer.validated_data
        return success_response(
            data={
                "access_token":  data["access_token"],
                "refresh_token": data["refresh_token"],
                "user": UserProfileSerializer(data["user"]).data,
            },
            message="Login berhasil.",
        )
RESET_TOKEN_TTL = 60 * 60  # detik
 
# Prefix cache key
CACHE_PREFIX = "pwd_reset:"
 
 
def _make_cache_key(token: str) -> str:
    """Hash token sebelum simpan ke cache — jangan simpan token plain."""
    hashed = hashlib.sha256(token.encode()).hexdigest()
    return f"{CACHE_PREFIX}{hashed}"
 
 
def _send_reset_email(to_email: str, reset_url: str) -> bool:
    """
    Kirim email reset password via SendGrid.
    Return True jika berhasil, False jika gagal.
    """
    import os
    from sendgrid import SendGridAPIClient
    from sendgrid.helpers.mail import Mail, Email, To, Content, HtmlContent
 
    api_key      = os.getenv("SENDGRID_API_KEY")
    from_email   = os.getenv("DEFAULT_FROM_EMAIL", "noreply@secretdrop.io")
    app_name     = os.getenv("APP_NAME", "SecretDrop")
 
    if not api_key:
        logger.error("[password_reset] SENDGRID_API_KEY tidak ditemukan di environment.")
        return False
 
    html_content = f"""
<!DOCTYPE html>
<html lang="id">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Reset Password</title>
</head>
<body style="margin:0;padding:0;background:#f5f5f5;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#f5f5f5;padding:40px 20px;">
    <tr>
      <td align="center">
        <table width="520" cellpadding="0" cellspacing="0"
          style="background:#ffffff;border-radius:12px;overflow:hidden;
                 box-shadow:0 2px 12px rgba(0,0,0,.08);">
 
          <!-- Header -->
          <tr>
            <td style="background:#0f172a;padding:28px 36px;">
              <p style="margin:0;color:#ffffff;font-size:18px;font-weight:600;
                         letter-spacing:-0.3px;">
                🔐 {app_name}
              </p>
            </td>
          </tr>
 
          <!-- Body -->
          <tr>
            <td style="padding:36px;">
              <h1 style="margin:0 0 12px;font-size:22px;font-weight:700;
                          color:#0f172a;letter-spacing:-0.5px;">
                Reset password kamu
              </h1>
              <p style="margin:0 0 24px;font-size:15px;color:#475569;line-height:1.6;">
                Kami menerima permintaan untuk mereset password akun kamu.
                Klik tombol di bawah untuk membuat password baru.
              </p>
 
              <!-- CTA Button -->
              <table cellpadding="0" cellspacing="0" style="margin-bottom:24px;">
                <tr>
                  <td style="background:#0f172a;border-radius:8px;">
                    <a href="{reset_url}"
                       style="display:inline-block;padding:13px 28px;
                              color:#ffffff;font-size:14px;font-weight:600;
                              text-decoration:none;letter-spacing:0.1px;">
                      Reset Password →
                    </a>
                  </td>
                </tr>
              </table>
 
              <!-- Warning -->
              <div style="background:#fef9c3;border:1px solid #fde047;
                          border-radius:8px;padding:14px 16px;margin-bottom:24px;">
                <p style="margin:0;font-size:13px;color:#854d0e;">
                  ⏱ Link ini hanya berlaku selama <strong>1 jam</strong>.
                  Setelah itu kamu perlu request ulang.
                </p>
              </div>
 
              <!-- URL fallback -->
              <p style="margin:0 0 6px;font-size:13px;color:#94a3b8;">
                Jika tombol tidak bekerja, copy link ini ke browser:
              </p>
              <p style="margin:0;font-size:12px;color:#64748b;
                         word-break:break-all;
                         background:#f8fafc;padding:10px 12px;
                         border-radius:6px;border:1px solid #e2e8f0;">
                {reset_url}
              </p>
            </td>
          </tr>
 
          <!-- Footer -->
          <tr>
            <td style="padding:20px 36px;border-top:1px solid #f1f5f9;">
              <p style="margin:0;font-size:12px;color:#94a3b8;line-height:1.6;">
                Jika kamu tidak merasa request ini, abaikan email ini —
                password kamu tidak akan berubah.<br>
                © {app_name} · Email ini dikirim otomatis, jangan dibalas.
              </p>
            </td>
          </tr>
 
        </table>
      </td>
    </tr>
  </table>
</body>
</html>
"""
 
    try:
        message = Mail(
            from_email = Email(from_email, app_name),
            to_emails  = To(to_email),
            subject    = f"Reset password {app_name}",
        )
        message.content = [HtmlContent(html_content)]
 
        sg     = SendGridAPIClient(api_key)
        res    = sg.send(message)
        status_code = res.status_code
 
        if status_code in (200, 202):
            logger.info(f"[password_reset] Email terkirim ke {to_email} (status {status_code})")
            return True
        else:
            logger.error(f"[password_reset] SendGrid error: status {status_code}")
            return False
 
    except Exception as e:
        logger.error(f"[password_reset] Gagal kirim email: {e}", exc_info=True)
        return False
 


class ForgotPasswordView(APIView):
    """
    POST /api/auth/forgot-password/
    Body: { "email": "user@example.com" }
 
    Selalu return 200 meski email tidak terdaftar —
    ini mencegah email enumeration attack.
    """
    permission_classes = [AllowAny]
    throttle_scope     = "forgot_password"
 
    def post(self, request):
        import os
        email = request.data.get("email", "").strip().lower()
 
        if not email:
            return Response(
                {"success": False, "message": "Email wajib diisi."},
                status=status.HTTP_400_BAD_REQUEST,
            )
 
        # Respons generik — tidak bocorkan apakah email terdaftar atau tidak
        generic_response = Response({
            "success": True,
            "message": (
                "Jika email ini terdaftar, kamu akan menerima "
                "link reset password dalam beberapa menit."
            ),
        })
 
        # Cari user
        from .models import User
        try:
            user = User.objects.get(email=email, is_active=True)
        except User.DoesNotExist:
            # Tetap return 200 — jangan bocorkan info
            logger.info(f"[password_reset] Email tidak ditemukan: {email}")
            return generic_response
 
        if user.is_banned:
            logger.warning(f"[password_reset] User banned coba reset: {email}")
            return generic_response
 
        # Cek rate limit — maks 3 request per 10 menit per email
        rate_key   = f"pwd_reset_rate:{email}"
        rate_count = cache.get(rate_key, 0)
        if rate_count >= 3:
            logger.warning(f"[password_reset] Rate limit hit: {email}")
            return generic_response
 
        # Generate token aman (32 bytes = 256-bit entropy)
        token    = secrets.token_urlsafe(32)
        cache_key = _make_cache_key(token)
 
        # Simpan ke cache: { user_id, email } — expire 1 jam
        cache.set(cache_key, {
            "user_id": str(user.id),
            "email":   user.email,
        }, timeout=RESET_TOKEN_TTL)
 
        # Increment rate limit counter
        cache.set(rate_key, rate_count + 1, timeout=60 * 10)
 
        # Build reset URL untuk FE
        frontend_url = os.getenv("FRONTEND_URL", "http://localhost:3000")
        reset_url    = f"{frontend_url}/reset-password?token={token}"
 
        # Kirim email
        sent = _send_reset_email(user.email, reset_url)
        if not sent:
            # Hapus token dari cache kalau email gagal
            cache.delete(cache_key)
            logger.error(f"[password_reset] Gagal kirim email ke {email}")
            return Response(
                {"success": False, "message": "Gagal mengirim email. Coba lagi nanti."},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
 
        return generic_response
 
 
# ===========================================================================
# VIEW 2 — Validasi token (GET, untuk FE cek sebelum render form)
# ===========================================================================
 
class ValidateResetTokenView(APIView):
    """
    GET /api/auth/reset-password/validate/?token=xxx
 
    FE pakai ini saat halaman reset-password di-load —
    kalau token tidak valid, langsung redirect ke halaman expired.
    """
    permission_classes = [AllowAny]
 
    def get(self, request):
        token = request.query_params.get("token", "").strip()
 
        if not token:
            return Response(
                {"valid": False, "message": "Token tidak ditemukan."},
                status=status.HTTP_400_BAD_REQUEST,
            )
 
        cache_key = _make_cache_key(token)
        data      = cache.get(cache_key)
 
        if not data:
            return Response(
                {"valid": False, "message": "Link reset sudah kedaluwarsa atau tidak valid."},
                status=status.HTTP_400_BAD_REQUEST,
            )
 
        return Response({
            "valid": True,
            "email": data["email"],
        })
 
 
# ===========================================================================
# VIEW 3 — Konfirmasi reset (set password baru)
# ===========================================================================
 
class ResetPasswordConfirmView(APIView):
    """
    POST /api/auth/reset-password/confirm/
    Body: {
      "token": "xxx",
      "password": "newpassword123",
      "password_confirm": "newpassword123"
    }
    """
    permission_classes = [AllowAny]
 
    def post(self, request):
        token            = request.data.get("token", "").strip()
        password         = request.data.get("password", "")
        password_confirm = request.data.get("password_confirm", "")
 
        # Validasi input
        if not token:
            return Response(
                {"success": False, "message": "Token tidak ditemukan."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if not password:
            return Response(
                {"success": False, "message": "Password baru wajib diisi."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if len(password) < 8:
            return Response(
                {"success": False, "message": "Password minimal 8 karakter."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if password != password_confirm:
            return Response(
                {"success": False, "message": "Password dan konfirmasi tidak cocok."},
                status=status.HTTP_400_BAD_REQUEST,
            )
 
        # Validasi token
        cache_key = _make_cache_key(token)
        data      = cache.get(cache_key)
 
        if not data:
            return Response(
                {
                    "success": False,
                    "message": "Link reset sudah kedaluwarsa atau tidak valid. "
                               "Silakan request ulang.",
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
 
        # Cari user
        from .models import User
        try:
            user = User.objects.get(id=data["user_id"], is_active=True)
        except User.DoesNotExist:
            cache.delete(cache_key)
            return Response(
                {"success": False, "message": "User tidak ditemukan."},
                status=status.HTTP_404_NOT_FOUND,
            )
 
        # Set password baru
        user.set_password(password)
        user.save(update_fields=["password"])
 
        # Hapus token — one-time use
        cache.delete(cache_key)
 
        # Hapus juga rate limit counter
        cache.delete(f"pwd_reset_rate:{user.email}")
 
        logger.info(f"[password_reset] Password berhasil direset: {user.email}")
 
        return Response({
            "success": True,
            "message": "Password berhasil diubah. Silakan login dengan password baru.",
        })

class ProfileView(APIView):
    """
    GET  /api/auth/me  — lihat profil
    PATCH /api/auth/me — update nama
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        serializer = UserProfileSerializer(request.user)
        return success_response(data=serializer.data)

    def patch(self, request):
        # Hanya full_name yang bisa diupdate via endpoint ini
        full_name = request.data.get("full_name", "").strip()
        if not full_name:
            return error_response(message="full_name tidak boleh kosong.")
        request.user.full_name = full_name
        request.user.save(update_fields=["full_name"])
        return success_response(
            data=UserProfileSerializer(request.user).data,
            message="Profil diperbarui.",
        )


# ===========================================================================
# SECRET VIEWS
# ===========================================================================

class SecretCreateView(APIView):
    """
    POST /api/secrets/
    Buat secret baru.
    - Anon user: maks 3/hari, maks 10 MB, wajib ada expiry
    - Registered user: unlimited, maks 100 MB

    Body berisi ciphertext dari browser (ZKE — server tidak terima plaintext).
    """
    permission_classes = [AllowAny]

    @transaction.atomic
    def post(self, request):
        serializer = SecretCreateSerializer(
            data=request.data,
            context={"request": request},
        )
        if not serializer.is_valid():
            return error_response(
                message="Gagal membuat secret.",
                errors=serializer.errors,
            )
    
        vd = serializer.validated_data
        try:
    
            # ── Jalankan server-side detection SEBELUM simpan ke DB ──────────────
            detection = run_server_detection(
                secret_type           = vd.get("secret_type", ""),
                mime_type             = vd.get("mime_type", ""),
                original_filename     = vd.get("original_filename", ""),
                file_size_bytes       = vd.get("file_size_bytes"),
                encrypted_payload     = vd.get("encrypted_payload", ""),
                encryption_iv         = vd.get("encryption_iv", ""),
                ip_address            = get_client_ip(request),
                user_agent            = request.META.get("HTTP_USER_AGENT", ""),
                is_authenticated      = request.user.is_authenticated,
                client_risk_score     = vd.get("client_risk_score", 0),
                client_rules_triggered = vd.get("client_rules_triggered", []),
                num_recipients        = vd.get("num_recipients", 1),
                has_password          = bool(vd.get("access_password")),
                has_email_whitelist   = bool(vd.get("email_whitelist")),
                expires_in_hours      = vd.get("expires_in_hours"),
                secret                = None,  # belum disimpan
            )
        except Exception as e:
            return error_response(message=f"Detection error: {str(e)}", status_code=500)

  
        # ── BLOCKED → tolak total ─────────────────────────────────────────────
        if detection.action == "blocked":
            # Simpan log meski secret tidak disimpan
            from .models import AIDetectionLog
            AIDetectionLog.objects.create(
                secret          = None,
                source          = AIDetectionLog.DetectionSource.SERVER,
                rules_triggered = detection.rules_triggered,
                risk_score      = detection.total_score,
                action_taken    = AIDetectionLog.ActionTaken.BLOCKED,
                ip_address      = get_client_ip(request),
                file_size_bytes = vd.get("file_size_bytes"),
                secret_type     = vd.get("secret_type", ""),
            )
            return error_response(
                message="Konten ini ditolak oleh sistem keamanan platform.",
                errors={"detection": detection.rules_triggered},
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            )
    
        # ── Gabungkan score client + server ──────────────────────────────────
        combined_score = min(
            100,
            vd.get("client_risk_score", 0) + detection.total_score
        )
        ai_flagged = combined_score >= 40
    
        # ── Simpan secret (serializer.save() sudah handle links + whitelist) ─

        try:
            secret, links = serializer.create(serializer.validated_data)
        except Exception as e:
            from rest_framework.exceptions import ValidationError
            if isinstance(e, ValidationError):
                return error_response(
                    message="Gagal membuat secret.",
                    errors={"detail": str(e.detail)},
                    status_code=status.HTTP_400_BAD_REQUEST,
                )
            return error_response(message="Gagal menyimpan secret.", status_code=500)
            
        # Update score dengan hasil gabungan
        secret.ai_risk_score = combined_score
        secret.ai_flagged    = ai_flagged
        secret.save(update_fields=["ai_risk_score", "ai_flagged"])
    
        # Update log server-side dengan relasi ke secret yang baru tersimpan
        from .models import AIDetectionLog
        AIDetectionLog.objects.filter(
            secret__isnull=True,
            ip_address=get_client_ip(request),
        ).order_by("-created_at").first()
        # (log sudah dibuat di dalam run_server_detection dengan secret=None,
        #  update relasi secret di sini)
        AIDetectionLog.objects.filter(
            source=AIDetectionLog.DetectionSource.SERVER,
            secret__isnull=True,
            ip_address=get_client_ip(request),
        ).order_by("-created_at").update(secret=secret)
    
        # ── Bangun response ───────────────────────────────────────────────────
        response_data = {
            "secret_id":    str(secret.id),
            "revoke_token": secret.revoke_token,
            "expires_at":   secret.expires_at,
            "ai_flagged":   secret.ai_flagged,
            "ai_score":     secret.ai_risk_score,
            "created_at":   secret.created_at,
            "links": [
                {
                    "id":       str(link.id),
                    "token":    link.token,
                    "label":    link.label,
                    "full_url": link.full_url,
                }
                for link in links
            ],
        }
    
        message = "Secret berhasil dibuat."
        if secret.ai_flagged:
            message += " Secret ini sedang dalam antrian review moderasi."
    
        return success_response(
            data        = response_data,
            message     = message,
            status_code = status.HTTP_201_CREATED,
        )


class MySecretsView(APIView):
    """
        GET /api/secrets/my/
        List semua secret milik user yang login.
        Support filter by status dan pagination sederhana.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        status_filter = request.query_params.get("status")
        page     = int(request.query_params.get("page", 1))
        per_page = min(int(request.query_params.get("per_page", 20)), 100)

        qs = Secret.objects.filter(
                creator_user=request.user
        ).prefetch_related("links", "email_whitelist").order_by("-created_at")

        if status_filter and status_filter in dict(Secret.Status.choices):
                qs = qs.filter(status=status_filter)

        total   = qs.count()
        offset  = (page - 1) * per_page
        secrets = qs[offset: offset + per_page]

        return success_response(data={
                "total":    total,
                "page":     page,
                "per_page": per_page,
                "secrets":  SecretDetailSerializer(secrets, many=True).data,
        })

class SecretDetailView(APIView):
    """
    GET /api/secrets/{id}/
    Detail secret untuk creator. Termasuk semua link dan whitelist.
    Tidak mengembalikan encrypted_payload.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request, secret_id):
        secret = self._get_secret(request, secret_id)
        if not secret:
            return error_response(
                message="Secret tidak ditemukan.",
                status_code=status.HTTP_404_NOT_FOUND,
            )
        serializer = SecretDetailSerializer(secret)
        return success_response(data=serializer.data)

    def _get_secret(self, request, secret_id):
        try:
            qs = Secret.objects.prefetch_related("links", "email_whitelist")
            if request.user.is_admin:
                return qs.get(id=secret_id)
            return qs.get(id=secret_id, creator_user=request.user)
        except Secret.DoesNotExist:
            return None


class SecretRevokeView(APIView):
    """
    DELETE /api/secrets/{id}/revoke/
    Revoke seluruh secret + hapus encrypted_payload dari DB.
    Auth via JWT atau revoke_token (untuk anon user).

    Ini operasi PERMANEN — data tidak bisa di-recover.
    """
    permission_classes = [AllowAny]

    @transaction.atomic
    def delete(self, request, secret_id):
        # Cari secret — bisa diakses siapapun yang punya revoke_token
        try:
            secret = Secret.objects.get(id=secret_id)
        except Secret.DoesNotExist:
            return error_response(
                message="Secret tidak ditemukan.",
                status_code=status.HTTP_404_NOT_FOUND,
            )

        serializer = SecretRevokeSerializer(
            data=request.data,
            context={"request": request, "secret": secret},
        )
        if not serializer.is_valid():
            return error_response(
                message="Revoke gagal.",
                errors=serializer.errors,
                status_code=status.HTTP_403_FORBIDDEN,
            )

        secret.revoke(hard_delete_payload=True)

        return success_response(
            message="Secret berhasil dicabut. Data telah dihapus permanen.",
            status_code=status.HTTP_200_OK,
        )

class SecretDeleteView(APIView):
    """
    DELETE /api/secrets/{id}/delete/
    Hapus riwayat secret dari list dashboard.
    Hanya bisa dilakukan oleh creator dan hanya untuk secret
    yang sudah expired/revoked (tidak bisa hapus secret yang masih active).
    """
    permission_classes = [IsAuthenticated]

    def delete(self, request, secret_id):
        try:
            secret = Secret.objects.get(id=secret_id, creator_user=request.user)
        except Secret.DoesNotExist:
            return error_response(
                message="Secret tidak ditemukan.",
                status_code=status.HTTP_404_NOT_FOUND,
            )

        if secret.status == Secret.Status.ACTIVE:
            return error_response(
                message="Secret yang masih aktif tidak bisa dihapus. Revoke dulu sebelum menghapus.",
                status_code=status.HTTP_400_BAD_REQUEST,
            )

        secret.delete()

        return success_response(
            message="Riwayat secret berhasil dihapus.",
            status_code=status.HTTP_200_OK,
        )




# ===========================================================================
# SECRET LINK ACCESS VIEW
# ===========================================================================

class SecretAccessView(APIView):
    """
    GET  /api/s/{token}/  — cek info link (apakah perlu email/password)
    POST /api/s/{token}/  — akses secret (validasi + return ciphertext)

    Browser akan mendekripsi ciphertext — server tidak pernah lihat plaintext.
    Setiap akses berhasil dicatat ke AccessLog dan menambah view count.
    """
    permission_classes = [AllowAny]

    def get(self, request, token):
        """Cek info link tanpa mengakses payload."""
        link = self._get_link(token)
        if not link:
            return error_response(
                message="Link tidak ditemukan.",
                status_code=status.HTTP_404_NOT_FOUND,
            )

        can_access, reason = link.can_be_accessed()
        secret = link.secret

        return success_response(data={
            "token":            token,
            "can_access":       can_access,
            "deny_reason":      reason,
            "secret_type":      secret.secret_type,
            "requires_email":   secret.email_whitelist.exists() or secret.domain_whitelist.exists(),
            "requires_password": bool(secret.access_password_hash),
            "has_expiry":       bool(secret.expires_at),
            "expires_at":       secret.expires_at,
            "views_remaining":  secret.views_remaining,
        })

    @transaction.atomic
    def post(self, request, token):
        """Akses secret — validasi lalu return ciphertext."""
        link = self._get_link(token)
        if not link:
            return error_response(
                message="Link tidak ditemukan.",
                status_code=status.HTTP_404_NOT_FOUND,
            )

        serializer = SecretAccessRequestSerializer(
            data=request.data,
            context={"request": request, "link": link},
        )
        if not serializer.is_valid():
            return error_response(
                message="Akses ditolak.",
                errors=serializer.errors,
                status_code=status.HTTP_403_FORBIDDEN,
            )

        secret           = serializer.validated_data["secret"]
        whitelist_entry  = serializer.validated_data.get("whitelist_entry")
        accessed_email   = serializer.validated_data.get("email", "")

        # Catat akses berhasil
        link.record_access()
        secret.increment_view()
        if whitelist_entry:
            whitelist_entry.record_access()

        # Log sukses
        AccessLog.objects.create(
            secret_link       = link,
            accessed_by_email = accessed_email,
            ip_address        = get_client_ip(request),
            user_agent        = request.META.get("HTTP_USER_AGENT", ""),
            result            = AccessLog.AccessResult.SUCCESS,
        )

        return success_response(
            data={
                "secret_id":         str(secret.id),
                "secret_type":       secret.secret_type,
                "encrypted_payload": secret.encrypted_payload,
                "encryption_iv":     secret.encryption_iv,
                "encryption_tag":    secret.encryption_tag,
                "encryption_salt":   secret.encryption_salt,
                "original_filename": secret.original_filename,
                "mime_type":         secret.mime_type,
                "file_size_bytes":   secret.file_size_bytes,
                "views_remaining":   secret.views_remaining,
                "accessed_at":       timezone.now(),
            },
            message="Secret berhasil diakses.",
        )

    def _get_link(self, token):
        try:
            return SecretLink.objects.select_related(
                "secret", "secret__creator_user"
            ).prefetch_related(
                "secret__email_whitelist"
            ).get(token=token)
        except SecretLink.DoesNotExist:
            return None


class SecretLinkRevokeView(APIView):
    """
    DELETE /api/links/{link_id}/revoke/
    Revoke satu link saja. Secret dan link lain tetap aktif.
    Auth via JWT atau revoke_token secret induk.
    """
    permission_classes = [AllowAny]

    def delete(self, request, link_id):
        try:
            link = SecretLink.objects.select_related("secret__creator_user").get(id=link_id)
        except SecretLink.DoesNotExist:
            return error_response(
                message="Link tidak ditemukan.",
                status_code=status.HTTP_404_NOT_FOUND,
            )

        serializer = SecretLinkRevokeSerializer(
            data=request.data,
            context={"request": request, "link": link},
        )
        if not serializer.is_valid():
            return error_response(
                message="Revoke link gagal.",
                errors=serializer.errors,
                status_code=status.HTTP_403_FORBIDDEN,
            )

        link.revoke()

        return success_response(
            message=f"Link /s/{link.token} berhasil dicabut.",
        )


# ===========================================================================
# ADMIN VIEWS
# ===========================================================================

class AdminSecretListView(APIView):
    """
    GET /api/admin/secrets/
    List semua secret dengan filter.
    Query params: status, flagged_only, page, per_page
    """
    permission_classes = [IsAdminUser]

    def get(self, request):
        status_filter  = request.query_params.get("status")
        flagged_only   = request.query_params.get("flagged_only") == "true"
        search         = request.query_params.get("search", "").strip()
        page           = int(request.query_params.get("page", 1))
        per_page       = min(int(request.query_params.get("per_page", 20)), 100)

        qs = Secret.objects.select_related(
            "creator_user", "anon_session"
        ).annotate(link_count=Count("links")).order_by("-created_at")

        if status_filter and status_filter in dict(Secret.Status.choices):
            qs = qs.filter(status=status_filter)
        if flagged_only:
            qs = qs.filter(ai_flagged=True)
        if search:
            qs = qs.filter(
                Q(creator_user__email__icontains=search) |
                Q(id__icontains=search)
            )

        total   = qs.count()
        offset  = (page - 1) * per_page
        secrets = qs[offset: offset + per_page]

        return success_response(data={
            "total":    total,
            "page":     page,
            "per_page": per_page,
            "secrets":  AdminSecretListSerializer(secrets, many=True).data,
        })


class AdminSecretActionView(APIView):
    """
    POST /api/admin/secrets/{id}/action/
    Aksi admin terhadap secret: approve atau block.
    Body: { "action": "approve" | "block", "admin_note": "..." }
    """
    permission_classes = [IsAdminUser]

    @transaction.atomic
    def post(self, request, secret_id):
        try:
            secret = Secret.objects.get(id=secret_id)
        except Secret.DoesNotExist:
            return error_response(
                message="Secret tidak ditemukan.",
                status_code=status.HTTP_404_NOT_FOUND,
            )

        serializer = AdminReviewActionSerializer(data=request.data)
        if not serializer.is_valid():
            return error_response(
                message="Data tidak valid.",
                errors=serializer.errors,
            )

        action     = serializer.validated_data["action"]
        admin_note = serializer.validated_data.get("admin_note", "")

        if action == "approve":
            secret.ai_flagged = False
            secret.save(update_fields=["ai_flagged"])
            # Update semua AI log terkait
            secret.ai_logs.filter(reviewed_at__isnull=True).update(
                action_taken  = AIDetectionLog.ActionTaken.ALLOWED,
                reviewed_by   = request.user,
                reviewed_at   = timezone.now(),
                admin_note    = admin_note or "Approved by admin.",
            )
            message = "Secret di-approve. Sekarang aktif normal."

        elif action == "block":
            secret.status    = Secret.Status.BLOCKED
            secret.ai_flagged = False
            secret.save(update_fields=["status", "ai_flagged"])
            secret.links.update(is_active=False)
            secret.ai_logs.filter(reviewed_at__isnull=True).update(
                action_taken = AIDetectionLog.ActionTaken.BLOCKED,
                reviewed_by  = request.user,
                reviewed_at  = timezone.now(),
                admin_note   = admin_note or "Blocked by admin.",
            )
            message = "Secret diblokir. Semua link dinonaktifkan."

        else:
            return error_response(message="Action tidak dikenal.")

        return success_response(
            data={"secret_id": str(secret.id), "new_status": secret.status},
            message=message,
        )


class AdminAIQueueView(APIView):
    """
    GET /api/admin/ai-queue/
    Antrian AI detection log yang belum di-review.
    Filter by action_taken, source, atau hanya unreviewed.
    """
    permission_classes = [IsAdminUser]

    def get(self, request):
        unreviewed_only = request.query_params.get("unreviewed_only", "true") == "true"
        action_filter   = request.query_params.get("action")
        page            = int(request.query_params.get("page", 1))
        per_page        = min(int(request.query_params.get("per_page", 20)), 100)

        qs = AIDetectionLog.objects.select_related(
            "secret", "reviewed_by"
        ).order_by("-created_at")

        if unreviewed_only:
            qs = qs.filter(reviewed_at__isnull=True)
        if action_filter in ("allowed", "flagged", "blocked"):
            qs = qs.filter(action_taken=action_filter)

        total  = qs.count()
        offset = (page - 1) * per_page
        logs   = qs[offset: offset + per_page]

        return success_response(data={
            "total":    total,
            "page":     page,
            "per_page": per_page,
            "logs":     AdminAIDetectionSerializer(logs, many=True).data,
        })


class AdminAIReviewView(APIView):
    """
    POST /api/admin/ai-logs/{log_id}/review/
    Review satu AI detection log.
    Body: { "action": "approve" | "block", "admin_note": "..." }
    """
    permission_classes = [IsAdminUser]

    @transaction.atomic
    def post(self, request, log_id):
        try:
            log = AIDetectionLog.objects.select_related("secret").get(id=log_id)
        except AIDetectionLog.DoesNotExist:
            return error_response(
                message="Log tidak ditemukan.",
                status_code=status.HTTP_404_NOT_FOUND,
            )

        if log.reviewed_at:
            return error_response(message="Log ini sudah di-review sebelumnya.")

        serializer = AdminReviewActionSerializer(data=request.data)
        if not serializer.is_valid():
            return error_response(errors=serializer.errors)

        action     = serializer.validated_data["action"]
        admin_note = serializer.validated_data.get("admin_note", "")

        log.mark_reviewed(request.user, note=admin_note)

        if action == "block" and log.secret:
            log.secret.status    = Secret.Status.BLOCKED
            log.secret.ai_flagged = False
            log.secret.save(update_fields=["status", "ai_flagged"])
            log.secret.links.update(is_active=False)
            message = "Log di-review. Secret diblokir."
        elif action == "approve" and log.secret:
            log.secret.ai_flagged = False
            log.secret.save(update_fields=["ai_flagged"])
            message = "Log di-review. Secret di-approve."
        else:
            message = "Log di-review."

        return success_response(
            data=AdminAIDetectionSerializer(log).data,
            message=message,
        )


class AdminUserListView(APIView):
    """
    GET /api/admin/users/
    List semua user dengan filter.
    Query params: search, is_banned, role, page, per_page
    """
    permission_classes = [IsAdminUser]

    def get(self, request):
        search     = request.query_params.get("search", "").strip()
        is_banned  = request.query_params.get("is_banned")
        role       = request.query_params.get("role")
        page       = int(request.query_params.get("page", 1))
        per_page   = min(int(request.query_params.get("per_page", 20)), 100)

        qs = User.objects.order_by("-created_at")

        if search:
            qs = qs.filter(
                Q(email__icontains=search) | Q(full_name__icontains=search)
            )
        if is_banned in ("true", "false"):
            qs = qs.filter(is_banned=(is_banned == "true"))
        if role in dict(User.Role.choices):
            qs = qs.filter(role=role)

        total   = qs.count()
        offset  = (page - 1) * per_page
        users   = qs[offset: offset + per_page]

        return success_response(data={
            "total":    total,
            "page":     page,
            "per_page": per_page,
            "users": [
                {
                    "id":                    str(u.id),
                    "email":                 u.email,
                    "full_name":             u.full_name,
                    "role":                  u.role,
                    "is_banned":             u.is_banned,
                    "is_active":             u.is_active,
                    "total_secrets_created": u.total_secrets_created,
                    "created_at":            u.created_at,
                }
                for u in users
            ],
        })


class AdminUserActionView(APIView):
    """
    POST /api/admin/users/{id}/action/
    Aksi admin terhadap user.
    Body: { "action": "ban" | "unban" | "promote" | "demote" }
    """
    permission_classes = [IsAdminUser]

    def post(self, request, user_id):
        try:
            target_user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return error_response(
                message="User tidak ditemukan.",
                status_code=status.HTTP_404_NOT_FOUND,
            )

        # Admin tidak bisa mengubah dirinya sendiri
        if target_user == request.user:
            return error_response(
                message="Anda tidak bisa mengubah akun Anda sendiri via endpoint ini."
            )

        action = request.data.get("action")
        valid_actions = ("ban", "unban", "promote", "demote")

        if action not in valid_actions:
            return error_response(
                message=f"Action tidak valid. Pilihan: {', '.join(valid_actions)}."
            )

        if action == "ban":
            target_user.is_banned = True
            target_user.is_active = False
            target_user.save(update_fields=["is_banned", "is_active"])
            message = f"{target_user.email} dibanned."

        elif action == "unban":
            target_user.is_banned = False
            target_user.is_active = True
            target_user.save(update_fields=["is_banned", "is_active"])
            message = f"{target_user.email} di-unban."

        elif action == "promote":
            target_user.role     = User.Role.ADMIN
            target_user.is_staff = True
            target_user.save(update_fields=["role", "is_staff"])
            message = f"{target_user.email} dipromosikan menjadi admin."

        elif action == "demote":
            target_user.role     = User.Role.USER
            target_user.is_staff = False
            target_user.save(update_fields=["role", "is_staff"])
            message = f"{target_user.email} dikembalikan ke role user."

        return success_response(
            data={"user_id": str(target_user.id), "action": action},
            message=message,
        )


class AdminStatsView(APIView):
    """
    GET /api/admin/stats/
    Statistik dashboard admin: ringkasan harian dan keseluruhan.
    """
    permission_classes = [IsAdminUser]

    def get(self, request):
        now   = timezone.now()
        today = now.date()
        today_start = timezone.make_aware(
            timezone.datetime.combine(today, timezone.datetime.min.time())
        )

        # Secret stats
        total_secrets      = Secret.objects.count()
        secrets_today      = Secret.objects.filter(created_at__gte=today_start).count()
        flagged_secrets    = Secret.objects.filter(ai_flagged=True).count()
        blocked_secrets    = Secret.objects.filter(status=Secret.Status.BLOCKED).count()
        active_secrets     = Secret.objects.filter(status=Secret.Status.ACTIVE).count()

        # AI detection stats
        pending_review     = AIDetectionLog.objects.filter(reviewed_at__isnull=True).count()
        blocked_today      = AIDetectionLog.objects.filter(
            action_taken=AIDetectionLog.ActionTaken.BLOCKED,
            created_at__gte=today_start
        ).count()

        # User stats
        total_users        = User.objects.count()
        banned_users       = User.objects.filter(is_banned=True).count()

        # Access stats hari ini
        access_today       = AccessLog.objects.filter(accessed_at__gte=today_start).count()
        denied_today       = AccessLog.objects.filter(
            accessed_at__gte=today_start
        ).exclude(result=AccessLog.AccessResult.SUCCESS).count()

        return success_response(data={
            "generated_at": now,
            "secrets": {
                "total":   total_secrets,
                "today":   secrets_today,
                "active":  active_secrets,
                "flagged": flagged_secrets,
                "blocked": blocked_secrets,
            },
            "ai_detection": {
                "pending_review": pending_review,
                "blocked_today":  blocked_today,
            },
            "users": {
                "total":  total_users,
                "banned": banned_users,
            },
            "access": {
                "total_today":  access_today,
                "denied_today": denied_today,
            },
        })


class AdminAccessLogsView(APIView):
    """
    GET /api/admin/access-logs/
    Log akses untuk audit. Filter by secret link token atau IP.
    """
    permission_classes = [IsAdminUser]

    def get(self, request):
        token      = request.query_params.get("token", "").strip()
        ip         = request.query_params.get("ip", "").strip()
        result     = request.query_params.get("result", "").strip()
        page       = int(request.query_params.get("page", 1))
        per_page   = min(int(request.query_params.get("per_page", 50)), 200)

        qs = AccessLog.objects.select_related("secret_link").order_by("-accessed_at")

        if token:
            qs = qs.filter(secret_link__token=token)
        if ip:
            qs = qs.filter(ip_address=ip)
        if result in dict(AccessLog.AccessResult.choices):
            qs = qs.filter(result=result)

        total  = qs.count()
        offset = (page - 1) * per_page
        logs   = qs[offset: offset + per_page]

        return success_response(data={
            "total":    total,
            "page":     page,
            "per_page": per_page,
            "logs":     AccessLogSerializer(logs, many=True).data,
        })