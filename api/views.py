from django.shortcuts import render
from django.utils import timezone
from django.db.models import Count, Q
from django.db import transaction

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