import re
import hashlib
from django.utils import timezone
from django.contrib.auth import authenticate
from rest_framework import serializers
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.hashers import make_password, check_password

from .models import (
    User, AnonymousSession, Secret, SecretLink,
    EmailWhitelist, AccessLog, AIDetectionLog, RateLimitConfig,
)


# ===========================================================================
# CONSTANTS & VALIDATORS
# ===========================================================================

# Tipe MIME yang diizinkan untuk upload file
ALLOWED_MIME_TYPES = {
    "application/pdf",
    "text/plain",
    "text/csv",
    "image/jpeg",
    "image/png",
    "image/gif",
    "image/webp",
    "application/zip",
    "application/x-zip-compressed",
    "application/msword",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.ms-excel",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
}

# Ekstensi file yang DIBLOKIR (walaupun mime type berbeda)
BLOCKED_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".sh", ".ps1", ".vbs",
    ".msi", ".dmg", ".app", ".jar", ".dll", ".so",
}

# Regex validasi base64 (untuk payload ZKE)
BASE64_RE = re.compile(r'^[A-Za-z0-9+/=_\-]+$')


def validate_base64(value, field_name="Field"):
    """Pastikan nilai adalah base64 valid."""
    if not BASE64_RE.match(value):
        raise serializers.ValidationError(
            f"{field_name} harus berupa string base64 valid."
        )
    return value


def validate_iv_length(value):
    """
    Nonce AES-GCM harus 96-bit = 12 bytes.
    Dalam base64: ceil(12 * 4/3) = 16 chars (tanpa padding) atau 16 chars.
    """
    import base64
    try:
        decoded = base64.urlsafe_b64decode(value + "==")
        if len(decoded) != 12:
            raise serializers.ValidationError(
                f"IV harus 12 bytes (96-bit). Diterima: {len(decoded)} bytes."
            )
    except Exception:
        raise serializers.ValidationError("IV bukan base64 valid.")
    return value


def validate_tag_length(value):
    """Auth tag AES-GCM harus 128-bit = 16 bytes."""
    import base64
    try:
        decoded = base64.urlsafe_b64decode(value + "==")
        if len(decoded) != 16:
            raise serializers.ValidationError(
                f"Auth tag harus 16 bytes (128-bit). Diterima: {len(decoded)} bytes."
            )
    except Exception:
        raise serializers.ValidationError("Auth tag bukan base64 valid.")
    return value


# ===========================================================================
# AUTH SERIALIZERS
# ===========================================================================

class UserRegisterSerializer(serializers.ModelSerializer):
    """
    Registrasi user baru.
    Password dikonfirmasi client-side tapi tetap divalidasi di sini.
    """
    password         = serializers.CharField(write_only=True, min_length=8,
                                             style={"input_type": "password"})
    password_confirm = serializers.CharField(write_only=True,
                                             style={"input_type": "password"})

    class Meta:
        model  = User
        fields = ("email", "full_name", "password", "password_confirm")

    def validate_email(self, value):
        email = value.lower().strip()
        if User.objects.filter(email=email).exists():
            raise serializers.ValidationError("Email ini sudah terdaftar.")
        return email

    def validate(self, data):
        if data["password"] != data["password_confirm"]:
            raise serializers.ValidationError({"password_confirm": "Password tidak cocok."})
        return data

    def create(self, validated_data):
        validated_data.pop("password_confirm")
        return User.objects.create_user(**validated_data)


class UserLoginSerializer(serializers.Serializer):
    """
    Login dengan email + password.
    Mengembalikan JWT access + refresh token jika sukses.
    """
    email    = serializers.EmailField()
    password = serializers.CharField(write_only=True, style={"input_type": "password"})

    def validate(self, data):
        email    = data["email"].lower().strip()
        password = data["password"]

        user = authenticate(request=self.context.get("request"),
                            email=email, password=password)

        if not user:
            raise serializers.ValidationError(
                {"non_field_errors": "Email atau password salah."}
            )
        if user.is_banned:
            raise serializers.ValidationError(
                {"non_field_errors": "Akun ini telah dinonaktifkan."}
            )
        if not user.is_active:
            raise serializers.ValidationError(
                {"non_field_errors": "Akun tidak aktif."}
            )

        # Generate JWT
        refresh = RefreshToken.for_user(user)
        data["user"]          = user
        data["access_token"]  = str(refresh.access_token)
        data["refresh_token"] = str(refresh)
        return data


class UserProfileSerializer(serializers.ModelSerializer):
    """Profil user yang sudah login (read-only)."""

    class Meta:
        model  = User
        fields = ("id", "email", "full_name", "role",
                  "total_secrets_created", "created_at")
        read_only_fields = fields


# ===========================================================================
# EMAIL WHITELIST SERIALIZER
# ===========================================================================

class EmailWhitelistSerializer(serializers.ModelSerializer):
    """Digunakan nested di dalam SecretCreateSerializer."""

    class Meta:
        model  = EmailWhitelist
        fields = ("id", "email", "access_count", "accessed_at")
        read_only_fields = ("id", "access_count", "accessed_at")

    def validate_email(self, value):
        return value.lower().strip()


# ===========================================================================
# SECRET LINK SERIALIZER
# ===========================================================================

class SecretLinkSerializer(serializers.ModelSerializer):
    """Info link untuk ditampilkan ke creator setelah secret dibuat."""
    full_url = serializers.ReadOnlyField()

    class Meta:
        model  = SecretLink
        fields = ("id", "token", "label", "full_url", "is_active",
                  "accessed_count", "last_accessed", "created_at", "revoked_at")
        read_only_fields = fields


class SecretLinkRevokeSerializer(serializers.Serializer):
    """
    Revoke satu link spesifik.
    Bisa diakses oleh creator (JWT) atau via revoke_token secret induk.
    """
    revoke_token = serializers.CharField(
        required=False, allow_blank=True,
        help_text="Wajib jika tidak menyertakan JWT. Revoke token dari secret induk."
    )

    def validate(self, data):
        link = self.context.get("link")
        request = self.context.get("request")

        if not link:
            raise serializers.ValidationError("Link tidak ditemukan.")

        if not link.is_active:
            raise serializers.ValidationError("Link ini sudah di-revoke sebelumnya.")

        # Validasi kepemilikan
        user = request.user if request else None
        revoke_token = data.get("revoke_token", "")

        # Cek via JWT (user login)
        if user and user.is_authenticated:
            secret = link.secret
            if secret.creator_user != user and not user.is_admin:
                raise serializers.ValidationError(
                    "Anda tidak memiliki akses untuk merevoke link ini."
                )
            return data

        # Cek via revoke_token (anon atau link tanpa login)
        if revoke_token:
            secret = link.secret
            if secret.revoke_token != revoke_token:
                raise serializers.ValidationError("Revoke token tidak valid.")
            return data

        raise serializers.ValidationError(
            "Autentikasi diperlukan: sertakan JWT atau revoke_token."
        )


# ===========================================================================
# SECRET CREATE SERIALIZER (core)
# ===========================================================================

class SecretCreateSerializer(serializers.Serializer):
    """
    Buat secret baru dengan Zero-Knowledge Encryption.

    Browser sudah mengenkripsi konten sebelum mengirim ke server.
    Server TIDAK menerima plaintext — hanya menerima:
      - encrypted_payload  : ciphertext base64
      - encryption_iv      : nonce 96-bit base64
      - encryption_tag     : GCM auth tag 128-bit base64
      - encryption_salt    : (opsional) salt PBKDF2 jika pakai password-derived key

    AI detection sudah dilakukan di browser sebelum enkripsi.
    Server menerima risk_score dan rules_triggered sebagai advisory.
    Server melakukan metadata scan sendiri secara independen.
    """

    # --- Tipe & metadata ---
    secret_type       = serializers.ChoiceField(choices=Secret.SecretType.choices)
    original_filename = serializers.CharField(
        required=False, allow_blank=True, max_length=255
    )
    mime_type         = serializers.CharField(
        required=False, allow_blank=True, max_length=100
    )
    file_size_bytes   = serializers.IntegerField(
        required=False, allow_null=True, min_value=1
    )

    # --- ZKE payload (wajib) ---
    encrypted_payload = serializers.CharField(
        help_text="Ciphertext AES-256-GCM hasil enkripsi di browser, base64."
    )
    encryption_iv     = serializers.CharField(
        max_length=32,
        help_text="Nonce 96-bit, base64url."
    )
    encryption_tag    = serializers.CharField(
        max_length=32,
        help_text="GCM authentication tag 128-bit, base64url."
    )
    encryption_salt   = serializers.CharField(
        required=False, allow_blank=True, max_length=64,
        help_text="Salt PBKDF2 base64. Wajib jika key di-derive dari password."
    )

    # --- Akses & expiry ---
    max_views         = serializers.IntegerField(
        default=1, min_value=1, max_value=100
    )
    expires_in_hours  = serializers.IntegerField(
        required=False, allow_null=True, min_value=1,
        help_text="Berapa jam sampai secret expired. Null = tidak ada expiry (hanya user login)."
    )
    num_recipients    = serializers.IntegerField(
        default=1, min_value=1, max_value=50,
        help_text="Jumlah link yang akan digenerate (satu per penerima)."
    )
    recipient_labels  = serializers.ListField(
        child=serializers.CharField(max_length=100),
        required=False, default=list,
        help_text="Label opsional per link. Jumlah harus sama dengan num_recipients."
    )

    # --- Password tambahan (opsional) ---
    access_password   = serializers.CharField(
        required=False, allow_blank=True, write_only=True,
        min_length=4, max_length=128,
        help_text="Password tambahan untuk membuka link. Akan di-hash di server."
    )

    # --- Email whitelist (opsional) ---
    email_whitelist   = serializers.ListField(
        child=serializers.EmailField(),
        required=False, default=list,
        help_text="Daftar email yang boleh mengakses secret. Kosong = semua boleh."
    )

    # --- AI detection dari client (advisory) ---
    client_risk_score    = serializers.IntegerField(
        required=False, default=0, min_value=0, max_value=100,
        help_text="Risk score dari AI detection di browser."
    )
    client_rules_triggered = serializers.ListField(
        child=serializers.CharField(max_length=100),
        required=False, default=list,
        help_text="Rules yang terpicu di browser. Contoh: ['pii_credit_card']."
    )

    # --- Fingerprint untuk anon session ---
    fingerprint_hash  = serializers.CharField(
        required=False, allow_blank=True, max_length=64,
        help_text="SHA-256 fingerprint browser. Wajib jika tidak menyertakan JWT."
    )

    # ------------------------------------------------------------------
    # Validasi individual field
    # ------------------------------------------------------------------

    def validate_encrypted_payload(self, value):
        if len(value) < 10:
            raise serializers.ValidationError("Payload terlalu pendek.")
        return validate_base64(value, "encrypted_payload")

    def validate_encryption_iv(self, value):
        validate_base64(value, "encryption_iv")
        return validate_iv_length(value)

    def validate_encryption_tag(self, value):
        validate_base64(value, "encryption_tag")
        return validate_tag_length(value)

    def validate_encryption_salt(self, value):
        if value:
            return validate_base64(value, "encryption_salt")
        return value

    def validate_mime_type(self, value):
        if value and value not in ALLOWED_MIME_TYPES:
            raise serializers.ValidationError(
                f"Tipe file '{value}' tidak diizinkan."
            )
        return value

    def validate_original_filename(self, value):
        if value:
            ext = "." + value.rsplit(".", 1)[-1].lower() if "." in value else ""
            if ext in BLOCKED_EXTENSIONS:
                raise serializers.ValidationError(
                    f"Ekstensi file '{ext}' tidak diizinkan dikirim."
                )
        return value

    def validate_email_whitelist(self, value):
        # Normalize + deduplicate
        return list({email.lower().strip() for email in value})

    def validate_recipient_labels(self, value):
        return [label.strip() for label in value if label.strip()]

    # ------------------------------------------------------------------
    # Cross-field validation
    # ------------------------------------------------------------------

    def validate(self, data):
        request = self.context.get("request")
        user = request.user if request else None
        is_authenticated = user and user.is_authenticated

        # -- Rate limit & file size check --
        config = (
            RateLimitConfig.get_for_registered()
            if is_authenticated
            else RateLimitConfig.get_for_anonymous()
        )

        file_size_bytes = data.get("file_size_bytes")
        if file_size_bytes:
            max_bytes = config.max_file_size_mb * 1024 * 1024
            if file_size_bytes > max_bytes:
                raise serializers.ValidationError({
                    "file_size_bytes": (
                        f"Ukuran file melebihi batas. "
                        f"Maks {config.max_file_size_mb} MB untuk akun Anda."
                    )
                })

        # -- Expiry check --
        expires_in_hours = data.get("expires_in_hours")
        if not is_authenticated and not expires_in_hours:
            raise serializers.ValidationError({
                "expires_in_hours": "Pengguna tanpa login wajib mengatur waktu kedaluwarsa."
            })
        if expires_in_hours:
            max_hours = config.max_expiry_days * 24
            if max_hours > 0 and expires_in_hours > max_hours:
                raise serializers.ValidationError({
                    "expires_in_hours": (
                        f"Maks {config.max_expiry_days} hari "
                        f"({max_hours} jam) untuk akun Anda."
                    )
                })

        # -- Recipient check --
        num_recipients = data.get("num_recipients", 1)
        if num_recipients > config.max_recipients:
            raise serializers.ValidationError({
                "num_recipients": (
                    f"Maks {config.max_recipients} penerima untuk akun Anda."
                )
            })

        # -- Label count check --
        labels = data.get("recipient_labels", [])
        if labels and len(labels) != num_recipients:
            raise serializers.ValidationError({
                "recipient_labels": (
                    f"Jumlah label ({len(labels)}) harus sama "
                    f"dengan num_recipients ({num_recipients})."
                )
            })

        # -- Anon: wajib fingerprint --
        if not is_authenticated:
            if not data.get("fingerprint_hash"):
                raise serializers.ValidationError({
                    "fingerprint_hash": "fingerprint_hash wajib untuk pengguna tanpa login."
                })

        # -- Client risk score: jika terlalu tinggi, tolak (double check server side) --
        client_risk_score = data.get("client_risk_score", 0)
        if client_risk_score >= 70:
            raise serializers.ValidationError({
                "client_risk_score": (
                    "Konten ini ditolak oleh pemeriksaan keamanan di browser Anda."
                )
            })

        return data

    # ------------------------------------------------------------------
    # Save (create secret + links + whitelist)
    # ------------------------------------------------------------------

    def create(self, validated_data):
        
        from django.utils import timezone

        request = self.context.get("request")
        user = request.user if request else None
        is_authenticated = user and user.is_authenticated

        # -- Siapkan expiry --
        expires_at = None
        expires_in_hours = validated_data.get("expires_in_hours")
        if expires_in_hours:
            expires_at = timezone.now() + timezone.timedelta(hours=expires_in_hours)

        # -- Hash access password jika ada --
        access_password = validated_data.pop("access_password", "")
        access_password_hash = ""
        if access_password:
            access_password_hash = make_password(access_password)

        # -- Tentukan anon session jika tidak login --
        anon_session = None
        if not is_authenticated:
            ip = self._get_client_ip(request)
            fingerprint = validated_data.get("fingerprint_hash", "")
            anon_session, _ = AnonymousSession.objects.get_or_create(
                ip_address=ip,
                fingerprint_hash=fingerprint,
            )
            if not anon_session.can_create_secret():
                raise serializers.ValidationError(
                    "Batas pembuatan secret harian tercapai. Silakan login untuk melanjutkan."
                )
            anon_session.increment_count()

        # -- Tentukan AI flagging --
        client_risk_score    = validated_data.get("client_risk_score", 0)
        client_rules         = validated_data.get("client_rules_triggered", [])
        ai_flagged           = client_risk_score >= 40

        # -- Buat Secret --
        secret = Secret.objects.create(
            creator_user      = user if is_authenticated else None,
            anon_session      = anon_session,
            secret_type       = validated_data["secret_type"],
            original_filename = validated_data.get("original_filename", ""),
            mime_type         = validated_data.get("mime_type", ""),
            file_size_bytes   = validated_data.get("file_size_bytes"),
            encrypted_payload = validated_data["encrypted_payload"],
            encryption_iv     = validated_data["encryption_iv"],
            encryption_tag    = validated_data["encryption_tag"],
            encryption_salt   = validated_data.get("encryption_salt", ""),
            max_views         = validated_data["max_views"],
            expires_at        = expires_at,
            access_password_hash = access_password_hash,
            ai_risk_score     = client_risk_score,
            ai_flagged        = ai_flagged,
        )

        # -- Buat SecretLink per penerima --
        num_recipients = validated_data.get("num_recipients", 1)
        labels         = validated_data.get("recipient_labels", [])
        links = []
        for i in range(num_recipients):
            label = labels[i] if i < len(labels) else ""
            link  = SecretLink.objects.create(secret=secret, label=label)
            links.append(link)

        # -- Buat EmailWhitelist --
        email_whitelist = validated_data.get("email_whitelist", [])
        for email in email_whitelist:
            EmailWhitelist.objects.create(secret=secret, email=email)

        # -- Simpan AI detection log --
        if client_risk_score > 0 or client_rules:
            action = (
                AIDetectionLog.ActionTaken.FLAGGED
                if ai_flagged
                else AIDetectionLog.ActionTaken.ALLOWED
            )
            AIDetectionLog.objects.create(
                secret          = secret,
                source          = AIDetectionLog.DetectionSource.CLIENT,
                rules_triggered = client_rules,
                risk_score      = client_risk_score,
                action_taken    = action,
                ip_address      = self._get_client_ip(request),
                file_size_bytes = validated_data.get("file_size_bytes"),
                secret_type     = validated_data["secret_type"],
            )

        return secret, links

    def _get_client_ip(self, request):
        if not request:
            return None
        x_forwarded = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded:
            return x_forwarded.split(",")[0].strip()
        return request.META.get("REMOTE_ADDR")


class SecretCreateResponseSerializer(serializers.Serializer):
    """Response setelah secret berhasil dibuat."""
    secret_id    = serializers.UUIDField()
    revoke_token = serializers.CharField(
        help_text="Simpan token ini. Dikembalikan SEKALI saja dan tidak disimpan di tempat lain."
    )
    links        = SecretLinkSerializer(many=True)
    expires_at   = serializers.DateTimeField(allow_null=True)
    ai_flagged   = serializers.BooleanField()
    created_at   = serializers.DateTimeField()


# ===========================================================================
# SECRET ACCESS SERIALIZER
# ===========================================================================

class SecretAccessRequestSerializer(serializers.Serializer):
    """
    Request untuk mengakses secret via link.
    Browser akan mendekripsi ciphertext yang dikembalikan — server tidak bisa baca.
    """
    email            = serializers.EmailField(
        required=False, allow_blank=True,
        help_text="Wajib jika secret memiliki email whitelist."
    )
    access_password  = serializers.CharField(
        required=False, allow_blank=True, write_only=True,
        help_text="Wajib jika secret dilindungi password tambahan."
    )

    def validate_email(self, value):
        return value.lower().strip() if value else ""

    def validate(self, data):
        
        link    = self.context.get("link")
        request = self.context.get("request")

        if not link:
            raise serializers.ValidationError("Link tidak ditemukan.")

        # -- Cek status link & secret --
        can_access, reason = link.can_be_accessed()
        if not can_access:
            reason_messages = {
                "link_revoked": "Link ini telah dicabut.",
                "revoked":      "Secret ini telah dicabut oleh pembuatnya.",
                "blocked":      "Secret ini diblokir oleh administrator.",
                "expired":      "Secret ini sudah kedaluwarsa.",
                "exhausted":    "Secret ini sudah mencapai batas jumlah akses.",
            }
            raise serializers.ValidationError(
                reason_messages.get(reason, "Secret tidak dapat diakses.")
            )

        secret = link.secret

        # -- Cek email whitelist --
        if secret.email_whitelist.exists():
            email = data.get("email", "")
            if not email:
                raise serializers.ValidationError({
                    "email": "Secret ini hanya bisa diakses oleh email tertentu. Masukkan email Anda."
                })
            whitelist_entry = secret.email_whitelist.filter(email=email).first()
            if not whitelist_entry:
                # Log akses ditolak
                self._log_access(link, email, request, AccessLog.AccessResult.DENIED_EMAIL)
                raise serializers.ValidationError({
                    "email": "Email Anda tidak terdaftar untuk mengakses secret ini."
                })
            data["whitelist_entry"] = whitelist_entry

        # -- Cek password tambahan --
        if secret.access_password_hash:
            access_password = data.get("access_password", "")
            if not access_password:
                raise serializers.ValidationError({
                    "access_password": "Secret ini dilindungi password. Masukkan password untuk melanjutkan."
                })
            is_valid = check_password(
                access_password,
                secret.access_password_hash
            )
            if not is_valid:
                self._log_access(link, data.get("email", ""), request,
                                 AccessLog.AccessResult.DENIED_PASSWORD)
                raise serializers.ValidationError({
                    "access_password": "Password salah."
                })

        data["link"]   = link
        data["secret"] = secret
        return data

    def _log_access(self, link, email, request, result):
        ip = ""
        ua = ""
        if request:
            x_forwarded = request.META.get("HTTP_X_FORWARDED_FOR")
            ip = x_forwarded.split(",")[0].strip() if x_forwarded else request.META.get("REMOTE_ADDR", "")
            ua = request.META.get("HTTP_USER_AGENT", "")
        AccessLog.objects.create(
            secret_link       = link,
            accessed_by_email = email,
            ip_address        = ip or None,
            user_agent        = ua,
            result            = result,
        )


class SecretAccessResponseSerializer(serializers.Serializer):
    """
    Response saat secret berhasil diakses.
    Mengembalikan ciphertext — browser yang mendekripsi.
    """
    secret_id         = serializers.UUIDField()
    secret_type       = serializers.CharField()
    encrypted_payload = serializers.CharField()
    encryption_iv     = serializers.CharField()
    encryption_tag    = serializers.CharField()
    encryption_salt   = serializers.CharField()
    original_filename = serializers.CharField()
    mime_type         = serializers.CharField()
    file_size_bytes   = serializers.IntegerField(allow_null=True)
    views_remaining   = serializers.IntegerField(allow_null=True)
    accessed_at       = serializers.DateTimeField()


# ===========================================================================
# SECRET DETAIL (untuk creator)
# ===========================================================================

class SecretDetailSerializer(serializers.ModelSerializer):
    """
    Detail secret untuk creator — termasuk semua link dan whitelist.
    Tidak mengembalikan encrypted_payload (tidak perlu dilihat creator via API ini).
    """
    links           = SecretLinkSerializer(many=True, read_only=True)
    email_whitelist = EmailWhitelistSerializer(many=True, read_only=True)
    views_remaining = serializers.ReadOnlyField()
    is_expired      = serializers.ReadOnlyField()
    creator_email   = serializers.SerializerMethodField()

    class Meta:
        model  = Secret
        fields = (
            "id", "secret_type", "original_filename", "mime_type",
            "file_size_bytes", "max_views", "current_views", "views_remaining",
            "expires_at", "is_expired", "status", "ai_flagged", "ai_risk_score",
            "revoke_token", "links", "email_whitelist",
            "creator_email", "created_at",
        )
        read_only_fields = fields

    def get_creator_email(self, obj):
        return obj.creator_user.email if obj.creator_user else None


# ===========================================================================
# SECRET REVOKE SERIALIZER
# ===========================================================================

class SecretRevokeSerializer(serializers.Serializer):
    """
    Revoke seluruh secret.
    Autentikasi via JWT (user login) atau revoke_token (anon / tanpa login).
    Setelah revoke, encrypted_payload dihapus permanen dari DB.
    """
    revoke_token = serializers.CharField(
        required=False, allow_blank=True,
        help_text="Wajib jika tidak menyertakan JWT."
    )
    confirm      = serializers.BooleanField(
        help_text="Harus True untuk konfirmasi revoke. Ini tidak bisa dibatalkan."
    )

    def validate_confirm(self, value):
        if not value:
            raise serializers.ValidationError(
                "Anda harus mengkonfirmasi revoke dengan mengirimkan confirm=true."
            )
        return value

    def validate(self, data):
        secret  = self.context.get("secret")
        request = self.context.get("request")

        if not secret:
            raise serializers.ValidationError("Secret tidak ditemukan.")

        if secret.status == Secret.Status.REVOKED:
            raise serializers.ValidationError("Secret ini sudah di-revoke sebelumnya.")

        user = request.user if request else None

        # Auth via JWT
        if user and user.is_authenticated:
            if secret.creator_user != user and not user.is_admin:
                raise serializers.ValidationError(
                    "Anda tidak memiliki akses untuk merevoke secret ini."
                )
            return data

        # Auth via revoke_token
        revoke_token = data.get("revoke_token", "")
        if not revoke_token:
            raise serializers.ValidationError(
                "Autentikasi diperlukan: sertakan JWT atau revoke_token."
            )
        if secret.revoke_token != revoke_token:
            raise serializers.ValidationError("Revoke token tidak valid.")

        return data


# ===========================================================================
# ADMIN SERIALIZERS
# ===========================================================================

class AdminSecretListSerializer(serializers.ModelSerializer):
    """
    List secret untuk admin — tampilkan info penting termasuk flagged.
    Tidak menampilkan encrypted_payload.
    """
    creator_email   = serializers.SerializerMethodField()
    link_count      = serializers.SerializerMethodField()
    status_display  = serializers.CharField(source="get_status_display", read_only=True)

    class Meta:
        model  = Secret
        fields = (
            "id", "secret_type", "creator_email", "status", "status_display",
            "ai_risk_score", "ai_flagged", "current_views", "max_views",
            "file_size_bytes", "mime_type", "expires_at",
            "link_count", "created_at",
        )
        read_only_fields = fields

    def get_creator_email(self, obj):
        if obj.creator_user:
            return obj.creator_user.email
        return f"anon ({obj.anon_session.ip_address if obj.anon_session else '?'})"

    def get_link_count(self, obj):
        return obj.links.count()


class AdminAIDetectionSerializer(serializers.ModelSerializer):
    """Detail AI detection log untuk antrian review admin."""
    secret_id      = serializers.SerializerMethodField()
    reviewed_by_email = serializers.SerializerMethodField()
    source_display = serializers.CharField(source="get_source_display", read_only=True)
    action_display = serializers.CharField(source="get_action_taken_display", read_only=True)

    class Meta:
        model  = AIDetectionLog
        fields = (
            "id", "secret_id", "source", "source_display",
            "rules_triggered", "risk_score", "action_taken", "action_display",
            "ip_address", "file_size_bytes", "secret_type",
            "admin_note", "reviewed_by_email", "reviewed_at",
            "created_at",
        )
        read_only_fields = fields

    def get_secret_id(self, obj):
        return str(obj.secret_id) if obj.secret_id else None

    def get_reviewed_by_email(self, obj):
        return obj.reviewed_by.email if obj.reviewed_by else None


class AdminReviewActionSerializer(serializers.Serializer):
    """Aksi review admin terhadap flagged secret."""

    action     = serializers.ChoiceField(choices=[("approve", "Approve"), ("block", "Block")])
    admin_note = serializers.CharField(required=False, allow_blank=True, max_length=500)


class AccessLogSerializer(serializers.ModelSerializer):
    """Read-only log akses untuk admin atau creator."""
    link_token     = serializers.CharField(source="secret_link.token", read_only=True)
    result_display = serializers.CharField(source="get_result_display", read_only=True)

    class Meta:
        model  = AccessLog
        fields = (
            "id", "link_token", "accessed_by_email", "ip_address",
            "user_agent", "result", "result_display", "accessed_at",
        )
        read_only_fields = fields