import uuid
import secrets
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager
from django.db import models
from django.utils import timezone
from django.core.validators import FileExtensionValidator, MinValueValidator, MaxValueValidator


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def generate_token(length=48):
    """Generate URL-safe random token."""
    return secrets.token_urlsafe(length)


def generate_revoke_token():
    return secrets.token_urlsafe(32)


def generate_short_token():
    """Token pendek untuk secret link URL (16 char, tetap aman)."""
    return secrets.token_urlsafe(16)


# ---------------------------------------------------------------------------
# 1. USER
# ---------------------------------------------------------------------------

class UserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError("Email wajib diisi.")
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("role", User.Role.ADMIN)
        return self.create_user(email, password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    """
    Custom user model berbasis email.
    Role: USER (default) atau ADMIN (akses Django admin + admin API).
    """

    class Role(models.TextChoices):
        USER  = "user",  "User"
        ADMIN = "admin", "Admin"

    id         = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email      = models.EmailField(unique=True)
    full_name  = models.CharField(max_length=150, blank=True)
    role       = models.CharField(max_length=10, choices=Role.choices, default=Role.USER)

    is_active  = models.BooleanField(default=True)
    is_staff   = models.BooleanField(default=False)   # akses Django admin
    is_banned  = models.BooleanField(default=False)   # banned oleh admin

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    # Statistik cepat (opsional, bisa dihitung dari relasi)
    total_secrets_created = models.PositiveIntegerField(default=0)

    USERNAME_FIELD  = "email"
    REQUIRED_FIELDS = []
    objects = UserManager()

    class Meta:
        db_table    = "users"
        verbose_name        = "User"
        verbose_name_plural = "Users"
        indexes = [
            models.Index(fields=["email"]),
            models.Index(fields=["role"]),
            models.Index(fields=["is_banned"]),
        ]

    def __str__(self):
        return self.email

    @property
    def is_admin(self):
        return self.role == self.Role.ADMIN

    @property
    def max_file_size_mb(self):
        """Batas upload berdasarkan status login."""
        return 100  # MB untuk registered user

    @property
    def max_secrets_per_day(self):
        return 9999  # unlimited praktisnya untuk user login


# ---------------------------------------------------------------------------
# 2. ANONYMOUS SESSION
# ---------------------------------------------------------------------------

class AnonymousSession(models.Model):
    """
    Melacak penggunaan oleh user yang belum login.
    Identifikasi via kombinasi IP + fingerprint hash (dari browser).
    Batas: 3 secret per hari, maks 10 MB per file.
    """

    id               = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    ip_address       = models.GenericIPAddressField()
    fingerprint_hash = models.CharField(max_length=64, db_index=True)
    # fingerprint_hash: SHA-256 dari kombinasi user-agent + bahasa browser
    # dihitung di frontend, dikirim saat create secret

    daily_count      = models.PositiveSmallIntegerField(default=0)
    last_reset_date  = models.DateField(default=timezone.now)

    created_at       = models.DateTimeField(auto_now_add=True)
    updated_at       = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "anonymous_sessions"
        verbose_name        = "Anonymous Session"
        verbose_name_plural = "Anonymous Sessions"
        unique_together = [("ip_address", "fingerprint_hash")]
        indexes = [
            models.Index(fields=["ip_address"]),
            models.Index(fields=["fingerprint_hash"]),
            models.Index(fields=["last_reset_date"]),
        ]

    def __str__(self):
        return f"Anon {self.ip_address} ({self.daily_count}/{self.max_secrets_per_day} hari ini)"
    
    @property
    def max_file_size_mb(self):
        config = RateLimitConfig.get_for_anonymous()
        return config.max_file_size_mb

    @property
    def max_secrets_per_day(self):
        config = RateLimitConfig.get_for_anonymous()
        return config.max_secrets_per_day

    def reset_if_new_day(self):
        """Reset counter jika sudah hari baru."""
        today = timezone.now().date()
        last_reset = self.last_reset_date
        # Konversi ke date jika masih datetime
        if hasattr(last_reset, 'date'):
            last_reset = last_reset.date()
        if last_reset < today:
            self.daily_count = 0
            self.last_reset_date = today
            self.save(update_fields=["daily_count", "last_reset_date"])

    def can_create_secret(self):
        self.reset_if_new_day()
        return self.daily_count < self.max_secrets_per_day

    def increment_count(self):
        self.daily_count += 1
        self.save(update_fields=["daily_count"])


# ---------------------------------------------------------------------------
# 3. SECRET (inti aplikasi)
# ---------------------------------------------------------------------------

class Secret(models.Model):
    """
    Menyimpan konten terenkripsi (ZKE).
    Server tidak pernah memegang key — hanya menyimpan ciphertext + IV + auth tag.

    Enkripsi dilakukan di browser (Web Crypto API, AES-256-GCM).
    Key di-derive dari password user via PBKDF2 di browser,
    atau di-generate random dan dikembalikan sekali ke creator via URL fragment (#key=...).

    PENTING:
    - encrypted_payload  : ciphertext (base64)
    - encryption_iv      : nonce 96-bit (base64), unik per enkripsi
    - encryption_tag     : GCM authentication tag 128-bit (base64)
    - encryption_salt    : salt PBKDF2 jika key di-derive dari password (base64)
    """

    class SecretType(models.TextChoices):
        TEXT     = "text",     "Teks"
        PASSWORD = "password", "Password"
        FILE     = "file",     "File"
        NOTE     = "note",     "Catatan"

    class Status(models.TextChoices):
        ACTIVE  = "active",  "Aktif"
        REVOKED = "revoked", "Dicabut"
        EXPIRED = "expired", "Kedaluwarsa"
        BLOCKED = "blocked", "Diblokir Admin"

    # Primary key & relasi
    id               = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    creator_user     = models.ForeignKey(
        User, on_delete=models.SET_NULL,
        null=True, blank=True, related_name="secrets",
        help_text="Null jika dibuat oleh anonymous user."
    )
    anon_session     = models.ForeignKey(
        AnonymousSession, on_delete=models.SET_NULL,
        null=True, blank=True, related_name="secrets",
        help_text="Null jika dibuat oleh user terdaftar."
    )

    # Tipe & metadata
    secret_type      = models.CharField(max_length=10, choices=SecretType.choices)
    original_filename = models.CharField(
        max_length=255, blank=True,
        help_text="Nama file asli (hanya untuk tipe file). Disimpan terenkripsi terpisah opsional."
    )
    mime_type        = models.CharField(max_length=100, blank=True)
    file_size_bytes  = models.PositiveBigIntegerField(
        null=True, blank=True,
        help_text="Ukuran file dalam bytes sebelum enkripsi."
    )

    # ZKE — payload terenkripsi
    encrypted_payload = models.TextField(
        help_text="Ciphertext base64 hasil enkripsi AES-256-GCM di browser."
    )
    encryption_iv     = models.CharField(
        max_length=32,
        help_text="Nonce 96-bit, base64. Unik per secret."
    )
    encryption_tag    = models.CharField(
        max_length=32,
        help_text="GCM auth tag 128-bit, base64."
    )
    encryption_salt   = models.CharField(
        max_length=64, blank=True,
        help_text="Salt PBKDF2 base64. Diisi jika key di-derive dari password user."
    )
    # Catatan: key enkripsi TIDAK disimpan di server.
    # Key dikembalikan ke creator via URL fragment (tidak masuk ke server log).

    # Akses & expiry
    max_views        = models.PositiveSmallIntegerField(
        default=1,
        validators=[MinValueValidator(1), MaxValueValidator(100)],
        help_text="Maks berapa kali link bisa dibuka. 0 = unlimited (hanya untuk user login)."
    )
    current_views    = models.PositiveIntegerField(default=0)
    expires_at       = models.DateTimeField(
        null=True, blank=True,
        help_text="Null = tidak ada expiry (hanya untuk user login)."
    )

    # Password tambahan untuk buka link (opsional)
    # Password ini di-hash di server — bukan bagian dari ZKE key
    access_password_hash = models.CharField(
        max_length=128, blank=True,
        help_text="Bcrypt hash dari password tambahan untuk akses link. Kosong = tidak ada password."
    )

    # Revoke
    revoke_token     = models.CharField(
        max_length=64, unique=True, default=generate_revoke_token,
        help_text="Token rahasia untuk revoke secret tanpa perlu login. Dikembalikan sekali ke creator."
    )

    # Status & AI
    status           = models.CharField(
        max_length=10, choices=Status.choices, default=Status.ACTIVE, db_index=True
    )
    ai_risk_score    = models.PositiveSmallIntegerField(
        default=0,
        validators=[MinValueValidator(0), MaxValueValidator(100)],
        help_text="Risk score 0–100 dari AI detection di browser/metadata server."
    )
    ai_flagged       = models.BooleanField(
        default=False,
        help_text="True jika perlu review admin (score 40–69)."
    )

    # Timestamps
    created_at       = models.DateTimeField(auto_now_add=True)
    updated_at       = models.DateTimeField(auto_now=True)
    revoked_at       = models.DateTimeField(null=True, blank=True)
    expired_at       = models.DateTimeField(
        null=True, blank=True,
        help_text="Kapan secret ini di-expire oleh sistem (beda dari expires_at yang di-set user)."
    )

    class Meta:
        db_table    = "secrets"
        verbose_name        = "Secret"
        verbose_name_plural = "Secrets"
        ordering    = ["-created_at"]
        indexes = [
            models.Index(fields=["status"]),
            models.Index(fields=["expires_at"]),
            models.Index(fields=["ai_flagged"]),
            models.Index(fields=["creator_user", "created_at"]),
            models.Index(fields=["revoke_token"]),
        ]

    def __str__(self):
        creator = self.creator_user.email if self.creator_user else "anon"
        return f"Secret [{self.secret_type}] by {creator} — {self.status}"

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def is_active(self):
        return self.status == self.Status.ACTIVE

    @property
    def is_expired(self):
        if self.expires_at and timezone.now() > self.expires_at:
            return True
        return False

    @property
    def views_remaining(self):
        if self.max_views == 0:
            return None  # unlimited
        return max(0, self.max_views - self.current_views)

    @property
    def is_exhausted(self):
        """True jika view count sudah habis."""
        if self.max_views == 0:
            return False
        return self.current_views >= self.max_views

    # ------------------------------------------------------------------
    # Methods
    # ------------------------------------------------------------------

    def can_be_accessed(self):
        """
        Cek apakah secret masih bisa diakses.
        Mengembalikan (bool, reason_string).
        """
        if self.status == self.Status.REVOKED:
            return False, "revoked"
        if self.status == self.Status.BLOCKED:
            return False, "blocked"
        if self.is_expired:
            return False, "expired"
        if self.is_exhausted:
            return False, "exhausted"
        return True, None

    def revoke(self, hard_delete_payload=True):
        """
        Cabut secret.
        hard_delete_payload=True: hapus ciphertext dari DB (true ZKE revoke).
        Setelah ini data tidak bisa di-recover oleh siapapun, termasuk admin.
        """
        self.status     = self.Status.REVOKED
        self.revoked_at = timezone.now()
        if hard_delete_payload:
            # Hapus payload — data musnah sepenuhnya
            self.encrypted_payload = ""
            self.encryption_iv     = ""
            self.encryption_tag    = ""
            self.encryption_salt   = ""
        self.save()
        # Non-aktifkan semua link terkait
        self.links.update(is_active=False)

    def mark_expired(self):
        self.status     = self.Status.EXPIRED
        self.expired_at = timezone.now()
        self.save(update_fields=["status", "expired_at"])

    def increment_view(self):
        self.current_views += 1
        self.save(update_fields=["current_views"])
        if self.is_exhausted:
            self.mark_expired()


# ---------------------------------------------------------------------------
# 4. SECRET LINK
# ---------------------------------------------------------------------------

class SecretLink(models.Model):
    """
    Setiap secret bisa punya beberapa link (sesuai jumlah penerima).
    Contoh: secret dengan max_recipients=3 akan generate 3 SecretLink.
    Setiap link punya token unik dan bisa di-revoke secara independen.
    """

    id         = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    secret     = models.ForeignKey(Secret, on_delete=models.CASCADE, related_name="links")
    token      = models.CharField(
        max_length=32, unique=True, default=generate_short_token,
        help_text="Token URL-safe yang membentuk link: /s/{token}"
    )
    label      = models.CharField(
        max_length=100, blank=True,
        help_text="Label opsional untuk membedakan penerima. Contoh: 'Link untuk Alice'."
    )

    is_active      = models.BooleanField(default=True, db_index=True)
    accessed_count = models.PositiveIntegerField(default=0)
    last_accessed  = models.DateTimeField(null=True, blank=True)

    created_at     = models.DateTimeField(auto_now_add=True)
    revoked_at     = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table    = "secret_links"
        verbose_name        = "Secret Link"
        verbose_name_plural = "Secret Links"
        indexes = [
            models.Index(fields=["token"]),
            models.Index(fields=["secret", "is_active"]),
        ]

    def __str__(self):
        return f"/s/{self.token} ({'aktif' if self.is_active else 'nonaktif'})"

    def revoke(self):
        """Cabut link ini saja. Secret dan link lain tetap aktif."""
        self.is_active  = False
        self.revoked_at = timezone.now()
        self.save(update_fields=["is_active", "revoked_at"])

    def record_access(self):
        self.accessed_count += 1
        self.last_accessed  = timezone.now()
        self.save(update_fields=["accessed_count", "last_accessed"])

    @property
    def full_url(self):
        """Kembalikan path link (tanpa domain, untuk fleksibilitas env)."""
        return f"/s/{self.token}"

    def can_be_accessed(self):
        if not self.is_active:
            return False, "link_revoked"
        # Delegasi ke secret
        return self.secret.can_be_accessed()


# ---------------------------------------------------------------------------
# 5. EMAIL WHITELIST
# ---------------------------------------------------------------------------

class EmailWhitelist(models.Model):
    """
    Daftar email yang diizinkan mengakses secret tertentu.
    Jika tabel ini kosong untuk sebuah secret, artinya siapapun boleh akses
    (selama punya link + password jika ada).
    """

    id         = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    secret     = models.ForeignKey(Secret, on_delete=models.CASCADE, related_name="email_whitelist")
    email      = models.EmailField()

    accessed_at  = models.DateTimeField(
        null=True, blank=True,
        help_text="Kapan email ini pertama kali berhasil mengakses secret."
    )
    access_count = models.PositiveSmallIntegerField(default=0)

    created_at   = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table    = "email_whitelist"
        verbose_name        = "Email Whitelist"
        verbose_name_plural = "Email Whitelist"
        unique_together = [("secret", "email")]
        indexes = [
            models.Index(fields=["secret", "email"]),
        ]

    def __str__(self):
        return f"{self.email} → Secret {self.secret_id}"

    def record_access(self):
        if not self.accessed_at:
            self.accessed_at = timezone.now()
        self.access_count += 1
        self.save(update_fields=["accessed_at", "access_count"])

# ---------------------------------------------------------------------------
# 6. Domain WHITELIST
# ---------------------------------------------------------------------------

class DomainWhitelist(models.Model):
    """
    Whitelist berdasarkan domain email.
    Contoh: @companyabc.com — semua email dengan domain ini bisa akses.
    """
    id         = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    secret     = models.ForeignKey(Secret, on_delete=models.CASCADE, related_name="domain_whitelist")
    domain     = models.CharField(
        max_length=255,
        help_text="Domain email. Contoh: companyabc.com (tanpa @)"
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "domain_whitelist"
        unique_together = [("secret", "domain")]

    def __str__(self):
        return f"@{self.domain} → Secret {self.secret_id}"
    
# ---------------------------------------------------------------------------
# 6. ACCESS LOG
# ---------------------------------------------------------------------------

class AccessLog(models.Model):
    """
    Log setiap upaya akses ke secret link.
    Menyimpan metadata akses: IP, email (jika whitelist), user agent, hasil akses.
    Tidak menyimpan konten secret (ZKE — server tidak bisa baca payload).
    """

    class AccessResult(models.TextChoices):
        SUCCESS          = "success",          "Berhasil"
        DENIED_PASSWORD  = "denied_password",  "Password salah"
        DENIED_EMAIL     = "denied_email",     "Email tidak di whitelist"
        DENIED_EXPIRED   = "denied_expired",   "Secret kedaluwarsa"
        DENIED_REVOKED   = "denied_revoked",   "Secret dicabut"
        DENIED_EXHAUSTED = "denied_exhausted", "View count habis"
        DENIED_BLOCKED   = "denied_blocked",   "Diblokir admin"

    id              = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    secret_link     = models.ForeignKey(SecretLink, on_delete=models.CASCADE, related_name="access_logs")

    accessed_by_email = models.EmailField(
        blank=True,
        help_text="Email accessor jika mereka memasukkan email untuk whitelist check."
    )
    ip_address      = models.GenericIPAddressField(null=True, blank=True)
    user_agent      = models.TextField(blank=True)
    referer         = models.URLField(blank=True, max_length=500)

    result          = models.CharField(
        max_length=20, choices=AccessResult.choices, default=AccessResult.SUCCESS
    )
    accessed_at     = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        db_table    = "access_logs"
        verbose_name        = "Access Log"
        verbose_name_plural = "Access Logs"
        ordering    = ["-accessed_at"]
        indexes = [
            models.Index(fields=["secret_link", "accessed_at"]),
            models.Index(fields=["result"]),
            models.Index(fields=["ip_address"]),
        ]

    def __str__(self):
        return f"[{self.result}] {self.secret_link.token} @ {self.accessed_at:%Y-%m-%d %H:%M}"


# ---------------------------------------------------------------------------
# 7. AI DETECTION LOG
# ---------------------------------------------------------------------------

class AIDetectionLog(models.Model):
    """
    Log hasil AI detection.
    Dalam arsitektur ZKE:
    - Scan konten (plaintext) dilakukan di BROWSER sebelum enkripsi.
    - Server menerima risk_score dan triggered_rules dari browser sebagai advisory.
    - Server melakukan scan METADATA sendiri (ukuran, tipe, rate, IP pattern).
    - Log ini menyimpan hasil dari keduanya.
    """

    class DetectionSource(models.TextChoices):
        CLIENT   = "client",   "Browser (client-side scan)"
        SERVER   = "server",   "Server (metadata scan)"

    class ActionTaken(models.TextChoices):
        ALLOWED = "allowed", "Diizinkan"
        FLAGGED = "flagged", "Diflag untuk review"
        BLOCKED = "blocked", "Diblokir otomatis"

    id              = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    secret          = models.ForeignKey(
        Secret, on_delete=models.CASCADE, related_name="ai_logs",
        null=True, blank=True,
        help_text="Null jika secret diblokir sebelum disimpan."
    )

    source          = models.CharField(max_length=10, choices=DetectionSource.choices)
    rules_triggered = models.JSONField(
        default=list,
        help_text="List rule yang terpicu. Contoh: ['pii_credit_card', 'keyword_malware']"
    )
    risk_score      = models.PositiveSmallIntegerField(
        validators=[MinValueValidator(0), MaxValueValidator(100)]
    )
    action_taken    = models.CharField(max_length=10, choices=ActionTaken.choices)

    # Metadata tambahan untuk audit
    ip_address      = models.GenericIPAddressField(null=True, blank=True)
    file_size_bytes = models.PositiveBigIntegerField(null=True, blank=True)
    secret_type     = models.CharField(max_length=10, blank=True)

    # Catatan admin (diisi saat review manual)
    admin_note      = models.TextField(blank=True)
    reviewed_by     = models.ForeignKey(
        User, on_delete=models.SET_NULL,
        null=True, blank=True, related_name="reviewed_detections"
    )
    reviewed_at     = models.DateTimeField(null=True, blank=True)

    created_at      = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table    = "ai_detection_logs"
        verbose_name        = "AI Detection Log"
        verbose_name_plural = "AI Detection Logs"
        ordering    = ["-created_at"]
        indexes = [
            models.Index(fields=["action_taken"]),
            models.Index(fields=["risk_score"]),
            models.Index(fields=["source"]),
            models.Index(fields=["reviewed_at"]),
            models.Index(fields=["created_at"]),
        ]

    def __str__(self):
        return f"[{self.source}] score={self.risk_score} → {self.action_taken} @ {self.created_at:%Y-%m-%d %H:%M}"

    def mark_reviewed(self, admin_user, note=""):
        self.reviewed_by = admin_user
        self.reviewed_at = timezone.now()
        self.admin_note  = note
        self.save(update_fields=["reviewed_by", "reviewed_at", "admin_note"])


# ---------------------------------------------------------------------------
# 8. RATE LIMIT CONFIG
# ---------------------------------------------------------------------------

class RateLimitConfig(models.Model):
    """
    Konfigurasi rate limit yang bisa diubah via Django admin tanpa deploy ulang.
    Gunakan singleton pattern: selalu ambil record pertama (atau buat jika belum ada).
    """

    class UserType(models.TextChoices):
        ANONYMOUS   = "anonymous",   "Anonymous (belum login)"
        REGISTERED  = "registered",  "Registered user"

    id                  = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user_type           = models.CharField(
        max_length=15, choices=UserType.choices, unique=True
    )
    max_secrets_per_day = models.PositiveSmallIntegerField(default=3)
    max_file_size_mb    = models.PositiveSmallIntegerField(default=10)
    max_recipients      = models.PositiveSmallIntegerField(
        default=10,
        help_text="Maks jumlah link (penerima) per secret."
    )
    max_expiry_days     = models.PositiveSmallIntegerField(
        default=7,
        help_text="Maks berapa hari secret bisa di-set expire. 0 = tidak ada batas."
    )
    is_active           = models.BooleanField(default=True)

    created_at          = models.DateTimeField(auto_now_add=True)
    updated_at          = models.DateTimeField(auto_now=True)

    class Meta:
        db_table    = "rate_limit_config"
        verbose_name        = "Rate Limit Config"
        verbose_name_plural = "Rate Limit Configs"

    def __str__(self):
        return f"RateLimit [{self.user_type}] — {self.max_secrets_per_day}/hari, maks {self.max_file_size_mb}MB"

    @classmethod
    def get_for_anonymous(cls):
        obj, _ = cls.objects.get_or_create(
            user_type=cls.UserType.ANONYMOUS,
            defaults={
                "max_secrets_per_day": 3,
                "max_file_size_mb":    10,
                "max_recipients":      5,
                "max_expiry_days":     3,
            }
        )
        return obj

    @classmethod
    def get_for_registered(cls):
        obj, _ = cls.objects.get_or_create(
            user_type=cls.UserType.REGISTERED,
            defaults={
                "max_secrets_per_day": 9999,
                "max_file_size_mb":    100,
                "max_recipients":      50,
                "max_expiry_days":     30,
            }
        )
        return obj