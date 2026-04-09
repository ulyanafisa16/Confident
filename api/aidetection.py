from __future__ import annotations

import base64
import logging
import math
import re
import time
from dataclasses import dataclass, field
from typing import Optional

from django.core.cache import cache
from django.utils import timezone

logger = logging.getLogger(__name__)


# ===========================================================================
# DATA CLASSES
# ===========================================================================

@dataclass
class RuleResult:
    """Hasil evaluasi satu rule."""
    rule_name:   str
    triggered:   bool
    score_delta: int          # berapa poin yang ditambahkan ke total score
    severity:    str          # "low", "medium", "high", "critical"
    detail:      str = ""     # penjelasan singkat kenapa triggered


@dataclass
class DetectionPayload:
    """
    Data yang dikirim ke detector.
    Semua field opsional — detector tetap berjalan dengan data yang tersedia.
    """
    # Metadata file
    secret_type:        str  = ""
    mime_type:          str  = ""
    original_filename:  str  = ""
    file_size_bytes:    Optional[int] = None

    # ZKE payload (ciphertext — hanya untuk analisis struktural, bukan konten)
    encrypted_payload:  str  = ""
    encryption_iv:      str  = ""

    # Behavioral context
    ip_address:         str  = ""
    fingerprint_hash:   str  = ""
    is_authenticated:   bool = False

    # Client-reported (advisory — bisa di-spoof, digunakan sebagai sinyal saja)
    client_risk_score:     int        = 0
    client_rules_triggered: list[str] = field(default_factory=list)

    # Request context
    user_agent:         str  = ""
    num_recipients:     int  = 1
    has_password:       bool = False
    has_email_whitelist: bool = False
    expires_in_hours:   Optional[int] = None


@dataclass
class DetectionResult:
    """Hasil agregat semua rule."""
    total_score:     int
    action:          str           # "allowed", "flagged", "blocked"
    rules_triggered: list[str]
    rule_details:    list[RuleResult]
    processed_at:    str

    @classmethod
    def from_results(cls, results: list[RuleResult]) -> DetectionResult:
        total_score = min(100, sum(r.score_delta for r in results if r.triggered))
        triggered   = [r.rule_name for r in results if r.triggered]

        if total_score >= 70:
            action = "blocked"
        elif total_score >= 40:
            action = "flagged"
        else:
            action = "allowed"

        return cls(
            total_score     = total_score,
            action          = action,
            rules_triggered = triggered,
            rule_details    = results,
            processed_at    = timezone.now().isoformat(),
        )


# ===========================================================================
# BASE RULE
# ===========================================================================

class Rule:
    """Base class untuk semua detection rule."""
    name:     str = "base_rule"
    severity: str = "low"

    def evaluate(self, payload: DetectionPayload) -> RuleResult:
        raise NotImplementedError

    def _result(self, triggered: bool, score: int, detail: str = "") -> RuleResult:
        return RuleResult(
            rule_name   = self.name,
            triggered   = triggered,
            score_delta = score if triggered else 0,
            severity    = self.severity,
            detail      = detail,
        )


# ===========================================================================
# RULE 1 — BLOCKED MIME TYPE
# File tipe eksekusi / skrip tidak boleh dikirim sama sekali.
# ===========================================================================

class BlockedMimeTypeRule(Rule):
    """
    Blokir tipe MIME yang berbahaya secara eksplisit.
    Ekstensi file eksekusi, skrip, dan binary berbahaya.
    Score: 80 (langsung block setelah dikombinasi rule lain).
    """
    name     = "blocked_mime_type"
    severity = "critical"

    BLOCKED_MIMES = {
        "application/x-executable",
        "application/x-msdownload",
        "application/x-msdos-program",
        "application/x-sh",
        "application/x-bat",
        "application/x-powershell",
        "application/java-archive",
        "application/x-java-applet",
        "application/x-httpd-php",
        "text/x-shellscript",
        "application/x-perl",
        "application/x-python-code",
    }

    BLOCKED_EXTENSIONS = {
        ".exe", ".bat", ".cmd", ".sh", ".ps1", ".ps2",
        ".vbs", ".vbe", ".js",  ".jse", ".wsf", ".wsh",
        ".msi", ".msp", ".jar", ".war", ".ear",
        ".dll", ".so",  ".dylib",
        ".php", ".asp", ".aspx", ".jsp",
        ".py",  ".rb",  ".pl",  ".cgi",
        ".scr", ".pif", ".com",
    }

    def evaluate(self, payload: DetectionPayload) -> RuleResult:
        mime = (payload.mime_type or "").lower().strip()
        filename = (payload.original_filename or "").lower()
        ext = "." + filename.rsplit(".", 1)[-1] if "." in filename else ""

        if mime in self.BLOCKED_MIMES:
            return self._result(True, 80, f"MIME type diblokir: {mime}")

        if ext in self.BLOCKED_EXTENSIONS:
            return self._result(True, 80, f"Ekstensi file diblokir: {ext}")

        return self._result(False, 0)


# ===========================================================================
# RULE 2 — FILE SIZE ANOMALY
# File sangat kecil atau sangat besar bisa mengindikasikan anomali.
# ===========================================================================

class FileSizeAnomalyRule(Rule):
    """
    Deteksi anomali ukuran file:
    - File sangat kecil (< 10 bytes) untuk tipe yang seharusnya lebih besar
    - File mendekati atau melebihi batas upload
    """
    name     = "file_size_anomaly"
    severity = "low"

    # Ukuran minimum yang masuk akal per tipe (bytes)
    MIN_SIZE_BY_TYPE = {
        "file": 100,
        "text": 1,
        "password": 1,
        "note": 1,
    }

    def evaluate(self, payload: DetectionPayload) -> RuleResult:
        size = payload.file_size_bytes
        if not size:
            return self._result(False, 0)

        secret_type = payload.secret_type or "file"
        min_size    = self.MIN_SIZE_BY_TYPE.get(secret_type, 1)

        # File terlalu kecil untuk tipenya
        if size < min_size:
            return self._result(True, 10,
                f"Ukuran file ({size} bytes) tidak wajar untuk tipe '{secret_type}'.")

        # File sangat besar (> 90 MB untuk user login, > 9 MB untuk anon)
        limit_mb   = 100 if payload.is_authenticated else 10
        limit_bytes = limit_mb * 1024 * 1024
        threshold   = limit_bytes * 0.9  # 90% dari batas

        if size > threshold:
            return self._result(True, 15,
                f"Ukuran file ({size / 1024 / 1024:.1f} MB) mendekati batas maksimum.")

        return self._result(False, 0)


# ===========================================================================
# RULE 3 — SUSPICIOUS FILENAME
# Nama file dengan pola berbahaya atau menyesatkan.
# ===========================================================================

class SuspiciousFilenameRule(Rule):
    """
    Deteksi nama file mencurigakan:
    - Double extension (file.pdf.exe)
    - Nama file yang menyamar sebagai file sistem
    - Karakter tidak wajar dalam nama file
    """
    name     = "suspicious_filename"
    severity = "medium"

    # Pola nama file yang menyamar sebagai file sistem
    SYSTEM_FILE_PATTERNS = re.compile(
        r"(system32|winlogon|svchost|lsass|csrss|explorer|"
        r"cmd|powershell|regedit|taskmgr|notepad)\.",
        re.IGNORECASE
    )

    # Double extension mencurigakan (file.pdf.exe, image.jpg.bat)
    DOUBLE_EXT_RE = re.compile(
        r"\.(pdf|doc|docx|xls|xlsx|jpg|jpeg|png|gif|zip|rar)"
        r"\.(exe|bat|cmd|sh|ps1|vbs|dll|scr|com|pif)$",
        re.IGNORECASE
    )

    # Karakter tidak wajar dalam nama file
    SUSPICIOUS_CHARS_RE = re.compile(r"[<>:\"\\|?*\x00-\x1f]")

    def evaluate(self, payload: DetectionPayload) -> RuleResult:
        filename = payload.original_filename or ""
        if not filename:
            return self._result(False, 0)

        if self.DOUBLE_EXT_RE.search(filename):
            return self._result(True, 50,
                f"Double extension mencurigakan: {filename}")

        if self.SYSTEM_FILE_PATTERNS.search(filename):
            return self._result(True, 35,
                f"Nama file menyerupai file sistem: {filename}")

        if self.SUSPICIOUS_CHARS_RE.search(filename):
            return self._result(True, 15,
                f"Karakter tidak wajar dalam nama file: {filename}")

        return self._result(False, 0)


# ===========================================================================
# RULE 4 — CIPHERTEXT ENTROPY ANOMALY
# Ciphertext yang valid seharusnya punya entropy tinggi (mendekati 8 bit/byte).
# Entropy rendah pada ciphertext mengindikasikan payload palsu atau tidak terenkripsi.
# ===========================================================================

class CiphertextEntropyRule(Rule):
    """
    Analisis entropy ciphertext (base64-decoded).

    AES-GCM menghasilkan output pseudo-random dengan entropy mendekati
    8 bit/byte. Jika entropy ciphertext sangat rendah:
    - Mungkin payload tidak benar-benar terenkripsi
    - Mungkin payload berisi data repetitif/padding berbahaya

    CATATAN: Ini analisis struktural, bukan analisis konten.
    Server TIDAK mendekripsi — hanya menganalisis distribusi byte ciphertext.
    """
    name     = "ciphertext_entropy_anomaly"
    severity = "medium"

    MIN_EXPECTED_ENTROPY = 7.0   # bit/byte — AES-GCM seharusnya ≥ 7.5
    SAMPLE_SIZE          = 1024  # bytes — cukup untuk estimasi entropy

    def evaluate(self, payload: DetectionPayload) -> RuleResult:
        ciphertext_b64 = payload.encrypted_payload
        if not ciphertext_b64 or len(ciphertext_b64) < 50:
            return self._result(False, 0)

        try:
            # Decode base64 untuk analisis byte
            padding    = "=" * (4 - len(ciphertext_b64) % 4) if len(ciphertext_b64) % 4 else ""
            raw_bytes  = base64.urlsafe_b64decode(ciphertext_b64[:self.SAMPLE_SIZE * 2] + padding)
            sample     = raw_bytes[:self.SAMPLE_SIZE]

            entropy = self._shannon_entropy(sample)

            if entropy < self.MIN_EXPECTED_ENTROPY:
                score = int((self.MIN_EXPECTED_ENTROPY - entropy) * 10)
                score = min(score, 30)
                return self._result(True, score,
                    f"Entropy ciphertext rendah: {entropy:.2f} bit/byte "
                    f"(expected ≥ {self.MIN_EXPECTED_ENTROPY}). "
                    f"Kemungkinan payload tidak terenkripsi dengan benar.")

        except Exception as e:
            logger.debug(f"[entropy_rule] Gagal decode ciphertext: {e}")

        return self._result(False, 0)

    @staticmethod
    def _shannon_entropy(data: bytes) -> float:
        """Hitung Shannon entropy dalam bit per byte."""
        if not data:
            return 0.0
        freq = {}
        for byte in data:
            freq[byte] = freq.get(byte, 0) + 1
        total = len(data)
        entropy = 0.0
        for count in freq.values():
            p = count / total
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy


# ===========================================================================
# RULE 5 — IV REUSE DETECTION
# IV (nonce) AES-GCM yang sama TIDAK BOLEH digunakan dua kali dengan key yang sama.
# Reuse IV dalam GCM mode = catastrophic failure (key bisa direcovery).
# Di sini kita cek apakah ada IV yang sama pernah digunakan sebelumnya.
# ===========================================================================

class IVReuseRule(Rule):
    """
    Deteksi reuse IV (nonce) AES-GCM.

    Dalam implementasi ZKE yang benar, setiap enkripsi menggunakan IV random baru.
    IV yang sama digunakan dua kali = bug serius di implementasi client,
    atau indikasi replay attack.

    Cek dilakukan via Redis cache untuk performa.
    """
    name     = "iv_reuse"
    severity = "high"

    CACHE_PREFIX  = "enc_iv:"
    CACHE_TIMEOUT = 60 * 60 * 24 * 30  # 30 hari

    def evaluate(self, payload: DetectionPayload) -> RuleResult:
        iv = payload.encryption_iv
        if not iv or len(iv) < 10:
            return self._result(False, 0)

        cache_key = f"{self.CACHE_PREFIX}{iv}"

        try:
            existing = cache.get(cache_key)
            if existing:
                return self._result(True, 40,
                    f"IV nonce telah digunakan sebelumnya. "
                    f"Kemungkinan replay attack atau bug implementasi client.")
            # Simpan IV ke cache
            cache.set(cache_key, "1", timeout=self.CACHE_TIMEOUT)
        except Exception as e:
            # Jika Redis down, lewati rule ini
            logger.warning(f"[iv_reuse_rule] Cache error: {e}")

        return self._result(False, 0)


# ===========================================================================
# RULE 6 — RATE ABUSE (IP-based)
# IP yang mengirim terlalu banyak secret dalam waktu singkat.
# ===========================================================================

class RateAbuseRule(Rule):
    """
    Deteksi pola abuse berdasarkan IP address.

    Threshold (per IP):
    - > 10 secret dalam 10 menit  → flagged
    - > 30 secret dalam 1 jam     → flagged
    - > 5  secret dalam 1 menit   → blocked (burst agresif)

    Menggunakan Redis sliding window counter.
    """
    name     = "rate_abuse"
    severity = "high"

    WINDOWS = [
        # (window_seconds, max_count, score_if_exceeded, label)
        (60,        5,  70, "burst_1min"),   # 5 dalam 1 menit → block
        (60 * 10,   10, 45, "burst_10min"),  # 10 dalam 10 menit → flag
        (60 * 60,   30, 30, "burst_1hour"),  # 30 dalam 1 jam → flag
    ]

    def evaluate(self, payload: DetectionPayload) -> RuleResult:
        ip = payload.ip_address
        if not ip:
            return self._result(False, 0)

        # User login dapat kelonggaran — hanya cek anon
        if payload.is_authenticated:
            return self._result(False, 0)

        now = int(time.time())

        try:
            for window_sec, max_count, score, label in self.WINDOWS:
                cache_key = f"rate:{ip}:{label}"
                current   = cache.get(cache_key) or 0

                if current >= max_count:
                    return self._result(True, score,
                        f"Rate abuse [{label}]: {current} request dari IP {ip} "
                        f"dalam {window_sec // 60} menit terakhir.")

            # Increment semua counter
            for window_sec, _, _, label in self.WINDOWS:
                cache_key = f"rate:{ip}:{label}"
                try:
                    cache.incr(cache_key)
                except Exception:
                    # Key belum ada — set baru
                    cache.set(cache_key, 1, timeout=window_sec)

        except Exception as e:
            logger.warning(f"[rate_abuse_rule] Cache error: {e}")

        return self._result(False, 0)


# ===========================================================================
# RULE 7 — SUSPICIOUS USER AGENT
# Bot, scraper, atau automated tool yang biasa dipakai untuk abuse.
# ===========================================================================

class SuspiciousUserAgentRule(Rule):
    """
    Deteksi user agent yang mencurigakan.
    Request dari bot atau tool otomatis bisa mengindikasikan abuse.
    """
    name     = "suspicious_user_agent"
    severity = "low"

    BLOCKED_UA_PATTERNS = re.compile(
        r"(python-requests|curl|wget|httpie|go-http|"
        r"scrapy|mechanize|libwww|okhttp|java/|"
        r"masscan|nmap|sqlmap|nikto|dirbuster)",
        re.IGNORECASE
    )

    def evaluate(self, payload: DetectionPayload) -> RuleResult:
        ua = payload.user_agent or ""
        if not ua:
            # Tidak ada user agent sama sekali — mencurigakan
            return self._result(True, 10,
                "Tidak ada User-Agent header dalam request.")

        if self.BLOCKED_UA_PATTERNS.search(ua):
            return self._result(True, 20,
                f"User-Agent teridentifikasi sebagai automation tool: {ua[:100]}")

        return self._result(False, 0)


# ===========================================================================
# RULE 8 — PAYLOAD SIZE VS CLAIMED SIZE MISMATCH
# Ukuran encrypted_payload (ciphertext) seharusnya sedikit lebih besar
# dari file_size_bytes asli (overhead AES-GCM ± auth tag 16 bytes).
# Mismatch besar mengindikasikan data manipulasi.
# ===========================================================================

class PayloadSizeMismatchRule(Rule):
    """
    Cek konsistensi antara file_size_bytes yang diklaim client
    dengan ukuran actual encrypted_payload.

    AES-GCM overhead: auth tag 16 bytes + IV 12 bytes + base64 encoding ~33%.
    Jadi: len(base64_payload) ≈ (file_size_bytes + 28) * 1.34

    Toleransi ±20% untuk variasi padding dan encoding.
    """
    name     = "payload_size_mismatch"
    severity = "medium"

    def evaluate(self, payload: DetectionPayload) -> RuleResult:
        claimed_size = payload.file_size_bytes
        ciphertext   = payload.encrypted_payload

        if not claimed_size or not ciphertext:
            return self._result(False, 0)

        # Estimasi ukuran ciphertext base64 dari claimed plaintext size
        expected_raw    = claimed_size + 28          # plaintext + GCM overhead
        expected_b64    = int(expected_raw * 1.34)   # base64 expansion ~4/3

        actual_b64_len  = len(ciphertext)
        tolerance       = expected_b64 * 0.20        # ±20%

        lower = expected_b64 - tolerance
        upper = expected_b64 + tolerance

        if actual_b64_len < lower or actual_b64_len > upper:
            ratio = actual_b64_len / expected_b64 if expected_b64 else 0
            return self._result(True, 25,
                f"Ukuran payload tidak konsisten dengan klaim. "
                f"Ekspektasi: ~{expected_b64} chars, actual: {actual_b64_len} chars "
                f"(rasio: {ratio:.2f}).")

        return self._result(False, 0)


# ===========================================================================
# RULE 9 — SUSPICIOUS CONFIGURATION
# Kombinasi konfigurasi yang tidak masuk akal atau lazim dipakai untuk abuse.
# ===========================================================================

class SuspiciousConfigRule(Rule):
    """
    Deteksi konfigurasi secret yang mencurigakan:
    - Banyak penerima + tidak ada password + tidak ada whitelist
      (terlalu terbuka untuk "confidential" secret)
    - max_views sangat tinggi + expired sangat lama
    - Anon user coba buat secret tanpa expiry (harusnya ditolak di serializer,
      tapi ini defense in depth)
    """
    name     = "suspicious_config"
    severity = "low"

    def evaluate(self, payload: DetectionPayload) -> RuleResult:
        details = []
        score   = 0

        num_recipients   = payload.num_recipients or 1
        has_password     = payload.has_password
        has_whitelist    = payload.has_email_whitelist
        expires_in_hours = payload.expires_in_hours
        is_auth          = payload.is_authenticated

        # Banyak penerima, tidak ada proteksi sama sekali
        if num_recipients > 10 and not has_password and not has_whitelist:
            score += 15
            details.append(
                f"{num_recipients} penerima tanpa password atau whitelist."
            )

        # Anon user tidak ada expiry (seharusnya sudah ditolak serializer)
        if not is_auth and not expires_in_hours:
            score += 20
            details.append("Anon user tanpa expiry — bypass validasi serializer?")

        # Expiry sangat panjang untuk anon (> 24 jam)
        if not is_auth and expires_in_hours and expires_in_hours > 24:
            score += 10
            details.append(
                f"Anon user meminta expiry {expires_in_hours} jam — melebihi batas wajar."
            )

        if score > 0:
            return self._result(True, score, " | ".join(details))

        return self._result(False, 0)


# ===========================================================================
# RULE 10 — CLIENT SCORE AMPLIFIER
# Jika client melaporkan score tinggi, server ikut naikan score-nya.
# Ini bukan trust penuh — hanya amplifikasi sinyal.
# ===========================================================================

class ClientScoreAmplifierRule(Rule):
    """
    Gunakan client_risk_score sebagai sinyal tambahan.

    Client bisa di-spoof, jadi kita tidak langsung percaya 100%.
    Tapi jika client melaporkan score tinggi + ada metadata anomali lain,
    gabungan ini jadi sinyal kuat.

    Formula: server tambah 30–50% dari client score sebagai sinyal.
    """
    name     = "client_score_amplifier"
    severity = "medium"

    def evaluate(self, payload: DetectionPayload) -> RuleResult:
        client_score = payload.client_risk_score or 0
        rules        = payload.client_rules_triggered or []

        if client_score <= 0:
            return self._result(False, 0)

        # Amplifikasi 40% dari client score (max 30 poin)
        amplified = min(int(client_score * 0.4), 30)

        if amplified >= 10:
            rule_names = ", ".join(rules[:3]) if rules else "tidak ada detail"
            return self._result(True, amplified,
                f"Client melaporkan risk score {client_score} "
                f"(rules: {rule_names}). "
                f"Server menambahkan {amplified} poin sebagai konfirmasi.")

        return self._result(False, 0)


# ===========================================================================
# MAIN DETECTOR
# ===========================================================================

class MetadataAIDetector:
    """
    Entry point untuk server-side AI detection.

    Menjalankan semua rule secara berurutan dan mengagregasi hasilnya.
    Setiap rule independen — kegagalan satu rule tidak menghentikan yang lain.

    Urutan rule diurutkan dari yang paling kritis (fast-fail) ke yang paling ringan.
    """

    RULES: list[Rule] = [
        BlockedMimeTypeRule(),        # Critical — cek dulu, paling cepat
        IVReuseRule(),                # High — replay attack
        RateAbuseRule(),              # High — rate limit berbasis IP
        SuspiciousFilenameRule(),     # Medium — nama file mencurigakan
        CiphertextEntropyRule(),      # Medium — analisis struktural
        PayloadSizeMismatchRule(),    # Medium — konsistensi ukuran
        SuspiciousConfigRule(),       # Low — konfigurasi tidak wajar
        FileSizeAnomalyRule(),        # Low — ukuran file anomali
        SuspiciousUserAgentRule(),    # Low — user agent bot
        ClientScoreAmplifierRule(),   # Advisory — amplifikasi sinyal client
    ]

    # Threshold fast-fail: jika satu rule critical terpicu, langsung stop
    FAST_FAIL_SCORE = 80

    def run(self, payload: DetectionPayload) -> DetectionResult:
        """
        Jalankan semua rule dan kembalikan DetectionResult.
        Aman dipanggil dari mana saja — semua exception ditangani internal.
        """
        results     = []
        total_score = 0

        for rule in self.RULES:
            try:
                result      = rule.evaluate(payload)
                results.append(result)

                if result.triggered:
                    total_score += result.score_delta
                    total_score  = min(total_score, 100)

                    logger.debug(
                        f"[detector] Rule '{rule.name}' triggered: "
                        f"+{result.score_delta} pts → total {total_score}. "
                        f"Detail: {result.detail}"
                    )

                    # Fast-fail: jika sudah pasti blocked, stop
                    if total_score >= self.FAST_FAIL_SCORE:
                        logger.info(
                            f"[detector] Fast-fail pada rule '{rule.name}' "
                            f"(score {total_score}). Stop evaluasi."
                        )
                        break

            except Exception as e:
                logger.error(
                    f"[detector] Rule '{rule.name}' error: {e}",
                    exc_info=True
                )
                # Lanjut ke rule berikutnya

        detection = DetectionResult.from_results(results)

        logger.info(
            f"[detector] Selesai. Score: {detection.total_score}, "
            f"Action: {detection.action}, "
            f"Rules triggered: {detection.rules_triggered}"
        )

        return detection

    def run_and_save(
        self,
        payload: DetectionPayload,
        secret=None,
        ip_address: str = "",
    ):
        """
        Jalankan detector + simpan hasil ke AIDetectionLog.
        Kembalikan DetectionResult.

        Gunakan ini dari views.py sebagai pengganti run() biasa.
        """
        from .models import AIDetectionLog

        result = self.run(payload)

        try:
            action_map = {
                "allowed": AIDetectionLog.ActionTaken.ALLOWED,
                "flagged": AIDetectionLog.ActionTaken.FLAGGED,
                "blocked": AIDetectionLog.ActionTaken.BLOCKED,
            }
            AIDetectionLog.objects.create(
                secret          = secret,
                source          = AIDetectionLog.DetectionSource.SERVER,
                rules_triggered = result.rules_triggered,
                risk_score      = result.total_score,
                action_taken    = action_map.get(result.action, AIDetectionLog.ActionTaken.ALLOWED),
                ip_address      = ip_address or payload.ip_address or None,
                file_size_bytes = payload.file_size_bytes,
                secret_type     = payload.secret_type,
            )
        except Exception as e:
            logger.error(f"[detector] Gagal simpan AIDetectionLog: {e}", exc_info=True)

        return result


# ===========================================================================
# CONVENIENCE FUNCTION
# Dipakai langsung dari views.py
# ===========================================================================

# Singleton detector — instansiasi sekali, reuse terus
_detector = MetadataAIDetector()


def run_server_detection(
    *,
    secret_type:          str  = "",
    mime_type:            str  = "",
    original_filename:    str  = "",
    file_size_bytes:      Optional[int] = None,
    encrypted_payload:    str  = "",
    encryption_iv:        str  = "",
    ip_address:           str  = "",
    user_agent:           str  = "",
    fingerprint_hash:     str  = "",
    is_authenticated:     bool = False,
    client_risk_score:    int  = 0,
    client_rules_triggered: list = None,
    num_recipients:       int  = 1,
    has_password:         bool = False,
    has_email_whitelist:  bool = False,
    expires_in_hours:     Optional[int] = None,
    secret=None,
) -> DetectionResult:
    """
    Convenience function — panggil langsung dari views/serializers.

    Contoh penggunaan di views.py:
        from .services.ai_detection import run_server_detection

        result = run_server_detection(
            secret_type       = validated_data["secret_type"],
            mime_type         = validated_data.get("mime_type", ""),
            file_size_bytes   = validated_data.get("file_size_bytes"),
            encrypted_payload = validated_data["encrypted_payload"],
            encryption_iv     = validated_data["encryption_iv"],
            ip_address        = get_client_ip(request),
            user_agent        = request.META.get("HTTP_USER_AGENT", ""),
            is_authenticated  = request.user.is_authenticated,
            client_risk_score = validated_data.get("client_risk_score", 0),
            secret            = saved_secret,  # None jika belum disimpan
        )

        if result.action == "blocked":
            raise ValidationError("Konten ini ditolak oleh sistem keamanan.")
    """
    payload = DetectionPayload(
        secret_type           = secret_type,
        mime_type             = mime_type,
        original_filename     = original_filename,
        file_size_bytes       = file_size_bytes,
        encrypted_payload     = encrypted_payload,
        encryption_iv         = encryption_iv,
        ip_address            = ip_address,
        user_agent            = user_agent,
        fingerprint_hash      = fingerprint_hash,
        is_authenticated      = is_authenticated,
        client_risk_score     = client_risk_score,
        client_rules_triggered = client_rules_triggered or [],
        num_recipients        = num_recipients,
        has_password          = has_password,
        has_email_whitelist   = has_email_whitelist,
        expires_in_hours      = expires_in_hours,
    )
    return _detector.run_and_save(payload, secret=secret, ip_address=ip_address)