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

# Cache config 5 menit
CONFIG_CACHE_PREFIX = "det_cfg"
CONFIG_CACHE_TTL    = 60 * 5


# ===========================================================================
# CONFIG LOADER — dengan versioning untuk hindari race condition
# ===========================================================================

def get_detection_config():
    """
    Ambil DetectionConfig dari cache (dengan versioning) atau DB.

    Cache key menyertakan version number sehingga saat admin simpan config
    baru (version naik), cache lama otomatis miss dan fetch config terbaru.
    Tidak perlu explicit invalidation — tidak ada race condition.
    """
    from .models import DetectionConfig

    # Ambil version terbaru dari DB (query ringan, hanya satu kolom)
    try:
        latest = DetectionConfig.objects.filter(
            is_active=True
        ).values('id', 'version').first()

        if not latest:
            return DetectionConfig.get()

        cache_key = f"{CONFIG_CACHE_PREFIX}_v{latest['version']}"
        cfg       = cache.get(cache_key)

        if cfg is None:
            cfg = DetectionConfig.objects.get(id=latest['id'])
            cache.set(cache_key, cfg, timeout=CONFIG_CACHE_TTL)

        return cfg

    except Exception as e:
        logger.warning(f"[detection_config] Gagal ambil config: {e}. Pakai default.")
        from .models import DetectionConfig
        return DetectionConfig.get()


# ===========================================================================
# DATA CLASSES
# ===========================================================================

@dataclass
class RuleResult:
    """Hasil evaluasi satu rule."""
    rule_name:   str
    triggered:   bool
    score_delta: int
    severity:    str
    rule_group:  str  = ""   # rules dalam group yang sama tidak stack
    detail:      str  = ""


@dataclass
class DetectionPayload:
    """Input ke detector. Semua field opsional — detector tetap jalan."""
    secret_type:            str  = ""
    mime_type:              str  = ""
    original_filename:      str  = ""
    file_size_bytes:        Optional[int] = None
    encrypted_payload:      str  = ""
    encryption_iv:          str  = ""
    ip_address:             str  = ""
    fingerprint_hash:       str  = ""
    is_authenticated:       bool = False
    client_risk_score:      int  = 0
    client_rules_triggered: list = field(default_factory=list)
    user_agent:             str  = ""
    num_recipients:         int  = 1
    has_password:           bool = False
    has_email_whitelist:    bool = False
    expires_in_hours:       Optional[int] = None


@dataclass
class RawDetectionResult:
    """
    Output MURNI dari Rule Engine — tidak tahu soal threshold config.
    Hanya berisi score mentah dan detail rules yang trigger.
    """
    raw_score:       int
    rules_triggered: list[str]
    rule_details:    list[RuleResult]
    processed_at:    str


@dataclass
class DetectionResult:
    """
    Output dari Decision Engine — menambahkan action berdasarkan config.
    Ini yang dikembalikan ke views.py.
    """
    total_score:     int
    action:          str   # "allowed" | "flagged" | "blocked"
    rules_triggered: list[str]
    rule_details:    list[RuleResult]
    processed_at:    str


def make_decision(raw: RawDetectionResult) -> DetectionResult:
    """
    Decision Engine — pisah dari Rule Engine.
    Ambil raw score, terapkan threshold dari config, tentukan action.

    Ini fix untuk masalah config coupling:
    Rule Engine tidak tahu soal threshold,
    Decision Engine yang memutuskan action.
    """
    cfg = get_detection_config()

    if raw.raw_score >= cfg.score_block:
        action = "blocked"
    elif raw.raw_score >= cfg.score_flag:
        action = "flagged"
    else:
        action = "allowed"

    return DetectionResult(
        total_score     = raw.raw_score,
        action          = action,
        rules_triggered = raw.rules_triggered,
        rule_details    = raw.rule_details,
        processed_at    = raw.processed_at,
    )


# ===========================================================================
# BASE RULE
# ===========================================================================

class Rule:
    name:          str = "base_rule"
    severity:      str = "low"
    config_switch: str = ""   # nama field di DetectionConfig untuk on/off
    rule_group:    str = ""   # rules dalam group yang sama tidak stack score

    def evaluate(self, payload: DetectionPayload) -> RuleResult:
        raise NotImplementedError

    def is_enabled(self, cfg) -> bool:
        if not self.config_switch:
            return True
        return bool(getattr(cfg, self.config_switch, True))

    def _result(self, triggered: bool, score: int, detail: str = "") -> RuleResult:
        return RuleResult(
            rule_name   = self.name,
            triggered   = triggered,
            score_delta = score if triggered else 0,
            severity    = self.severity,
            rule_group  = self.rule_group,
            detail      = detail,
        )


# ===========================================================================
# INDIVIDUAL RULES
# ===========================================================================

class BlockedMimeTypeRule(Rule):
    name          = "blocked_mime_type"
    severity      = "critical"
    config_switch = "rule_blocked_mime"
    rule_group    = "file_check"

    BLOCKED_MIMES = {
        "application/x-executable", "application/x-msdownload",
        "application/x-msdos-program", "application/x-sh",
        "application/x-bat", "application/x-powershell",
        "application/java-archive", "application/x-httpd-php",
        "text/x-shellscript", "application/x-perl",
    }
    BLOCKED_EXTS = {
        ".exe", ".bat", ".cmd", ".sh", ".ps1", ".ps2", ".vbs",
        ".msi", ".jar", ".dll", ".so", ".php", ".asp", ".aspx",
        ".jsp", ".cgi", ".scr", ".pif", ".com",
    }

    def evaluate(self, payload: DetectionPayload) -> RuleResult:
        mime = (payload.mime_type or "").lower().strip()
        name = (payload.original_filename or "").lower()
        ext  = "." + name.rsplit(".", 1)[-1] if "." in name else ""

        if mime in self.BLOCKED_MIMES:
            return self._result(True, 80, f"MIME diblokir: {mime}")
        if ext in self.BLOCKED_EXTS:
            return self._result(True, 80, f"Ekstensi diblokir: {ext}")
        return self._result(False, 0)


class SuspiciousFilenameRule(Rule):
    name          = "suspicious_filename"
    severity      = "medium"
    config_switch = "rule_suspicious_filename"
    rule_group    = "file_check"

    SYSTEM_RE    = re.compile(r"(system32|winlogon|svchost|lsass|cmd|powershell)\.", re.I)
    DOUBLE_EXT   = re.compile(r"\.(pdf|doc|docx|xls|jpg|jpeg|png|zip)\.(exe|bat|cmd|sh|ps1|dll)$", re.I)
    BAD_CHARS    = re.compile(r"[<>:\"\\|?*\x00-\x1f]")

    def evaluate(self, payload: DetectionPayload) -> RuleResult:
        fn = payload.original_filename or ""
        if not fn:
            return self._result(False, 0)
        if self.DOUBLE_EXT.search(fn):
            return self._result(True, 50, f"Double extension: {fn}")
        if self.SYSTEM_RE.search(fn):
            return self._result(True, 35, f"Nama mirip system file: {fn}")
        if self.BAD_CHARS.search(fn):
            return self._result(True, 15, f"Karakter tidak wajar: {fn}")
        return self._result(False, 0)


class FileSizeAnomalyRule(Rule):
    name          = "file_size_anomaly"
    severity      = "low"
    config_switch = "rule_file_size_anomaly"
    rule_group    = "file_check"

    def evaluate(self, payload: DetectionPayload) -> RuleResult:
        size = payload.file_size_bytes
        if not size:
            return self._result(False, 0)
        min_size    = 100 if payload.secret_type == "file" else 1
        if size < min_size:
            return self._result(True, 10, f"Ukuran file ({size} bytes) tidak wajar.")
        limit_bytes = (100 if payload.is_authenticated else 10) * 1024 * 1024
        if size > limit_bytes * 0.9:
            return self._result(True, 15, f"Ukuran mendekati batas ({size/1024/1024:.1f} MB).")
        return self._result(False, 0)


class IVReuseRule(Rule):
    name          = "iv_reuse"
    severity      = "high"
    config_switch = "rule_iv_reuse"
    rule_group    = "crypto_check"
    CACHE_PREFIX  = "enc_iv:"
    TTL           = 60 * 60 * 24 * 30

    def evaluate(self, payload: DetectionPayload) -> RuleResult:
        iv = payload.encryption_iv
        if not iv or len(iv) < 10:
            return self._result(False, 0)
        try:
            key = f"{self.CACHE_PREFIX}{iv}"
            if cache.get(key):
                return self._result(True, 40, "IV nonce dipakai ulang — kemungkinan replay attack.")
            cache.set(key, "1", timeout=self.TTL)
        except Exception as e:
            logger.warning(f"[iv_reuse] Cache error: {e}")
        return self._result(False, 0)


class CiphertextEntropyRule(Rule):
    name          = "ciphertext_entropy"
    severity      = "medium"
    config_switch = "rule_entropy_anomaly"
    rule_group    = "crypto_check"
    MIN_ENTROPY   = 7.0
    SAMPLE        = 1024

    def evaluate(self, payload: DetectionPayload) -> RuleResult:
        b64 = payload.encrypted_payload
        if not b64 or len(b64) < 50:
            return self._result(False, 0)
        try:
            pad  = "=" * (4 - len(b64) % 4) if len(b64) % 4 else ""
            raw  = base64.urlsafe_b64decode(b64[:self.SAMPLE * 2] + pad)
            ent  = self._entropy(raw[:self.SAMPLE])
            if ent < self.MIN_ENTROPY:
                score = min(int((self.MIN_ENTROPY - ent) * 10), 30)
                return self._result(True, score, f"Entropy ciphertext rendah: {ent:.2f} bit/byte")
        except Exception:
            pass
        return self._result(False, 0)

    @staticmethod
    def _entropy(data: bytes) -> float:
        if not data: return 0.0
        freq = {}
        for b in data: freq[b] = freq.get(b, 0) + 1
        t = len(data)
        return -sum((c/t) * math.log2(c/t) for c in freq.values())


class PayloadSizeMismatchRule(Rule):
    name          = "payload_size_mismatch"
    severity      = "medium"
    config_switch = "rule_payload_size"
    rule_group    = "crypto_check"

    def evaluate(self, payload: DetectionPayload) -> RuleResult:
        claimed = payload.file_size_bytes
        ct      = payload.encrypted_payload
        if not claimed or not ct:
            return self._result(False, 0)
        expected = int((claimed + 28) * 1.34)
        tol      = expected * 0.20
        actual   = len(ct)
        if actual < expected - tol or actual > expected + tol:
            ratio = actual / expected if expected else 0
            return self._result(True, 25,
                f"Ukuran payload tidak konsisten. Expected ~{expected}, actual {actual} (ratio {ratio:.2f})")
        return self._result(False, 0)


class RateAbuseRule(Rule):
    """
    Rate tracking pakai IP + fingerprint (bukan IP saja).
    Lebih tahan terhadap shared IP (NAT, kantor, dll).
    """
    name          = "rate_abuse"
    severity      = "high"
    config_switch = "rule_rate_abuse"
    rule_group    = "rate_check"

    def evaluate(self, payload: DetectionPayload) -> RuleResult:
        if payload.is_authenticated or not payload.ip_address:
            return self._result(False, 0)

        cfg = get_detection_config()
        ip  = payload.ip_address
        fp  = payload.fingerprint_hash or "nofp"

        # Gunakan IP + fingerprint sebagai identifier yang lebih akurat
        identifier = f"{ip}:{fp}"

        windows = [
            (60,   cfg.rate_burst_1min,  70, "1min"),
            (600,  cfg.rate_burst_10min, 45, "10min"),
            (3600, cfg.rate_burst_1hour, 30, "1hour"),
        ]

        try:
            for window_sec, max_count, score, label in windows:
                key     = f"rate:{identifier}:{label}"
                current = cache.get(key) or 0
                if current >= max_count:
                    return self._result(True, score,
                        f"Rate abuse [{label}]: {current} req dari {ip}")

            # Increment semua window
            for window_sec, _, _, label in windows:
                key = f"rate:{identifier}:{label}"
                try:
                    cache.incr(key)
                except Exception:
                    cache.set(key, 1, timeout=window_sec)

        except Exception as e:
            logger.warning(f"[rate_abuse] Cache error: {e}")

        return self._result(False, 0)


class SuspiciousConfigRule(Rule):
    name          = "suspicious_config"
    severity      = "low"
    config_switch = "rule_suspicious_config"
    rule_group    = "behavior_check"

    def evaluate(self, payload: DetectionPayload) -> RuleResult:
        details, score = [], 0
        if payload.num_recipients > 10 and not payload.has_password and not payload.has_email_whitelist:
            score += 15
            details.append(f"{payload.num_recipients} penerima tanpa proteksi.")
        if not payload.is_authenticated and not payload.expires_in_hours:
            score += 20
            details.append("Anon user tanpa expiry.")
        if not payload.is_authenticated and payload.expires_in_hours and payload.expires_in_hours > 24:
            score += 10
            details.append(f"Anon expiry {payload.expires_in_hours} jam.")
        if score:
            return self._result(True, score, " | ".join(details))
        return self._result(False, 0)


class SuspiciousUserAgentRule(Rule):
    name          = "suspicious_user_agent"
    severity      = "low"
    config_switch = "rule_suspicious_ua"
    rule_group    = "behavior_check"

    BOT_RE = re.compile(
        r"(python-requests|curl|wget|httpie|go-http|scrapy|"
        r"mechanize|libwww|okhttp|java/|masscan|sqlmap|nikto)",
        re.I
    )

    def evaluate(self, payload: DetectionPayload) -> RuleResult:
        ua = payload.user_agent or ""
        if not ua:
            return self._result(True, 10, "Tidak ada User-Agent header.")
        if self.BOT_RE.search(ua):
            return self._result(True, 20, f"UA terindikasi automation: {ua[:80]}")
        return self._result(False, 0)


class ClientScoreAmplifierRule(Rule):
    name          = "client_score_amplifier"
    severity      = "medium"
    config_switch = "rule_client_amplifier"
    rule_group    = "advisory"

    def evaluate(self, payload: DetectionPayload) -> RuleResult:
        score = payload.client_risk_score or 0
        if score <= 0:
            return self._result(False, 0)
        amplified = min(int(score * 0.4), 30)
        if amplified >= 10:
            rules = ", ".join((payload.client_rules_triggered or [])[:3])
            return self._result(True, amplified,
                f"Client score {score} (rules: {rules or '-'}). Server +{amplified}.")
        return self._result(False, 0)


# ===========================================================================
# COMBINATION RULES — weighted scoring, bukan rigid all()
# ===========================================================================

class ComboAnonAbuseRule(Rule):
    """
    Deteksi pola anon user yang tidak wajar.
    Pakai weighted scoring — tidak harus semua kondisi terpenuhi.

    Kondisi + bobot:
      Anon user                      : wajib (tanpa ini rule tidak jalan)
      Tidak ada expiry / > 24 jam    : +15
      Banyak penerima (> 5)          : +10
      Tidak ada password             : +5
      Tidak ada whitelist            : +5
    Total maks: 35
    Trigger kalau total weighted ≥ 20
    """
    name          = "combo_anon_abuse"
    severity      = "high"
    config_switch = "rule_combo_anon_abuse"
    rule_group    = "combo_abuse"   # group dengan combo lain — tidak stack

    def evaluate(self, payload: DetectionPayload) -> RuleResult:
        # Hanya berlaku untuk anon user
        if payload.is_authenticated:
            return self._result(False, 0)

        weighted = 0
        details  = []

        if not payload.expires_in_hours or payload.expires_in_hours > 24:
            weighted += 15
            details.append("tanpa expiry wajar")

        if payload.num_recipients > 5:
            weighted += 10
            details.append(f"{payload.num_recipients} penerima")

        if not payload.has_password:
            weighted += 5
            details.append("tanpa password")

        if not payload.has_email_whitelist:
            weighted += 5
            details.append("tanpa whitelist")

        if weighted >= 20:
            return self._result(True, weighted,
                f"Pola anon mencurigakan: {', '.join(details)}. Weighted score: {weighted}")

        return self._result(False, 0)


class ComboMalwareDistributionRule(Rule):
    """
    Deteksi pola distribusi file berbahaya.
    Weighted scoring — tidak semua kondisi harus terpenuhi.

    Kondisi + bobot:
      Tipe secret = file             : wajib
      Ukuran > 1 MB                  : +20
      Anon user                      : +15
      Bot/automation user-agent      : +20
      Tidak ada password             : +10
    Total maks: 65
    Trigger kalau total weighted ≥ 35
    """
    name          = "combo_malware_dist"
    severity      = "high"
    config_switch = "rule_combo_malware_dist"
    rule_group    = "combo_abuse"

    BOT_RE = re.compile(
        r"(python-requests|curl|wget|httpie|go-http|scrapy)", re.I
    )

    def evaluate(self, payload: DetectionPayload) -> RuleResult:
        # Hanya untuk file upload
        if payload.secret_type != "file":
            return self._result(False, 0)

        weighted = 0
        details  = []

        if payload.file_size_bytes and payload.file_size_bytes > 1_000_000:
            weighted += 20
            mb = payload.file_size_bytes / 1_000_000
            details.append(f"file {mb:.1f} MB")

        if not payload.is_authenticated:
            weighted += 15
            details.append("anon user")

        ua = payload.user_agent or ""
        if not ua or self.BOT_RE.search(ua):
            weighted += 20
            details.append("bot UA")

        if not payload.has_password:
            weighted += 10
            details.append("tanpa password")

        if weighted >= 35:
            return self._result(True, weighted,
                f"Pola distribusi file mencurigakan: {', '.join(details)}. Weighted: {weighted}")

        return self._result(False, 0)


class ComboRapidCreateRule(Rule):
    """
    Deteksi pembuatan secret secara cepat dan identik dari IP + fingerprint yang sama.
    Indikasi bot atau skrip otomatis.

    Trigger kalau:
      - ≥ 3 secret dengan signature identik (same type + recipients + expiry range)
      - Dalam 5 menit terakhir
      - Dari identifier (IP + fingerprint) yang sama
    """
    name          = "combo_rapid_create"
    severity      = "high"
    config_switch = "rule_combo_rapid_create"
    rule_group    = "combo_abuse"

    CACHE_PREFIX = "rapid:"
    CACHE_TTL    = 60 * 5  # 5 menit
    THRESHOLD    = 3

    def evaluate(self, payload: DetectionPayload) -> RuleResult:
        if payload.is_authenticated or not payload.ip_address:
            return self._result(False, 0)

        ip  = payload.ip_address
        fp  = payload.fingerprint_hash or "nofp"
        sig = f"{payload.secret_type}:{payload.num_recipients}:{payload.expires_in_hours}"

        sig_key   = f"{self.CACHE_PREFIX}sig:{ip}:{fp}"
        count_key = f"{self.CACHE_PREFIX}cnt:{ip}:{fp}"

        try:
            prev_sig = cache.get(sig_key)
            count    = cache.get(count_key) or 0

            if prev_sig == sig and count >= self.THRESHOLD:
                return self._result(True, 40,
                    f"Rapid create: {count}+ secret identik dari {ip} dalam 5 menit.")

            cache.set(sig_key, sig, timeout=self.CACHE_TTL)
            try:
                cache.incr(count_key)
            except Exception:
                cache.set(count_key, 1, timeout=self.CACHE_TTL)

        except Exception as e:
            logger.warning(f"[rapid_create] Cache error: {e}")

        return self._result(False, 0)


# ===========================================================================
# RULE ENGINE — menghasilkan raw score tanpa tahu config threshold
# ===========================================================================

class RuleEngine:
    """
    Menjalankan semua rules dan menghasilkan RawDetectionResult.
    Tidak tahu soal threshold (score_flag, score_block) — murni scoring.

    Rule Group Logic:
      Rules dalam group yang sama bersaing — hanya score tertinggi yang dihitung.
      Ini mencegah score stacking dari kondisi yang tumpang tindih.

      Contoh: ComboAnonAbuseRule dan ComboMalwareDistributionRule
      keduanya dalam group "combo_abuse" — hanya yang score-nya lebih tinggi
      yang masuk ke total, bukan keduanya dijumlah.
    """

    ALL_RULES: list[Rule] = [
        # Critical — cek dulu, paling cepat
        BlockedMimeTypeRule(),

        # Crypto checks
        IVReuseRule(),
        CiphertextEntropyRule(),
        PayloadSizeMismatchRule(),

        # File checks
        SuspiciousFilenameRule(),
        FileSizeAnomalyRule(),

        # Rate & behavior
        RateAbuseRule(),
        SuspiciousConfigRule(),
        SuspiciousUserAgentRule(),

        # Combination rules (dalam satu group — tidak stack)
        ComboMalwareDistributionRule(),
        ComboAnonAbuseRule(),
        ComboRapidCreateRule(),

        # Advisory
        ClientScoreAmplifierRule(),
    ]

    # Score ini kalau tercapai, langsung stop (tidak perlu cek semua rule)
    FAST_FAIL_SCORE = 80

    def run(self, payload: DetectionPayload) -> RawDetectionResult:
        cfg = get_detection_config()

        results    = []
        group_best: dict[str, int] = {}   # group → score tertinggi di group itu
        total_score = 0

        for rule in self.ALL_RULES:
            # Skip rule yang dimatikan admin
            if not rule.is_enabled(cfg):
                logger.debug(f"[engine] Rule '{rule.name}' dinonaktifkan.")
                continue

            try:
                result = rule.evaluate(payload)
                results.append(result)

                if not result.triggered:
                    continue

                # Rule group logic — hanya ambil score tertinggi dari satu group
                group = result.rule_group
                if group:
                    prev_best = group_best.get(group, 0)
                    if result.score_delta > prev_best:
                        # Kurangi score lama dari group ini, tambah yang baru
                        total_score  = total_score - prev_best + result.score_delta
                        group_best[group] = result.score_delta
                    # Kalau bukan yang tertinggi di group, tidak tambah score
                    else:
                        logger.debug(
                            f"[engine] Rule '{rule.name}' triggered tapi kalah "
                            f"di group '{group}' (score {result.score_delta} < {prev_best})."
                        )
                        continue
                else:
                    # Rule tanpa group — langsung tambah
                    total_score += result.score_delta

                total_score = min(total_score, 100)

                logger.debug(
                    f"[engine] '{rule.name}' triggered: "
                    f"+{result.score_delta} → total {total_score}. {result.detail}"
                )

                # Fast fail — kalau sudah pasti blocked, stop
                if total_score >= self.FAST_FAIL_SCORE:
                    logger.info(f"[engine] Fast-fail di '{rule.name}' (score {total_score}).")
                    break

            except Exception as e:
                logger.error(f"[engine] Rule '{rule.name}' error: {e}", exc_info=True)

        triggered = [r.rule_name for r in results if r.triggered]
        logger.info(f"[engine] Raw score: {total_score}, Rules: {triggered}")

        return RawDetectionResult(
            raw_score       = total_score,
            rules_triggered = triggered,
            rule_details    = results,
            processed_at    = timezone.now().isoformat(),
        )


# ===========================================================================
# DETECTOR — gabungkan Rule Engine + Decision Engine
# ===========================================================================

class MetadataAIDetector:
    """
    Entry point utama.
    Orkestrasi: RuleEngine → raw score → make_decision → action.
    """

    def __init__(self):
        self.engine = RuleEngine()

    def run(self, payload: DetectionPayload) -> DetectionResult:
        raw    = self.engine.run(payload)
        result = make_decision(raw)
        logger.info(
            f"[detector] Score: {result.total_score}, "
            f"Action: {result.action}, "
            f"Rules: {result.rules_triggered}"
        )
        return result

    def run_and_save(
        self,
        payload: DetectionPayload,
        secret=None,
        ip_address: str = "",
    ) -> DetectionResult:
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
                reviewed_at     = timezone.now() if result.action == "allowed" else None,
            )
        except Exception as e:
            logger.error(f"[detector] Gagal simpan AIDetectionLog: {e}", exc_info=True)

        return result


# Singleton
_detector = MetadataAIDetector()


# ===========================================================================
# PUBLIC API — dipanggil dari views.py
# ===========================================================================

def run_server_detection(
    *,
    secret_type:            str  = "",
    mime_type:              str  = "",
    original_filename:      str  = "",
    file_size_bytes:        Optional[int] = None,
    encrypted_payload:      str  = "",
    encryption_iv:          str  = "",
    ip_address:             str  = "",
    user_agent:             str  = "",
    fingerprint_hash:       str  = "",
    is_authenticated:       bool = False,
    client_risk_score:      int  = 0,
    client_rules_triggered: list = None,
    num_recipients:         int  = 1,
    has_password:           bool = False,
    has_email_whitelist:    bool = False,
    expires_in_hours:       Optional[int] = None,
    secret=None,
) -> DetectionResult:
    """
    Convenience function — panggil langsung dari views.py.
    Tidak ada perubahan di views.py yang diperlukan.
    """
    payload = DetectionPayload(
        secret_type            = secret_type,
        mime_type              = mime_type,
        original_filename      = original_filename,
        file_size_bytes        = file_size_bytes,
        encrypted_payload      = encrypted_payload,
        encryption_iv          = encryption_iv,
        ip_address             = ip_address,
        user_agent             = user_agent,
        fingerprint_hash       = fingerprint_hash,
        is_authenticated       = is_authenticated,
        client_risk_score      = client_risk_score,
        client_rules_triggered = client_rules_triggered or [],
        num_recipients         = num_recipients,
        has_password           = has_password,
        has_email_whitelist    = has_email_whitelist,
        expires_in_hours       = expires_in_hours,
    )
    return _detector.run_and_save(payload, secret=secret, ip_address=ip_address)