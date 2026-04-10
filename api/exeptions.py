import logging
import traceback

from django.conf import settings
from django.core.exceptions import PermissionDenied as DjangoPermissionDenied
from django.core.exceptions import ValidationError as DjangoValidationError
from django.http import Http404

from rest_framework import status
from rest_framework.exceptions import (
    APIException,
    AuthenticationFailed,
    MethodNotAllowed,
    NotAuthenticated,
    NotFound,
    ParseError,
    PermissionDenied,
    Throttled,
    UnsupportedMediaType,
    ValidationError,
)
from rest_framework.response import Response
from rest_framework.views import exception_handler as drf_default_handler

logger = logging.getLogger(__name__)


# ===========================================================================
# CUSTOM APP EXCEPTIONS
# Exception khusus untuk domain logic aplikasi ini.
# Lemparkan dari model/service, tangkap di exception handler.
# ===========================================================================

class AppException(APIException):
    """Base class untuk semua custom exception aplikasi."""
    status_code = status.HTTP_400_BAD_REQUEST
    default_code = "app_error"
    default_detail = "Terjadi kesalahan pada aplikasi."


class SecretNotFoundException(AppException):
    status_code  = status.HTTP_404_NOT_FOUND
    default_code = "secret_not_found"
    default_detail = "Secret tidak ditemukan atau sudah tidak tersedia."


class SecretExpiredException(AppException):
    status_code  = status.HTTP_410_GONE
    default_code = "secret_expired"
    default_detail = "Secret ini sudah kedaluwarsa."


class SecretRevokedException(AppException):
    status_code  = status.HTTP_410_GONE
    default_code = "secret_revoked"
    default_detail = "Secret ini telah dicabut oleh pembuatnya."


class SecretBlockedException(AppException):
    status_code  = status.HTTP_403_FORBIDDEN
    default_code = "secret_blocked"
    default_detail = "Secret ini diblokir oleh administrator."


class SecretExhaustedException(AppException):
    status_code  = status.HTTP_410_GONE
    default_code = "secret_exhausted"
    default_detail = "Secret ini sudah mencapai batas jumlah akses."


class InvalidRevokeTokenException(AppException):
    status_code  = status.HTTP_403_FORBIDDEN
    default_code = "invalid_revoke_token"
    default_detail = "Revoke token tidak valid atau sudah kedaluwarsa."


class RateLimitExceededException(AppException):
    status_code  = status.HTTP_429_TOO_MANY_REQUESTS
    default_code = "rate_limit_exceeded"
    default_detail = (
        "Batas pembuatan secret harian telah tercapai. "
        "Silakan login untuk melanjutkan atau coba lagi besok."
    )


class ContentBlockedException(AppException):
    status_code  = status.HTTP_422_UNPROCESSABLE_ENTITY
    default_code = "content_blocked"
    default_detail = "Konten ini ditolak oleh sistem keamanan platform."


class FileSizeExceededException(AppException):
    status_code  = status.HTTP_413_REQUEST_ENTITY_TOO_LARGE
    default_code = "file_too_large"
    default_detail = "Ukuran file melebihi batas yang diizinkan."


class InvalidEncryptionPayloadException(AppException):
    status_code  = status.HTTP_400_BAD_REQUEST
    default_code = "invalid_encryption_payload"
    default_detail = "Payload enkripsi tidak valid. Pastikan proses enkripsi di browser berjalan dengan benar."


class AccountBannedException(AppException):
    status_code  = status.HTTP_403_FORBIDDEN
    default_code = "account_banned"
    default_detail = "Akun ini telah dinonaktifkan."


# ===========================================================================
# ERROR CODE MAPPING
# Map setiap exception class ke kode string yang dikirim ke client.
# ===========================================================================

EXCEPTION_CODE_MAP = {
    # Auth
    NotAuthenticated:          ("authentication_required",  "Autentikasi diperlukan. Silakan login."),
    AuthenticationFailed:      ("authentication_failed",    "Autentikasi gagal. Token tidak valid atau sudah kedaluwarsa."),
    PermissionDenied:          ("permission_denied",        "Anda tidak memiliki akses ke resource ini."),
    DjangoPermissionDenied:    ("permission_denied",        "Anda tidak memiliki akses ke resource ini."),

    # Not found
    NotFound:                  ("not_found",                "Resource yang diminta tidak ditemukan."),
    Http404:                   ("not_found",                "Resource yang diminta tidak ditemukan."),

    # Input errors
    ValidationError:           ("validation_error",         "Data yang dikirim tidak valid."),
    DjangoValidationError:     ("validation_error",         "Data yang dikirim tidak valid."),
    ParseError:                ("parse_error",              "Request body tidak dapat diparse. Pastikan format JSON benar."),
    UnsupportedMediaType:      ("unsupported_media_type",   "Tipe media tidak didukung."),
    MethodNotAllowed:          ("method_not_allowed",       "HTTP method tidak diizinkan untuk endpoint ini."),

    # Rate limit
    Throttled:                 ("too_many_requests",        "Terlalu banyak request. Silakan coba lagi nanti."),
}


# ===========================================================================
# FORMAT HELPERS
# ===========================================================================

def _format_validation_errors(detail) -> dict:
    """
    Ubah DRF validation error detail menjadi dict yang bersih.

    Input bisa berupa:
      - str                     → {"non_field_errors": ["..."]}
      - list[str]               → {"non_field_errors": [...]}
      - dict[field, list[str]]  → {"field": ["error1", "error2"]}
      - ErrorDetail             → string-like object dari DRF
    """
    if isinstance(detail, str):
        return {"non_field_errors": [detail]}

    if isinstance(detail, list):
        return {"non_field_errors": [str(e) for e in detail]}

    if isinstance(detail, dict):
        formatted = {}
        for key, value in detail.items():
            if isinstance(value, list):
                formatted[key] = [str(e) for e in value]
            elif isinstance(value, dict):
                formatted[key] = _format_validation_errors(value)
            else:
                formatted[key] = [str(value)]
        return formatted

    return {"non_field_errors": [str(detail)]}


def _build_error_response(
    message:     str,
    code:        str,
    errors:      dict,
    status_code: int,
) -> Response:
    """Bangun response error dengan format standar."""
    return Response(
        {
            "success": False,
            "message": message,
            "code":    code,
            "errors":  errors,
            "status":  status_code,
        },
        status=status_code,
    )


def _safe_message(exc: Exception, default: str) -> str:
    """
    Ambil pesan dari exception.
    Di production, sembunyikan detail internal untuk 5xx.
    """
    if isinstance(exc, APIException):
        detail = exc.detail
        if isinstance(detail, str):
            return detail
        if isinstance(detail, list) and detail:
            return str(detail[0])
        if isinstance(detail, dict):
            # Ambil pesan pertama dari dict
            for value in detail.values():
                if isinstance(value, list) and value:
                    return str(value[0])
                return str(value)
    return default


# ===========================================================================
# MAIN EXCEPTION HANDLER
# Didaftarkan di settings.py:
#   REST_FRAMEWORK = {
#       "EXCEPTION_HANDLER": "secrets_app.exceptions.custom_exception_handler"
#   }
# ===========================================================================

def custom_exception_handler(exc: Exception, context: dict) -> Response:
    """
    Custom exception handler untuk DRF.

    Dipanggil otomatis oleh DRF setiap kali view melempar exception.
    context berisi: {"view": view_instance, "request": request, "args": ..., "kwargs": ...}
    """
    request  = context.get("request")
    view     = context.get("view")
    view_name = view.__class__.__name__ if view else "UnknownView"

    # ── 1. ValidationError ──────────────────────────────────────────────────
    if isinstance(exc, (ValidationError, DjangoValidationError)):
        detail = getattr(exc, "detail", str(exc))
        errors = _format_validation_errors(detail)

        # Ambil pesan pertama sebagai message utama
        first_msg = next(
            (v[0] if isinstance(v, list) and v else str(v)
             for v in errors.values()),
            "Data yang dikirim tidak valid."
        )

        logger.warning(
            f"[{view_name}] ValidationError: {errors}",
            extra={"request": request},
        )
        return _build_error_response(
            message     = str(first_msg),
            code        = "validation_error",
            errors      = errors,
            status_code = status.HTTP_400_BAD_REQUEST,
        )

    # ── 2. Custom App Exceptions ─────────────────────────────────────────────
    if isinstance(exc, AppException):
        logger.warning(
            f"[{view_name}] {exc.__class__.__name__}: {exc.detail}",
            extra={"request": request},
        )
        errors = _format_validation_errors(exc.detail) if isinstance(exc.detail, dict) else {}
        return _build_error_response(
            message     = _safe_message(exc, exc.default_detail),
            code        = exc.default_code,
            errors      = errors,
            status_code = exc.status_code,
        )

    # ── 3. Auth & Permission ─────────────────────────────────────────────────
    if isinstance(exc, NotAuthenticated):
        logger.debug(f"[{view_name}] NotAuthenticated", extra={"request": request})
        return _build_error_response(
            message     = "Autentikasi diperlukan. Silakan login terlebih dahulu.",
            code        = "authentication_required",
            errors      = {},
            status_code = status.HTTP_401_UNAUTHORIZED,
        )

    if isinstance(exc, AuthenticationFailed):
        logger.warning(
            f"[{view_name}] AuthenticationFailed: {exc.detail}",
            extra={"request": request},
        )
        return _build_error_response(
            message     = "Token tidak valid atau sudah kedaluwarsa. Silakan login ulang.",
            code        = "authentication_failed",
            errors      = {},
            status_code = status.HTTP_401_UNAUTHORIZED,
        )

    if isinstance(exc, (PermissionDenied, DjangoPermissionDenied)):
        logger.warning(
            f"[{view_name}] PermissionDenied",
            extra={"request": request},
        )
        return _build_error_response(
            message     = "Anda tidak memiliki akses ke resource ini.",
            code        = "permission_denied",
            errors      = {},
            status_code = status.HTTP_403_FORBIDDEN,
        )

    # ── 4. Not Found ─────────────────────────────────────────────────────────
    if isinstance(exc, (NotFound, Http404)):
        logger.debug(
            f"[{view_name}] NotFound: {exc}",
            extra={"request": request},
        )
        return _build_error_response(
            message     = "Resource yang diminta tidak ditemukan.",
            code        = "not_found",
            errors      = {},
            status_code = status.HTTP_404_NOT_FOUND,
        )

    # ── 5. Rate Limit ─────────────────────────────────────────────────────────
    if isinstance(exc, Throttled):
        wait = getattr(exc, "wait", None)
        message = "Terlalu banyak request."
        if wait:
            message += f" Coba lagi dalam {int(wait)} detik."

        logger.warning(
            f"[{view_name}] Throttled: wait={wait}s",
            extra={"request": request},
        )
        return _build_error_response(
            message     = message,
            code        = "too_many_requests",
            errors      = {"wait_seconds": int(wait) if wait else None},
            status_code = status.HTTP_429_TOO_MANY_REQUESTS,
        )

    # ── 6. Method & Media Type ────────────────────────────────────────────────
    if isinstance(exc, MethodNotAllowed):
        return _build_error_response(
            message     = f"Method '{exc.args[0] if exc.args else ''}' tidak diizinkan.",
            code        = "method_not_allowed",
            errors      = {},
            status_code = status.HTTP_405_METHOD_NOT_ALLOWED,
        )

    if isinstance(exc, ParseError):
        logger.warning(
            f"[{view_name}] ParseError: {exc.detail}",
            extra={"request": request},
        )
        return _build_error_response(
            message     = "Request body tidak dapat diparse. Pastikan format JSON valid.",
            code        = "parse_error",
            errors      = {},
            status_code = status.HTTP_400_BAD_REQUEST,
        )

    if isinstance(exc, UnsupportedMediaType):
        return _build_error_response(
            message     = "Content-Type tidak didukung. Gunakan application/json.",
            code        = "unsupported_media_type",
            errors      = {},
            status_code = status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
        )

    # ── 7. Generic APIException ───────────────────────────────────────────────
    if isinstance(exc, APIException):
        logger.error(
            f"[{view_name}] APIException ({exc.status_code}): {exc.detail}",
            extra={"request": request},
        )
        errors = _format_validation_errors(exc.detail) if isinstance(exc.detail, dict) else {}
        return _build_error_response(
            message     = _safe_message(exc, "Terjadi kesalahan pada server."),
            code        = getattr(exc, "default_code", "api_error"),
            errors      = errors,
            status_code = exc.status_code,
        )

    # ── 8. Unhandled Exception (500) ─────────────────────────────────────────
    # Log SELALU dengan traceback penuh untuk debugging.
    # Response ke client TIDAK boleh bocorkan detail internal.
    logger.error(
        f"[{view_name}] Unhandled exception: {exc.__class__.__name__}: {exc}\n"
        f"{traceback.format_exc()}",
        extra={"request": request},
        exc_info=True,
    )

    if settings.DEBUG:
        # Development: tampilkan detail error
        return _build_error_response(
            message     = f"[DEBUG] {exc.__class__.__name__}: {str(exc)}",
            code        = "internal_server_error",
            errors      = {"traceback": traceback.format_exc().splitlines()[-5:]},
            status_code = status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    # Production: sembunyikan detail
    return _build_error_response(
        message     = "Terjadi kesalahan internal. Tim kami telah diberitahu.",
        code        = "internal_server_error",
        errors      = {},
        status_code = status.HTTP_500_INTERNAL_SERVER_ERROR,
    )