from unittest.mock import MagicMock, patch

from django.test import TestCase, override_settings
from rest_framework import status
from rest_framework.exceptions import (
    AuthenticationFailed,
    MethodNotAllowed,
    NotAuthenticated,
    NotFound,
    ParseError,
    PermissionDenied,
    Throttled,
    ValidationError,
)

from .exceptions import (
    AccountBannedException,
    ContentBlockedException,
    FileSizeExceededException,
    InvalidEncryptionPayloadException,
    InvalidRevokeTokenException,
    RateLimitExceededException,
    SecretBlockedException,
    SecretExpiredException,
    SecretExhaustedException,
    SecretNotFoundException,
    SecretRevokedException,
    _format_validation_errors,
    custom_exception_handler,
)


# ===========================================================================
# HELPERS
# ===========================================================================

def make_context(view_name="TestView"):
    view         = MagicMock()
    view.__class__.__name__ = view_name
    request      = MagicMock()
    request.META = {}
    return {"view": view, "request": request}


def call_handler(exc, view_name="TestView"):
    """Shortcut: panggil handler dan kembalikan Response."""
    return custom_exception_handler(exc, make_context(view_name))


# ===========================================================================
# TEST FORMAT HELPERS
# ===========================================================================

class TestFormatValidationErrors(TestCase):

    def test_string_input(self):
        result = _format_validation_errors("Error terjadi")
        self.assertEqual(result, {"non_field_errors": ["Error terjadi"]})

    def test_list_input(self):
        result = _format_validation_errors(["Error 1", "Error 2"])
        self.assertEqual(result, {"non_field_errors": ["Error 1", "Error 2"]})

    def test_dict_input(self):
        result = _format_validation_errors({
            "email":    ["Email tidak valid."],
            "password": ["Password terlalu pendek."],
        })
        self.assertIn("email", result)
        self.assertIn("password", result)
        self.assertEqual(result["email"], ["Email tidak valid."])

    def test_nested_dict(self):
        result = _format_validation_errors({
            "address": {"city": ["Kota wajib diisi."]}
        })
        self.assertIn("address", result)

    def test_empty_dict(self):
        result = _format_validation_errors({})
        self.assertEqual(result, {})


# ===========================================================================
# TEST RESPONSE FORMAT KONSISTENSI
# ===========================================================================

class TestResponseFormat(TestCase):
    """Semua response error harus punya format yang sama."""

    def _assert_format(self, response):
        """Assert format standar."""
        self.assertIsNotNone(response)
        data = response.data
        self.assertIn("success",  data)
        self.assertIn("message",  data)
        self.assertIn("code",     data)
        self.assertIn("errors",   data)
        self.assertIn("status",   data)
        self.assertFalse(data["success"])
        self.assertIsInstance(data["message"], str)
        self.assertIsInstance(data["code"], str)
        self.assertIsInstance(data["errors"], dict)

    def test_validation_error_format(self):
        exc = ValidationError({"email": ["Email tidak valid."]})
        response = call_handler(exc)
        self._assert_format(response)

    def test_not_found_format(self):
        self._assert_format(call_handler(NotFound()))

    def test_permission_denied_format(self):
        self._assert_format(call_handler(PermissionDenied()))

    def test_not_authenticated_format(self):
        self._assert_format(call_handler(NotAuthenticated()))

    def test_throttled_format(self):
        self._assert_format(call_handler(Throttled(wait=30)))

    def test_custom_exception_format(self):
        self._assert_format(call_handler(SecretExpiredException()))


# ===========================================================================
# TEST STATUS CODE
# ===========================================================================

class TestStatusCodes(TestCase):

    def test_validation_error_400(self):
        r = call_handler(ValidationError("invalid"))
        self.assertEqual(r.status_code, 400)

    def test_not_authenticated_401(self):
        r = call_handler(NotAuthenticated())
        self.assertEqual(r.status_code, 401)

    def test_auth_failed_401(self):
        r = call_handler(AuthenticationFailed())
        self.assertEqual(r.status_code, 401)

    def test_permission_denied_403(self):
        r = call_handler(PermissionDenied())
        self.assertEqual(r.status_code, 403)

    def test_not_found_404(self):
        r = call_handler(NotFound())
        self.assertEqual(r.status_code, 404)

    def test_method_not_allowed_405(self):
        r = call_handler(MethodNotAllowed("DELETE"))
        self.assertEqual(r.status_code, 405)

    def test_throttled_429(self):
        r = call_handler(Throttled(wait=60))
        self.assertEqual(r.status_code, 429)

    # Custom app exceptions
    def test_secret_not_found_404(self):
        self.assertEqual(call_handler(SecretNotFoundException()).status_code, 404)

    def test_secret_expired_410(self):
        self.assertEqual(call_handler(SecretExpiredException()).status_code, 410)

    def test_secret_revoked_410(self):
        self.assertEqual(call_handler(SecretRevokedException()).status_code, 410)

    def test_secret_blocked_403(self):
        self.assertEqual(call_handler(SecretBlockedException()).status_code, 403)

    def test_secret_exhausted_410(self):
        self.assertEqual(call_handler(SecretExhaustedException()).status_code, 410)

    def test_invalid_revoke_token_403(self):
        self.assertEqual(call_handler(InvalidRevokeTokenException()).status_code, 403)

    def test_rate_limit_429(self):
        self.assertEqual(call_handler(RateLimitExceededException()).status_code, 429)

    def test_content_blocked_422(self):
        self.assertEqual(call_handler(ContentBlockedException()).status_code, 422)

    def test_file_too_large_413(self):
        self.assertEqual(call_handler(FileSizeExceededException()).status_code, 413)

    def test_invalid_encryption_400(self):
        self.assertEqual(call_handler(InvalidEncryptionPayloadException()).status_code, 400)

    def test_account_banned_403(self):
        self.assertEqual(call_handler(AccountBannedException()).status_code, 403)


# ===========================================================================
# TEST ERROR CODE
# ===========================================================================

class TestErrorCodes(TestCase):

    def _code(self, exc):
        return call_handler(exc).data["code"]

    def test_validation_error_code(self):
        self.assertEqual(self._code(ValidationError("x")), "validation_error")

    def test_not_authenticated_code(self):
        self.assertEqual(self._code(NotAuthenticated()), "authentication_required")

    def test_auth_failed_code(self):
        self.assertEqual(self._code(AuthenticationFailed()), "authentication_failed")

    def test_permission_denied_code(self):
        self.assertEqual(self._code(PermissionDenied()), "permission_denied")

    def test_not_found_code(self):
        self.assertEqual(self._code(NotFound()), "not_found")

    def test_throttled_code(self):
        self.assertEqual(self._code(Throttled(wait=10)), "too_many_requests")

    def test_secret_expired_code(self):
        self.assertEqual(self._code(SecretExpiredException()), "secret_expired")

    def test_secret_revoked_code(self):
        self.assertEqual(self._code(SecretRevokedException()), "secret_revoked")

    def test_rate_limit_code(self):
        self.assertEqual(self._code(RateLimitExceededException()), "rate_limit_exceeded")

    def test_content_blocked_code(self):
        self.assertEqual(self._code(ContentBlockedException()), "content_blocked")


# ===========================================================================
# TEST THROTTLED — wait seconds
# ===========================================================================

class TestThrottled(TestCase):

    def test_throttled_with_wait(self):
        r = call_handler(Throttled(wait=45))
        self.assertIn("45", r.data["message"])
        self.assertEqual(r.data["errors"]["wait_seconds"], 45)

    def test_throttled_without_wait(self):
        r = call_handler(Throttled())
        self.assertIsNotNone(r)
        self.assertEqual(r.status_code, 429)


# ===========================================================================
# TEST UNHANDLED EXCEPTION (500)
# ===========================================================================

class TestUnhandledException(TestCase):

    @override_settings(DEBUG=False)
    def test_production_hides_traceback(self):
        r = call_handler(RuntimeError("DB connection error"))
        self.assertEqual(r.status_code, 500)
        self.assertEqual(r.data["code"], "internal_server_error")
        # Pastikan detail error tidak bocor ke client
        self.assertNotIn("DB connection error", r.data["message"])
        self.assertNotIn("DB connection error", str(r.data["errors"]))

    @override_settings(DEBUG=True)
    def test_debug_shows_detail(self):
        r = call_handler(RuntimeError("something broke"))
        self.assertEqual(r.status_code, 500)
        # Di debug mode, pesan error boleh tampil
        self.assertIn("something broke", r.data["message"])

    @override_settings(DEBUG=False)
    def test_500_always_logs(self):
        with patch("secrets_app.exceptions.logger") as mock_logger:
            call_handler(ValueError("unexpected"))
            mock_logger.error.assert_called_once()


# ===========================================================================
# TEST VALIDATION ERROR DETAIL
# ===========================================================================

class TestValidationErrorDetail(TestCase):

    def test_field_errors_preserved(self):
        exc = ValidationError({
            "email":    ["Email tidak valid."],
            "password": ["Minimal 8 karakter."],
        })
        r = call_handler(exc)
        self.assertIn("email",    r.data["errors"])
        self.assertIn("password", r.data["errors"])

    def test_non_field_errors(self):
        exc = ValidationError(["Password dan konfirmasi tidak cocok."])
        r = call_handler(exc)
        self.assertIn("non_field_errors", r.data["errors"])

    def test_string_validation_error(self):
        exc = ValidationError("Email sudah terdaftar.")
        r = call_handler(exc)
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.data["code"], "validation_error")


# ===========================================================================
# TEST HTTP404 (Django, bukan DRF)
# ===========================================================================

class TestDjangoExceptions(TestCase):

    def test_http404(self):
        from django.http import Http404
        r = call_handler(Http404())
        self.assertEqual(r.status_code, 404)
        self.assertEqual(r.data["code"], "not_found")

    def test_django_permission_denied(self):
        from django.core.exceptions import PermissionDenied as DjangoPD
        r = call_handler(DjangoPD())
        self.assertEqual(r.status_code, 403)
        self.assertEqual(r.data["code"], "permission_denied")