from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView

from .views import (
    # Auth
    RegisterView,
    LoginView,
    ProfileView,

    # Secret
    SecretCreateView,
    SecretDetailView,
    SecretRevokeView,
    MySecretsView,

    # SecretLink
    SecretAccessView,
    SecretLinkRevokeView,

    # Admin
    AdminSecretListView,
    AdminSecretActionView,
    AdminAIQueueView,
    AdminAIReviewView,
    AdminUserListView,
    AdminUserActionView,
    AdminStatsView,
    AdminAccessLogsView,
)

# ---------------------------------------------------------------------------
# App-level URL patterns (di-include dari project urls.py)
# ---------------------------------------------------------------------------

urlpatterns = [

    # ── Auth ──────────────────────────────────────────────────────────────
    # POST   /api/auth/register/       — daftar user baru
    # POST   /api/auth/login/          — login, return JWT
    # POST   /api/auth/refresh/        — refresh access token
    # GET    /api/auth/me/             — profil user (authenticated)
    # PATCH  /api/auth/me/             — update nama

    path("auth/register/",  RegisterView.as_view(),      name="auth-register"),
    path("auth/login/",     LoginView.as_view(),          name="auth-login"),
    path("auth/refresh/",   TokenRefreshView.as_view(),   name="auth-refresh"),
    path("auth/me/",        ProfileView.as_view(),         name="auth-profile"),

    # ── Secret (core) ─────────────────────────────────────────────────────
    # POST   /api/secrets/             — buat secret baru (anon/user)
    # GET    /api/secrets/my/          — list secret milik user login
    # GET    /api/secrets/{id}/        — detail secret (creator/admin)
    # DELETE /api/secrets/{id}/revoke/ — revoke seluruh secret

    path("secrets/",                SecretCreateView.as_view(),  name="secret-create"),
    path("secrets/my/",             MySecretsView.as_view(),     name="secret-my-list"),
    path("secrets/<uuid:secret_id>/",         SecretDetailView.as_view(), name="secret-detail"),
    path("secrets/<uuid:secret_id>/revoke/",  SecretRevokeView.as_view(), name="secret-revoke"),

    # ── Secret Link access ────────────────────────────────────────────────
    # GET    /api/s/{token}/    — info link (perlu email/password?)
    # POST   /api/s/{token}/    — akses secret (return ciphertext)

    path("s/<str:token>/",    SecretAccessView.as_view(),     name="secret-access"),

    # ── Link management ───────────────────────────────────────────────────
    # DELETE /api/links/{link_id}/revoke/ — revoke satu link saja

    path("links/<uuid:link_id>/revoke/",  SecretLinkRevokeView.as_view(), name="link-revoke"),

    # ── Admin ─────────────────────────────────────────────────────────────
    # GET    /api/admin/stats/                          — dashboard stats
    # GET    /api/admin/secrets/                        — list semua secret
    # POST   /api/admin/secrets/{id}/action/            — approve/block secret
    # GET    /api/admin/ai-queue/                       — antrian review AI
    # POST   /api/admin/ai-logs/{log_id}/review/        — review satu AI log
    # GET    /api/admin/users/                          — list user
    # POST   /api/admin/users/{id}/action/              — ban/unban/promote
    # GET    /api/admin/access-logs/                    — audit log akses

    path("admin/stats/",                         AdminStatsView.as_view(),        name="admin-stats"),
    path("admin/secrets/",                       AdminSecretListView.as_view(),   name="admin-secret-list"),
    path("admin/secrets/<uuid:secret_id>/action/", AdminSecretActionView.as_view(), name="admin-secret-action"),
    path("admin/ai-queue/",                      AdminAIQueueView.as_view(),      name="admin-ai-queue"),
    path("admin/ai-logs/<uuid:log_id>/review/",  AdminAIReviewView.as_view(),     name="admin-ai-review"),
    path("admin/users/",                         AdminUserListView.as_view(),     name="admin-user-list"),
    path("admin/users/<uuid:user_id>/action/",   AdminUserActionView.as_view(),   name="admin-user-action"),
    path("admin/access-logs/",                   AdminAccessLogsView.as_view(),   name="admin-access-logs"),
]