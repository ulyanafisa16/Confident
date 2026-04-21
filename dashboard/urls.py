from django.urls import path
from django.contrib.auth import views as auth_views
from .views import (
    dashboard,
    users_list, user_detail_api, user_ban, user_unban, user_create, users_bulk,
    secrets_list, secret_detail_api, secret_revoke, secrets_bulk,
    links_list, link_revoke,
    ai_logs_list, ai_log_detail_api, ai_log_approve, ai_log_block, ai_logs_bulk,
    access_logs_list,
    rate_limits, rate_limit_update,
    anon_sessions,
)

app_name = 'admin_panel'

urlpatterns = [
    # Dashboard
    path('',                    dashboard,         name='dashboard'),

    # Users
    path('users/',              users_list,        name='users'),
    path('users/create/',       user_create,       name='user_create'),
    path('users/bulk/',         users_bulk,        name='users_bulk'),
    path('users/<uuid:user_id>/detail/',  user_detail_api, name='user_detail_api'),
    path('users/<uuid:user_id>/ban/',     user_ban,        name='user_ban'),
    path('users/<uuid:user_id>/unban/',   user_unban,      name='user_unban'),

    # Secrets
    path('secrets/',            secrets_list,      name='secrets'),
    path('secrets/bulk/',       secrets_bulk,      name='secrets_bulk'),
    path('secrets/<uuid:secret_id>/detail/', secret_detail_api, name='secret_detail_api'),
    path('secrets/<uuid:secret_id>/revoke/', secret_revoke,     name='secret_revoke'),

    # Links
    path('links/',              links_list,        name='links'),
    path('links/<uuid:link_id>/revoke/', link_revoke, name='link_revoke'),

    # AI Detection
    path('ai-logs/',            ai_logs_list,      name='ai_logs'),
    path('ai-logs/bulk/',       ai_logs_bulk,      name='ai_logs_bulk'),
    path('ai-logs/<uuid:log_id>/detail/',  ai_log_detail_api, name='ai_log_detail_api'),
    path('ai-logs/<uuid:log_id>/approve/', ai_log_approve,    name='ai_log_approve'),
    path('ai-logs/<uuid:log_id>/block/',   ai_log_block,      name='ai_log_block'),

    # Access Logs
    path('access-logs/',        access_logs_list,  name='access_logs'),

    # Rate Limits
    path('rate-limits/',        rate_limits,       name='rate_limits'),
    path('rate-limits/<uuid:config_id>/update/', rate_limit_update, name='rate_limit_update'),

    # Anon Sessions
    path('anon-sessions/',      anon_sessions,     name='anon_sessions'),

    # LOGIN
    path('login/', auth_views.LoginView.as_view(
        template_name='admin_panel/login.html',
        redirect_authenticated_user=True,
    ), name='login'),

    # LOGOUT
    path('logout/', auth_views.LogoutView.as_view(
        next_page='admin_panel:login'
    ), name='logout'),
]
