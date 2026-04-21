from django.shortcuts import render, get_object_or_404, redirect
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.db.models import Q, Count
from django.http import JsonResponse
from django.views.decorators.http import require_POST
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.views import View
from functools import wraps
import json
from datetime import timedelta, date
from django.contrib.auth.views import LoginView

from api.models import (
    User, AnonymousSession, Secret, SecretLink,
    AccessLog, AIDetectionLog, RateLimitConfig,
)


class CustomLoginView(LoginView):
    template_name = 'login.html'
    
    def get_success_url(self):
        return '/dashboard/'

# ─────────────────────────────────────────────
# DECORATOR
# ─────────────────────────────────────────────

def admin_required(view_func):
    """Pastikan user sudah login DAN memiliki role admin."""
    @wraps(view_func)
    @login_required(login_url='admin_panel:login')
    def wrapper(request, *args, **kwargs):
        if not request.user.is_admin:
            return JsonResponse({'error': 'Forbidden'}, status=403)
        return view_func(request, *args, **kwargs)
    return wrapper


def admin_context(request):
    """Context global yang disuntikkan ke semua halaman admin."""
    return {
        'ai_flagged_count': AIDetectionLog.objects.filter(
            reviewed_at__isnull=True, action_taken__in=['flagged', 'blocked']
        ).count()
    }


# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

def json_ok(message='OK', **extra):
    return JsonResponse({'ok': True, 'message': message, **extra})


def json_err(message, status=400):
    return JsonResponse({'ok': False, 'error': message}, status=status)


def paginate(qs, request, per_page=20):
    paginator = Paginator(qs, per_page)
    page_num  = request.GET.get('page', 1)
    return paginator.get_page(page_num)


# ─────────────────────────────────────────────
# DASHBOARD
# ─────────────────────────────────────────────

@admin_required
def dashboard(request):
    today    = timezone.now().date()
    week_ago = today - timedelta(days=7)

    # Distribusi tipe secret
    type_counts = (
        Secret.objects.filter(status='active')
        .values('secret_type')
        .annotate(count=Count('id'))
        .order_by('-count')
    )
    total_active = Secret.objects.filter(status='active').count()
    type_colors  = {'text': 'var(--text-primary)', 'password': 'var(--blue)',
                    'file': 'var(--amber)', 'note': 'var(--green)'}
    type_labels  = {'text': 'Teks', 'password': 'Password', 'file': 'File', 'note': 'Catatan'}
    distribution = [
        {
            'label': type_labels.get(t['secret_type'], t['secret_type']),
            'count': t['count'],
            'pct':   round(t['count'] / total_active * 100) if total_active else 0,
            'color': type_colors.get(t['secret_type'], 'var(--gray)'),
        }
        for t in type_counts
    ]

    # Activity 14 hari
    activity = []
    for i in range(13, -1, -1):
        d = today - timedelta(days=i)
        count = AccessLog.objects.filter(
            accessed_at__date=d, result='success'
        ).count()
        activity.append(count)

    stats = {
        'total_users':         User.objects.count(),
        'new_users_week':      User.objects.filter(created_at__date__gte=week_ago).count(),
        'active_secrets':      total_active,
        'secrets_today':       Secret.objects.filter(created_at__date=today).count(),
        'ai_flagged':          Secret.objects.filter(ai_flagged=True).count(),
        'access_today':        AccessLog.objects.filter(accessed_at__date=today, result='success').count(),
        'access_14days_total': sum(activity),
        'type_distribution':   distribution,
    }

    recent_secrets = (
        Secret.objects.select_related('creator_user', 'anon_session')
        .order_by('-created_at')[:10]
    )

    ctx = {
        'stats':          stats,
        'recent_secrets': recent_secrets,
        'activity_data':  json.dumps(activity),
        **admin_context(request),
    }
    return render(request, 'admin_panel/dashboard.html', ctx)


# ─────────────────────────────────────────────
# USERS
# ─────────────────────────────────────────────

@admin_required
def users_list(request):
    qs = User.objects.order_by('-created_at')

    # Filter
    role   = request.GET.get('role')
    status = request.GET.get('status')
    q      = request.GET.get('q', '').strip()

    if role:
        qs = qs.filter(role=role)
    if status == 'banned':
        qs = qs.filter(is_banned=True)
    if q:
        qs = qs.filter(Q(email__icontains=q) | Q(full_name__icontains=q))

    sort = request.GET.get('sort', '-created_at')
    if sort in ('joined', '-joined'):
        qs = qs.order_by('created_at' if sort == 'joined' else '-created_at')

    ctx = {'page_obj': paginate(qs, request), **admin_context(request)}
    return render(request, 'admin_panel/users.html', ctx)


@admin_required
def user_detail_api(request, user_id):
    """AJAX — detail user untuk modal."""
    user = get_object_or_404(User, id=user_id)
    return JsonResponse({
        'id':             str(user.id),
        'email':          user.email,
        'full_name':      user.full_name or '–',
        'role':           user.get_role_display(),
        'is_active':      user.is_active,
        'is_banned':      user.is_banned,
        'total_secrets':  user.total_secrets_created,
        'created_at':     user.created_at.strftime('%d %b %Y, %H:%M WIB'),
    })


@admin_required
@require_POST
def user_ban(request, user_id):
    user = get_object_or_404(User, id=user_id)
    if user.is_admin:
        return json_err('Tidak bisa mem-ban admin lain.')
    user.is_banned = True
    user.is_active = False
    user.save(update_fields=['is_banned', 'is_active'])
    return json_ok(f'{user.email} dibanned.')


@admin_required
@require_POST
def user_unban(request, user_id):
    user = get_object_or_404(User, id=user_id)
    user.is_banned = False
    user.is_active = True
    user.save(update_fields=['is_banned', 'is_active'])
    return json_ok(f'{user.email} di-unban.')


@admin_required
@require_POST
def user_create(request):
    email     = request.POST.get('email', '').strip()
    full_name = request.POST.get('full_name', '').strip()
    password  = request.POST.get('password', '')
    role      = request.POST.get('role', 'user')

    if not email or not password:
        messages.error(request, 'Email dan password wajib diisi.')
        return redirect('admin_panel:users')

    if User.objects.filter(email=email).exists():
        messages.error(request, f'Email {email} sudah terdaftar.')
        return redirect('admin_panel:users')

    user = User.objects.create_user(email=email, password=password,
                                    full_name=full_name, role=role)
    if role == 'admin':
        user.is_staff = True
        user.save(update_fields=['is_staff'])

    messages.success(request, f'User {email} berhasil dibuat.')
    return redirect('admin_panel:users')


@admin_required
@require_POST
def users_bulk(request):
    """Bulk action: ban | unban | promote."""
    body   = json.loads(request.body)
    ids    = body.get('ids', [])
    action = body.get('action')

    qs = User.objects.filter(id__in=ids)
    if action == 'ban':
        count = qs.exclude(role='admin').update(is_banned=True, is_active=False)
        return json_ok(f'{count} user dibanned.', count=count)
    elif action == 'unban':
        count = qs.update(is_banned=False, is_active=True)
        return json_ok(f'{count} user di-unban.', count=count)
    elif action == 'promote':
        count = qs.update(role=User.Role.ADMIN, is_staff=True)
        return json_ok(f'{count} user dijadikan admin.', count=count)
    return json_err('Action tidak dikenal.')


# ─────────────────────────────────────────────
# SECRETS
# ─────────────────────────────────────────────

@admin_required
def secrets_list(request):
    qs = (Secret.objects
          .select_related('creator_user', 'anon_session')
          .order_by('-created_at'))

    status     = request.GET.get('status')
    ai_flagged = request.GET.get('ai_flagged')
    type_      = request.GET.get('type')
    q          = request.GET.get('q', '').strip()

    if status:
        qs = qs.filter(status=status)
    if ai_flagged:
        qs = qs.filter(ai_flagged=True)
    if type_:
        qs = qs.filter(secret_type=type_)
    if q:
        qs = qs.filter(
            Q(id__icontains=q) | Q(creator_user__email__icontains=q)
        )

    ctx = {'page_obj': paginate(qs, request), **admin_context(request)}
    return render(request, 'admin_panel/secrets.html', ctx)


@admin_required
def secret_detail_api(request, secret_id):
    """AJAX — detail secret untuk modal."""
    s = get_object_or_404(
        Secret.objects.select_related('creator_user'), id=secret_id
    )
    return JsonResponse({
        'id':              str(s.id),
        'secret_type':     s.secret_type,
        'status':          s.status,
        'creator_user':    s.creator_user.email if s.creator_user else None,
        'created_at':      s.created_at.strftime('%d %b %Y, %H:%M WIB'),
        'expires_at':      s.expires_at.strftime('%d %b %Y, %H:%M WIB') if s.expires_at else None,
        'current_views':   s.current_views,
        'max_views':       s.max_views,
        'ai_risk_score':   s.ai_risk_score,
        'ai_rules':        [],   # dari AIDetectionLog jika diperlukan
        'original_filename': s.original_filename or None,
        'file_size_bytes': s.file_size_bytes,
    })


@admin_required
@require_POST
def secret_revoke(request, secret_id):
    secret = get_object_or_404(Secret, id=secret_id)
    secret.revoke(hard_delete_payload=True)
    return json_ok('Secret di-revoke dan payload dihapus.')


@admin_required
@require_POST
def secrets_bulk(request):
    body   = json.loads(request.body)
    ids    = body.get('ids', [])
    action = body.get('action')

    qs = Secret.objects.filter(id__in=ids)
    if action == 'block':
        count = qs.update(status=Secret.Status.BLOCKED)
        return json_ok(f'{count} secret diblokir.', count=count)
    elif action == 'revoke':
        count = 0
        for s in qs:
            s.revoke(hard_delete_payload=True)
            count += 1
        return json_ok(f'{count} secret di-revoke.', count=count)
    return json_err('Action tidak dikenal.')


# ─────────────────────────────────────────────
# SECRET LINKS
# ─────────────────────────────────────────────

@admin_required
def links_list(request):
    qs = SecretLink.objects.select_related('secret').order_by('-created_at')
    q  = request.GET.get('q', '').strip()
    if q:
        qs = qs.filter(Q(token__icontains=q) | Q(label__icontains=q))

    ctx = {'page_obj': paginate(qs, request), **admin_context(request)}
    return render(request, 'admin_panel/links.html', ctx)


@admin_required
@require_POST
def link_revoke(request, link_id):
    link = get_object_or_404(SecretLink, id=link_id)
    link.revoke()
    return json_ok(f'Link /s/{link.token} di-revoke.')


# ─────────────────────────────────────────────
# AI DETECTION LOGS
# ─────────────────────────────────────────────

@admin_required
def ai_logs_list(request):
    qs = AIDetectionLog.objects.select_related('secret', 'reviewed_by').order_by('-created_at')

    reviewed = request.GET.get('reviewed')
    source   = request.GET.get('source')

    if reviewed == '0':
        qs = qs.filter(reviewed_at__isnull=True)
    elif reviewed == '1':
        qs = qs.filter(reviewed_at__isnull=False)
    if source:
        qs = qs.filter(source=source)

    ctx = {
        'page_obj':        paginate(qs, request),
        'unreviewed_count': AIDetectionLog.objects.filter(reviewed_at__isnull=True).count(),
        **admin_context(request),
    }
    return render(request, 'admin_panel/ai_logs.html', ctx)


@admin_required
def ai_log_detail_api(request, log_id):
    log = get_object_or_404(AIDetectionLog, id=log_id)
    return JsonResponse({
        'id':             str(log.id),
        'source':         log.get_source_display(),
        'risk_score':     log.risk_score,
        'action_taken':   log.action_taken,
        'rules_triggered': log.rules_triggered,
        'ip_address':     log.ip_address or '–',
        'secret_type':    log.secret_type or '–',
        'file_size_bytes': log.file_size_bytes,
        'created_at':     log.created_at.strftime('%d %b %Y, %H:%M WIB'),
        'admin_note':     log.admin_note or '–',
        'reviewed_by':    log.reviewed_by.email if log.reviewed_by else None,
        'reviewed_at':    log.reviewed_at.strftime('%d %b %Y, %H:%M') if log.reviewed_at else None,
    })


@admin_required
@require_POST
def ai_log_approve(request, log_id):
    log = get_object_or_404(AIDetectionLog, id=log_id)
    log.mark_reviewed(request.user, note='Marked safe via admin panel.')
    if log.secret:
        log.secret.ai_flagged = False
        log.secret.save(update_fields=['ai_flagged'])
    return json_ok('Log ditandai aman.')


@admin_required
@require_POST
def ai_log_block(request, log_id):
    log = get_object_or_404(AIDetectionLog, id=log_id)
    log.mark_reviewed(request.user, note='Blocked via admin review.')
    if log.secret:
        log.secret.status = Secret.Status.BLOCKED
        log.secret.save(update_fields=['status'])
    return json_ok('Secret diblokir setelah review.')


@admin_required
@require_POST
def ai_logs_bulk(request):
    body   = json.loads(request.body)
    ids    = body.get('ids', [])
    action = body.get('action')

    logs = AIDetectionLog.objects.filter(id__in=ids)
    count = 0
    for log in logs:
        if action == 'approve':
            log.mark_reviewed(request.user, note='Bulk approve.')
            if log.secret:
                log.secret.ai_flagged = False
                log.secret.save(update_fields=['ai_flagged'])
        elif action == 'block':
            log.mark_reviewed(request.user, note='Bulk block.')
            if log.secret:
                log.secret.status = Secret.Status.BLOCKED
                log.secret.save(update_fields=['status'])
        count += 1

    action_label = 'di-approve' if action == 'approve' else 'diblokir'
    return json_ok(f'{count} item {action_label}.', count=count)


# ─────────────────────────────────────────────
# ACCESS LOGS
# ─────────────────────────────────────────────

@admin_required
def access_logs_list(request):
    qs = (AccessLog.objects
          .select_related('secret_link')
          .order_by('-accessed_at'))

    result = request.GET.get('result')
    q      = request.GET.get('q', '').strip()

    if result:
        qs = qs.filter(result=result)
    if q:
        qs = qs.filter(
            Q(ip_address__icontains=q) | Q(accessed_by_email__icontains=q)
            | Q(secret_link__token__icontains=q)
        )

    ctx = {'page_obj': paginate(qs, request, per_page=50), **admin_context(request)}
    return render(request, 'admin_panel/access_logs.html', ctx)


# ─────────────────────────────────────────────
# RATE LIMITS
# ─────────────────────────────────────────────

@admin_required
def rate_limits(request):
    RateLimitConfig.get_for_anonymous()   # ensure exists
    RateLimitConfig.get_for_registered()  # ensure exists
    configs = RateLimitConfig.objects.all().order_by('user_type')
    ctx = {'configs': configs, **admin_context(request)}
    return render(request, 'admin_panel/rate_limits.html', ctx)


@admin_required
@require_POST
def rate_limit_update(request, config_id):
    config = get_object_or_404(RateLimitConfig, id=config_id)
    config.max_secrets_per_day = int(request.POST.get('max_secrets_per_day', config.max_secrets_per_day))
    config.max_file_size_mb    = int(request.POST.get('max_file_size_mb',    config.max_file_size_mb))
    config.max_recipients      = int(request.POST.get('max_recipients',      config.max_recipients))
    config.max_expiry_days     = int(request.POST.get('max_expiry_days',     config.max_expiry_days))
    config.is_active           = request.POST.get('is_active') == '1'
    config.save()
    messages.success(request, 'Konfigurasi rate limit berhasil disimpan.')
    return redirect('admin_panel:rate_limits')


# ─────────────────────────────────────────────
# ANONYMOUS SESSIONS
# ─────────────────────────────────────────────

@admin_required
def anon_sessions(request):
    qs = AnonymousSession.objects.order_by('-created_at')
    q  = request.GET.get('q', '').strip()
    if q:
        qs = qs.filter(
            Q(ip_address__icontains=q) | Q(fingerprint_hash__icontains=q)
        )
    ctx = {'page_obj': paginate(qs, request), **admin_context(request)}
    return render(request, 'admin_panel/anon_sessions.html', ctx)
