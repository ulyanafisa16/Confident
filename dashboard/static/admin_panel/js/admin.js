/* admin.js — SecretVault Admin Panel */

/* ── CSRF ── */
const CSRF = () =>
  document.cookie.split('; ').find(r => r.startsWith('csrftoken='))?.split('=')[1] || '';

/* ── SIDEBAR (mobile) ── */
window.openSidebar = function () {
  document.getElementById('sidebar')?.classList.add('open');
  document.getElementById('sidebar-overlay')?.classList.add('open');
  document.body.style.overflow = 'hidden';
};

window.closeSidebar = function () {
  document.getElementById('sidebar')?.classList.remove('open');
  document.getElementById('sidebar-overlay')?.classList.remove('open');
  document.body.style.overflow = '';
};

// Tutup sidebar saat klik nav-item di mobile
document.addEventListener('DOMContentLoaded', () => {
  if (window.innerWidth <= 768) {
    document.querySelectorAll('.nav-item').forEach(item => {
      item.addEventListener('click', closeSidebar);
    });
  }
});

/* ── MODAL ── */
function openModal(id)  { document.getElementById(id)?.classList.add('open'); }
function closeModal(id) { document.getElementById(id)?.classList.remove('open'); }

document.addEventListener('click', e => {
  if (e.target.classList.contains('modal-overlay')) {
    e.target.classList.remove('open');
  }
});

/* ── FLASH MESSAGE ── */
function flash(msg, type = 'info') {
  const container = document.getElementById('flash-container') || document.body;
  const el = document.createElement('div');
  el.className = `alert-banner alert-${type}`;
  el.style.cssText = 'box-shadow:0 8px 24px rgba(0,0,0,.4);animation:slideIn .2s ease';
  el.innerHTML = `
    <svg width="15" height="15" fill="none" viewBox="0 0 16 16" style="flex-shrink:0;margin-top:1px">
      <circle cx="8" cy="8" r="6" stroke="currentColor" stroke-width="1.5"/>
      <path d="M8 7v4M8 5.5v.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
    </svg>
    <span>${msg}</span>`;
  container.appendChild(el);
  setTimeout(() => el.remove(), 4000);
}

/* ── AUTO DISMISS DJANGO MESSAGES ── */
document.addEventListener('DOMContentLoaded', () => {
  const msgs = document.querySelectorAll('#flash-container .alert-banner');
  msgs.forEach((el, i) => {
    setTimeout(() => {
      el.style.transition = 'opacity .3s, transform .3s';
      el.style.opacity = '0';
      el.style.transform = 'translateX(10px)';
      setTimeout(() => el.remove(), 300);
    }, 3500 + i * 200);
  });
});

/* ── CONFIRM ACTION ── */
async function confirmAction(url, message, successMsg) {
  if (!confirm(message)) return;
  try {
    const res  = await fetch(url, {
      method: 'POST',
      headers: { 'X-CSRFToken': CSRF(), 'Content-Type': 'application/json' }
    });
    const data = await res.json();
    if (data.ok) {
      flash(successMsg || data.message, 'success');
      setTimeout(() => location.reload(), 900);
    } else {
      flash(data.error || 'Terjadi kesalahan.', 'error');
    }
  } catch {
    flash('Koneksi gagal. Coba lagi.', 'error');
  }
}

/* ── BULK SELECT ── */
function initBulkSelect() {
  const masterCb = document.getElementById('cb-master');
  const rowCbs   = document.querySelectorAll('.cb-row');
  if (!masterCb) return;

  masterCb.addEventListener('change', () => {
    rowCbs.forEach(c => c.checked = masterCb.checked);
    updateBulkBar();
  });
  rowCbs.forEach(c => c.addEventListener('change', () => {
    const checked = [...rowCbs].filter(x => x.checked).length;
    masterCb.indeterminate = checked > 0 && checked < rowCbs.length;
    masterCb.checked = checked === rowCbs.length;
    updateBulkBar();
  }));
}

function getSelectedIds() {
  return [...document.querySelectorAll('.cb-row:checked')].map(c => c.dataset.id);
}

function updateBulkBar() {
  const bar   = document.getElementById('bulk-bar');
  const count = document.getElementById('bulk-count');
  const ids   = getSelectedIds();
  if (!bar) return;
  if (ids.length > 0) {
    bar.style.display = 'flex';
    if (count) count.textContent = `${ids.length} dipilih`;
  } else {
    bar.style.display = 'none';
  }
}

async function bulkAction(url, action, confirmMsg, successMsg) {
  const ids = getSelectedIds();
  if (!ids.length) { flash('Pilih minimal satu baris.', 'warning'); return; }
  if (!confirm(confirmMsg.replace('{n}', ids.length))) return;
  try {
    const res  = await fetch(url, {
      method: 'POST',
      headers: { 'X-CSRFToken': CSRF(), 'Content-Type': 'application/json' },
      body: JSON.stringify({ ids, action })
    });
    const data = await res.json();
    if (data.ok) {
      flash(successMsg.replace('{n}', data.count ?? ids.length), 'success');
      setTimeout(() => location.reload(), 900);
    } else {
      flash(data.error || 'Terjadi kesalahan.', 'error');
    }
  } catch {
    flash('Koneksi gagal. Coba lagi.', 'error');
  }
}

/* ── SEARCH (debounced) ── */
function initSearch(inputId, paramName = 'q') {
  const input = document.getElementById(inputId);
  if (!input) return;
  let timer;
  input.addEventListener('input', () => {
    clearTimeout(timer);
    timer = setTimeout(() => {
      const url = new URL(location.href);
      if (input.value.trim()) url.searchParams.set(paramName, input.value.trim());
      else url.searchParams.delete(paramName);
      url.searchParams.delete('page');
      location.href = url.toString();
    }, 450);
  });
}

/* ── SCORE HELPERS ── */
function scoreClass(score) {
  if (score >= 70) return 'high';
  if (score >= 40) return 'mid';
  return 'low';
}

function scoreBarHtml(score) {
  return `
    <div class="score-wrap">
      <div class="score-bar">
        <div class="score-fill ${scoreClass(score)}" style="width:${score}%"></div>
      </div>
      <span class="score-num">${score}</span>
    </div>`;
}

/* ── BADGE HELPERS ── */
function statusBadge(status) {
  const map = {
    active:  ['green', 'Aktif'],
    revoked: ['gray',  'Dicabut'],
    expired: ['amber', 'Expired'],
    blocked: ['red',   'Diblokir'],
  };
  const [color, label] = map[status] || ['gray', status];
  return `<span class="badge badge-${color}">
    <span class="badge-dot" style="background:var(--${color})"></span>${label}
  </span>`;
}

function actionBadge(action) {
  const map = {
    allowed: ['green', 'Diizinkan'],
    flagged: ['amber', 'Diflag'],
    blocked: ['red',   'Diblokir'],
  };
  const [color, label] = map[action] || ['gray', action];
  return `<span class="badge badge-${color}">
    <span class="badge-dot" style="background:var(--${color})"></span>${label}
  </span>`;
}

/* ── FORMAT HELPERS ── */
function formatBytes(bytes) {
  if (!bytes) return '–';
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / 1048576).toFixed(1) + ' MB';
}

function formatDate(iso) {
  if (!iso) return '–';
  return new Date(iso).toLocaleString('id-ID', {
    day: '2-digit', month: 'short', year: 'numeric',
    hour: '2-digit', minute: '2-digit'
  });
}

/* ── DETAIL MODAL (AJAX) ── */
async function loadDetail(url, modalId) {
  openModal(modalId);
  const body = document.getElementById(modalId + '-body');
  if (!body) return;
  body.innerHTML = '<div style="text-align:center;padding:40px;color:var(--text-3)"><div class="spinner"></div></div>';
  try {
    const res  = await fetch(url, { headers: { 'Accept': 'application/json' } });
    const data = await res.json();
    renderDetailModal(body, data);
  } catch {
    body.innerHTML = '<div class="empty-state">Gagal memuat detail.</div>';
  }
}

function renderDetailModal(container, d) {
  const row = (label, val) =>
    `<div class="detail-row">
      <div class="detail-label">${label}</div>
      <div class="detail-val">${val ?? '–'}</div>
    </div>`;

  container.innerHTML = [
    row('Tipe',       `<span class="badge badge-gray">${d.secret_type || '–'}</span>`),
    row('Status',     statusBadge(d.status)),
    row('Pembuat',    d.creator_user || '<span class="text-muted">anon</span>'),
    row('Dibuat',     formatDate(d.created_at)),
    row('Expires',    d.expires_at ? formatDate(d.expires_at) : '<span class="text-muted">Tidak ada</span>'),
    row('Views',      `<span class="mono">${d.current_views ?? 0} / ${d.max_views ?? 1}</span>`),
    row('AI Score',   scoreBarHtml(d.ai_risk_score ?? 0)),
    d.ai_rules?.length ? row('Rules', `<span class="mono" style="font-size:11px">${d.ai_rules.join(', ')}</span>`) : '',
    d.original_filename ? row('File', `<span class="mono">${d.original_filename}</span> · ${formatBytes(d.file_size_bytes)}`) : '',
    row('Payload',    '<span class="mono text-muted" style="font-size:11px">[ZKE — server tidak bisa baca]</span>'),
  ].filter(Boolean).join('');
}

/* ── COPY TO CLIPBOARD ── */
async function copyText(text, btn) {
  try {
    await navigator.clipboard.writeText(text);
    const orig = btn.textContent;
    btn.textContent = 'Tersalin!';
    setTimeout(() => btn.textContent = orig, 1800);
  } catch {
    flash('Gagal menyalin.', 'error');
  }
}

/* ── CSS ANIMATION ── */
const style = document.createElement('style');
style.textContent = `
  @keyframes slideIn {
    from { opacity: 0; transform: translateX(12px); }
    to   { opacity: 1; transform: translateX(0); }
  }
  .spinner {
    width: 18px; height: 18px;
    border: 2px solid var(--border);
    border-top-color: var(--accent);
    border-radius: 50%;
    animation: spin .6s linear infinite;
    display: inline-block;
  }
  @keyframes spin { to { transform: rotate(360deg); } }
`;
document.head.appendChild(style);

/* ── INIT ── */
document.addEventListener('DOMContentLoaded', () => {
  initBulkSelect();
  initSearch('search-input');
});