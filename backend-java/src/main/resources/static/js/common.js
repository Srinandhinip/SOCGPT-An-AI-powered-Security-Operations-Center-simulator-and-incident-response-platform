/* ==========================================================================
   SOCGPT dashboard — shared helpers (used by every page)
   ========================================================================== */
(function () {
  'use strict';
  const SOC = (window.SOC = {});

  /* ---------- icons (inline SVG, no external files) ---------- */
  const P = {
    shield: '<path d="M12 3l8 3v6c0 4.5-3.2 8.3-8 9-4.8-.7-8-4.5-8-9V6l8-3z"/>',
    grid: '<rect x="3" y="3" width="7" height="9" rx="1.5"/><rect x="14" y="3" width="7" height="5" rx="1.5"/><rect x="14" y="12" width="7" height="9" rx="1.5"/><rect x="3" y="16" width="7" height="5" rx="1.5"/>',
    search: '<circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/>',
    file: '<path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5M9 13h6M9 17h4"/>',
    check: '<path d="M5 12l5 5L20 7"/>',
    x: '<path d="M6 6l12 12M18 6L6 18"/>',
    alert: '<path d="M12 3l10 18H2L12 3z"/><path d="M12 10v5M12 18v.01"/>',
    bolt: '<path d="M13 2L4 14h7l-1 8 9-12h-7l1-8z"/>',
    clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
    user: '<circle cx="12" cy="8" r="4"/><path d="M4 21c0-4 4-6 8-6s8 2 8 6"/>',
    play: '<path d="M7 4l13 8-13 8V4z"/>',
    refresh: '<path d="M20 12a8 8 0 1 1-2.3-5.7M20 4v5h-5"/>',
    database: '<ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v6c0 1.7 3.6 3 8 3s8-1.3 8-3V5M4 11v6c0 1.7 3.6 3 8 3s8-1.3 8-3v-6"/>',
    bug: '<path d="M9 9a3 3 0 0 1 6 0v6a3 3 0 0 1-6 0V9zM12 6V3M5 8l3 2M19 8l-3 2M4 14h4M16 14h4M5 20l3-2M19 20l-3-2"/>',
    key: '<circle cx="8" cy="15" r="4"/><path d="M11 12l9-9M16 7l3 3M14 9l2 2"/>',
    radar: '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="4.5"/><path d="M12 12l6-6"/>',
    download: '<path d="M12 3v12M7 10l5 5 5-5M4 21h16"/>',
    list: '<path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/>',
    target: '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><circle cx="12" cy="12" r="1.2"/>',
    lock: '<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/>',
    wrench: '<path d="M14.7 6.3a4 4 0 0 0-5.4 5.4L3 18l3 3 6.3-6.3a4 4 0 0 0 5.4-5.4l-2.6 2.6-2.4-.6-.6-2.4 2.6-2.6z"/>',
    layers: '<path d="M12 3l9 5-9 5-9-5 9-5zM3 13l9 5 9-5M3 17.5l9 5 9-5"/>',
    sparkle: '<path d="M12 3l1.8 5.2L19 10l-5.2 1.8L12 17l-1.8-5.2L5 10l5.2-1.8L12 3zM19 16l.8 2.2L22 19l-2.2.8L19 22l-.8-2.2L16 19l2.2-.8L19 16z"/>',
    info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 8v.01"/>',
    flag: '<path d="M5 21V4M5 4h11l-2 4 2 4H5"/>',
    undo: '<path d="M9 14L4 9l5-5M4 9h11a5 5 0 0 1 0 10h-3"/>',
    eye: '<path d="M2 12s4-7 10-7 10 7 10 7-4 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>',
    logout: '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9"/>',
    link: '<path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1"/>',
    mail: '<rect x="3" y="5" width="18" height="14" rx="2"/><path d="M3 7l9 6 9-6"/>',
    chart: '<path d="M4 20V10M10 20V4M16 20v-7M22 20H2"/>'
  };
  SOC.icon = (name, size) =>
    `<svg class="ic" viewBox="0 0 24 24" width="${size || 18}" height="${size || 18}" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${P[name] || ''}</svg>`;

  /* ---------- lookup tables ---------- */
  SOC.EVENT_META = {
    brute_force: { label: 'Brute force', icon: 'key' },
    sqli: { label: 'SQL injection', icon: 'database' },
    port_scan: { label: 'Port scan', icon: 'radar' },
    malware: { label: 'Malware', icon: 'bug' }
  };
  SOC.eventMeta = (t) => SOC.EVENT_META[t] || { label: t || 'Unknown', icon: 'alert' };

  SOC.SEV_COLOR = { CRITICAL: '#ff3b5c', HIGH: '#ff8a3d', MEDIUM: '#f5c542', LOW: '#4ade80' };
  SOC.sevColor = (s) => SOC.SEV_COLOR[s] || '#4f8cff';

  SOC.STATUS_LABEL = {
    OPEN: 'Open', INVESTIGATING: 'Investigating', AWAITING_APPROVAL: 'Awaiting approval',
    REMEDIATED: 'Remediated', CLOSED: 'Closed'
  };
  SOC.CSF_INFO = {
    Govern: 'Policies, roles and risk strategy are set and communicated.',
    Identify: 'Assets, vulnerabilities and organisational risk are understood.',
    Protect: 'Safeguards (access control, MFA, patching) limit the impact.',
    Detect: 'Anomalies and compromises are found through monitoring.',
    Respond: 'Actions are taken to investigate, contain and remediate.',
    Recover: 'Operations are restored and lessons are learned.'
  };

  /* ---------- tiny utilities ---------- */
  SOC.esc = (s) =>
    String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  // The backend sends local date-times like 2026-10-04T14:41:46.2039465 (7 fraction digits).
  SOC.parseTime = (iso) => {
    if (!iso) return null;
    const m = String(iso).match(/^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(\.\d+)?/);
    if (!m) { const d = new Date(iso); return isNaN(d) ? null : d; }
    return new Date(m[1] + (m[2] ? m[2].slice(0, 4) : ''));
  };
  SOC.timeAgo = (iso) => {
    const d = SOC.parseTime(iso);
    if (!d) return '—';
    const s = Math.max(0, Math.round((Date.now() - d.getTime()) / 1000));
    if (s < 5) return 'just now';
    if (s < 60) return s + 's ago';
    if (s < 3600) return Math.floor(s / 60) + 'm ago';
    if (s < 86400) return Math.floor(s / 3600) + 'h ago';
    return Math.floor(s / 86400) + 'd ago';
  };
  SOC.fmtTime = (iso) => {
    const d = SOC.parseTime(iso);
    return d ? d.toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' }) : '—';
  };
  SOC.fmtDuration = (sec) => {
    if (sec == null) return '—';
    sec = Math.round(sec);
    if (sec < 60) return sec + 's';
    if (sec < 3600) return Math.floor(sec / 60) + 'm ' + (sec % 60) + 's';
    return Math.floor(sec / 3600) + 'h ' + Math.floor((sec % 3600) / 60) + 'm';
  };
  SOC.initials = (name) => String(name || '?').trim().slice(0, 2).toUpperCase();
  SOC.avatarColor = (name) => {
    let h = 0;
    for (const ch of String(name || '')) h = (h * 31 + ch.charCodeAt(0)) % 360;
    return `hsl(${h} 65% 52%)`;
  };
  SOC.parseJsonList = (text) => {
    if (!text) return [];
    try { const v = JSON.parse(text); return Array.isArray(v) ? v : []; } catch (e) { return []; }
  };

  SOC.sevPill = (sev) => `<span class="sev sev-${SOC.esc(sev)}">${SOC.esc(sev || '—')}</span>`;
  SOC.statusBadge = (st) => `<span class="st st-${SOC.esc(st)}">${SOC.esc(SOC.STATUS_LABEL[st] || st || '—')}</span>`;

  SOC.countUp = (el, to, opts) => {
    opts = opts || {};
    const dec = opts.decimals || 0;
    const from = el._v || 0;
    el._v = to;
    if (from === to) { el.textContent = to.toFixed(dec); return; }
    const t0 = performance.now();
    const step = (t) => {
      const k = Math.min(1, (t - t0) / 650);
      const e = 1 - Math.pow(1 - k, 3);
      el.textContent = (from + (to - from) * e).toFixed(dec);
      if (k < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  };

  /* ---------- sign-in state (token kept in this browser only) ---------- */
  const TOKEN_KEY = 'socgpt.token', USER_KEY = 'socgpt.user';
  SOC.token = () => { try { return localStorage.getItem(TOKEN_KEY); } catch (e) { return null; } };
  SOC.me = () => { try { return JSON.parse(localStorage.getItem(USER_KEY) || 'null'); } catch (e) { return null; } };
  SOC.setSession = (token, user) => { try { localStorage.setItem(TOKEN_KEY, token); localStorage.setItem(USER_KEY, JSON.stringify(user)); } catch (e) { /* private mode */ } };
  SOC.clearSession = () => { try { localStorage.removeItem(TOKEN_KEY); localStorage.removeItem(USER_KEY); } catch (e) { /* ignore */ } };
  SOC.gotoLogin = () => {
    const here = location.pathname.split('/').pop() + location.search;
    location.replace('login.html' + (here && here !== 'login.html' ? '?next=' + encodeURIComponent(here) : ''));
  };
  SOC.logout = () => { SOC.clearSession(); location.replace('login.html'); };
  SOC.ROLE_LABEL = { admin: 'Admin', soc_manager: 'SOC manager', analyst: 'Analyst' };
  SOC.currentUser = () => SOC.me();
  // pages other than login need a token; send people to the sign-in page right away
  if (!window.SOC_PUBLIC && !SOC.token()) SOC.gotoLogin();

  /* ---------- API ---------- */
  SOC.api = async (path, opts) => {
    opts = Object.assign({}, opts);
    opts.headers = Object.assign({}, opts.headers);
    if (SOC.token()) opts.headers.Authorization = 'Bearer ' + SOC.token();
    if (opts.json !== undefined) { opts.method = opts.method || 'POST'; opts.headers['Content-Type'] = 'application/json'; opts.body = JSON.stringify(opts.json); delete opts.json; }
    let res;
    try { res = await fetch(path, opts); }
    catch (e) { throw new Error('Cannot reach the backend — is Spring Boot running?'); }
    const text = await res.text();
    let data = null;
    try { data = text ? JSON.parse(text) : null; } catch (e) { data = text; }
    if (!res.ok) {
      if (res.status === 401 && !window.SOC_PUBLIC) { SOC.clearSession(); SOC.gotoLogin(); }
      const msg = (data && (data.message || data.error)) || ('Request failed (HTTP ' + res.status + ')');
      const err = new Error(msg);
      err.status = res.status;
      throw err;
    }
    return data;
  };

  // fetch a file with the token (an <a href> cannot send the Authorization header) and save it
  SOC.download = async (path, filename) => {
    const res = await fetch(path, { headers: { Authorization: 'Bearer ' + SOC.token() } });
    if (!res.ok) {
      let msg = 'Download failed (HTTP ' + res.status + ')';
      try { const d = await res.json(); msg = d.message || d.error || msg; } catch (e) { /* not json */ }
      if (res.status === 401) { SOC.clearSession(); SOC.gotoLogin(); }
      throw new Error(msg);
    }
    const url = URL.createObjectURL(await res.blob());
    const a = document.createElement('a');
    a.href = url; a.download = filename;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 4000);
  };

  /* ---------- toasts ---------- */
  SOC.toast = (title, message, type, ms) => {
    let box = document.getElementById('toasts');
    if (!box) { box = document.createElement('div'); box.id = 'toasts'; document.body.appendChild(box); }
    const icon = { success: 'check', error: 'x', alert: 'alert', info: 'info' }[type || 'info'] || 'info';
    const el = document.createElement('div');
    el.className = 'toast ' + (type || 'info');
    el.innerHTML = `<span class="t-i">${SOC.icon(icon, 20)}</span><div><b>${SOC.esc(title)}</b>${message ? `<span>${SOC.esc(message)}</span>` : ''}</div>`;
    box.appendChild(el);
    const close = () => { el.classList.add('out'); setTimeout(() => el.remove(), 300); };
    el.addEventListener('click', close);
    setTimeout(close, ms || 4800);
  };

  /* ---------- confirm modal ---------- */
  SOC.modal = (o) =>
    new Promise((resolve) => {
      const wrap = document.createElement('div');
      wrap.className = 'modal-wrap';
      wrap.innerHTML = `
        <div class="modal" role="dialog" aria-modal="true">
          <div class="modal-ic ${o.tone || ''}">${SOC.icon(o.icon || 'shield', 24)}</div>
          <h3>${SOC.esc(o.title)}</h3>
          <p>${o.message || ''}</p>
          ${o.input ? `<textarea id="modalInput" placeholder="${SOC.esc(o.input)}"></textarea>` : ''}
          <div class="modal-actions">
            <button class="btn ghost" data-act="cancel">Cancel</button>
            <button class="btn ${o.tone || 'primary'}" data-act="ok">${SOC.esc(o.confirmText || 'Confirm')}</button>
          </div>
        </div>`;
      document.body.appendChild(wrap);
      const done = (ok) => {
        const value = wrap.querySelector('#modalInput') ? wrap.querySelector('#modalInput').value.trim() : '';
        document.removeEventListener('keydown', onKey, true);
        wrap.remove();
        resolve({ ok, value });
      };
      const onKey = (e) => { if (e.key === 'Escape') { e.stopPropagation(); done(false); } };
      document.addEventListener('keydown', onKey, true);
      wrap.addEventListener('click', (e) => {
        if (e.target === wrap) done(false);
        const act = e.target.closest('[data-act]');
        if (act) done(act.dataset.act === 'ok');
      });
      const first = wrap.querySelector('#modalInput') || wrap.querySelector('[data-act="ok"]');
      if (first) first.focus();
    });

  /* ---------- tooltip for charts ---------- */
  SOC.tip = (html, evt) => {
    let t = document.getElementById('tip');
    if (!t) { t = document.createElement('div'); t.id = 'tip'; t.className = 'tip'; document.body.appendChild(t); }
    t.innerHTML = html;
    t.classList.add('show');
    const w = t.offsetWidth, h = t.offsetHeight;
    let x = evt.clientX + 14, y = evt.clientY - h - 12;
    if (x + w > window.innerWidth - 8) x = evt.clientX - w - 14;
    if (y < 8) y = evt.clientY + 18;
    t.style.left = x + 'px';
    t.style.top = y + 'px';
  };
  SOC.tipHide = () => { const t = document.getElementById('tip'); if (t) t.classList.remove('show'); };

  /* ---------- live indicator + polling ---------- */
  SOC.setLive = (ok, msg) => {
    const dot = document.getElementById('tbDot');
    if (dot) dot.classList.toggle('off', !ok);
    const el = document.getElementById('live');
    if (!el) return;
    el.classList.toggle('off', !ok);
    el.querySelector('span:last-child').textContent = ok ? 'Live · updating' : (msg || 'Backend offline');
  };
  SOC.poll = (fn, ms) => {
    let busy = false;
    const tick = async () => {
      if (busy) return;
      busy = true;
      try { await fn(); SOC.setLive(true); }
      catch (e) { SOC.setLive(false, e.message && e.message.indexOf('Cannot reach') === 0 ? 'Backend offline' : 'Update failed'); console.warn(e); }
      finally { busy = false; }
    };
    tick();
    setInterval(() => { if (!document.hidden) tick(); }, ms);
    document.addEventListener('visibilitychange', () => { if (!document.hidden) tick(); });
    return tick;
  };

  /* ---------- sidebar ---------- */
  SOC.mountSidebar = (active) => {
    const links = [
      { id: 'dash', href: 'index.html', label: 'Command Center', icon: 'grid' },
      { id: 'inc', href: 'incidents.html', label: 'Investigations', icon: 'search', badge: true },
      { id: 'audit', href: 'audit.html', label: 'Audit & Governance', icon: 'file' },
      // Mailpit (the local inbox that catches the alert e-mails) runs on its own port
      { id: 'mail', href: 'http://localhost:8025', label: 'Mailbox ↗', icon: 'mail', ext: true }
    ];
    document.getElementById('sidebar').innerHTML = `
      <a class="brand" href="index.html">
        <div class="brand-logo">${SOC.icon('shield', 22)}</div>
        <div><div class="brand-name">SOCGPT</div><div class="brand-sub">AI Security Operations</div></div>
      </a>
      <nav class="nav">
        <div class="nav-label">Workspace</div>
        ${links.map((l) => `<a href="${l.href}" ${l.ext ? 'target="_blank" rel="noopener"' : ''} class="${l.id === active ? 'active' : ''}">${SOC.icon(l.icon, 19)}<span>${l.label}</span>${l.badge ? '<span class="nav-badge" id="navBadge">0</span>' : ''}</a>`).join('')}
      </nav>
      <div class="side-foot">
        <div class="side-card" id="userCard">
          <div class="user-row">
            <div class="avatar" id="actingAvatar">?</div>
            <div class="who"><b id="whoName">…</b><span class="role-pill" id="whoRole"></span></div>
            <button class="icon-btn" id="logoutBtn" title="Sign out" aria-label="Sign out">${SOC.icon('logout', 17)}</button>
          </div>
        </div>
        <div class="live" id="live"><span class="dot"></span><span>Connecting…</span></div>
      </div>`;
    SOC.paintUser();
    SOC.mountTopbar();
    document.getElementById('logoutBtn').addEventListener('click', SOC.logout);
    SOC.refreshBadge();
    setInterval(SOC.refreshBadge, 5000);
    // confirm the token is still valid and the role is current (a 401 sends us to the login page)
    SOC.api('/api/auth/me').then((u) => {
      const cur = SOC.me() || {};
      if (u && (u.role !== cur.role || u.username !== cur.username)) { SOC.setSession(SOC.token(), u); SOC.paintUser(); }
    }).catch(() => { /* handled in SOC.api */ });
  };

  SOC.paintUser = () => {
    const u = SOC.me();
    if (!u) return;
    const av = document.getElementById('actingAvatar');
    av.textContent = SOC.initials(u.username);
    av.style.background = SOC.avatarColor(u.username);
    document.getElementById('whoName').textContent = u.username;
    const pill = document.getElementById('whoRole');
    pill.textContent = SOC.ROLE_LABEL[u.role] || u.role;
    pill.className = 'role-pill r-' + u.role;
  };

  SOC.setNavBadge = (n) => {
    const b = document.getElementById('navBadge');
    if (!b) return;
    b.textContent = n;
    b.classList.toggle('show', n > 0);
  };
  SOC.refreshBadge = async () => {
    try { const s = await SOC.api('/api/stats'); SOC.setNavBadge(s.awaitingApproval || 0); SOC.paintTop(s); } catch (e) { /* ignore */ }
  };

  /* ---------- threat level (same maths for the status bar and the dashboard gauge) ---------- */
  SOC.THREAT_LEVELS = [
    { max: 15, name: 'LOW', c: '#3ddc97' }, { max: 40, name: 'GUARDED', c: '#38bdf8' },
    { max: 65, name: 'ELEVATED', c: '#fbbf24' }, { max: 85, name: 'HIGH', c: '#ff8a3d' }, { max: 101, name: 'SEVERE', c: '#ff3b5c' }
  ];
  SOC.threat = (s) => {
    const open = (s.openIncidents || 0) + (s.awaitingApproval || 0);
    const score = Math.min(100, Math.round((s.awaitingApproval || 0) * 10 + (s.openIncidents || 0) * 8 + (s.activeChains || 0) * 22 + Math.min(30, open * 2) + (s.criticalOpen || 0) * 0));
    const lvl = SOC.THREAT_LEVELS.find((l) => score < l.max);
    return { score, name: lvl.name, c: lvl.c };
  };

  /* ---------- top status bar ---------- */
  SOC.mountTopbar = () => {
    const main = document.querySelector('.main');
    if (!main || document.getElementById('topbar')) return;
    const u = SOC.me() || {};
    const bar = document.createElement('div');
    bar.className = 'topbar'; bar.id = 'topbar';
    bar.innerHTML = `
      <span class="tb-item"><span class="tb-dot" id="tbDot"></span><b>SOC OPERATIONAL</b></span><span class="tb-sep"></span>
      <span class="tb-item"><span class="tb-label">Threat level</span><span class="threat-pill" id="tbThreat" style="--tc:#38bdf8">…</span></span>
      <span class="tb-item"><span class="tb-label">Awaiting decision</span><b id="tbWait">0</b></span>
      <span class="tb-item"><span class="tb-label">Active chains</span><b id="tbChains">0</b></span>
      <span class="tb-right">
        <span class="tb-item"><span class="tb-label">On duty</span><b>${SOC.esc(u.username || '')}</b></span>
        <span class="tb-clock" id="tbClock"></span>
      </span>`;
    main.prepend(bar);
    const tick = () => {
      const d = new Date();
      document.getElementById('tbClock').textContent = d.toISOString().slice(0, 19).replace('T', ' ') + ' UTC';
    };
    tick(); setInterval(tick, 1000);
  };
  SOC.paintTop = (s) => {
    const pill = document.getElementById('tbThreat');
    if (!pill) return;
    const t = SOC.threat(s);
    pill.textContent = t.name; pill.style.setProperty('--tc', t.c);
    document.getElementById('tbWait').textContent = s.awaitingApproval || 0;
    document.getElementById('tbChains').textContent = s.activeChains || 0;
    SOC.lastStats = s;
  };
})();
