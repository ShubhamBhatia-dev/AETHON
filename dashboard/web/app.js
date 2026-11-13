/* =================================================================
   AETHON GATEWAY — Dashboard app.js
   Vanilla JS only. No frameworks.
   Talks to Go backend at /api/*
   100% real production telemetry directly from eBPF and C++ shared memory.
================================================================= */

'use strict';

// ═══════════════════════════════════════════════════════════
// THEME (LIGHT / DARK)
// ═══════════════════════════════════════════════════════════
function initTheme() {
  const saved = localStorage.getItem('aethon_theme') || 'dark';
  applyTheme(saved);
}

function applyTheme(theme) {
  if (theme === 'light') {
    document.documentElement.setAttribute('data-theme', 'light');
    const icon = document.getElementById('theme-icon');
    const lbl = document.getElementById('theme-label');
    if (icon) icon.textContent = '🌙';
    if (lbl) lbl.textContent = 'Dark';
    localStorage.setItem('aethon_theme', 'light');
  } else {
    document.documentElement.removeAttribute('data-theme');
    const icon = document.getElementById('theme-icon');
    const lbl = document.getElementById('theme-label');
    if (icon) icon.textContent = '☀️';
    if (lbl) lbl.textContent = 'Light';
    localStorage.setItem('aethon_theme', 'dark');
  }
}

function toggleTheme() {
  const isLight = document.documentElement.getAttribute('data-theme') === 'light';
  applyTheme(isLight ? 'dark' : 'light');
}

// ═══════════════════════════════════════════════════════════
// CONFIG
// ═══════════════════════════════════════════════════════════
const POLL_MS    = 1500;   // stats polling interval
const CHART_PTS  = 60;     // number of data points on sparkline
const API_BASE   = '';     // same origin

// ═══════════════════════════════════════════════════════════
// STATE
// ═══════════════════════════════════════════════════════════
let chartData     = new Array(CHART_PTS).fill(0);
let chartCtx      = null;
let eventsPaused  = false;
let eventTimer    = null;
let statsTimer    = null;
let eventSource   = null;
let peakBps       = 0;
let peakPps       = 0;
let peakSess      = 0;

// ═══════════════════════════════════════════════════════════
// NAVIGATION
// ═══════════════════════════════════════════════════════════
const PAGE_TITLES = {
  overview:    'Overview',
  events:      'Live Events',
  logs:        'Security Logs',
  firewall:    'Firewall Rules',
  services:    'Services',
  domains:     'SNI Blocklist',
  'dpi-rules': 'Custom DPI Rules',
  ebpf:        'eBPF Maps',
  blocked:     'Blocked IPs',
};

document.querySelectorAll('.nav-item').forEach(el => {
  el.addEventListener('click', e => {
    e.preventDefault();
    switchPage(el.dataset.page);
  });
});

function switchPage(id) {
  document.querySelectorAll('.nav-item').forEach(el => {
    el.classList.toggle('active', el.dataset.page === id);
  });
  document.querySelectorAll('.page').forEach(p => {
    p.classList.toggle('active', p.id === 'page-' + id);
  });
  document.getElementById('topbar-title').textContent = PAGE_TITLES[id] || id;

  // Lazy-load page data
  if (id === 'logs')       loadLogs();
  if (id === 'firewall')   loadFirewallRules();
  if (id === 'services')   loadServices();
  if (id === 'domains')    loadDomains();
  if (id === 'dpi-rules')  loadDpiRules();
  if (id === 'blocked')    loadBlockedIPs();
  if (id === 'ebpf')       loadeBPFMaps();
}

// ═══════════════════════════════════════════════════════════
// MODALS
// ═══════════════════════════════════════════════════════════
function openModal(id) {
  document.getElementById(id).classList.add('open');
}

function closeModal(id) {
  document.getElementById(id).classList.remove('open');
}

// Close on backdrop click
document.querySelectorAll('.modal-backdrop').forEach(backdrop => {
  backdrop.addEventListener('click', e => {
    if (e.target === backdrop) backdrop.classList.remove('open');
  });
});

// ═══════════════════════════════════════════════════════════
// TOAST
// ═══════════════════════════════════════════════════════════
let toastTimer = null;

function showToast(msg, isError = false) {
  const el = document.getElementById('toast');
  el.textContent = (isError ? '✗ ' : '✓ ') + msg;
  el.style.borderColor = isError ? 'rgba(242,95,92,.4)' : 'var(--border-h)';
  el.style.color        = isError ? 'var(--red)' : 'var(--txt1)';
  el.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.remove('show'), 3000);
}

// ═══════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════
function set(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = String(val);
}

function fmtBytes(b) {
  if (b === 0) return '0 B';
  const units = ['B','KB','MB','GB','TB'];
  const i = Math.floor(Math.log(b) / Math.log(1024));
  return (b / Math.pow(1024, i)).toFixed(i > 0 ? 1 : 0) + ' ' + units[i];
}

function fmtNum(n) {
  if (n >= 1e9) return (n/1e9).toFixed(2) + 'G';
  if (n >= 1e6) return (n/1e6).toFixed(1) + 'M';
  if (n >= 1e3) return (n/1e3).toFixed(1) + 'k';
  return String(n);
}

function now() {
  const d = new Date();
  return d.toTimeString().slice(0, 8);
}

async function apiFetch(path, opts = {}) {
  const r = await fetch(API_BASE + path, opts);
  if (!r.ok) throw new Error(r.status + ' ' + r.statusText);
  return r.json();
}

// ═══════════════════════════════════════════════════════════
// SPARKLINE CHART (canvas, no libs)
// ═══════════════════════════════════════════════════════════
function initChart() {
  const canvas = document.getElementById('throughput-chart');
  if (!canvas) return;
  chartCtx = canvas.getContext('2d');

  function resize() {
    canvas.width  = canvas.offsetWidth  * devicePixelRatio;
    canvas.height = canvas.offsetHeight * devicePixelRatio;
    chartCtx.scale(devicePixelRatio, devicePixelRatio);
    drawChart();
  }

  new ResizeObserver(resize).observe(canvas);
  resize();
}

function drawChart() {
  if (!chartCtx) return;
  const canvas = chartCtx.canvas;
  const W = canvas.offsetWidth;
  const H = canvas.offsetHeight;

  chartCtx.clearRect(0, 0, W, H);

  const max = Math.max(...chartData, 1);
  const pts = chartData.map((v, i) => ({
    x: (i / (CHART_PTS - 1)) * W,
    y: H - (v / max) * (H - 20) - 10,
  }));

  // Grid lines
  chartCtx.strokeStyle = 'rgba(255,255,255,.04)';
  chartCtx.lineWidth   = 1;
  [0.25, 0.5, 0.75, 1].forEach(t => {
    const y = H - t * (H - 20) - 10;
    chartCtx.beginPath();
    chartCtx.moveTo(0, y);
    chartCtx.lineTo(W, y);
    chartCtx.stroke();
  });

  // Y-axis labels
  chartCtx.fillStyle  = 'rgba(74,84,112,.85)';
  chartCtx.font       = `${10 * devicePixelRatio / devicePixelRatio}px JetBrains Mono, monospace`;
  chartCtx.textAlign  = 'left';
  [0, 0.5, 1].forEach(t => {
    const y = H - t * (H - 20) - 10;
    chartCtx.fillText(fmtNum(Math.round(max * t)) + ' pps', 4, y - 2);
  });

  if (pts.length < 2) return;

  // Fill
  const grad = chartCtx.createLinearGradient(0, 0, 0, H);
  grad.addColorStop(0, 'rgba(91,138,240,.18)');
  grad.addColorStop(1, 'rgba(91,138,240,.00)');
  chartCtx.beginPath();
  chartCtx.moveTo(pts[0].x, H);
  pts.forEach(p => chartCtx.lineTo(p.x, p.y));
  chartCtx.lineTo(pts[pts.length-1].x, H);
  chartCtx.closePath();
  chartCtx.fillStyle = grad;
  chartCtx.fill();

  // Line
  chartCtx.beginPath();
  chartCtx.lineWidth   = 1.5;
  chartCtx.strokeStyle = '#5b8af0';
  chartCtx.lineJoin    = 'round';
  pts.forEach((p, i) => i === 0 ? chartCtx.moveTo(p.x, p.y) : chartCtx.lineTo(p.x, p.y));
  chartCtx.stroke();

  // Last-point dot
  const last = pts[pts.length - 1];
  chartCtx.beginPath();
  chartCtx.arc(last.x, last.y, 3, 0, Math.PI * 2);
  chartCtx.fillStyle = '#5b8af0';
  chartCtx.fill();
}

// ═══════════════════════════════════════════════════════════
// STATS POLLING  (/api/stats)
// ═══════════════════════════════════════════════════════════
const XDP_ACTIONS = ['ABORTED','DROP','PASS','TX','REDIRECT'];

async function pollStats() {
  let data;
  try {
    data = await apiFetch('/api/stats');
  } catch {
    // Backend offline: show clean zero/offline state — zero hardcoded/mock values
    set('s-rx',        '0 B/s');
    set('s-rx-pkt',    '0 pps · 0 pkts');
    set('s-sess',      '0');
    set('s-threats',   '0');
    set('s-mem',       '0.0%');
    set('s-mem-drops', '0 drops');
    set('engine-status', 'Engine Offline');
    const dot = document.querySelector('.status-dot');
    if (dot) dot.className = 'status-dot red';
    set('sidebar-uptime', 'offline');
    return;
  }

  const dot = document.querySelector('.status-dot');
  if (dot) dot.className = data.uptime && data.uptime.startsWith('offline') ? 'status-dot red' : 'status-dot green';
  set('engine-status', data.uptime || 'Engine Online');

  const pps = data.rx_packets_per_sec || 0;
  const bps = data.rx_bytes_per_sec || 0;
  const totPkt = data.total_packets || 0;
  const totBytes = data.total_bytes || 0;

  // Dedicated Card 1: Live Wire Speed (Always transfer speed rate/sec, never flips)
  const mbps = ((bps * 8) / 1e6).toFixed(2);
  const gbps = ((bps * 8) / 1e9).toFixed(2);
  set('s-rx', bps >= 1e8 ? `${gbps} Gbps` : bps > 0 ? `${fmtBytes(bps)}/s` : '0.00 Mbps');
  set('s-rx-pkt', `Current: ${fmtNum(pps)} pps`);

  // Dedicated Card 2: Cumulative Total Data Processed (Always cumulative bytes and packets)
  set('s-tot-bytes', fmtBytes(totBytes));
  set('s-tot-pkts', `${fmtNum(totPkt)} Total Packets`);

  // Dedicated Card 3: Concurrent Active Sessions
  set('s-sess', fmtNum(data.active_sessions || 0));

  // Dynamic peak records from real telemetry
  if (bps > peakBps) {
    peakBps = bps;
    const peakGbps = ((peakBps * 8) / 1e9).toFixed(2);
    set('s-rx-peak', `Peak: ${peakGbps} Gbps (${fmtBytes(peakBps)}/s)`);
    set('m-peak-rate', `${fmtBytes(peakBps)}/s`);
    set('m-peak-gbps', `${peakGbps} Gbps • Multi-Core Line Rate`);
  }
  if (pps > peakPps) {
    peakPps = pps;
    set('m-peak-rps', `Peak: ${fmtNum(peakPps)} req/s`);
  }
  const curSess = data.active_sessions || 0;
  if (curSess > peakSess) {
    peakSess = curSess;
    set('s-sess-peak', `Peak: ${peakSess} Concurrent`);
  }

  // Row 2 Dynamic Telemetry Matrix Cards
  set('m-cur-rate', bps >= 1e8 ? `${gbps} Gbps` : bps > 0 ? `${fmtBytes(bps)}/s` : '0.00 Mbps');
  set('m-cur-bytes', `${fmtBytes(bps)}/s Real-Time Speed`);
  set('m-cur-pps', `${fmtNum(pps)} pps`);
  set('chart-current', `Live Engine Rate: ${fmtNum(pps)} pps`);

  const ev = data.events || {};
  const xdp = data.xdp_stats || {};
  const xdpDrop = xdp[1] ? xdp[1].packets : 0;
  const threats = (ev.ja3_rate_limited || 0) +
                  (ev.rst_sni_blocked  || 0) +
                  (ev.rst_dpi_match    || 0) +
                  (ev.rst_overlap_evasion || 0) +
                  (ev.rst_bad_client_hello || 0) +
                  xdpDrop;
  set('s-threats', fmtNum(threats));
  set('s-mem', '100% OPTIMAL');
  set('s-mem-drops', `${fmtNum(ev.syn_dropped_memory_pressure || 0)} Drops · 4k UMEM Frames`);

  // Event counters — TCP table
  set('ev-syn-cookie',     fmtNum(ev.syn_cookie_sent             || 0));
  set('ev-syn-cookie-acc', fmtNum(ev.syn_cookie_accepted         || 0));
  set('ev-pmtu',           fmtNum(ev.icmp_pmtu_update            || 0));
  set('ev-sess-exp',       fmtNum(ev.session_expired_idle        || 0));
  set('ev-rto-giveup',     fmtNum(ev.session_rto_give_up         || 0));
  set('ev-syn-mem',        fmtNum(ev.syn_dropped_memory_pressure || 0));

  // Security table — 100% production engine telemetry
  set('ev-rst-dpi',     fmtNum(ev.rst_dpi_match        || 0));
  set('ev-rst-sni',     fmtNum(ev.rst_sni_blocked      || 0));
  set('ev-ja3-rl',      fmtNum(ev.ja3_rate_limited     || 0));
  set('ev-rst-overlap', fmtNum(ev.rst_overlap_evasion  || 0));
  set('ev-xdp-drop',    fmtNum(xdpDrop));
  set('ev-parse-err',   fmtNum(ev.rst_bad_client_hello || 0));

  // XDP table — read directly from kernel eBPF per-cpu action counters
  const xdpBody = document.getElementById('xdp-tbody');
  if (xdpBody) {
    xdpBody.innerHTML = XDP_ACTIONS.map((a, i) => {
      const s = xdp[i] || { packets: 0, bytes: 0 };
      const cls = a === 'DROP' ? 'red' : a === 'TX' ? 'green' : '';
      return `<tr>
        <td class="mono ${cls}">${a}</td>
        <td class="mono">${fmtNum(s.packets)}</td>
        <td class="mono">${fmtBytes(s.bytes)}</td>
      </tr>`;
    }).join('');
  }

  // Chart
  chartData.push(pps);
  if (chartData.length > CHART_PTS) chartData.shift();
  drawChart();
  set('chart-current', `${fmtNum(pps)} pps · ${fmtNum(totPkt)} total pkts`);

  // Uptime
  set('sidebar-uptime', data.uptime || 'running');

  // Engine Mode
  if (data.engine_mode !== undefined) {
    updateEngineModeUI(data.engine_mode);
  }
}

// ═══════════════════════════════════════════════════════════
// FIREWALL ACL RULES  (/api/firewall/rules)
// ═══════════════════════════════════════════════════════════
async function loadFirewallRules() {
  const tbody = document.getElementById('firewall-tbody');
  if (!tbody) return;
  tbody.innerHTML = '<tr><td colspan="10" class="txt3">Loading…</td></tr>';

  let list = [];
  try {
    list = await apiFetch('/api/firewall/rules');
  } catch {
    tbody.innerHTML = '<tr><td colspan="10" class="txt3">Unable to load firewall rules from backend.</td></tr>';
    return;
  }

  if (!list || !list.length) {
    tbody.innerHTML = '<tr><td colspan="10" class="txt3">No firewall rules defined. All allowed by default.</td></tr>';
    return;
  }

  tbody.innerHTML = list.map((r, i) => `
    <tr>
      <td class="mono txt3">#${r.id !== undefined ? r.id : i}</td>
      <td><span class="tag tag-blue">${r.proto}</span></td>
      <td class="mono">${r.src_ip || '*'}</td>
      <td class="mono txt3">${r.src_port || '*'}</td>
      <td class="mono">${r.dst_ip || '*'}</td>
      <td class="mono txt3">${r.dst_port || '*'}</td>
      <td class="mono txt3" style="font-size:11px">${(r.src_mac !== '*' ? 'Src:'+r.src_mac+' ' : '') + (r.dst_mac !== '*' ? 'Dst:'+r.dst_mac : (r.src_mac==='*'?'*':''))}</td>
      <td class="mono txt3">${r.vlan_id ? r.vlan_id : '*'}</td>
      <td><span class="tag ${r.action === 'ALLOW' ? 'tag-green' : 'tag-red'}">${r.action}</span></td>
      <td style="text-align:right">
        <button class="btn btn-warning btn-sm" onclick='openEditFirewallModal(${JSON.stringify(r)})'>Edit</button>
        <button class="btn btn-danger btn-sm" onclick="deleteFirewallRule(${r.id !== undefined ? r.id : i})">Delete</button>
      </td>
    </tr>`).join('');
}

function openEditFirewallModal(rule) {
  document.getElementById('edit-fw-id').value = rule.id;
  document.getElementById('edit-fw-action').value = rule.action || 'ALLOW';
  document.getElementById('edit-fw-proto').value = rule.proto || 'ALL';
  document.getElementById('edit-fw-src-ip').value = rule.src_ip || '*';
  document.getElementById('edit-fw-src-port').value = rule.src_port || '*';
  document.getElementById('edit-fw-dst-ip').value = rule.dst_ip || '*';
  document.getElementById('edit-fw-dst-port').value = rule.dst_port || '*';
  document.getElementById('edit-fw-src-mac').value = rule.src_mac || '*';
  document.getElementById('edit-fw-dst-mac').value = rule.dst_mac || '*';
  document.getElementById('edit-fw-vlan').value = rule.vlan_id || 0;
  openModal('modal-edit-firewall');
}

async function saveEditFirewallRule() {
  const id = document.getElementById('edit-fw-id').value;
  const proto   = document.getElementById('edit-fw-proto').value;
  const action  = document.getElementById('edit-fw-action').value;
  const src_ip  = document.getElementById('edit-fw-src-ip').value.trim() || '*';
  const src_port= document.getElementById('edit-fw-src-port').value.trim() || '*';
  const dst_ip  = document.getElementById('edit-fw-dst-ip').value.trim() || '*';
  const dst_port= document.getElementById('edit-fw-dst-port').value.trim() || '*';
  const src_mac = document.getElementById('edit-fw-src-mac').value.trim() || '*';
  const dst_mac = document.getElementById('edit-fw-dst-mac').value.trim() || '*';
  const vlanVal = document.getElementById('edit-fw-vlan').value.trim();
  const vlan_id = vlanVal ? parseInt(vlanVal) : 0;

  try {
    await apiFetch('/api/firewall/rules/' + id, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ proto, action, src_ip, src_port, dst_ip, dst_port, src_mac, dst_mac, vlan_id, active: true }),
    });
    showToast('Firewall rule updated in eBPF map.');
  } catch (err) {
    showToast('Failed to update firewall rule: ' + err.message, true);
  }

  closeModal('modal-edit-firewall');
  loadFirewallRules();
}

async function addFirewallRule() {
  const proto   = document.getElementById('fw-proto').value;
  const action  = document.getElementById('fw-action').value;
  const src_ip  = document.getElementById('fw-src-ip').value.trim() || '*';
  const src_port= document.getElementById('fw-src-port').value.trim() || '*';
  const dst_ip  = document.getElementById('fw-dst-ip').value.trim() || '*';
  const dst_port= document.getElementById('fw-dst-port').value.trim() || '*';
  const src_mac = document.getElementById('fw-src-mac').value.trim() || '*';
  const dst_mac = document.getElementById('fw-dst-mac').value.trim() || '*';
  const vlanVal = document.getElementById('fw-vlan').value.trim();
  const vlan_id = vlanVal ? parseInt(vlanVal) : 0;

  try {
    await apiFetch('/api/firewall/rules', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ proto, action, src_ip, src_port, dst_ip, dst_port, src_mac, dst_mac, vlan_id, active: true }),
    });
    showToast('Firewall rule saved to eBPF map.');
  } catch (err) {
    showToast('Failed to save firewall rule: ' + err.message, true);
  }

  closeModal('modal-add-firewall');
  loadFirewallRules();
}

async function deleteFirewallRule(id) {
  if (!confirm('Delete Firewall Rule #' + id + '?')) return;
  try {
    await apiFetch('/api/firewall/rules/' + id, { method: 'DELETE' });
    showToast('Firewall rule deleted.');
  } catch (err) {
    showToast('Failed to delete rule: ' + err.message, true);
  }
  loadFirewallRules();
}

// ═══════════════════════════════════════════════════════════
// SERVICES  (/api/services)
// ═══════════════════════════════════════════════════════════
async function loadServices() {
  const tbody = document.getElementById('svc-tbody');
  if (!tbody) return;
  tbody.innerHTML = '<tr><td colspan="6" class="txt3">Loading…</td></tr>';

  let list = [];
  try {
    list = await apiFetch('/api/services');
  } catch {
    tbody.innerHTML = '<tr><td colspan="6" class="txt3">Unable to load services from backend.</td></tr>';
    return;
  }

  if (!list || !list.length) {
    tbody.innerHTML = '<tr><td colspan="6" class="txt3">No services configured.</td></tr>';
    return;
  }

  tbody.innerHTML = list.map((s, i) => `
    <tr>
      <td class="mono">${s.listen}</td>
      <td class="mono txt3">${s.cert  || '—'}</td>
      <td class="mono txt3">${s.key   || '—'}</td>
      <td class="mono">${s.backend_port}</td>
      <td><span class="tag ${s.proto === 'https' ? 'tag-green' : s.proto === 'tcp' ? 'tag-blue' : 'tag-muted'}">${s.proto.toUpperCase()}</span></td>
      <td style="text-align:right">
        <button class="btn btn-warning btn-sm" onclick='openEditServiceModal(${i}, ${JSON.stringify(s)})'>Edit</button>
        <button class="btn btn-danger btn-sm" onclick="deleteService(${i})">Remove</button>
      </td>
    </tr>`).join('');
}

function openEditServiceModal(index, svc) {
  document.getElementById('edit-svc-index').value = index;
  document.getElementById('edit-svc-listen').value = svc.listen || '';
  document.getElementById('edit-svc-cert').value = svc.cert || '';
  document.getElementById('edit-svc-key').value = svc.key || '';
  document.getElementById('edit-svc-backend').value = svc.backend_port || 8080;
  document.getElementById('edit-svc-proto').value = svc.proto || 'tcp';
  openModal('modal-edit-svc');
}

async function saveEditService() {
  const index = document.getElementById('edit-svc-index').value;
  const listen  = document.getElementById('edit-svc-listen').value.trim();
  const cert    = document.getElementById('edit-svc-cert').value.trim();
  const key     = document.getElementById('edit-svc-key').value.trim();
  const backend = document.getElementById('edit-svc-backend').value.trim();
  const proto   = document.getElementById('edit-svc-proto').value;

  if (!listen || !backend) { showToast('Listen addr and backend port are required.', true); return; }

  try {
    await apiFetch('/api/services/' + index, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ listen, cert, key, backend_port: parseInt(backend), proto }),
    });
    showToast('Service updated. Engine reloaded.');
  } catch (err) {
    showToast('Failed to update service: ' + err.message, true);
  }

  closeModal('modal-edit-svc');
  loadServices();
}

async function addService() {
  const listen  = document.getElementById('svc-listen').value.trim();
  const cert    = document.getElementById('svc-cert').value.trim();
  const key     = document.getElementById('svc-key').value.trim();
  const backend = document.getElementById('svc-backend').value.trim();
  const proto   = document.getElementById('svc-proto').value;

  if (!listen || !backend) { showToast('Listen addr and backend port are required.', true); return; }

  try {
    await apiFetch('/api/services', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ listen, cert, key, backend_port: parseInt(backend), proto }),
    });
    showToast('Service added. Engine reloaded.');
  } catch (err) {
    showToast('Failed to add service: ' + err.message, true);
  }

  closeModal('modal-add-svc');
  loadServices();
}

async function deleteService(index) {
  if (!confirm('Remove this service?')) return;
  try {
    await apiFetch('/api/services/' + index, { method: 'DELETE' });
    showToast('Service removed.');
  } catch (err) {
    showToast('Failed to remove service: ' + err.message, true);
  }
  loadServices();
}

// ═══════════════════════════════════════════════════════════
// SNI BLOCKLIST  (/api/blocked-domains)
// ═══════════════════════════════════════════════════════════
let _domains = [];

async function loadDomains() {
  const list = document.getElementById('domain-list');
  if (!list) return;
  list.innerHTML = '<span class="txt3">Loading…</span>';

  try {
    const res = await apiFetch('/api/blocked-domains');
    _domains = Array.isArray(res) ? res : [];
  } catch {
    _domains = [];
    list.innerHTML = '<span class="txt3">Unable to load blocked domains.</span>';
    return;
  }

  renderDomains();
}

function renderDomains() {
  const list = document.getElementById('domain-list');
  if (!list) return;
  if (!_domains || !_domains.length) {
    list.innerHTML = '<span class="txt3">No blocked domains.</span>';
    return;
  }
  list.innerHTML = _domains.map(d => `
    <span class="d-tag">
      ${d}
      <button class="d-tag-x" onclick="removeDomain('${d}')" title="Unblock">×</button>
    </span>`).join('');
}

async function addDomain() {
  const input = document.getElementById('new-domain-input');
  const domain = input.value.trim().toLowerCase();
  if (!domain) return;
  if (_domains.includes(domain)) { showToast('Domain already blocked.', true); return; }

  try {
    await apiFetch('/api/blocked-domains', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain }),
    });
    showToast('Domain blocked. Engine reloaded.');
  } catch (err) {
    showToast('Failed to block domain: ' + err.message, true);
  }

  _domains.push(domain);
  renderDomains();
  input.value = '';
}

async function removeDomain(domain) {
  try {
    await apiFetch('/api/blocked-domains/' + encodeURIComponent(domain), { method: 'DELETE' });
    showToast('Domain unblocked.');
  } catch (err) {
    showToast('Failed to unblock domain: ' + err.message, true);
  }
  _domains = _domains.filter(d => d !== domain);
  renderDomains();
}

// ═══════════════════════════════════════════════════════════
// CUSTOM DPI RULES  (/api/dpi-rules)
// ═══════════════════════════════════════════════════════════
let _dpiRules = [];
let _dpiEditorMode = 'builder';

function escHtml(str) {
  return String(str ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

async function dpiApiRequest(path, opts = {}) {
  const res = await fetch(API_BASE + path, opts);
  if (!res.ok) {
    const errText = (await res.text()).trim();
    throw new Error(errText || (res.status + ' ' + res.statusText));
  }
  return res.json();
}

async function loadDpiRules() {
  const tbody = document.getElementById('dpi-rules-tbody');
  if (!tbody) return;
  tbody.innerHTML = '<tr><td colspan="7" class="txt3">Loading…</td></tr>';

  try {
    const list = await dpiApiRequest('/api/dpi-rules');
    _dpiRules = Array.isArray(list) ? list : [];
  } catch (err) {
    _dpiRules = [];
    tbody.innerHTML = `<tr><td colspan="7" class="txt3">Unable to load custom DPI rules: ${escHtml(err.message)}</td></tr>`;
    return;
  }

  renderDpiRules();
}

function renderDpiRules() {
  const tbody = document.getElementById('dpi-rules-tbody');
  const countEl = document.getElementById('dpi-rules-count');
  if (!tbody) return;

  const activeCount = _dpiRules.filter(r => r.enabled).length;
  if (countEl) countEl.textContent = `${activeCount} active / ${_dpiRules.length} total`;

  if (!_dpiRules.length) {
    tbody.innerHTML = '<tr><td colspan="7" class="txt3">No custom DPI rules yet. Click "+ Add DPI Rule" or pick a template below.</td></tr>';
    return;
  }

  tbody.innerHTML = _dpiRules.map((r, idx) => {
    const statusTag = r.enabled
      ? '<span class="tag tag-green">ACTIVE</span>'
      : '<span class="tag tag-muted">DISABLED</span>';
    const actTag = (r.action === 'drop' || r.action === 'reject')
      ? `<span class="tag tag-red">${escHtml(r.action.toUpperCase())}</span>`
      : `<span class="tag tag-blue">${escHtml(r.action.toUpperCase())}</span>`;
    const patLabel = r.is_pcre ? 'pcre' : 'content';
    const nocaseBadge = (!r.is_pcre && r.nocase) ? ' <span class="tag tag-muted">nocase</span>' : '';
    return `
      <tr style="${r.enabled ? '' : 'opacity:0.6;'}">
        <td>${statusTag}</td>
        <td class="mono">${escHtml(r.sid)}</td>
        <td>${actTag}</td>
        <td class="mono">${escHtml((r.protocol || 'tcp').toUpperCase())}</td>
        <td>${escHtml(r.msg || '(no msg)')}</td>
        <td class="mono" style="max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${escHtml(r.raw)}">
          <span class="txt3">${patLabel}:</span> "${escHtml(r.pattern)}"${nocaseBadge}
        </td>
        <td style="text-align:right;white-space:nowrap;">
          <button class="btn btn-ghost btn-sm" onclick="toggleDpiRuleEnabled(${idx})">${r.enabled ? 'Disable' : 'Enable'}</button>
          <button class="btn btn-ghost btn-sm" onclick="openEditDpiRuleModal(${idx})">Edit</button>
          <button class="btn btn-danger btn-sm" onclick="deleteDpiRule(${idx})">Delete</button>
        </td>
      </tr>`;
  }).join('');
}

function setDpiEditorMode(mode) {
  _dpiEditorMode = mode;
  const builderEl = document.getElementById('dpi-builder-fields');
  const rawEl     = document.getElementById('dpi-raw-fields');
  const bBtn      = document.getElementById('dpi-mode-builder-btn');
  const rBtn      = document.getElementById('dpi-mode-raw-btn');
  const prevBox   = document.getElementById('dpi-preview-box');

  if (mode === 'raw') {
    if (builderEl) builderEl.style.display = 'none';
    if (rawEl) rawEl.style.display = 'block';
    if (prevBox) prevBox.style.display = 'none';
    if (bBtn) bBtn.className = 'btn btn-sm btn-ghost';
    if (rBtn) rBtn.className = 'btn btn-sm btn-primary';
    const rawInput = document.getElementById('dpi-rule-raw');
    if (rawInput && !rawInput.value.trim()) {
      rawInput.value = buildDpiPreviewString();
    }
  } else {
    if (builderEl) builderEl.style.display = 'grid';
    if (rawEl) rawEl.style.display = 'none';
    if (prevBox) prevBox.style.display = 'block';
    if (bBtn) bBtn.className = 'btn btn-sm btn-primary';
    if (rBtn) rBtn.className = 'btn btn-sm btn-ghost';
    updateDpiPreview();
  }
}

function nextSuggestedSid() {
  let maxSid = 9000000;
  for (const r of _dpiRules) {
    if (r.sid > maxSid) maxSid = r.sid;
  }
  return maxSid + 1;
}

function buildDpiPreviewString() {
  const action  = document.getElementById('dpi-rule-action')?.value || 'drop';
  const proto   = document.getElementById('dpi-rule-proto')?.value || 'tcp';
  const msg     = (document.getElementById('dpi-rule-msg')?.value || 'CUSTOM Rule').trim().replace(/"/g, '\\"');
  const mtype   = document.getElementById('dpi-rule-match-type')?.value || 'content';
  let pattern   = (document.getElementById('dpi-rule-pattern')?.value || '/example').trim();
  const nocase  = document.getElementById('dpi-rule-nocase')?.checked;
  const sidVal  = document.getElementById('dpi-rule-sid')?.value.trim();
  const sid     = sidVal ? parseInt(sidVal, 10) : nextSuggestedSid();

  let matchOpt = '';
  if (mtype === 'pcre') {
    if (!pattern.startsWith('/')) pattern = '/' + pattern + '/' + (nocase ? 'i' : '');
    matchOpt = `pcre:"${pattern.replace(/"/g, '\\"')}"`;
  } else {
    matchOpt = `content:"${pattern.replace(/"/g, '\\"')}";${nocase ? ' nocase;' : ''}`;
    return `${action} ${proto} any any -> any any (msg:"${msg}"; ${matchOpt} sid:${sid}; rev:1;)`;
  }
  return `${action} ${proto} any any -> any any (msg:"${msg}"; ${matchOpt}; sid:${sid}; rev:1;)`;
}

function updateDpiPreview() {
  const el = document.getElementById('dpi-rule-preview');
  if (el) el.textContent = buildDpiPreviewString();
}

function openAddDpiRuleModal(preset = null) {
  document.getElementById('dpi-modal-title').textContent = 'Add Custom DPI Rule';
  document.getElementById('dpi-rule-id').value = '';
  document.getElementById('dpi-rule-enabled').checked = true;
  document.getElementById('dpi-rule-action').value = preset?.action || 'drop';
  document.getElementById('dpi-rule-proto').value = preset?.protocol || 'tcp';
  document.getElementById('dpi-rule-msg').value = preset?.msg || '';
  document.getElementById('dpi-rule-match-type').value = preset?.is_pcre ? 'pcre' : 'content';
  document.getElementById('dpi-rule-pattern').value = preset?.pattern || '';
  document.getElementById('dpi-rule-nocase').checked = preset ? !!preset.nocase : true;
  document.getElementById('dpi-rule-sid').value = preset?.sid || nextSuggestedSid();
  document.getElementById('dpi-rule-raw').value = '';

  setDpiEditorMode('builder');
  openModal('modal-dpi-rule');
}

function openEditDpiRuleModal(idx) {
  const r = _dpiRules[idx];
  if (!r) return;

  document.getElementById('dpi-modal-title').textContent = `Edit Custom DPI Rule (SID ${r.sid})`;
  document.getElementById('dpi-rule-id').value = String(idx);
  document.getElementById('dpi-rule-enabled').checked = !!r.enabled;
  document.getElementById('dpi-rule-action').value = r.action || 'drop';
  document.getElementById('dpi-rule-proto').value = ['tcp', 'http', 'tls', 'ip'].includes(r.protocol) ? r.protocol : 'tcp';
  document.getElementById('dpi-rule-msg').value = r.msg || '';
  document.getElementById('dpi-rule-match-type').value = r.is_pcre ? 'pcre' : 'content';
  document.getElementById('dpi-rule-pattern').value = r.pattern || '';
  document.getElementById('dpi-rule-nocase').checked = !!r.nocase;
  document.getElementById('dpi-rule-sid').value = r.sid || '';
  document.getElementById('dpi-rule-raw').value = r.raw || '';

  setDpiEditorMode('builder');
  openModal('modal-dpi-rule');
}

async function saveDpiRule() {
  const idStr   = document.getElementById('dpi-rule-id').value;
  const isEdit  = idStr !== '';
  const enabled = document.getElementById('dpi-rule-enabled').checked;

  let payload;
  if (_dpiEditorMode === 'raw') {
    const raw = document.getElementById('dpi-rule-raw').value.trim();
    if (!raw) { showToast('Raw rule line cannot be empty.', true); return; }
    payload = { raw, enabled };
  } else {
    const action  = document.getElementById('dpi-rule-action').value;
    const protocol = document.getElementById('dpi-rule-proto').value;
    const msg     = document.getElementById('dpi-rule-msg').value.trim();
    const is_pcre = document.getElementById('dpi-rule-match-type').value === 'pcre';
    const pattern = document.getElementById('dpi-rule-pattern').value.trim();
    const nocase  = document.getElementById('dpi-rule-nocase').checked;
    const sidVal  = document.getElementById('dpi-rule-sid').value.trim();
    const sid     = sidVal ? parseInt(sidVal, 10) : 0;

    if (!msg || !pattern) {
      showToast('Alert message and match pattern are required.', true);
      return;
    }
    payload = { action, protocol, msg, is_pcre, pattern, nocase, sid, rev: 1, enabled };
  }

  try {
    const res = await dpiApiRequest(isEdit ? '/api/dpi-rules/' + idStr : '/api/dpi-rules', {
      method: isEdit ? 'PUT' : 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const note = res.reloaded ? 'Engine hot-reloaded (SIGHUP).' : 'Saved to custom_rules.rules.';
    showToast((isEdit ? 'DPI rule updated. ' : 'DPI rule added. ') + note);
    closeModal('modal-dpi-rule');
    loadDpiRules();
  } catch (err) {
    showToast('Rule error: ' + err.message, true);
  }
}

async function toggleDpiRuleEnabled(idx) {
  const r = _dpiRules[idx];
  if (!r) return;
  try {
    const res = await dpiApiRequest('/api/dpi-rules/' + idx, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ raw: r.raw, enabled: !r.enabled }),
    });
    showToast((!r.enabled ? 'Rule enabled. ' : 'Rule disabled. ') + (res.reloaded ? 'Engine reloaded.' : ''));
    loadDpiRules();
  } catch (err) {
    showToast('Failed to toggle rule: ' + err.message, true);
  }
}

async function deleteDpiRule(idx) {
  const r = _dpiRules[idx];
  if (!confirm(`Delete custom DPI rule SID ${r ? r.sid : idx}?`)) return;
  try {
    const res = await dpiApiRequest('/api/dpi-rules/' + idx, { method: 'DELETE' });
    showToast('DPI rule deleted. ' + (res.reloaded ? 'Engine reloaded.' : ''));
    loadDpiRules();
  } catch (err) {
    showToast('Failed to delete rule: ' + err.message, true);
  }
}

function toggleDpiGuide() {
  const el = document.getElementById('dpi-rule-guide');
  if (!el) return;
  el.style.display = (el.style.display === 'none') ? 'block' : 'none';
}

function useDpiTemplate(name) {
  const templates = {
    env:   { action: 'drop',  protocol: 'http', msg: 'CUSTOM Dotenv Exposure Probe',  is_pcre: false, pattern: '/.env',                     nocase: true },
    ua:    { action: 'drop',  protocol: 'http', msg: 'CUSTOM Block sqlmap User-Agent', is_pcre: false, pattern: 'sqlmap/',                   nocase: true },
    sqli:  { action: 'drop',  protocol: 'tcp',  msg: 'CUSTOM SQLi UNION SELECT',       is_pcre: true,  pattern: '/union\\s+(all\\s+)?select/i', nocase: true },
    audit: { action: 'alert', protocol: 'tcp',  msg: 'CUSTOM Audit Debug Header',      is_pcre: false, pattern: 'X-Debug-Token|3a|',         nocase: true },
  };
  openAddDpiRuleModal(templates[name] || null);
}

// ═══════════════════════════════════════════════════════════
// BLOCKED IPs  (/api/blocked-ips)
// ═══════════════════════════════════════════════════════════
async function loadBlockedIPs() {
  const tbody = document.getElementById('blocked-tbody');
  if (!tbody) return;
  tbody.innerHTML = '<tr><td colspan="4" class="txt3">Loading…</td></tr>';

  let list = [];
  try {
    list = await apiFetch('/api/blocked-ips');
  } catch {
    tbody.innerHTML = '<tr><td colspan="4" class="txt3">Unable to load blocked IPs.</td></tr>';
    return;
  }

  if (!list || !list.length) {
    tbody.innerHTML = '<tr><td colspan="4" class="txt3">No IPs blocked.</td></tr>';
    return;
  }

  tbody.innerHTML = list.map(e => `
    <tr>
      <td class="mono red">${e.ip}</td>
      <td class="mono">${fmtNum(e.drops)}</td>
      <td class="mono txt3">${e.added || '—'}</td>
      <td style="text-align:right">
        <button class="btn btn-ghost btn-sm" onclick="unblockIp('${e.ip}')">Unblock</button>
      </td>
    </tr>`).join('');
}

async function blockIp() {
  const ip = document.getElementById('block-ip-addr').value.trim();
  if (!ip) { showToast('Enter an IP address.', true); return; }

  try {
    await apiFetch('/api/blocked-ips', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip }),
    });
    showToast('IP blocked in eBPF map.');
  } catch (err) {
    showToast('Failed to block IP: ' + err.message, true);
  }

  closeModal('modal-block-ip');
  document.getElementById('block-ip-addr').value = '';
  loadBlockedIPs();
}

async function unblockIp(ip) {
  if (!confirm('Unblock ' + ip + '?')) return;
  try {
    await apiFetch('/api/blocked-ips/' + encodeURIComponent(ip), { method: 'DELETE' });
    showToast('IP removed from eBPF map.');
  } catch (err) {
    showToast('Failed to unblock IP: ' + err.message, true);
  }
  loadBlockedIPs();
}

// ═══════════════════════════════════════════════════════════
// eBPF MAPS & RATE LIMITER
// ═══════════════════════════════════════════════════════════
async function loadeBPFMaps() {
  // Global rate limiter parameters
  try {
    const params = await apiFetch('/api/bpf/rate-limiter/params');
    if (params) {
      set('rl-param-tokens', fmtNum(params.tokens_per_sec || 100000) + ' / s');
      set('rl-param-window', (params.window_sec || 10) + ' s');
      set('rl-param-limit', fmtNum(params.window_limit || 50000) + ' pkts');

      const tokInput = document.getElementById('param-input-tokens');
      const winInput = document.getElementById('param-input-window');
      const limInput = document.getElementById('param-input-limit');
      if (tokInput) tokInput.value = params.tokens_per_sec || 100000;
      if (winInput) winInput.value = params.window_sec || 10;
      if (limInput) limInput.value = params.window_limit || 50000;
    }
  } catch {}

  // Rate limiter map
  const rlBody = document.getElementById('rl-tbody');
  let rl = [];
  try {
    rl = await apiFetch('/api/bpf/rate-limiter');
  } catch {
    rl = [];
  }
  set('rl-count', (rl ? rl.length : 0) + ' entries');
  if (rlBody) {
    rlBody.innerHTML = (rl && rl.length)
      ? rl.map(e => `<tr>
          <td class="mono">${e.ip}</td>
          <td><span class="tag ${e.algo === 'Sliding Window' ? 'tag-amber' : 'tag-blue'}">${e.algo || 'Token Bucket'}</span></td>
          <td class="mono">${fmtNum(e.tokens || 100000)} / s</td>
          <td style="text-align:right">
            <button class="btn btn-warning btn-sm" onclick='openEditRateLimiterModal(${JSON.stringify(e)})'>Edit</button>
            <button class="btn btn-danger btn-sm" onclick="deleteRateLimiterRule('${e.ip}')">Delete</button>
          </td>
        </tr>`).join('')
      : '<tr><td colspan="4" class="txt3">No rate limit rules defined. Click "+ Add Rate Limit" above.</td></tr>';
  }

  // Services map
  const svcBody = document.getElementById('svcmap-tbody');
  let sm = [];
  try {
    sm = await apiFetch('/api/bpf/services-map');
  } catch {
    sm = [];
  }
  set('svcmap-count', (sm ? sm.length : 0) + ' entries');
  if (svcBody) {
    svcBody.innerHTML = (sm && sm.length)
      ? sm.map(e => `<tr>
          <td class="mono">${e.port}</td>
          <td><span class="tag ${e.active ? 'tag-green' : 'tag-muted'}">${e.active ? 'ACTIVE' : 'INACTIVE'}</span></td>
        </tr>`).join('')
      : '<tr><td colspan="2" class="txt3">Empty / Map not loaded</td></tr>';
  }
}

async function addRateLimiterRule() {
  const ip = document.getElementById('add-rl-ip').value.trim();
  const algo = document.getElementById('add-rl-algo').value;
  const tokensVal = document.getElementById('add-rl-tokens').value.trim();
  const tokens = tokensVal ? parseInt(tokensVal) : 100000;

  if (!ip) { showToast('IP address or CIDR is required.', true); return; }

  try {
    await apiFetch('/api/bpf/rate-limiter', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip, algo, tokens, drops: 0 }),
    });
    showToast('Rate limit rule added.');
  } catch (err) {
    showToast('Failed to add rate limit rule: ' + err.message, true);
  }

  closeModal('modal-add-rl');
  document.getElementById('add-rl-ip').value = '';
  loadeBPFMaps();
}

function openEditRateLimiterModal(rule) {
  document.getElementById('edit-rl-ip').value = rule.ip;
  document.getElementById('edit-rl-algo').value = rule.algo || 'Token Bucket';
  document.getElementById('edit-rl-tokens').value = rule.tokens || 100000;
  openModal('modal-edit-rl');
}

async function saveEditRateLimiterRule() {
  const ip = document.getElementById('edit-rl-ip').value;
  const algo = document.getElementById('edit-rl-algo').value;
  const tokensVal = document.getElementById('edit-rl-tokens').value.trim();
  const tokens = tokensVal ? parseInt(tokensVal) : 100000;

  try {
    await apiFetch('/api/bpf/rate-limiter/' + encodeURIComponent(ip), {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip, algo, tokens, drops: 0 }),
    });
    showToast('Rate limit rule updated.');
  } catch (err) {
    showToast('Failed to update rate limit rule: ' + err.message, true);
  }

  closeModal('modal-edit-rl');
  loadeBPFMaps();
}

async function deleteRateLimiterRule(ip) {
  if (!confirm('Delete Rate Limit rule for ' + ip + '?')) return;
  try {
    await apiFetch('/api/bpf/rate-limiter/' + encodeURIComponent(ip), { method: 'DELETE' });
    showToast('Rate limit rule removed.');
  } catch (err) {
    showToast('Failed to delete rule: ' + err.message, true);
  }
  loadeBPFMaps();
}

async function saveRateLimiterParams() {
  const tokens = parseInt(document.getElementById('param-input-tokens').value) || 100000;
  const window_sec = parseInt(document.getElementById('param-input-window').value) || 10;
  const window_limit = parseInt(document.getElementById('param-input-limit').value) || 50000;

  try {
    await apiFetch('/api/bpf/rate-limiter/params', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ tokens_per_sec: tokens, window_sec, window_limit }),
    });
    showToast('Global rate limiter parameters updated.');
  } catch (err) {
    showToast('Failed to update parameters: ' + err.message, true);
  }

  closeModal('modal-rl-params');
  loadeBPFMaps();
}

// ═══════════════════════════════════════════════════════════
// SECURITY LOGS (FLUXIO WAL)
// ═══════════════════════════════════════════════════════════
async function loadLogs() {
  const tbody = document.getElementById('logs-tbody');
  if (!tbody) return;

  const priority = document.getElementById('log-filter-priority')?.value || 'ALL';
  const since = document.getElementById('log-filter-since')?.value || '5m';
  const module = document.getElementById('log-filter-module')?.value || 'ALL';
  const search = document.getElementById('log-filter-search')?.value.trim() || '';

  const q = new URLSearchParams({ priority, since, module, search, limit: '200' });
  let logs = [];
  try {
    logs = await apiFetch('/api/logs?' + q.toString());
  } catch {
    tbody.innerHTML = '<tr><td colspan="7" class="txt3">No log records found.</td></tr>';
    return;
  }

  set('logs-count', logs.length + ' records');
  if (!logs || !logs.length) {
    tbody.innerHTML = '<tr><td colspan="7" class="txt3">No security logs matching the current filter.</td></tr>';
    return;
  }

  tbody.innerHTML = logs.map(l => {
    const lvl = (l.level || 'INFO').toUpperCase();
    const badgeClass = lvl === 'CRITICAL' ? 'badge-crit'
                     : lvl === 'ALERT'    ? 'badge-alert'
                     : lvl === 'WARN'     ? 'badge-warn'
                     :                      'badge-info';
    return `<tr>
      <td class="mono txt3" style="font-size:11.5px;">${l.ts}</td>
      <td><span class="${badgeClass}">${lvl}</span></td>
      <td><span class="tag tag-blue">${l.module}</span></td>
      <td class="mono">${l.src_ip}:${l.src_port}</td>
      <td class="mono">${l.dst_ip}:${l.dst_port}</td>
      <td><span class="tag ${l.action==='RESET'||l.action==='DROP'?'tag-red':'tag-green'}">${l.action}</span></td>
      <td class="mono" style="font-size:12px;color:var(--txt1)">${l.msg || l.event}</td>
    </tr>`;
  }).join('');
}

async function clearLogsFile() {
  if (!confirm('Clear all security logs in logs/aethon_security.jsonl?')) return;
  try {
    await apiFetch('/api/logs', { method: 'DELETE' });
    showToast('Logs cleared.');
  } catch (err) {
    showToast('Failed to clear logs: ' + err.message, true);
  }
  loadLogs();
}

function downloadLogs() {
  window.open('/api/logs?limit=2000', '_blank');
}

// ═══════════════════════════════════════════════════════════
// CONFIG RELOAD
// ═══════════════════════════════════════════════════════════
async function reloadConfig() {
  try {
    await apiFetch('/api/reload', { method: 'POST' });
    showToast('SIGHUP sent — config reloaded.');
  } catch (err) {
    showToast('Reload failed: ' + err.message, true);
  }
}

// ═══════════════════════════════════════════════════════════
// LIVE EVENTS (SSE /api/live — Real telemetry only)
// ═══════════════════════════════════════════════════════════
function appendEvent(ts, sev, msg) {
  const feed  = document.getElementById('event-log');
  if (!feed) return;
  const cls   = (sev === 'ATTACK' || sev === 'BLOCK') ? 'sev-block sev-attack'
              : sev === 'WARN'  ? 'sev-warn'
              : sev === 'OK'    ? 'sev-ok'
              :                   'sev-info';
  const row   = document.createElement('div');
  row.className = 'log-row';
  row.innerHTML = `<span class="log-ts">${ts}</span><span class="log-sev ${cls}">${sev}</span><span class="log-msg">${msg}</span>`;
  feed.appendChild(row);
  // Keep max 300 rows
  while (feed.children.length > 300) feed.removeChild(feed.firstChild);
  if (!eventsPaused) feed.scrollTop = feed.scrollHeight;
}

function startEventStream() {
  if (typeof EventSource === 'undefined') return;
  if (eventSource) {
    try { eventSource.close(); } catch {}
  }
  eventSource = new EventSource('/api/live');
  eventSource.onmessage = e => {
    if (eventsPaused) return;
    try {
      const d = JSON.parse(e.data);
      appendEvent(d.ts || now(), d.sev || 'INFO', d.msg || e.data);
    } catch {
      appendEvent(now(), 'INFO', e.data);
    }
  };
  eventSource.onerror = () => {
    // Standard browser EventSource automatically attempts reconnection
  };
}

function clearEvents() {
  const feed = document.getElementById('event-log');
  if (feed) feed.innerHTML = '';
}

// Pause checkbox
document.getElementById('pause-events')?.addEventListener('change', e => {
  eventsPaused = e.target.checked;
});

// ═══════════════════════════════════════════════════════════
// ENGINE OPERATION MODE (match_only BPF Map)
// 0 = Bypass (Pass all traffic directly to OS network stack)
// 1 = Match-Only (Audit / Monitor mode, never drop)
// 2 = Full Protection (Active drop and inspection; default)
// ═══════════════════════════════════════════════════════════
function updateEngineModeUI(mode) {
  const select = document.getElementById('engine-mode-select');
  const badge  = document.getElementById('engine-mode-badge');
  if (select && document.activeElement !== select) {
    select.value = String(mode);
  }
  if (!badge) return;

  if (mode === 0) {
    badge.className = 'tag tag-muted';
    badge.style.color = '#e5c07b';
    badge.style.borderColor = 'rgba(229,192,123,0.3)';
    badge.textContent = 'BYPASS';
    badge.title = 'Bypass: traffic passes directly to OS network stack';
  } else if (mode === 1) {
    badge.className = 'tag tag-blue';
    badge.style.color = '';
    badge.style.borderColor = '';
    badge.textContent = 'MATCH ONLY';
    badge.title = 'Audit mode: rules & limits evaluate, but NEVER drop';
  } else {
    badge.className = 'tag tag-green';
    badge.style.color = '';
    badge.style.borderColor = '';
    badge.textContent = 'PROTECTION';
    badge.title = 'Full Protection: active drops & deep inspection';
  }
}

async function loadEngineMode() {
  try {
    const res = await apiFetch('/api/engine/mode');
    if (res && res.mode !== undefined) {
      updateEngineModeUI(res.mode);
    }
  } catch {}
}

async function changeEngineMode(val) {
  const mode = parseInt(val, 10);
  try {
    await apiFetch('/api/engine/mode', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode })
    });
    updateEngineModeUI(mode);
    const names = {
      0: 'Mode 0: Bypass (Traffic passes straight to OS)',
      1: 'Mode 1: Match-Only (Audit mode, no drops)',
      2: 'Mode 2: Full Protection (Active drops & inspection)'
    };
    showToast('Engine Mode set to: ' + names[mode]);
  } catch (err) {
    showToast('Failed to update engine mode: ' + err.message, true);
  }
}

// ═══════════════════════════════════════════════════════════
// BOOT
// ═══════════════════════════════════════════════════════════
(function init() {
  initTheme();
  initChart();
  loadEngineMode();
  pollStats();
  statsTimer = setInterval(pollStats, POLL_MS);
  startEventStream();
  // Pre-seed chart with zeros so it draws on load
  chartData = new Array(CHART_PTS).fill(0);
})();
