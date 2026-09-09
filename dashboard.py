"""
dashboard.py — LinkKeeper control panel (stdlib only) on http://127.0.0.1:8901

A vanilla single-page app: sidebar nav (Dashboard / Connections / Advisor /
Settings), a first-run setup wizard, and a settings page that edits config.json.
Privileged actions (apply Windows fixes, install autostart, join open Wi-Fi) are
handed to the elevated daemon over the file-based command channel.

Security: binds to 127.0.0.1 only; POST requests are rejected unless Host/Origin
are localhost (DNS-rebind / CSRF guard); every network-derived string is
HTML-escaped in the client. Run: python dashboard.py  (--port to override).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote

import commandbus
import store

HERE = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(HERE, "config.json")
STATUS_PATH = os.path.join(HERE, "logs", "status.json")
PORT = 8901

# Only these dot-paths may be changed via POST /api/config — a settings
# allowlist so the UI can never rewrite arbitrary config (or inject links).
ALLOWED_SETTINGS = {
    "decision.prefer_wired", "decision.switchback_dwell_seconds",
    "decision.switch_margin_ms", "decision.fail_after_bad_probes",
    "wifi.autoreconnect", "wifi.ssids", "wifi.retry_seconds",
    "wifi.open_join.enabled", "wifi.open_join.min_signal_pct",
    "wifi.open_join.blocklist",
    "notify.enabled", "advisor.enabled", "speedtest.enabled",
    "manual_pin", "ui.theme", "ui.wizard_completed",
    "netscan.enabled", "netscan.alert_new_devices",
    "netscan.scan_interval_seconds", "netscan.known", "netscan.ignore",
    "netscan.scan_wifi", "netscan.wifi_scan_interval_seconds",
    "netscan.router_scan", "netscan.router_scan_interval_seconds",
    "netscan.unknown_device_ttl_days", "netscan.max_unknown_devices",
}


def read_status() -> dict:
    try:
        with open(STATUS_PATH, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


# Hard ceiling on device records served to the Network tab — independent of
# linkkeeper.py's own live-registry eviction (netscan.unknown_device_ttl_days /
# max_unknown_devices); protects the dashboard even if that eviction is off,
# misconfigured, or status.json predates this upgrade.
NETWORK_DEVICE_CAP = 60


def cap_devices(devices: list) -> tuple:
    """Trim `devices` to at most NETWORK_DEVICE_CAP entries. Every 'known'
    (trusted, user-curated, small) device is always kept in full; unknown/seen
    devices fill whatever budget remains, in their existing priority order
    (new/online first — see linkkeeper._device_snapshot). Returns
    (capped_list, original_count) so the client can render an honest
    '+N more' note — same pattern as the sparkline's 'averaged from N samples'."""
    known = [d for d in devices if d.get("known")]
    unknown = [d for d in devices if not d.get("known")]
    budget = max(0, NETWORK_DEVICE_CAP - len(known))
    return known + unknown[:budget], len(devices)


def status_for_client() -> dict:
    """read_status() with the Network-tab device cap applied — the single seam
    both GET /api/status and the SSE stream go through, so neither path can
    bypass it."""
    snap = read_status()
    devices = snap.get("devices") or []
    capped, total = cap_devices(devices)
    if total > len(capped):
        snap = dict(snap, devices=capped, devices_total=total)
    return snap


def read_config() -> dict:
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def _atomic_write(cfg: dict) -> None:
    tmp = CONFIG_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(cfg, fh, indent=2)
    os.replace(tmp, CONFIG_PATH)


def set_pin(name):
    cfg = read_config()
    cfg["manual_pin"] = name
    _atomic_write(cfg)


def apply_settings(patch: dict) -> dict:
    """Apply a {dot.path: value} patch, restricted to ALLOWED_SETTINGS."""
    cfg = read_config()
    applied = {}
    for path, value in patch.items():
        if path not in ALLOWED_SETTINGS:
            continue
        parts = path.split(".")
        node = cfg
        for p in parts[:-1]:
            node = node.setdefault(p, {})
            if not isinstance(node, dict):
                break
        else:
            node[parts[-1]] = value
            applied[path] = value
    _atomic_write(cfg)
    return applied


# ---------------------------------------------------------------------------
# page (SPA shell). All dynamic/network text is escaped client-side via esc().
# ---------------------------------------------------------------------------

PAGE = r"""<!doctype html>
<html lang="en" class="dark"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>LinkKeeper</title>
<style>
  /* shadcn-admin token system — matches the Soluvae/fleet dashboards (see
     C:\Users\User\Desktop\Amit Launchers\Team Status\DESIGN.md). System font
     stack only, no CDN — keeps this dashboard zero-external-dependency /
     minimum-latency; Inter is used automatically if the OS already has it. */
  :root{
    --bg:oklch(12.9% .042 264.695); --card:oklch(14% .04 259.21); --card2:oklch(27.9% .041 260.031);
    --stroke:oklch(100% 0 0/.1); --txt:oklch(98.4% .003 247.858); --dim:oklch(70.4% .04 256.788);
    --up:oklch(72% .17 162); --down:oklch(70.4% .191 22.216); --warn:oklch(80% .16 85);
    --pri:oklch(92.9% .013 255.508); --pri-fg:oklch(20.8% .042 265.755);
    --radius:.625rem; --sidebar-w:240px; --sidebar-w-collapsed:48px; --header-h:56px;
  }
  html.light{
    --bg:oklch(100% 0 0); --card:oklch(100% 0 0); --card2:oklch(96.8% .007 247.896);
    --stroke:oklch(92.9% .013 255.508); --txt:oklch(12.9% .042 264.695); --dim:oklch(55.4% .046 257.417);
    --up:oklch(60% .15 162); --down:oklch(57.7% .245 27.325); --warn:oklch(70% .16 70);
    --pri:oklch(20.8% .042 265.755); --pri-fg:oklch(98.4% .003 247.858);
  }
  * { scrollbar-width: thin; scrollbar-color: color-mix(in oklch, var(--txt) 18%, transparent) transparent; }
  ::-webkit-scrollbar { width: 8px; height: 8px; }
  ::-webkit-scrollbar-track, ::-webkit-scrollbar-corner { background: transparent; }
  ::-webkit-scrollbar-thumb { background: color-mix(in oklch, var(--txt) 18%, transparent); border-radius: 8px;
    border: 2px solid transparent; background-clip: content-box; }
  ::-webkit-scrollbar-thumb:hover { background: color-mix(in oklch, var(--txt) 32%, transparent); background-clip: content-box; }
  *{box-sizing:border-box} html,body{height:100%}
  body{margin:0;overflow:hidden;font:14px/1.55 Inter,ui-sans-serif,system-ui,"Segoe UI",Roboto,Arial,sans-serif;
    color:var(--txt);background:var(--bg);-webkit-font-smoothing:antialiased}
  a{color:var(--pri);text-decoration:none}
  /* shell: sidebar + header + scrolling content, shadcn-admin layout */
  .app{display:flex;height:100vh}
  .sidebar{width:var(--sidebar-w);min-width:var(--sidebar-w);background:var(--bg);border-right:1px solid var(--stroke);
    display:flex;flex-direction:column;transition:width .15s ease,min-width .15s ease;overflow:hidden}
  .sidebar.collapsed{width:var(--sidebar-w-collapsed);min-width:var(--sidebar-w-collapsed)}
  .brand{display:flex;align-items:center;gap:10px;padding:12px 14px 8px;height:var(--header-h);white-space:nowrap}
  .brand .logo{width:30px;height:30px;border-radius:8px;background:var(--pri);color:var(--pri-fg);
    display:flex;align-items:center;justify-content:center;flex-shrink:0;font-size:15px}
  .brand .name{font-weight:600;font-size:14.5px;line-height:1.2}
  .sidebar.collapsed .brand .name{display:none}
  .sidebar.collapsed .brand{padding-left:9px}
  .nav{flex:1;overflow-y:auto;padding:6px 8px;display:flex;flex-direction:column;gap:2px}
  .nav-group{padding:12px 8px 4px;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.5px;color:var(--dim);white-space:nowrap}
  .sidebar.collapsed .nav-group{display:none}
  .nav-item{display:flex;align-items:center;gap:11px;padding:8px 10px;border-radius:calc(var(--radius) - 2px);
    font-size:14px;font-weight:500;white-space:nowrap;color:var(--dim)}
  .nav-item .ic{width:18px;text-align:center;flex-shrink:0}
  .nav-item:hover{background:var(--card2);color:var(--txt)}
  .nav-item.on{background:var(--card2);color:var(--txt)}
  .nav-item .badge{margin-left:auto;background:var(--warn);color:var(--pri-fg);border-radius:999px;font-size:11px;
    font-weight:700;min-width:18px;height:18px;padding:0 6px;display:none;align-items:center;justify-content:center}
  .sidebar.collapsed .nav-item{justify-content:center;padding:9px 0}
  .sidebar.collapsed .nav-item span:not(.ic),.sidebar.collapsed .nav-item .badge{display:none}
  .side-foot{margin-top:auto;color:var(--dim);font-size:11px;padding:10px 14px;white-space:nowrap}
  .sidebar.collapsed .side-foot{display:none}
  /* header */
  .main{flex:1;display:flex;flex-direction:column;min-width:0}
  .header{height:var(--header-h);display:flex;align-items:center;gap:12px;padding:0 16px;border-bottom:1px solid var(--stroke);
    background:var(--bg);flex-shrink:0}
  .icon-btn{background:none;border:none;border-radius:calc(var(--radius) - 2px);padding:7px;cursor:pointer;
    color:var(--txt);display:inline-flex;font-size:15px;line-height:1}
  .icon-btn:hover{background:var(--card2)}
  .hdr-status{display:flex;align-items:center;gap:8px;font-size:13px;color:var(--dim)}
  .hdr-status .dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}
  .content{flex:1;overflow-y:auto;padding:26px 30px 60px}
  .view-wrap{max-width:1000px;margin:0 auto}
  h1{font-size:21px;font-weight:650;margin:0 0 3px;letter-spacing:-.01em}
  .sub{color:var(--dim);font-size:13px;margin:0 0 22px}
  h2{font-size:12px;text-transform:uppercase;letter-spacing:.7px;color:var(--dim);margin:30px 0 12px}
  .grid{display:grid;gap:14px;grid-template-columns:repeat(auto-fit,minmax(min(230px,100%),1fr))}
  .card{background:var(--card);border:1px solid var(--stroke);border-radius:var(--radius);padding:16px 18px;position:relative}
  .card.primary{border-color:color-mix(in oklch, var(--pri) 55%, transparent);
    box-shadow:0 0 0 1px color-mix(in oklch, var(--pri) 22%, transparent) inset}
  .card.untrusted{border-color:color-mix(in oklch, var(--warn) 50%, transparent)}
  .badgep{position:absolute;top:14px;right:14px;font-size:11px;font-weight:700;color:var(--pri);
    border:1px solid color-mix(in oklch, var(--pri) 50%, transparent);border-radius:999px;padding:2px 9px}
  .name{font-size:16px;font-weight:600;display:flex;align-items:center;gap:9px}
  .dot{width:10px;height:10px;border-radius:50%;display:inline-block}
  .dot.up{background:var(--up);box-shadow:0 0 9px var(--up)} .dot.down{background:var(--down);box-shadow:0 0 9px var(--down)}
  .tag{font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:.5px;color:var(--dim);
    border:1px solid var(--stroke);border-radius:999px;padding:1px 7px;margin-left:auto}
  .tag.warn{color:var(--warn);border-color:color-mix(in oklch, var(--warn) 50%, transparent)}
  .alias{color:var(--dim);font-size:12px;margin:3px 0 13px;word-break:break-all}
  .stats{display:flex;gap:16px;margin-bottom:13px} .stat .v{font-size:19px;font-weight:650}
  .stat .k{color:var(--dim);font-size:10.5px;text-transform:uppercase;letter-spacing:.5px}
  button{font:inherit;color:var(--txt);background:var(--card2);border:1px solid var(--stroke);border-radius:calc(var(--radius) - 2px);
    padding:8px 13px;cursor:pointer;transition:.15s;font-weight:500}
  button:hover{background:color-mix(in oklch, var(--card2) 70%, var(--txt) 12%)}
  button.on,button.primary{background:var(--pri);border-color:var(--pri);color:var(--pri-fg)}
  button:disabled{opacity:.5;cursor:default}
  table{width:100%;border-collapse:collapse;font-size:13px}
  td,th{text-align:left;padding:8px 10px;border-bottom:1px solid var(--stroke)} th{color:var(--dim);font-weight:500}
  .empty{color:var(--dim)}
  h2.nsec{margin-top:34px}
  .wifi-list{display:flex;flex-direction:column;gap:2px}
  .wifi-row{display:flex;align-items:center;gap:12px;padding:9px 14px;background:var(--card);
    border:1px solid var(--stroke);border-radius:calc(var(--radius) - 2px)}
  .wifi-ssid{font-weight:500;flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .wifi-meta{color:var(--dim);font-size:12px;white-space:nowrap}
  .wifi-sig{color:var(--dim);font-size:12px;width:38px;text-align:right;font-variant-numeric:tabular-nums}
  .wifi-bars{display:inline-flex;align-items:flex-end;gap:2px;height:15px;width:20px}
  .wifi-bars i{width:3px;background:var(--stroke);border-radius:1px}
  .wifi-bars i:nth-child(1){height:35%} .wifi-bars i:nth-child(2){height:55%}
  .wifi-bars i:nth-child(3){height:78%} .wifi-bars i:nth-child(4){height:100%}
  .wifi-bars.b1 i:nth-child(-n+1),.wifi-bars.b2 i:nth-child(-n+2),
  .wifi-bars.b3 i:nth-child(-n+3),.wifi-bars.b4 i:nth-child(-n+4){background:var(--up)}
  .row{display:flex;align-items:center;justify-content:space-between;gap:14px;padding:14px 16px;background:var(--card);
    border:1px solid var(--stroke);border-radius:var(--radius);margin-bottom:10px}
  .row .lbl{font-weight:600} .row .desc{color:var(--dim);font-size:12.5px;margin-top:2px;max-width:560px}
  /* toggle */
  .sw{position:relative;width:44px;height:25px;flex:0 0 44px}
  .sw input{opacity:0;width:0;height:0} .sw .sl{position:absolute;inset:0;background:var(--card2);border:1px solid var(--stroke);
    border-radius:999px;transition:.2s;cursor:pointer} .sw .sl:before{content:"";position:absolute;width:19px;height:19px;left:2px;top:2px;
    background:var(--dim);border-radius:50%;transition:.2s} .sw input:checked+.sl{background:var(--pri);border-color:var(--pri)}
  .sw input:checked+.sl:before{transform:translateX(19px);background:var(--pri-fg)}
  input[type=number],input[type=text]{background:var(--card2);border:1px solid var(--stroke);color:var(--txt);
    border-radius:calc(var(--radius) - 3px);padding:7px 10px;font:inherit;width:90px}
  /* advice */
  .adv{background:var(--card);border:1px solid var(--stroke);border-radius:calc(var(--radius) + 2px);padding:11px 15px;margin-bottom:10px}
  .adv.crit{border-color:color-mix(in oklch, var(--down) 55%, transparent)}
  .adv.warn{border-color:color-mix(in oklch, var(--warn) 45%, transparent)}
  .adv summary{cursor:pointer;font-weight:600;list-style:none} .adv summary::-webkit-details-marker{display:none}
  .adv .why{color:var(--dim);font-size:12.5px;margin:8px 0 2px} .adv ol{margin:6px 0 4px 20px;font-size:13px}
  .adv .sev{margin-right:6px} .adv.crit .sev{color:var(--down)} .adv.warn .sev{color:var(--warn)} .adv.info .sev{color:var(--pri)}
  .hidden{display:none!important}
  /* wizard */
  .wz{position:fixed;inset:0;background:color-mix(in oklch, var(--bg) 72%, transparent);backdrop-filter:blur(6px);
    display:grid;place-items:center;z-index:50;padding:20px}
  .wzcard{width:min(600px,94vw);background:var(--card);border:1px solid var(--stroke);border-radius:calc(var(--radius) + 6px);
    padding:28px 30px;max-height:90vh;overflow:auto}
  .wzsteps{display:flex;gap:6px;margin-bottom:20px} .wzsteps i{height:4px;flex:1;border-radius:3px;background:var(--card2)}
  .wzsteps i.on{background:var(--pri)}
  .wzcard h3{font-size:20px;margin:0 0 6px} .wzcard p{color:var(--dim);margin:0 0 16px}
  .wzactions{display:flex;justify-content:space-between;margin-top:24px}
  .pill{display:inline-block;font-size:12px;color:var(--dim);border:1px solid var(--stroke);border-radius:999px;padding:2px 10px;margin:2px 4px 2px 0}
  .ok{color:var(--up)} .bad{color:var(--down)}
  @media(max-width:900px){ .sidebar{width:var(--sidebar-w-collapsed);min-width:var(--sidebar-w-collapsed)}
    .brand .name,.nav-group,.nav-item span:not(.ic),.nav-item .badge,.side-foot{display:none} .content{padding:20px} }
</style></head><body>
<div class="app">
<aside class="sidebar" id="sidebar">
  <div class="brand"><div class="logo">🔗</div><div class="name">LinkKeeper</div></div>
  <div class="nav" id="nav">
    <div class="nav-group">General</div>
    <a href="#dashboard" data-v="dashboard" class="nav-item on"><span class="ic">📊</span><span>Dashboard</span></a>
    <a href="#connections" data-v="connections" class="nav-item"><span class="ic">🔌</span><span>Connections</span></a>
    <a href="#network" data-v="network" class="nav-item"><span class="ic">📡</span><span>Network</span><span class="badge" id="netBadge">0</span></a>
    <div class="nav-group">Insight</div>
    <a href="#advisor" data-v="advisor" class="nav-item"><span class="ic">💡</span><span>Advisor</span><span class="badge" id="advBadge">0</span></a>
    <a href="#history" data-v="history" class="nav-item"><span class="ic">🗂️</span><span>History</span></a>
    <div class="nav-group">Settings</div>
    <a href="#settings" data-v="settings" class="nav-item"><span class="ic">⚙️</span><span>Settings</span></a>
  </div>
  <div class="side-foot">v1 · localhost only</div>
</aside>
<div class="main">
  <header class="header">
    <button class="icon-btn" id="toggle-left" title="Toggle sidebar">☰</button>
    <div class="hdr-status" id="hdrStatus"><span class="dot" style="background:var(--dim)"></span><span>…</span></div>
    <button class="icon-btn" id="theme-toggle" title="Toggle theme" style="margin-left:auto">
      <span id="theme-sun">☀️</span><span id="theme-moon" hidden>🌙</span></button>
  </header>
  <div class="content" id="content"><div class="view-wrap">
    <section id="v-dashboard"></section>
    <section id="v-connections" class="hidden"></section>
    <section id="v-network" class="hidden"></section>
    <section id="v-advisor" class="hidden"></section>
    <section id="v-history" class="hidden"></section>
    <section id="v-settings" class="hidden"></section>
  </div></div>
</div>
</div>
<div id="wizard" class="wz hidden"></div>

<script>
const $ = s => document.querySelector(s);
function esc(s){ return String(s==null?'':s).replace(/[&<>"']/g, c => (
  {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
async function api(path, body, method){
  const o = {method: method || (body?'POST':'GET')};
  if(body){ o.headers={'Content-Type':'application/json'}; o.body=JSON.stringify(body); }
  const r = await fetch(path,o);
  const txt = await r.text();
  if(!txt) return null;                       // empty body -> null (don't throw)
  try { return JSON.parse(txt); } catch(e){ return txt; }
}
let STATUS={}, CONFIG={};
function fmtAge(s){ return s<2?'just now':(s<60?Math.round(s)+'s ago':Math.round(s/60)+'m ago'); }

// ---- theme (shadcn: html.light / default dark), persisted ----
function applyTheme(t){
  document.documentElement.classList.toggle('light', t==='light');
  $('#theme-sun').hidden = (t==='light');
  $('#theme-moon').hidden = (t!=='light');
}
let THEME='dark';
try{ THEME = localStorage.getItem('lk_theme') || 'dark'; }catch(e){}
applyTheme(THEME);
$('#theme-toggle').addEventListener('click', () => {
  THEME = THEME==='light' ? 'dark' : 'light';
  try{ localStorage.setItem('lk_theme', THEME); }catch(e){}
  applyTheme(THEME);
});

// ---- sidebar collapse, persisted; auto-collapse when narrow ----
const SIDEBAR_NARROW_PX = 900;
function applySidebar(){
  const narrow = window.innerWidth > 0 && window.innerWidth < SIDEBAR_NARROW_PX;
  let collapsed = false;
  try{ collapsed = localStorage.getItem('lk_sidebar_collapsed')==='1'; }catch(e){}
  $('#sidebar').classList.toggle('collapsed', narrow || collapsed);
}
$('#toggle-left').addEventListener('click', () => {
  let collapsed = false;
  try{
    collapsed = localStorage.getItem('lk_sidebar_collapsed')==='1';
    localStorage.setItem('lk_sidebar_collapsed', collapsed?'0':'1');
  }catch(e){}
  applySidebar();
});
applySidebar();
window.addEventListener('resize', applySidebar);

// ---- router ----
const views=['dashboard','connections','network','advisor','history','settings'];
function route(){
  let v=(location.hash||'#dashboard').slice(1);
  if(!views.includes(v)) v='dashboard';
  views.forEach(x=>{ $('#v-'+x).classList.toggle('hidden', x!==v);
    document.querySelector('[data-v="'+x+'"]').classList.toggle('on', x===v); });
  render();
}
window.addEventListener('hashchange', route);

// ---- data: poll every 2.5s (always-on safety net) + SSE for sub-second updates ----
function updateHeaderStatus(){
  const age = STATUS.updated_epoch ? (Date.now()/1000 - STATUS.updated_epoch) : 999;
  const online = (STATUS.links||[]).some(l=>l.healthy);
  const hs=$('#hdrStatus'); const stale = age>15;
  hs.innerHTML = `<span class="dot" style="background:${online&&!stale?'var(--up)':'var(--down)'}"></span>`+
    `<span>${!STATUS.updated?'daemon offline':online?(stale?'stalled?':'online'):'OFFLINE'} · updated ${fmtAge(age)}</span>`;
}
function afterDataUpdate(){
  updateHeaderStatus();
  const adv=(STATUS.advice||[]).filter(a=>a.severity!=='info').length;
  const b=$('#advBadge'); b.style.display=adv?'flex':'none'; b.textContent=adv;
  const nnew=(STATUS.devices||[]).filter(d=>d.is_new).length;
  const nb=$('#netBadge'); if(nb){ nb.style.display=nnew?'flex':'none'; nb.textContent=nnew; }
  // first-run wizard
  if(CONFIG.ui && CONFIG.ui.wizard_completed===false && $('#wizard').classList.contains('hidden')) openWizard();
  render();
}
async function refresh(){
  try{ STATUS = await api('/api/status'); }catch(e){}
  try{ CONFIG = await api('/api/config'); }catch(e){}
  afterDataUpdate();
}
setInterval(refresh, 2500);            // fallback poll — keeps working even if SSE is unavailable
setInterval(updateHeaderStatus, 1000); // ticks "updated Xs ago" between data refreshes

function startStream(){
  if(typeof EventSource === 'undefined') return;   // no SSE support -> poll-only, silently
  try{
    const es = new EventSource('/api/stream');
    es.onmessage = e => {
      try{
        const d = JSON.parse(e.data);
        if(d.status) STATUS = d.status;
        if(d.config) CONFIG = d.config;
        afterDataUpdate();
      }catch(err){}
    };
    // no onerror handling needed — EventSource auto-reconnects, and the 2.5s
    // poll above keeps the UI correct regardless.
  }catch(e){}
}

// ---- renderers ----
function linkCard(l){
  const kind = l.wired ? 'wired' : 'Wi-Fi';
  const untrusted = l.trusted===false;
  return `<div class="card ${l.is_primary?'primary':''} ${untrusted?'untrusted':''}">
    ${l.is_primary?'<div class="badgep">PRIMARY</div>':''}
    <div class="name"><span class="dot ${l.healthy?'up':'down'}"></span>${esc(l.name)}
      <span class="tag ${untrusted?'warn':''}">${untrusted?'open · untrusted':kind}</span></div>
    <div class="alias">${esc(l.alias)} · ${esc(l.source_ip||'—')}</div>
    <div class="stats">
      <div class="stat"><div class="v">${l.latency_ms==null?'—':l.latency_ms}<span style=font-size:11px> ms</span></div><div class="k">latency</div></div>
      <div class="stat"><div class="v">${l.jitter_ms==null?'—':l.jitter_ms}</div><div class="k">jitter</div></div>
      <div class="stat"><div class="v">${l.loss_pct}<span style=font-size:11px>%</span></div><div class="k">loss</div></div>
    </div>
    <button class="${STATUS.manual_pin===l.name?'on':''}" data-pin="${esc(l.name)}" data-pinned="${STATUS.manual_pin===l.name}">
      ${STATUS.manual_pin===l.name?'Unpin':'Pin as primary'}</button>
  </div>`;
}
function render(){
  const v=(location.hash||'#dashboard').slice(1);
  if(v==='dashboard') renderDash();
  else if(v==='connections') renderConns();
  else if(v==='network') renderNetwork();
  else if(v==='advisor') renderAdvisor();
  else if(v==='history') renderHistory();
  else if(v==='settings') renderSettings();
}
function renderDash(){
  const links=STATUS.links||[]; const age=STATUS.updated_epoch?(Date.now()/1000-STATUS.updated_epoch):999;
  const hist=(STATUS.history||[]);
  $('#v-dashboard').innerHTML = `
    <h1>Dashboard</h1>
    <p class="sub">Primary: <b>${esc(STATUS.primary||'none')}</b> · updated ${fmtAge(age)}${STATUS.dry_run?' · <span style=color:var(--warn)>dry-run</span>':''}</p>
    <div class="grid">${links.length?links.map(linkCard).join(''):'<p class="empty">No connections yet — plug in a phone / enable a hotspot.</p>'}</div>
    <h2>Recent switches</h2>
    <table><thead><tr><th>Time</th><th>From</th><th>To</th><th>Latency</th></tr></thead><tbody>
      ${hist.length?hist.slice(0,8).map(h=>`<tr><td>${esc(h.time)}</td><td>${esc(h.from)}</td><td>${esc(h.to)}</td><td>${h.latency_ms} ms</td></tr>`).join(''):'<tr><td colspan=4 class=empty>none yet</td></tr>'}
    </tbody></table>`;
}
function renderConns(){
  const links=STATUS.links||[];
  $('#v-connections').innerHTML = `<h1>Connections</h1>
    <p class="sub">Every link LinkKeeper is monitoring right now, best first.</p>
    <div class="grid">${links.length?links.map(linkCard).join(''):'<p class="empty">Nothing connected.</p>'}</div>`;
}
function deviceCard(d){
  const knownMacs=((CONFIG.netscan&&CONFIG.netscan.known)||[]).map(k=>String(k.mac||'').toUpperCase());
  const known = d.known || knownMacs.includes(d.mac);   // reflect a fresh Trust before the next daemon scan
  const isnew = d.is_new && !known;
  const tag = known?'trusted' : (isnew?'NEW' : (d.randomized?'randomized':'seen'));
  const maker = d.vendor || '';
  const title = esc(d.name || maker || d.ip || d.mac);
  const makerLine = (maker && d.name) ? `${esc(maker)} · ` : '';   // avoid repeating maker when it is the title
  const btns = known
    ? `<button data-name="${esc(d.mac)}">Rename</button>`
    : `<button class="on" data-trust="${esc(d.mac)}">Trust</button><button data-name="${esc(d.mac)}">Name</button>`;
  return `<div class="card ${isnew?'untrusted':''}">
    <div class="name"><span class="dot ${d.online?'up':'down'}"></span>${title}
      <span class="tag ${isnew?'warn':''}">${tag}</span></div>
    <div class="alias">${makerLine}${esc(d.ip||'—')} · ${esc(d.mac)}${d.randomized?' · randomized MAC':''}</div>
    <div class="stats">
      <div class="stat"><div class="v">${d.online?'online':'offline'}</div><div class="k">status</div></div>
      <div class="stat"><div class="v">${maker?esc(maker):'—'}</div><div class="k">maker</div></div>
      <div class="stat"><div class="v">${d.state?esc(d.state):'—'}</div><div class="k">arp</div></div>
    </div>
    ${btns}</div>`;
}
function wifiRow(w){
  const sig=Math.max(0,Math.min(100,w.signal|0));
  const bars=sig>=75?4:sig>=50?3:sig>=25?2:1;
  const meta=[w.band||'',w.channel?('ch '+w.channel):'',w.secured?'🔒':'open'].filter(Boolean).join(' · ');
  return `<div class="wifi-row">
    <span class="wifi-bars b${bars}" title="${sig}%"><i></i><i></i><i></i><i></i></span>
    <span class="wifi-ssid">${esc(w.ssid)}</span>
    <span class="wifi-meta">${esc(meta)}</span>
    <span class="wifi-sig">${sig}%</span></div>`;
}
const PORT_NAMES={23:'Telnet',21:'FTP',7547:'TR-069',5555:'ADB',1900:'UPnP/SSDP',80:'HTTP admin'};
function renderNetwork(){
  const devs=STATUS.devices||[]; const ns=CONFIG.netscan||{};
  const nnew=devs.filter(d=>d.is_new).length, online=devs.filter(d=>d.online).length;
  const off = ns.enabled===false ? '<span style=color:var(--warn)>Scanning is OFF — enable it in Settings.</span> ' : '';
  const wifi=STATUS.wifi_nearby||[];
  let wifiSection='';
  if(ns.scan_wifi!==false){
    const body = wifi.length
      ? `<div class="wifi-list">${wifi.map(wifiRow).join('')}</div>`
      : '<p class="empty">No nearby Wi-Fi networks listed. Windows Location must be ON to scan — see the Advisor if it is off.</p>';
    wifiSection=`<h2 class="nsec">Wi-Fi Nearby${wifi.length?` · ${wifi.length}`:''}</h2>
      <p class="sub">Access points your Wi-Fi radio can see right now, strongest first.</p>${body}`;
  }
  let routerSection='';
  if(ns.router_scan!==false){
    const r=STATUS.router||{}; const findings=r.findings||[];
    const body = !r.gateway
      ? '<p class="empty">Router not identified yet.</p>'
      : findings.length
        ? `<div class="wifi-list">${findings.map(f=>`<div class="wifi-row">
             <span class="tag warn" style="flex:0 0 auto">exposed</span>
             <span class="wifi-ssid">${esc(PORT_NAMES[f.port]||('Port '+f.port))} (${f.port})</span>
             <span class="wifi-meta">${esc(f.host||r.gateway)}</span></div>`).join('')}</div>`
        : `<p class="empty">No risky ports found open on ${esc(r.gateway)}. ✓</p>`;
    routerSection=`<h2 class="nsec">Router${findings.length?` · ${findings.length} exposed`:''}</h2>
      <p class="sub">A reachability check on your gateway's known-risky ports — not a vulnerability scan.</p>${body}`;
  }
  const devTotal=STATUS.devices_total||devs.length;
  const capNote = devTotal>devs.length ? ` · showing ${devs.length} of ${devTotal} — see History for the rest` : '';
  $('#v-network').innerHTML = `<h1>Network</h1>
    <p class="sub">${off}${devs.length} device${devs.length===1?'':'s'} on your LAN${capNote} · ${online} online${nnew?` · <span style=color:var(--warn)>${nnew} new</span>`:''}. Trust the ones that are yours — you will be alerted when a new one appears.</p>
    <div class="grid">${devs.length?devs.map(deviceCard).join(''):'<p class="empty">No devices seen yet — the daemon scans every minute.</p>'}</div>
    ${wifiSection}
    ${routerSection}`;
}
function renderAdvisor(){
  const adv=STATUS.advice||[];
  $('#v-advisor').innerHTML = `<h1>Advisor</h1>
    <p class="sub">Why a connection dropped — and the exact fix, per device.</p>
    ${adv.length?adv.map(a=>`<details class="adv ${a.severity}" ${a.severity==='crit'?'open':''}>
      <summary><span class="sev">${a.severity==='crit'?'✖':a.severity==='warn'?'⚠':'ℹ'}</span>${esc(a.title)}</summary>
      <div class="why">${esc(a.why)}</div><ol>${a.steps.map(s=>`<li>${esc(s)}</li>`).join('')}</ol>
    </details>`).join(''):'<p class="empty">All good — no issues detected.</p>'}`;
}
function tsStr(ts){ try{ return new Date(ts*1000).toLocaleString(); }catch(e){ return ''; } }
function sparkline(res, label){
  const ser=((res&&res.points)||[]).filter(p=>p.latency_ms!=null);
  if(ser.length<2) return '';
  const W=600,H=80,pad=6, lat=ser.map(p=>p.latency_ms);
  const max=Math.max(...lat), min=Math.min(...lat), rng=(max-min)||1, step=(W-2*pad)/(ser.length-1);
  const pts=ser.map((p,i)=>`${(pad+i*step).toFixed(1)},${(H-pad-(p.latency_ms-min)/rng*(H-2*pad)).toFixed(1)}`).join(' ');
  const raw=(res&&res.raw_count)||ser.length, hrs=res&&res.window_hours;
  const capNote = raw>ser.length ? ` (averaged from ${raw} samples)` : '';
  return `<h2>Latency — ${esc(label)}${hrs?` · last ${hrs}h`:''}</h2>
    <div class="card" style="padding:8px">
      <svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" style="width:100%;height:80px;display:block">
        <polyline points="${pts}" fill="none" stroke="var(--up)" stroke-width="1.5"/></svg></div>
    <p class="sub">${ser.length} points${capNote} · ${min.toFixed(0)}–${max.toFixed(0)} ms</p>`;
}
let histData=null, histSeries=null;
let histOpen={devices:true, activity:false, switches:false, outages:false};
async function renderHistory(){
  const el=$('#v-history');
  if(!histData && !el.querySelector('h1')) el.innerHTML='<h1>History</h1><p class="empty">loading…</p>';
  histData=await api('/api/history');
  histSeries=STATUS.primary ? await api('/api/series/'+encodeURIComponent(STATUS.primary)) : null;
  drawHistory();
}
function toggleHist(k){
  if(k==='all-expand'){ for(const x in histOpen) histOpen[x]=true; }
  else if(k==='all-collapse'){ for(const x in histOpen) histOpen[x]=false; }
  else if(k in histOpen){ histOpen[k]=!histOpen[k]; }
  drawHistory();
}
function hsec(key,title,cnt,inner){
  const open=histOpen[key];
  return `<h2 data-hist="${key}" style="cursor:pointer;user-select:none">${open?'▾':'▸'} ${esc(title)} <span style="color:var(--dim);font-weight:400;font-size:13px">(${cnt})</span></h2>${open?inner:''}`;
}
function drawHistory(){
  const el=$('#v-history'), h=histData;
  if(!h){ el.innerHTML='<h1>History</h1><p class="empty">No records yet — the daemon fills this over time.</p>'; return; }
  const st=h.stats||{}, mb=((st.db_bytes||0)/1048576).toFixed(1), now=Date.now()/1000;
  const chart=STATUS.primary?sparkline(histSeries, STATUS.primary):'';
  const dv=(h.devices||[]).slice(0,50).map(d=>`<tr><td>${esc(d.name||d.mac)}</td><td>${esc(d.last_ip||'')}</td><td>${fmtAge(now-(d.last_seen||now))}</td><td>${esc(tsStr(d.first_seen))}</td><td>${d.trusted?'✓':''}${d.randomized?' 🎲':''}</td></tr>`).join('');
  const ev=(h.events||[]).slice(0,80).map(e=>`<tr><td>${esc(tsStr(e.ts))}</td><td>${esc(e.mac)}</td><td><span class="tag ${e.event==='new'?'warn':''}">${esc(e.event)}</span></td><td>${esc(e.ip||'')}</td></tr>`).join('');
  const sw=(h.switches||[]).slice(0,40).map(s=>`<tr><td>${esc(tsStr(s.ts))}</td><td>${esc(s.from_link)} → ${esc(s.to_link)}</td><td>${s.latency_ms==null?'':s.latency_ms+' ms'}</td><td>${esc(s.reason||'')}</td></tr>`).join('');
  const out=(h.outages||[]).slice(0,25).map(o=>`<tr><td>${esc(tsStr(o.started))}</td><td>${o.ended?esc(tsStr(o.ended)):'ongoing'}</td><td>${o.duration_s?Math.round(o.duration_s)+' s':''}</td></tr>`).join('');
  const tbl=(head,body,cols,empty)=>`<table><thead><tr>${head}</tr></thead><tbody>${body||`<tr><td colspan=${cols} class=empty>${empty}</td></tr>`}</tbody></table>`;
  el.innerHTML=`<h1>History</h1>
    <p class="sub">Local SQLite records · ${st.devices||0} devices · ${st.events||0} events · ${st.switches||0} switches · ${st.samples||0} samples · ${mb} MB · <span style="color:var(--up)">updated ${new Date().toLocaleTimeString()}</span></p>
    <div style="margin:6px 0 4px"><button class="sm" data-hist="all-expand">Expand all</button> <button class="sm" data-hist="all-collapse">Collapse all</button></div>
    ${chart}
    ${hsec('devices','Devices — last seen',(h.devices||[]).length, tbl('<th>Device</th><th>IP</th><th>Last seen</th><th>First seen</th><th>Trusted</th>', dv, 5, 'none yet'))}
    ${hsec('activity','Activity log',(h.events||[]).length, tbl('<th>When</th><th>Device</th><th>Event</th><th>IP</th>', ev, 4, 'none yet'))}
    ${hsec('switches','Connection switches',(h.switches||[]).length, tbl('<th>When</th><th>Change</th><th>Latency</th><th>Type</th>', sw, 4, 'none yet'))}
    ${hsec('outages','Outages',(h.outages||[]).length, tbl('<th>Started</th><th>Ended</th><th>Duration</th>', out, 3, 'none — never fully offline'))}`;
}
function toggleRow(label, desc, path, checked){
  return `<div class="row"><div><div class="lbl">${label}</div><div class="desc">${desc}</div></div>
    <label class="sw"><input type="checkbox" ${checked?'checked':''} data-cfg="${path}" data-kind="bool"><span class="sl"></span></label></div>`;
}
function numRow(label, desc, path, val){
  return `<div class="row"><div><div class="lbl">${label}</div><div class="desc">${desc}</div></div>
    <input type="number" value="${val}" data-cfg="${path}" data-kind="num"></div>`;
}
function renderSettings(){
  const c=CONFIG; if(!c.decision){ $('#v-settings').innerHTML='<h1>Settings</h1><p class=empty>loading…</p>'; return; }
  const oj=(c.wifi&&c.wifi.open_join)||{};
  $('#v-settings').innerHTML = `<h1>Settings</h1><p class="sub">Changes apply within a few seconds — the daemon reloads live.</p>
    <h2>Link selection</h2>
    ${toggleRow('Prefer wired links','USB tether / Ethernet beat Wi-Fi while they are clean.','decision.prefer_wired',c.decision.prefer_wired)}
    ${numRow('Switch-back dwell (s)','Wait this long before returning to a recovered link (anti-flap).','decision.switchback_dwell_seconds',c.decision.switchback_dwell_seconds)}
    <h2>Wi-Fi</h2>
    ${toggleRow('Auto-reconnect hotspots','Keep the Wi-Fi radio on the best saved hotspot.','wifi.autoreconnect',c.wifi.autoreconnect)}
    ${toggleRow('Join open Wi-Fi (last resort)','UNTRUSTED. Only when all your phones are down, and only if the network has real internet. Needs Windows Location on to scan.','wifi.open_join.enabled',oj.enabled)}
    ${numRow('Open Wi-Fi min signal (%)','Ignore weak open networks below this.','wifi.open_join.min_signal_pct',oj.min_signal_pct||55)}
    <h2>Notifications</h2>
    ${toggleRow('Desktop toasts','Pop a notification on every link switch / new issue.','notify.enabled',c.notify.enabled)}
    <h2>Network scan</h2>
    ${toggleRow('Scan the LAN for devices','Discover devices on your network and show them on the Network tab.','netscan.enabled',(c.netscan&&c.netscan.enabled)!==false)}
    ${toggleRow('Alert on new devices','Toast when an untrusted device joins that was not present at startup.','netscan.alert_new_devices',!(c.netscan)||c.netscan.alert_new_devices!==false)}
    ${numRow('Scan interval (s)','How often to sweep the network for devices.','netscan.scan_interval_seconds',(c.netscan&&c.netscan.scan_interval_seconds)||60)}
    ${toggleRow('List nearby Wi-Fi','Show access points your radio can see on the Network tab. Needs Windows Location on.','netscan.scan_wifi',!(c.netscan)||c.netscan.scan_wifi!==false)}
    ${numRow('Wi-Fi scan interval (s)','How often to refresh the nearby-Wi-Fi list (heavier than the LAN scan).','netscan.wifi_scan_interval_seconds',(c.netscan&&c.netscan.wifi_scan_interval_seconds)||300)}
    ${toggleRow('Check the router for exposed services','TCP-probe a handful of risky ports (telnet, FTP, UPnP...) on your gateway. Reachability check only, not a vulnerability scan.','netscan.router_scan',!(c.netscan)||c.netscan.router_scan!==false)}
    ${numRow('Router check interval (s)','How often to re-check the router.','netscan.router_scan_interval_seconds',(c.netscan&&c.netscan.router_scan_interval_seconds)||3600)}
    ${numRow('Forget unknown devices after (days)','Untrusted/unknown devices offline this long are dropped from the live Network view. History is never deleted — see the History tab. 0 = never.','netscan.unknown_device_ttl_days',(c.netscan&&c.netscan.unknown_device_ttl_days)??14)}
    ${numRow('Max unknown devices shown','Safety cap on how many untrusted/unknown devices are kept live at once (oldest-offline dropped first). Trusted devices are never capped. 0 = no cap.','netscan.max_unknown_devices',(c.netscan&&c.netscan.max_unknown_devices)??200)}
    <h2>Setup</h2>
    <div class="row"><div><div class="lbl">Re-run the setup wizard</div><div class="desc">Detect connections, apply Windows fixes, install autostart.</div></div>
      <button data-act="openwizard">Open wizard</button></div>`;
}

// ---- actions ----
async function pin(name, pinned){ await api('/api/pin',{name:pinned?null:name}); refresh(); }
async function setCfg(path, value){ await api('/api/config',{[path]:value}); await refresh(); }
function knownList(){ return ((CONFIG.netscan&&CONFIG.netscan.known)||[]).map(k=>Object.assign({},k)); }
async function trustDevice(mac){
  const dev=(STATUS.devices||[]).find(d=>d.mac===mac); const known=knownList();
  if(known.some(k=>String(k.mac||'').toUpperCase()===mac)) return;
  known.push({mac:mac, name:(dev&&dev.name)||'', trusted:true});
  await setCfg('netscan.known', known);
}
async function nameDevice(mac){
  const dev=(STATUS.devices||[]).find(d=>d.mac===mac);
  const nm=prompt('Name this device:', (dev&&dev.name)||''); if(nm===null) return;
  const known=knownList(); const i=known.findIndex(k=>String(k.mac||'').toUpperCase()===mac);
  if(i>=0){ known[i].name=nm; known[i].trusted=true; } else { known.push({mac:mac, name:nm, trusted:true}); }
  await setCfg('netscan.known', known);
}
async function runCommand(action, args){
  const {id}=await api('/api/command',{action,args:args||{}});
  for(let i=0;i<40;i++){ await new Promise(r=>setTimeout(r,500));
    const res=await api('/api/command/'+id); if(res){ return res; } }
  return {ok:false,output:'timed out'};
}

// ---- wizard ---- (var, not let: inline onclick handlers can't see top-level let/const)
var WZ=0;
function openWizard(){ WZ=0; $('#wizard').classList.remove('hidden'); drawWizard(); }
function closeWizard(){ $('#wizard').classList.add('hidden'); }
const WSTEPS=['welcome','connections','winfix','openwifi','autostart','done'];
function bars(){ return `<div class="wzsteps">${WSTEPS.map((_,i)=>`<i class="${i<=WZ?'on':''}"></i>`).join('')}</div>`; }
function nav(back,nextLabel){ return `<div class="wzactions">
  <button ${back?'':'disabled'} data-act="back">Back</button>
  <button class="primary" data-act="next">${nextLabel||'Next'}</button></div>`; }
function drawWizard(){
  const el=$('#wizard'); const step=WSTEPS[WZ]; let h=bars();
  if(step==='welcome'){
    h+=`<h3>Welcome to LinkKeeper</h3><p>It keeps this PC online by always using the best working connection — USB tether, Wi-Fi hotspot, Ethernet, even Bluetooth — and switching automatically when one fails. Let's set it up in a few steps.</p>`+nav(false,'Get started');
  } else if(step==='connections'){
    const links=STATUS.links||[];
    h+=`<h3>Your connections</h3><p>These are the links LinkKeeper sees right now. Plug in phones / enable hotspots to add more — they're detected automatically.</p>
      <div>${links.length?links.map(l=>`<span class="pill">${l.healthy?'🟢':'🔴'} ${esc(l.name)} · ${l.wired?'wired':'Wi-Fi'}</span>`).join(''):'<span class="empty">none detected yet</span>'}</div>`+nav(true);
  } else if(step==='winfix'){
    const issues=(STATUS.advice||[]).filter(a=>a.id&&a.id.startsWith('win:'));
    h+=`<h3>Windows keep-alive fixes</h3><p>Windows can silently suspend USB tethers and break them after shutdown. LinkKeeper detected:</p>
      <div id="wzfix">${issues.length?issues.map(a=>`<div class="pill bad">⚠ ${esc(a.title.replace('Windows: ',''))}</div>`).join(''):'<span class="ok">✓ none — already optimized</span>'}</div>
      <div class="wzactions"><button data-act="back">Back</button>
      ${issues.length?`<button class="primary" id="wzApply" data-act="apply">Apply all fixes</button>`:`<button class="primary" data-act="next">Next</button>`}</div>`;
  } else if(step==='openwifi'){
    const oj=(CONFIG.wifi&&CONFIG.wifi.open_join)||{};
    h+=`<h3>Open Wi-Fi (optional)</h3><p>As a <b>last resort</b> — only when all your phones are down — LinkKeeper can join a password-free Wi-Fi network that has real internet. It's treated as untrusted and dropped the instant a phone is back.</p>
      ${toggleRow('Auto-join open Wi-Fi','Off by default. Needs Windows Location on to scan for networks.','wifi.open_join.enabled',oj.enabled)}
      ${oj.enabled?`<div class="row"><div><div class="lbl">Windows Location</div><div class="desc">Required to scan for new networks.</div></div>
        <button data-act="openloc">Open Location settings</button></div>`:''}
      `+nav(true);
  } else if(step==='autostart'){
    h+=`<h3>Start automatically</h3><p>Install LinkKeeper as a background task so it runs (elevated) every time you log in.</p>
      <div id="wzTaskMsg" class="desc"></div>
      <div class="wzactions"><button data-act="back">Back</button>
      <button class="primary" id="wzInstall" data-act="install">Install autostart</button></div>`;
  } else if(step==='done'){
    h+=`<h3>All set 🎉</h3><p>LinkKeeper is now watching your connections and will keep this PC online automatically. You can tweak anything under Settings.</p>
      <div class="wzactions"><span></span><button class="primary" data-act="finish">Finish</button></div>`;
  }
  el.innerHTML=`<div class="wzcard">${h}</div>`;
}
// One delegated click/change handler for the whole app — real addEventListener,
// so it fires reliably (inline onclick can't see top-level let/const and was
// unreliable under some embedded browsers).
function doAct(a){
  if(a==='next'){ WZ++; drawWizard(); }
  else if(a==='back'){ WZ--; drawWizard(); }
  else if(a==='apply') wzApplyFixes();
  else if(a==='install') wzInstall();
  else if(a==='finish') finishWizard();
  else if(a==='openloc') runCommand('enable_location_help');
  else if(a==='openwizard'){ setCfg('ui.wizard_completed',false); openWizard(); }
}
document.addEventListener('click', e=>{
  const p=e.target.closest('[data-pin]'); if(p){ pin(p.dataset.pin, p.dataset.pinned==='true'); return; }
  const t=e.target.closest('[data-trust]'); if(t){ trustDevice(t.dataset.trust); return; }
  const nm=e.target.closest('[data-name]'); if(nm){ nameDevice(nm.dataset.name); return; }
  const hs=e.target.closest('[data-hist]'); if(hs){ toggleHist(hs.dataset.hist); return; }
  const a=e.target.closest('[data-act]'); if(a){ e.preventDefault(); doAct(a.dataset.act); }
});
document.addEventListener('change', e=>{
  const c=e.target.closest('[data-cfg]'); if(!c) return;
  setCfg(c.dataset.cfg, c.dataset.kind==='bool'? c.checked : (parseInt(c.value)||0));
});
async function wzApplyFixes(){ const b=$('#wzApply'); b.disabled=true; b.textContent='Applying… (accept UAC if asked)';
  const r=await runCommand('apply_windows_fixes'); b.textContent=r.ok?'✓ Applied':'Failed'; setTimeout(()=>{WZ++;drawWizard();},700); }
async function wzInstall(){ const b=$('#wzInstall'); b.disabled=true; b.textContent='Installing…';
  const r=await runCommand('install_task'); $('#wzTaskMsg').innerHTML=r.ok?'<span class=ok>✓ '+esc(r.output)+'</span>':'<span class=bad>'+esc(r.output)+'</span>';
  b.textContent=r.ok?'✓ Installed':'Retry'; b.disabled=false; if(r.ok) setTimeout(()=>{WZ++;drawWizard();},800); }
async function finishWizard(){ await api('/api/config',{'ui.wizard_completed':true}); closeWizard(); refresh(); }

route(); refresh(); startStream();
</script></body></html>"""


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json"):
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")   # always serve fresh (local dashboard)
        self.end_headers()
        self.wfile.write(data)

    def _local_only(self) -> bool:
        # DNS-rebind / CSRF guard: only accept POSTs whose Host & Origin are local
        host = (self.headers.get("Host") or "").split(":")[0].lower()
        if host not in ("127.0.0.1", "localhost", "::1", ""):
            return False
        origin = self.headers.get("Origin")
        if origin and not re.match(r"^https?://(127\.0\.0\.1|localhost|\[::1\])(:\d+)?$", origin):
            return False
        return True

    def do_GET(self):
        path = self.path.split("?", 1)[0]          # ignore query string (cache-busters etc.)
        if path == "/" or path.startswith("/index"):
            self._send(200, PAGE, "text/html; charset=utf-8")
        elif path.startswith("/api/status"):
            self._send(200, json.dumps(status_for_client()))
        elif path.startswith("/api/config"):
            self._send(200, json.dumps(read_config()))
        elif path.startswith("/api/history"):
            self._send(200, json.dumps({
                "devices": store.all_devices(300),
                "events": store.recent_events(100),  # client renders at most 80 — small buffer, not 120 of overfetch
                "switches": store.switches(100),
                "outages": store.outage_log(50),
                "stats": store.stats(),
            }))
        elif path.startswith("/api/series/"):
            link = unquote(path.split("/api/series/", 1)[1])
            # Bounded by TIME (recent trend), not raw row count — a row-count cap
            # silently shrinks/grows with the probe interval. Then downsampled to
            # a fixed point budget so the chart never plots more points than it
            # has pixels for (was drawing every raw sample, which just painted
            # over itself and looked like solid fill at a few thousand rows).
            window_hours = 6
            raw = store.link_series(link, since=time.time() - window_hours * 3600, limit=20000)
            points = store.downsample_series(raw, buckets=180)
            self._send(200, json.dumps({
                "points": points, "raw_count": len(raw), "window_hours": window_hours,
            }))
        elif path.startswith("/api/device/"):
            mac = unquote(path.split("/api/device/", 1)[1])
            self._send(200, json.dumps(store.device_timeline(mac)))
        elif path.startswith("/api/command/"):
            cid = path.rsplit("/", 1)[-1]
            # Always valid JSON: `null` while pending (a 204 with an empty body
            # made the browser's r.json() throw and hung the poll loop).
            self._send(200, json.dumps(commandbus.result(cid)))
        elif path.startswith("/api/stream"):
            self._stream_status()
        else:
            self._send(404, json.dumps({"error": "not found"}))

    def _stream_status(self):
        """Server-Sent Events: push a fresh {status, config} snapshot the moment
        status.json or config.json changes on disk (the daemon writes both
        atomically), instead of making the browser poll. Runs on this
        connection's own thread (ThreadingHTTPServer) so it never blocks other
        requests; exits cleanly the instant the browser tab closes or navigates
        away (write fails -> caught below), which is when EventSource drops the
        connection. Client falls back to (and always keeps) its 2.5s poll, so a
        client without EventSource support, or a stream that silently stalls,
        still stays correct — this only shaves the typical latency down."""
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "keep-alive")
            self.end_headers()
        except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError, OSError):
            return
        last_status_mtime = last_config_mtime = None
        last_sent = 0.0
        try:
            while True:
                try:
                    smtime = os.path.getmtime(STATUS_PATH)
                except OSError:
                    smtime = None
                try:
                    cmtime = os.path.getmtime(CONFIG_PATH)
                except OSError:
                    cmtime = None
                changed = smtime != last_status_mtime or cmtime != last_config_mtime
                now = time.time()
                if changed:
                    last_status_mtime, last_config_mtime = smtime, cmtime
                    payload = json.dumps({"status": status_for_client(), "config": read_config()})
                    self.wfile.write(f"data: {payload}\n\n".encode("utf-8"))
                    self.wfile.flush()
                    last_sent = now
                elif now - last_sent > 15:            # heartbeat keeps idle connections alive
                    self.wfile.write(b": heartbeat\n\n")
                    self.wfile.flush()
                    last_sent = now
                time.sleep(0.3)
        except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError, OSError):
            pass  # client disconnected — normal, not an error

    def do_POST(self):
        if not self._local_only():
            self._send(403, json.dumps({"error": "local requests only"}))
            return
        try:
            length = int(self.headers.get("Content-Length", 0))
        except (TypeError, ValueError):
            length = 0
        if length < 0 or length > 1_000_000:
            self._send(413, json.dumps({"error": "too large"}))
            return
        raw = self.rfile.read(length) if length else b"{}"
        try:
            payload = json.loads(raw or b"{}")
        except ValueError:
            payload = {}
        try:
            if self.path.startswith("/api/pin"):
                set_pin(payload.get("name"))
                self._send(200, json.dumps({"ok": True, "manual_pin": payload.get("name")}))
            elif self.path.startswith("/api/config"):
                applied = apply_settings(payload if isinstance(payload, dict) else {})
                self._send(200, json.dumps({"ok": True, "applied": applied}))
            elif self.path.startswith("/api/command"):
                cid = commandbus.submit(payload.get("action", ""), payload.get("args"))
                self._send(200, json.dumps({"id": cid}))
            else:
                self._send(404, json.dumps({"error": "not found"}))
        except ValueError as exc:
            self._send(400, json.dumps({"error": str(exc)}))

    def log_message(self, *a):
        pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=PORT)
    ap.add_argument("--host", default="127.0.0.1")
    args = ap.parse_args()
    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"LinkKeeper dashboard on http://{args.host}:{args.port}  (Ctrl+C to stop)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
