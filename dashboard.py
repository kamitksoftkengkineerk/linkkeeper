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
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import commandbus

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
}


def read_status() -> dict:
    try:
        with open(STATUS_PATH, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


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
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>LinkKeeper</title>
<style>
  /* Warm Rail palette — see C:\Users\User\Desktop\Amit Launchers\Team Status\DESIGN.md.
     Dark-only per spec (the old light-mode variant is dropped); the blue radial
     glow is dropped too — spec rule is "no cool blue-greys anywhere". */
  :root{ --bg:#141413; --bg2:#1c1b19; --card:rgba(255,255,255,.05); --card2:rgba(255,255,255,.08);
    --stroke:#30302e; --txt:#f2efe9; --dim:#b3ada2; --up:#8fae6c; --down:#c9584c;
    --pri:#cc785c; --warn:#d4a83a; --acc:#cc785c; }
  * { scrollbar-width: thin; scrollbar-color: rgba(255,255,255,0.14) transparent; }
  ::-webkit-scrollbar { width: 8px; height: 8px; }
  ::-webkit-scrollbar-track, ::-webkit-scrollbar-corner { background: transparent; }
  ::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.14); border-radius: 8px;
    border: 2px solid transparent; background-clip: content-box; }
  ::-webkit-scrollbar-thumb:hover { background: rgba(255,255,255,0.30); background-clip: content-box; }
  *{box-sizing:border-box} html,body{height:100%}
  body{margin:0;font:14.5px/1.55 -apple-system,Segoe UI,Roboto,system-ui,sans-serif;color:var(--txt);
    background:var(--bg);display:flex;min-height:100vh}
  a{color:var(--pri);text-decoration:none}
  /* sidebar */
  .side{width:230px;flex:0 0 230px;background:linear-gradient(180deg,var(--bg2),transparent);
    border-right:1px solid var(--stroke);padding:20px 14px;display:flex;flex-direction:column;gap:4px;position:sticky;top:0;height:100vh}
  .brand{display:flex;align-items:center;gap:10px;font-weight:700;font-size:17px;padding:6px 10px 14px}
  .brand .logo{width:26px;height:26px;border-radius:8px;background:linear-gradient(135deg,var(--pri),var(--acc));
    display:grid;place-items:center;font-size:15px}
  .status{display:flex;align-items:center;gap:8px;font-size:12px;color:var(--dim);padding:4px 12px 14px}
  .status .dot{width:9px;height:9px;border-radius:50%}
  .nav{display:flex;flex-direction:column;gap:2px}
  .nav a{display:flex;align-items:center;gap:11px;padding:9px 12px;border-radius:10px;color:var(--dim);font-weight:500}
  .nav a .ic{width:18px;text-align:center}
  .nav a:hover{background:var(--card);color:var(--txt)}
  .nav a.on{background:var(--card2);color:var(--txt)}
  .nav a .badge{margin-left:auto;background:var(--warn);color:#1a1200;border-radius:20px;font-size:11px;font-weight:700;padding:0 7px;display:none}
  .side .foot{margin-top:auto;color:var(--dim);font-size:11px;padding:10px 12px}
  /* main */
  .main{flex:1;min-width:0;padding:28px 34px 60px;max-width:1000px}
  h1{font-size:22px;font-weight:650;margin:0 0 3px}
  .sub{color:var(--dim);font-size:13px;margin:0 0 22px}
  h2{font-size:12px;text-transform:uppercase;letter-spacing:.7px;color:var(--dim);margin:30px 0 12px}
  .grid{display:grid;gap:14px;grid-template-columns:repeat(auto-fit,minmax(min(230px,100%),1fr))}
  .card{background:var(--card);border:1px solid var(--stroke);border-radius:16px;padding:16px 18px;position:relative}
  .card.primary{border-color:rgba(204,120,92,/*--pri*/ .55);box-shadow:0 0 0 1px rgba(204,120,92,/*--pri*/ .22) inset}
  .card.untrusted{border-color:rgba(212,168,58,/*--warn*/ .5)}
  .badgep{position:absolute;top:14px;right:14px;font-size:11px;font-weight:700;color:var(--pri);
    border:1px solid rgba(204,120,92,/*--pri*/ .5);border-radius:20px;padding:2px 9px}
  .name{font-size:16px;font-weight:600;display:flex;align-items:center;gap:9px}
  .dot{width:10px;height:10px;border-radius:50%;display:inline-block}
  .dot.up{background:var(--up);box-shadow:0 0 9px var(--up)} .dot.down{background:var(--down);box-shadow:0 0 9px var(--down)}
  .tag{font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:.5px;color:var(--dim);
    border:1px solid var(--stroke);border-radius:20px;padding:1px 7px;margin-left:auto}
  .tag.warn{color:var(--warn);border-color:rgba(212,168,58,/*--warn*/ .5)}
  .alias{color:var(--dim);font-size:12px;margin:3px 0 13px;word-break:break-all}
  .stats{display:flex;gap:16px;margin-bottom:13px} .stat .v{font-size:19px;font-weight:650}
  .stat .k{color:var(--dim);font-size:10.5px;text-transform:uppercase;letter-spacing:.5px}
  button{font:inherit;color:var(--txt);background:var(--card2);border:1px solid var(--stroke);border-radius:10px;
    padding:8px 13px;cursor:pointer;transition:.15s;font-weight:500}
  button:hover{background:rgba(255,255,255,.16)} button.on{background:var(--pri);border-color:var(--pri);color:#241812}
  button.primary{background:var(--pri);border-color:var(--pri);color:#241812}
  button:disabled{opacity:.5;cursor:default}
  table{width:100%;border-collapse:collapse;font-size:13px}
  td,th{text-align:left;padding:8px 10px;border-bottom:1px solid var(--stroke)} th{color:var(--dim);font-weight:500}
  .empty{color:var(--dim)}
  .row{display:flex;align-items:center;justify-content:space-between;gap:14px;padding:14px 16px;background:var(--card);
    border:1px solid var(--stroke);border-radius:14px;margin-bottom:10px}
  .row .lbl{font-weight:600} .row .desc{color:var(--dim);font-size:12.5px;margin-top:2px;max-width:560px}
  /* toggle */
  .sw{position:relative;width:44px;height:25px;flex:0 0 44px}
  .sw input{opacity:0;width:0;height:0} .sw .sl{position:absolute;inset:0;background:var(--card2);border:1px solid var(--stroke);
    border-radius:20px;transition:.2s;cursor:pointer} .sw .sl:before{content:"";position:absolute;width:19px;height:19px;left:2px;top:2px;
    background:var(--dim);border-radius:50%;transition:.2s} .sw input:checked+.sl{background:var(--pri);border-color:var(--pri)}
  .sw input:checked+.sl:before{transform:translateX(19px);background:#fff}
  input[type=number],input[type=text]{background:var(--card2);border:1px solid var(--stroke);color:var(--txt);
    border-radius:9px;padding:7px 10px;font:inherit;width:90px}
  /* advice */
  .adv{background:var(--card);border:1px solid var(--stroke);border-radius:13px;padding:11px 15px;margin-bottom:10px}
  .adv.crit{border-color:rgba(201,88,76,/*--down*/ .55)} .adv.warn{border-color:rgba(212,168,58,/*--warn*/ .45)}
  .adv summary{cursor:pointer;font-weight:600;list-style:none} .adv summary::-webkit-details-marker{display:none}
  .adv .why{color:var(--dim);font-size:12.5px;margin:8px 0 2px} .adv ol{margin:6px 0 4px 20px;font-size:13px}
  .adv .sev{margin-right:6px} .adv.crit .sev{color:var(--down)} .adv.warn .sev{color:var(--warn)} .adv.info .sev{color:var(--pri)}
  .hidden{display:none!important}
  /* wizard */
  .wz{position:fixed;inset:0;background:rgba(6,9,15,.72);backdrop-filter:blur(6px);display:grid;place-items:center;z-index:50;padding:20px}
  .wzcard{width:min(600px,94vw);background:var(--bg2);border:1px solid var(--stroke);border-radius:20px;padding:28px 30px;max-height:90vh;overflow:auto}
  .wzsteps{display:flex;gap:6px;margin-bottom:20px} .wzsteps i{height:4px;flex:1;border-radius:3px;background:var(--card2)}
  .wzsteps i.on{background:var(--pri)}
  .wzcard h3{font-size:20px;margin:0 0 6px} .wzcard p{color:var(--dim);margin:0 0 16px}
  .wzactions{display:flex;justify-content:space-between;margin-top:24px}
  .pill{display:inline-block;font-size:12px;color:var(--dim);border:1px solid var(--stroke);border-radius:20px;padding:2px 10px;margin:2px 4px 2px 0}
  .ok{color:var(--up)} .bad{color:var(--down)}
  @media(max-width:720px){ .side{width:64px;flex-basis:64px} .brand span,.nav a span,.status,.side .foot{display:none} .main{padding:20px} }
</style></head><body>
<nav class="side">
  <div class="brand"><span class="logo">🔗</span><span>LinkKeeper</span></div>
  <div class="status" id="sideStatus"><span class="dot" style="background:var(--dim)"></span><span>…</span></div>
  <div class="nav" id="nav">
    <a href="#dashboard" data-v="dashboard" class="on"><span class="ic">📊</span><span>Dashboard</span></a>
    <a href="#connections" data-v="connections"><span class="ic">🔌</span><span>Connections</span></a>
    <a href="#advisor" data-v="advisor"><span class="ic">💡</span><span>Advisor</span><span class="badge" id="advBadge">0</span></a>
    <a href="#settings" data-v="settings"><span class="ic">⚙️</span><span>Settings</span></a>
  </div>
  <div class="foot">v1 · localhost only</div>
</nav>
<main class="main">
  <section id="v-dashboard"></section>
  <section id="v-connections" class="hidden"></section>
  <section id="v-advisor" class="hidden"></section>
  <section id="v-settings" class="hidden"></section>
</main>
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

// ---- router ----
const views=['dashboard','connections','advisor','settings'];
function route(){
  let v=(location.hash||'#dashboard').slice(1);
  if(!views.includes(v)) v='dashboard';
  views.forEach(x=>{ $('#v-'+x).classList.toggle('hidden', x!==v);
    document.querySelector('[data-v="'+x+'"]').classList.toggle('on', x===v); });
  render();
}
window.addEventListener('hashchange', route);

// ---- data ----
async function refresh(){
  try{ STATUS = await api('/api/status'); }catch(e){}
  try{ CONFIG = await api('/api/config'); }catch(e){}
  // sidebar status
  const age = STATUS.updated_epoch ? (Date.now()/1000 - STATUS.updated_epoch) : 999;
  const online = (STATUS.links||[]).some(l=>l.healthy);
  const sd=$('#sideStatus'); const stale = age>15;
  sd.innerHTML = `<span class="dot" style="background:${online&&!stale?'var(--up)':'var(--down)'}"></span>`+
    `<span>${!STATUS.updated?'daemon offline':online?(stale?'stalled?':'online'):'OFFLINE'}</span>`;
  const adv=(STATUS.advice||[]).filter(a=>a.severity!=='info').length;
  const b=$('#advBadge'); b.style.display=adv?'inline-block':'none'; b.textContent=adv;
  // first-run wizard
  if(CONFIG.ui && CONFIG.ui.wizard_completed===false && $('#wizard').classList.contains('hidden')) openWizard();
  render();
}
setInterval(refresh, 2500);

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
  else if(v==='advisor') renderAdvisor();
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
function renderAdvisor(){
  const adv=STATUS.advice||[];
  $('#v-advisor').innerHTML = `<h1>Advisor</h1>
    <p class="sub">Why a connection dropped — and the exact fix, per device.</p>
    ${adv.length?adv.map(a=>`<details class="adv ${a.severity}" ${a.severity==='crit'?'open':''}>
      <summary><span class="sev">${a.severity==='crit'?'✖':a.severity==='warn'?'⚠':'ℹ'}</span>${esc(a.title)}</summary>
      <div class="why">${esc(a.why)}</div><ol>${a.steps.map(s=>`<li>${esc(s)}</li>`).join('')}</ol>
    </details>`).join(''):'<p class="empty">All good — no issues detected.</p>'}`;
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
    <h2>Setup</h2>
    <div class="row"><div><div class="lbl">Re-run the setup wizard</div><div class="desc">Detect connections, apply Windows fixes, install autostart.</div></div>
      <button data-act="openwizard">Open wizard</button></div>`;
}

// ---- actions ----
async function pin(name, pinned){ await api('/api/pin',{name:pinned?null:name}); refresh(); }
async function setCfg(path, value){ await api('/api/config',{[path]:value}); await refresh(); }
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

route(); refresh();
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
        if self.path == "/" or self.path.startswith("/index"):
            self._send(200, PAGE, "text/html; charset=utf-8")
        elif self.path.startswith("/api/status"):
            self._send(200, json.dumps(read_status()))
        elif self.path.startswith("/api/config"):
            self._send(200, json.dumps(read_config()))
        elif self.path.startswith("/api/command/"):
            cid = self.path.rsplit("/", 1)[-1]
            # Always valid JSON: `null` while pending (a 204 with an empty body
            # made the browser's r.json() throw and hung the poll loop).
            self._send(200, json.dumps(commandbus.result(cid)))
        else:
            self._send(404, json.dumps({"error": "not found"}))

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
