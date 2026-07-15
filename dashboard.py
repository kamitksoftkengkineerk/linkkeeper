"""
dashboard.py — LinkKeeper glass dashboard (stdlib only) on http://127.0.0.1:8901

Reads the daemon's logs/status.json snapshot and renders a live view of both
links, the current primary, and switch history. Lets you pin/unpin a link
(writes config.json manual_pin; the daemon picks it up on its next cycle).

Run:  python dashboard.py       (add --port to override 8901)
"""

from __future__ import annotations

import argparse
import json
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(HERE, "config.json")
STATUS_PATH = os.path.join(HERE, "logs", "status.json")
PORT = 8901


def read_status() -> dict:
    try:
        with open(STATUS_PATH, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def set_pin(name):
    with open(CONFIG_PATH, "r", encoding="utf-8") as fh:
        cfg = json.load(fh)
    cfg["manual_pin"] = name
    # atomic write (tmp + os.replace) so the daemon, which re-reads config.json
    # every 4s, never observes a truncated/half-written file
    tmp = CONFIG_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(cfg, fh, indent=2)
    os.replace(tmp, CONFIG_PATH)


PAGE = r"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>LinkKeeper</title>
<style>
  :root{ --bg:#0b0f17; --card:rgba(255,255,255,.06); --stroke:rgba(255,255,255,.12);
         --txt:#e7ecf5; --dim:#8b98ad; --up:#39d98a; --down:#ff5c6c; --pri:#4c9ffe;
         --warn:#ffb020; }
  *{box-sizing:border-box}
  body{margin:0;font:15px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;color:var(--txt);
       background:radial-gradient(1200px 700px at 70% -10%,#17233b 0,var(--bg) 55%);min-height:100vh}
  .wrap{max-width:840px;margin:0 auto;padding:28px 20px 60px}
  h1{font-size:22px;font-weight:650;margin:0 0 2px;letter-spacing:.2px}
  .sub{color:var(--dim);font-size:13px;margin-bottom:22px}
  .stale{color:var(--warn)}
  .grid{display:grid;gap:16px;grid-template-columns:repeat(auto-fit,minmax(240px,1fr))}
  .card{background:var(--card);border:1px solid var(--stroke);border-radius:16px;padding:18px;
        backdrop-filter:blur(12px);position:relative;overflow:hidden}
  .card.primary{border-color:rgba(76,159,254,.6);box-shadow:0 0 0 1px rgba(76,159,254,.25) inset}
  .badge{position:absolute;top:14px;right:14px;font-size:11px;font-weight:600;color:var(--pri);
         border:1px solid rgba(76,159,254,.5);border-radius:20px;padding:2px 9px}
  .name{font-size:17px;font-weight:600;display:flex;align-items:center;gap:9px}
  .kind{font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:.5px;color:var(--dim);
        border:1px solid var(--stroke);border-radius:20px;padding:1px 7px;margin-left:auto}
  .dot{width:10px;height:10px;border-radius:50%;display:inline-block}
  .dot.up{background:var(--up);box-shadow:0 0 10px var(--up)}
  .dot.down{background:var(--down);box-shadow:0 0 10px var(--down)}
  .alias{color:var(--dim);font-size:12px;margin:2px 0 14px}
  .stats{display:flex;gap:18px;margin-bottom:14px}
  .stat .v{font-size:20px;font-weight:650}
  .stat .k{color:var(--dim);font-size:11px;text-transform:uppercase;letter-spacing:.5px}
  button{font:inherit;color:var(--txt);background:rgba(255,255,255,.08);border:1px solid var(--stroke);
         border-radius:10px;padding:7px 12px;cursor:pointer;transition:.15s}
  button:hover{background:rgba(255,255,255,.16)}
  button.on{background:var(--pri);border-color:var(--pri);color:#04101f}
  h2{font-size:13px;text-transform:uppercase;letter-spacing:.6px;color:var(--dim);margin:34px 0 12px}
  table{width:100%;border-collapse:collapse;font-size:13px}
  td,th{text-align:left;padding:8px 10px;border-bottom:1px solid rgba(255,255,255,.07)}
  th{color:var(--dim);font-weight:500}
  .empty{color:var(--dim)}
  .adv{background:var(--card);border:1px solid var(--stroke);border-radius:12px;padding:10px 14px;margin-bottom:10px}
  .adv.crit{border-color:rgba(255,92,108,.55)}
  .adv.warn{border-color:rgba(255,176,32,.45)}
  .adv summary{cursor:pointer;font-weight:600;font-size:14px;list-style:none}
  .adv summary::-webkit-details-marker{display:none}
  .adv .sev{margin-right:6px}
  .adv.crit .sev{color:var(--down)} .adv.warn .sev{color:var(--warn)} .adv.info .sev{color:var(--pri)}
  .adv .why{color:var(--dim);font-size:12.5px;margin:8px 0 2px}
  .adv ol{margin:6px 0 4px 20px;padding:0;font-size:13px}
  .adv li{margin:3px 0}
</style></head><body>
<div class="wrap">
  <h1>LinkKeeper</h1>
  <div class="sub" id="sub">connecting…</div>
  <div class="grid" id="grid"></div>
  <div id="adviceWrap" style="display:none">
    <h2>Advice — keep every connection alive</h2>
    <div id="advice"></div>
  </div>
  <h2>Recent switches</h2>
  <table id="hist"><thead><tr><th>Time</th><th>From</th><th>To</th><th>Latency</th></tr></thead>
  <tbody><tr><td colspan="4" class="empty">none yet</td></tr></tbody></table>
</div>
<script>
async function api(path, body){
  const o = body ? {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)} : {};
  const r = await fetch(path, o); return r.json();
}
async function pin(name, pinned){ await api('/api/pin', {name: pinned ? null : name}); refresh(); }
function fmtAge(s){ return s<2?'just now':(s<60?Math.round(s)+'s ago':Math.round(s/60)+'m ago'); }
async function refresh(){
  let d; try{ d = await api('/api/status'); }catch(e){ return; }
  const sub = document.getElementById('sub');
  if(!d.updated){ sub.innerHTML='<span class="stale">daemon not running — no status yet</span>';
                  document.getElementById('grid').innerHTML=''; return; }
  const age = (Date.now()/1000) - d.updated_epoch;
  const stale = age > 15;
  sub.innerHTML = 'Primary: <b>'+(d.primary||'none')+'</b> · updated '
     + '<span class="'+(stale?'stale':'')+'">'+fmtAge(age)+(stale?' (daemon stalled?)':'')+'</span>'
     + (d.dry_run?' · <span class="stale">dry-run</span>':'')
     + (d.manual_pin?' · pinned to <b>'+d.manual_pin+'</b>':'');
  document.getElementById('grid').innerHTML = (d.links||[]).map(l=>{
    const pinned = d.manual_pin===l.name;
    const kind = l.wired===false ? 'Wi-Fi' : 'wired';
    return `<div class="card ${l.is_primary?'primary':''}">
      ${l.is_primary?'<div class="badge">PRIMARY</div>':''}
      <div class="name"><span class="dot ${l.healthy?'up':'down'}"></span>${l.name}
        <span class="kind">${kind}</span></div>
      <div class="alias">${l.alias} · ${l.source_ip||'—'}</div>
      <div class="stats">
        <div class="stat"><div class="v">${l.latency_ms==null?'—':l.latency_ms+'<span style=font-size:12px> ms</span>'}</div><div class="k">latency</div></div>
        <div class="stat"><div class="v">${l.jitter_ms==null?'—':l.jitter_ms}<span style=font-size:12px> ms</span></div><div class="k">jitter</div></div>
        <div class="stat"><div class="v">${l.loss_pct}<span style=font-size:12px>%</span></div><div class="k">loss</div></div>
      </div>
      <button class="${pinned?'on':''}" onclick="pin('${l.name}',${pinned})">${pinned?'Unpin':'Pin as primary'}</button>
    </div>`;
  }).join('');
  const adv = (d.advice||[]);
  document.getElementById('adviceWrap').style.display = adv.length ? '' : 'none';
  document.getElementById('advice').innerHTML = adv.map(a=>`
    <details class="adv ${a.severity}">
      <summary><span class="sev">${a.severity==='crit'?'✖':a.severity==='warn'?'⚠':'ℹ'}</span> ${a.title}</summary>
      <div class="why">${a.why}</div>
      <ol>${a.steps.map(s=>`<li>${s}</li>`).join('')}</ol>
    </details>`).join('');
  const rows = (d.history||[]);
  document.getElementById('hist').querySelector('tbody').innerHTML =
    rows.length ? rows.map(h=>`<tr><td>${h.time}</td><td>${h.from}</td><td>${h.to}</td><td>${h.latency_ms} ms</td></tr>`).join('')
                : '<tr><td colspan="4" class="empty">none yet</td></tr>';
}
refresh(); setInterval(refresh, 2000);
</script></body></html>"""


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json"):
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/" or self.path.startswith("/index"):
            self._send(200, PAGE, "text/html; charset=utf-8")
        elif self.path.startswith("/api/status"):
            self._send(200, json.dumps(read_status()))
        else:
            self._send(404, json.dumps({"error": "not found"}))

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b"{}"
        try:
            payload = json.loads(raw or b"{}")
        except ValueError:
            payload = {}
        if self.path.startswith("/api/pin"):
            set_pin(payload.get("name"))  # name=None clears the pin
            self._send(200, json.dumps({"ok": True, "manual_pin": payload.get("name")}))
        else:
            self._send(404, json.dumps({"error": "not found"}))

    def log_message(self, *a):  # silence default request logging
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
