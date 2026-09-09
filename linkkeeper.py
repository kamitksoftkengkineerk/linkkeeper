"""
LinkKeeper — keeps a Windows PC's internet alive across multiple phone links.

It continuously probes each WAN link (USB tether + Wi-Fi hotspot), and points
Windows' default route at the best healthy one by rewriting interface metrics.
When the current link degrades or dies, traffic fails over automatically; it
switches back only after a dwell time (anti-flap).

Usage:
    python linkkeeper.py                 # run the daemon (needs admin to apply)
    python linkkeeper.py --verbose       # also log to console
    python linkkeeper.py --once          # single probe/decide cycle, then exit
    python linkkeeper.py --dry-run       # probe + decide, never change metrics
    python linkkeeper.py --status        # print current link health and exit
    python linkkeeper.py --speedtest     # run a one-off speed test per link

Design notes live in the plan; the OS-touching bits are in netroute.py.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import socket
import sys
import time
import urllib.request
from collections import deque
from logging.handlers import RotatingFileHandler

import advisor
import commandbus
import netroute
import openwifi
import ouidb
import store

HERE = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(HERE, "config.json")
STATUS_PATH = os.path.join(HERE, "logs", "status.json")

log = logging.getLogger("linkkeeper")

# rolling record of primary-link changes, surfaced on the dashboard
_switch_history: deque = deque(maxlen=50)

# advisor bookkeeping
_last_seen: dict = {"_start": time.time()}   # link name -> last time discovered
_unhealthy_since: dict = {}                  # link name -> since when unhealthy
_win_checks: dict = {"ts": 0.0}              # cached Windows power-setting checks
_advice_toasted: dict = {}                   # advice id -> last toast time
_wifi_bad_cycles = 0                         # consecutive cycles current hotspot had no internet

# LAN device scan (dashboard Network tab + new-device alerts)
_net_scan: dict = {"last": 0.0, "baseline": None}   # rate-limit ts + first-scan MAC set
_net_devices: dict = {}                             # mac -> device record
_wifi_scan: dict = {"last": 0.0, "nets": []}        # nearby-Wi-Fi cache (slower interval)
_router_scan: dict = {"last": 0.0, "findings": []}  # risky-port cache (slowest interval)

# Small, deliberately conservative set of ports worth flagging if reachable on
# the gateway — services that are either legacy-insecure (telnet, ftp) or
# unusual enough on a consumer router to be worth a look (adb, TR-069, UPnP).
_ROUTER_RISKY_PORTS = [23, 21, 7547, 5555, 1900, 80]


# ---------------------------------------------------------------------------
# config
# ---------------------------------------------------------------------------

def load_config() -> dict:
    # First run (fresh clone): seed config.json from the shipped template.
    if not os.path.exists(CONFIG_PATH):
        example = os.path.join(HERE, "config.example.json")
        if os.path.exists(example):
            import shutil
            shutil.copyfile(example, CONFIG_PATH)
    with open(CONFIG_PATH, "r", encoding="utf-8") as fh:
        return json.load(fh)


# ---------------------------------------------------------------------------
# per-link runtime state (survives across cycles)
# ---------------------------------------------------------------------------

class LinkState:
    def __init__(self, loss_window: int):
        self.results = deque(maxlen=loss_window)   # recent bool successes
        self.latencies = deque(maxlen=10)          # recent latencies (for jitter)
        self.consecutive_fail = 0
        self.latency_ms = float("inf")
        self.last_speed_mbps = None

    @property
    def loss_pct(self) -> float:
        if not self.results:
            return 0.0
        return 100.0 * (1 - sum(self.results) / len(self.results))

    @property
    def jitter_ms(self) -> float:
        import statistics
        return statistics.pstdev(self.latencies) if len(self.latencies) > 1 else 0.0


# keyed by friendly link name
_states: dict[str, LinkState] = {}


# ---------------------------------------------------------------------------
# probing
# ---------------------------------------------------------------------------

def tcp_probe(source_ip: str, host: str, port: int, timeout: float) -> float | None:
    """TCP-connect from a specific source IP. Returns latency in ms, or None."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.settimeout(timeout)
        s.bind((source_ip, 0))          # force egress via this link's interface
        start = time.perf_counter()
        s.connect((host, port))
        return (time.perf_counter() - start) * 1000.0
    except OSError:
        return None
    finally:
        s.close()


def probe_link(link: "netroute.WanLink", cfg: dict, state: LinkState) -> None:
    """Probe one link over its own pinned path; update its state in place."""
    timeout = cfg["probe"]["timeout_seconds"]
    if link.probe_target:
        # dedicated target reached via this link's pinned /32 route
        ports = cfg["probe"].get("ports", [443, 53])
        attempts = [(link.probe_target, int(p)) for p in ports]
    else:
        # fallback (e.g. --status un-elevated, no route pinned): shared targets
        attempts = [(h, int(p)) for h, p in cfg["probe"]["targets"]]
    best = None
    for host, port in attempts:
        ms = tcp_probe(link.source_ip, host, port, timeout)
        if ms is not None:
            best = ms if best is None else min(best, ms)
    ok = best is not None
    state.results.append(ok)
    dec = cfg["decision"]
    if ok:
        state.consecutive_fail = 0
        state.latency_ms = best
        state.latencies.append(best)
    else:
        state.consecutive_fail += 1
        state.latency_ms = float("inf")
    # Debounced health: a link only counts as DOWN after fail_after_bad_probes
    # consecutive misses (recovery is still instant). This absorbs single-probe
    # blips that would otherwise force a full failover every few seconds. A link
    # that has never succeeded is not considered healthy on a miss.
    fail_thresh = dec.get("fail_after_bad_probes", 3)
    link.healthy = ok or (bool(state.latencies) and state.consecutive_fail < fail_thresh)
    link.latency_ms = state.latency_ms
    link.jitter_ms = state.jitter_ms
    link.loss_pct = state.loss_pct
    # quality score (lower is better): latency + weighted jitter + loss penalty.
    # Loss is weighted heavily — a 40%-loss link is near-unusable no matter how
    # fast its surviving packets are (observed live: lossy M34 must not beat
    # clean Wi-Fi just because it's wired). During a debounced blip (healthy but
    # this probe missed) we score off the last-good latency so the link doesn't
    # jump to infinity and get dropped for a single miss; the rising loss_pct
    # still degrades it gradually.
    jw = dec.get("jitter_weight", 0.5)
    lw = dec.get("loss_weight_ms_per_pct", 20)
    if link.healthy:
        base = best if ok else (state.latencies[-1] if state.latencies else float("inf"))
        link.score = base + jw * state.jitter_ms + lw * state.loss_pct
    else:
        link.score = float("inf")


# ---------------------------------------------------------------------------
# link discovery + config matching
# ---------------------------------------------------------------------------

def managed_links(cfg: dict) -> list["netroute.WanLink"]:
    """Discover WAN interfaces and keep only those matching config (or all,
    if config 'links' is empty). Attach friendly name, preference, and a
    dedicated probe target from the pool."""
    discovered = netroute.discover_wan_interfaces()
    rules = cfg.get("links", [])
    # With no rules, manage everything. With rules, still manage anything that
    # provides internet but no rule named (unless it looks virtual/VPN) so any
    # connection technology is covered.
    manage_unmatched = cfg.get("manage_unmatched", not rules)
    excludes = [e.lower() for e in cfg.get("exclude", [])]

    result = []
    for lk in discovered:
        matched = False
        for rule in rules:
            if _rule_matches(rule, lk):
                lk.name = rule.get("name", lk.alias)
                lk.preference = int(rule.get("preference", 100))
                result.append(lk)
                matched = True
                break
        if matched:
            continue
        if manage_unmatched and not _is_excluded(lk, excludes):
            lk.name = lk.alias or f"if{lk.if_index}"
            lk.preference = 100
            result.append(lk)

    assign_probe_targets(result, cfg)
    return result


# persistent link-name -> probe-target, so a link keeps its dedicated IP across
# cycles (no churn) and targets never collide between two present links
_target_map: dict[str, str] = {}


def assign_probe_targets(links, cfg):
    """Give each managed link a stable, distinct probe target from the pool.
    Reuses a link's prior target; assigns a free one to new links; logs (and
    leaves unprobed) any link beyond the pool size instead of colliding."""
    pool = cfg["probe"].get("pool", [])
    if not pool:
        return
    present = {lk.name for lk in links}
    used = {t for n, t in _target_map.items() if n in present}
    for lk in sorted(links, key=lambda l: l.name):
        cur = _target_map.get(lk.name)
        if cur in pool:
            lk.probe_target = cur
            continue
        free = [p for p in pool if p not in used]
        if not free:
            log.error("more managed links than probe-pool IPs (%d) — %s left unprobed",
                      len(pool), lk.name)
            continue
        _target_map[lk.name] = free[0]
        used.add(free[0])
        lk.probe_target = free[0]


def _is_excluded(lk: "netroute.WanLink", excludes: list) -> bool:
    """True if an interface looks virtual/VPN/tunnel (by name or description)
    and should not be treated as a real WAN link."""
    hay = (lk.alias + " " + lk.description).lower()
    return any(e in hay for e in excludes)


def _rule_matches(rule: dict, lk: "netroute.WanLink") -> bool:
    """A rule matches if its alias-substring hits the adapter name/description
    AND (if given) its USB vid and media class also match. The vid check is what
    tells two USB tethers (M34 vs OnePlus) apart."""
    needle = rule.get("match_alias", "").lower()
    if needle and needle not in lk.alias.lower() and needle not in lk.description.lower():
        return False
    if rule.get("vid") and rule["vid"].upper() != lk.vid.upper():
        return False
    if rule.get("ssid") and not _ssid_matches(rule["ssid"], lk.ssid):
        return False
    if "media" in rule:
        want_wired = rule["media"].lower() == "wired"
        if want_wired != lk.wired:
            return False
    return True


# per-link pinned route cache: name -> (target, gateway, if_index)
_pinned: dict[str, tuple] = {}


def ensure_probe_routes(links, dry_run):
    """Make sure each link's probe target is pinned to a /32 route via that
    link's gateway. Re-pins only when a link's gateway/index/target changes.
    Vanished links have their cache entry AND their orphaned /32 route removed,
    so (a) a reappearing link always re-pins (Windows drops ActiveStore routes
    when an interface goes down) and (b) a stale /32 can't blackhole that IP."""
    present = {lk.name for lk in links}
    for name in list(_pinned):
        if name not in present:
            target = _pinned[name][0]
            if not dry_run:
                try:
                    netroute.del_host_route(target)
                except RuntimeError:
                    pass
            del _pinned[name]
            _target_map.pop(name, None)
    for lk in links:
        if not lk.probe_target:
            continue
        want = (lk.probe_target, lk.gateway, lk.if_index)
        if _pinned.get(lk.name) == want:
            continue
        if dry_run:
            log.info("[dry-run] would pin %s -> %s via %s (if %d)",
                     lk.name, lk.probe_target, lk.gateway, lk.if_index)
            _pinned[lk.name] = want
            continue
        try:
            # clear this target from every interface, then pin it to this link
            netroute.del_host_route(lk.probe_target)
            netroute.add_host_route(lk.probe_target, lk.if_index, lk.gateway)
            _pinned[lk.name] = want
            log.info("pinned probe route %s -> %s via %s",
                     lk.name, lk.probe_target, lk.gateway)
        except RuntimeError as exc:
            log.warning("could not pin probe route for %s: %s", lk.name, exc)


# ---------------------------------------------------------------------------
# decision engine (with hysteresis / anti-flap)
# ---------------------------------------------------------------------------

def _rank_key(lk, dec):
    """Sort key for 'best link' (lower is better):
      1. trusted first  — an untrusted auto-joined open network is only ever
         chosen when no trusted link (your phones) is healthy.
      2. wired first while CLEAN — a wired link keeps its class privilege until
         its loss crosses wired_degraded_loss_pct (a flapping tether must not
         beat a solid hotspot).
      3. quality score (latency + jitter + loss).
      4. preference tiebreak."""
    trust_rank = 0 if lk.trusted else 1
    clean = lk.loss_pct < dec.get("wired_degraded_loss_pct", 25)
    wired_rank = 0 if (dec.get("prefer_wired", True) and lk.wired and clean) else 1
    return (trust_rank, wired_rank, lk.score, lk.preference)


def choose_link(links, cfg, current_name):
    """Return the link that should be primary, applying anti-flap rules.

    'Best' = wired-preferred, then lowest quality score (latency + jitter).
    We only switch away from a healthy current primary if a rival is a better
    class (wired vs wireless) or beats its score by more than switch_margin_ms,
    and the anti-flap dwell has elapsed."""
    dec = cfg["decision"]
    healthy = [lk for lk in links if lk.healthy]
    if not healthy:
        return None

    current = next((lk for lk in links if lk.name == current_name), None)
    dwell_ok = (time.time() - _last_switch_at) > dec["switchback_dwell_seconds"]

    # Manual override wins if the pinned link is healthy — but still respect the
    # anti-flap dwell so a flapping pinned link doesn't flip the route every few
    # seconds (unless it's already current, or nothing else is up).
    pin = cfg.get("manual_pin")
    if pin:
        pinned = next((lk for lk in healthy if lk.name == pin), None)
        if pinned:
            if current is None or current.name == pin or dwell_ok:
                return pinned
            return current  # hold current until dwell elapses
        # pinned link not healthy: fall through to normal selection

    best = min(healthy, key=lambda lk: _rank_key(lk, dec))

    if current is None or not current.healthy:
        return best  # no current, or current died -> take the best now
    if best.name == current.name:
        return current

    # current still healthy but a rival looks better: require a better class OR
    # a meaningful score win, plus the dwell, before switching (anti-flap).
    better_class = _rank_key(best, dec)[:2] < _rank_key(current, dec)[:2]
    margin = dec.get("switch_margin_ms", dec.get("latency_margin_ms", 60))
    better_score = current.score - best.score > margin
    if (better_class or better_score) and dwell_ok:
        return best
    return current


# ---------------------------------------------------------------------------
# applying the choice
# ---------------------------------------------------------------------------

_last_switch_at = 0.0
_current_name = None
_metric_fail_count = [0]   # consecutive Set-NetIPInterface failures (elevation?)


def apply_choice(chosen, links, cfg, dry_run):
    """Set metrics so `chosen` is primary and the rest are backups."""
    global _last_switch_at, _current_name
    dec = cfg["decision"]

    if chosen is None:
        log.warning("no healthy link — leaving metrics untouched")
        return

    changed = chosen.name != _current_name
    for lk in links:
        want = dec["metric_primary"] if lk.name == chosen.name else dec["metric_backup"]
        if lk.metric != want:
            if dry_run:
                log.info("[dry-run] would set %s metric %d -> %d",
                         lk.name, lk.metric, want)
            else:
                # Tolerate a per-link failure (adapter unplugged mid-cycle, or an
                # unelevated daemon) so the cycle still finishes and writes status
                # instead of aborting before write_status/advisor.
                try:
                    netroute.set_interface_metric(lk.if_index, want)
                    lk.metric = want
                    _metric_fail_count[0] = 0
                except RuntimeError as exc:
                    _metric_fail_count[0] += 1
                    log.warning("could not set metric on %s: %s", lk.name, exc)

    if changed:
        if not dry_run:
            netroute.flush_dns()
        prev = _current_name
        _last_switch_at = time.time()
        _current_name = chosen.name
        _switch_history.appendleft({
            "time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "from": prev or "-",
            "to": chosen.name,
            "latency_ms": round(chosen.latency_ms, 1),
        })
        store.record_switch(prev or "-", chosen.name, round(chosen.latency_ms, 1),
                            "wired" if chosen.wired else "wireless")
        log.info("PRIMARY -> %s (%.0f ms, jitter %.0f, loss %.0f%%)",
                 chosen.name, chosen.latency_ms, chosen.jitter_ms,
                 _states[chosen.name].loss_pct)
        if not dry_run and cfg.get("notify", {}).get("enabled", True) and prev:
            kind = "wired" if chosen.wired else "Wi-Fi"
            netroute.notify(
                f"Internet now on {chosen.name} ({kind}, {chosen.latency_ms:.0f} ms)"
            )


# ---------------------------------------------------------------------------
# optional speed test (opt-in, data-cost aware)
# ---------------------------------------------------------------------------

def speed_test(link, cfg) -> float | None:
    """Download a small file bound to this link; return Mbps (or None)."""
    url = cfg["speedtest"]["url"]
    orig = socket.socket

    def bound_socket(*a, **k):
        s = orig(*a, **k)
        try:
            s.bind((link.source_ip, 0))
        except OSError:
            pass
        return s

    socket.socket = bound_socket  # monkeypatch so urllib egresses this link
    try:
        start = time.perf_counter()
        with urllib.request.urlopen(url, timeout=20) as resp:
            data = resp.read()
        secs = time.perf_counter() - start
        return (len(data) * 8) / secs / 1e6 if secs > 0 else None
    except Exception as exc:  # noqa: BLE001 - report and move on
        log.warning("speedtest failed on %s: %s", link.name, exc)
        return None
    finally:
        socket.socket = orig


# ---------------------------------------------------------------------------
# cycle + main loop
# ---------------------------------------------------------------------------

def refresh_win_checks(cfg):
    """Occasionally re-check Windows power settings that kill tethers."""
    minutes = cfg.get("advisor", {}).get("windows_check_minutes", 30)
    if time.time() - _win_checks["ts"] < minutes * 60:
        return
    _win_checks["ts"] = time.time()
    _win_checks["usb_suspend"] = netroute.usb_selective_suspend_enabled()
    _win_checks["fast_startup"] = netroute.fast_startup_enabled()
    _win_checks["hubs_sleepy"] = netroute.usb_hubs_allowed_to_sleep()
    _win_checks["location"] = netroute.location_services_on()
    log.debug("win checks: usb_suspend=%s fast_startup=%s hubs=%d",
              _win_checks.get("usb_suspend"), _win_checks.get("fast_startup"),
              len(_win_checks.get("hubs_sleepy") or []))


def maybe_scan_lan(cfg):
    """Every netscan.scan_interval_seconds, ping-sweep the local /24 + read the
    ARP table (no elevation), then update the device cache. Devices present at
    the first scan of this run are baselined (never alerted); a MAC that appears
    later and isn't in netscan.known is flagged is_new (drives the advisor
    intruder rule -> toast + dashboard). Never raises into the failover loop."""
    ns = cfg.get("netscan", {})
    if not ns.get("enabled", True):
        return
    if time.time() - _net_scan["last"] < ns.get("scan_interval_seconds", 60):
        return
    _net_scan["last"] = time.time()
    try:
        found = netroute.lan_scan()
    except Exception as exc:                       # scan must never break failover
        log.debug("lan_scan failed: %s", exc)
        return
    now = time.time()
    known = {str(e.get("mac", "")).upper(): e for e in ns.get("known", []) if e.get("mac")}
    ignore = {str(m).upper() for m in ns.get("ignore", [])}
    if _net_scan["baseline"] is None:              # first scan this run = baseline
        _net_scan["baseline"] = {d["mac"] for d in found}
    baseline = _net_scan["baseline"]
    seen_now = set()
    for d in found:
        mac = d["mac"]
        if mac in ignore:
            continue
        seen_now.add(mac)
        rec = _net_devices.setdefault(mac, {"mac": mac, "first_seen": now})
        is_known = mac in known
        rec.update({
            "ip": d["ip"], "state": d["state"], "randomized": d["randomized"],
            "vendor": ouidb.vendor(mac),           # maker name, "" if unknown/randomized
            "last_seen": now, "online": True, "known": is_known,
            "name": (known[mac].get("name") if is_known else rec.get("name", "")),
            "is_new": (not is_known) and (mac not in baseline),
        })
    for mac, rec in _net_devices.items():          # devices no longer answering
        if mac not in seen_now:
            rec["online"] = False
            rec["is_new"] = False
    store.record_scan(_device_snapshot())          # persist registry + presence
    if time.time() - _net_scan.get("last_prune", 0) > 21600:   # ~6h
        _net_scan["last_prune"] = time.time()
        store.prune(ns.get("db_retention_days", 0))


def _device_snapshot():
    """Device list for status.json + advisor: new & online first, then by IP."""
    def key(r):
        ip = [int(x) for x in r["ip"].split(".")] if r.get("ip") else [0, 0, 0, 0]
        return (0 if r.get("is_new") else 1, 0 if r.get("online") else 1, ip)
    return sorted(_net_devices.values(), key=key)


def maybe_scan_wifi(cfg):
    """Every netscan.wifi_scan_interval_seconds, list nearby Wi-Fi networks for
    the dashboard's "Wi-Fi Nearby" view. Slower cadence than the LAN scan (a Wi-Fi
    scan is heavier and the RF picture barely changes minute to minute). Needs
    Windows Location ON; when it's off the cache clears and the advisor's existing
    Location-off item explains why. Never raises into the failover loop."""
    ns = cfg.get("netscan", {})
    if not ns.get("enabled", True) or not ns.get("scan_wifi", True):
        return
    interval = ns.get("wifi_scan_interval_seconds", 300)
    if time.time() - _wifi_scan["last"] < interval:
        return
    _wifi_scan["last"] = time.time()
    try:
        _wifi_scan["nets"] = netroute.wlan_scan_all()
    except Exception as exc:                       # scan must never break failover
        log.debug("wlan_scan_all failed: %s", exc)
        _wifi_scan["nets"] = []


def maybe_scan_router(cfg):
    """Every netscan.router_scan_interval_seconds (default 1h), TCP-connect to
    a small set of risky ports on the gateway. Reachability check only — never
    claims a CVE/vulnerability, just "this port answers" (see advisor.py). Each
    connect attempt has its own short timeout so a filtered/black-holed port
    can't stall the daemon; the whole scan runs well under a failover cycle.
    Never raises into the failover loop."""
    ns = cfg.get("netscan", {})
    if not ns.get("enabled", True) or not ns.get("router_scan", True):
        return
    interval = ns.get("router_scan_interval_seconds", 3600)
    if time.time() - _router_scan["last"] < interval:
        return
    _router_scan["last"] = time.time()
    try:
        gw = netroute.default_gateway()
        _router_scan["gateway"] = gw
        if not gw:
            _router_scan["findings"] = []
            return
        ports = ns.get("router_ports") or _ROUTER_RISKY_PORTS
        findings = [{"port": p, "host": gw} for p in ports
                    if netroute.tcp_port_open(gw, p, timeout=1.5)]
        _router_scan["findings"] = findings
    except Exception as exc:                       # scan must never break failover
        log.debug("router scan failed: %s", exc)
        _router_scan["findings"] = []


_last_recovery: dict = {}   # adapter name -> last Restart-NetAdapter attempt
_stale_cycles: dict = {}    # adapter name -> consecutive cycles seen stale


def maybe_recover_tethers(links, dry_run, cfg):
    """Self-heal stale USB tethers: if Windows still shows a Remote NDIS
    adapter that isn't routing, bounce it with Restart-NetAdapter — the
    no-replug recovery. Only after it's been stale for several CONSECUTIVE
    cycles, so a single transient discovery miss (mid-DHCP, a 1-cycle route
    blip) can never bounce a live/recovering tether. Rate-limited 5 min."""
    if dry_run:
        return
    active = {lk.if_index for lk in links}
    try:
        stale = set(netroute.stale_tether_adapters(active))
    except RuntimeError:
        return
    need = cfg.get("advisor", {}).get("stale_cycles_before_bounce", 4)
    now = time.time()
    for name in list(_stale_cycles):          # reset counters for no-longer-stale
        if name not in stale:
            del _stale_cycles[name]
    for name in stale:
        _stale_cycles[name] = _stale_cycles.get(name, 0) + 1
        if _stale_cycles[name] < need:
            continue                          # not stale long enough yet
        if now - _last_recovery.get(name, 0) < 300:
            continue
        _last_recovery[name] = now
        log.info("tether '%s' stale for %d cycles — Restart-NetAdapter recovery",
                 name, _stale_cycles[name])
        try:
            netroute.restart_adapter(name)
        except RuntimeError as exc:
            log.warning("tether recovery failed for %s: %s", name, exc)


def update_advisor_state(links, cfg):
    """Track when each saved link was last seen / went unhealthy. Prune state
    for links that vanished so a reappearing link gets a fresh grace period and
    LinkState. _wifi_bad_cycles counts ONLY the link actually on the Wi-Fi radio
    (not e.g. a dead Bluetooth PAN), so a broken BT tether can't force the radio
    to abandon a working hotspot."""
    global _wifi_bad_cycles
    now = time.time()
    present = {lk.name for lk in links}
    for d in (_unhealthy_since, _last_seen):
        for name in list(d):
            if name != "_start" and name not in present:
                d.pop(name, None)
    for name in list(_states):
        if name not in present:
            del _states[name]

    wifi_adapter = cfg.get("wifi", {}).get("adapter", "Wi-Fi").lower()
    ssids = cfg.get("wifi", {}).get("ssids") or []
    wifi_bad = False
    for lk in links:
        _last_seen[lk.name] = now
        if lk.healthy:
            _unhealthy_since.pop(lk.name, None)
        else:
            _unhealthy_since.setdefault(lk.name, now)
            on_radio = (lk.alias.lower() == wifi_adapter
                        or any(s.lower() in lk.ssid.lower() for s in ssids if s))
            if not lk.wired and on_radio:
                wifi_bad = True
    _wifi_bad_cycles = (_wifi_bad_cycles + 1) if wifi_bad else 0


def toast_advice(advice, cfg):
    """Toast newly-appearing advice (rate-limited to once/30min per item)."""
    if not cfg.get("notify", {}).get("enabled", True):
        return
    now = time.time()
    for a in advice:
        if a["severity"] == "info":
            continue
        if now - _advice_toasted.get(a["id"], 0) > 1800:
            _advice_toasted[a["id"]] = now
            netroute.notify(a["title"] + " — open dashboard :8901 for fix steps")


def write_status(links, chosen, cfg, dry_run, advice=None, devices=None):
    """Publish a snapshot to logs/status.json for the dashboard to read."""
    snap = {
        "updated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "updated_epoch": time.time(),
        "primary": chosen.name if chosen else None,
        "manual_pin": cfg.get("manual_pin"),
        "dry_run": dry_run,
        "advice": advice or [],
        "links": [
            {
                "name": lk.name,
                "alias": lk.alias,
                "source_ip": lk.source_ip,
                "healthy": lk.healthy,
                "wired": lk.wired,
                "trusted": lk.trusted,
                "ssid": lk.ssid,
                "latency_ms": None if lk.latency_ms == float("inf")
                              else round(lk.latency_ms, 1),
                "jitter_ms": round(lk.jitter_ms, 1),
                "loss_pct": round(_states[lk.name].loss_pct, 1),
                "metric": lk.metric,
                "is_primary": bool(chosen) and lk.name == chosen.name,
            }
            for lk in links
        ],
        "history": list(_switch_history),
        "devices": devices or [],
        "wifi_nearby": _wifi_scan["nets"],
        "router": {"gateway": _router_scan.get("gateway", ""),
                   "findings": _router_scan["findings"]},
    }
    try:
        os.makedirs(os.path.dirname(STATUS_PATH), exist_ok=True)
        tmp = STATUS_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(snap, fh, indent=2)
        os.replace(tmp, STATUS_PATH)  # atomic swap so readers never see half a file
    except OSError as exc:
        log.warning("could not write status.json: %s", exc)


_last_wifi_attempt = 0.0


def maybe_reconnect_wifi(cfg, dry_run):
    """Keep the single Wi-Fi radio on the best available saved hotspot. If it's
    not connected to any SSID in the priority list, try them in order (rate-
    limited) so the Wi-Fi backup self-heals and prefers the best hotspot."""
    global _last_wifi_attempt
    wc = cfg.get("wifi", {})
    if not wc.get("autoreconnect") or dry_run:
        return
    # accept either a single 'ssid' or a prioritized 'ssids' list
    ssids = wc.get("ssids") or ([wc["ssid"]] if wc.get("ssid") else [])
    if not ssids:
        return
    if time.time() - _last_wifi_attempt < wc.get("retry_seconds", 20):
        return
    adapter = wc.get("adapter", "Wi-Fi")
    try:
        current = netroute.wifi_connected_ssid(adapter)
    except RuntimeError:
        return
    on_known = any(_ssid_matches(s, current) for s in ssids if s)
    rotate = on_known and _wifi_bad_cycles >= cfg["decision"]["fail_after_bad_probes"]
    if on_known and not rotate:
        return  # on one of our hotspots and it works — leave it
    _last_wifi_attempt = time.time()
    # If the current hotspot is up but has NO internet, rotate to the others
    # first — "keep the PC online from any available connection".
    candidates = ([s for s in ssids if not _ssid_matches(s, current)] + ssids) if rotate else ssids
    seen = set()
    for ssid in candidates:  # priority order; stop at the first that sticks
        if ssid in seen:
            continue
        seen.add(ssid)
        log.info("Wi-Fi on '%s'%s — trying hotspot '%s'",
                 current or "nothing", " (no internet)" if rotate else "", ssid)
        try:
            netroute.wifi_connect(ssid, adapter)
        except RuntimeError as exc:
            log.warning("  '%s' failed: %s", ssid, exc)  # e.g. no saved profile
            continue
        time.sleep(3)
        if _ssid_matches(ssid, netroute.wifi_connected_ssid(adapter)):
            log.info("Wi-Fi connected to '%s'", ssid)
            break


def _ssid_matches(configured: str, current: str) -> bool:
    """True if `current` (a Get-NetConnectionProfile name) is `configured`,
    allowing Windows' ' 2'/' 3' duplicate-name suffix — anchored so a different
    network merely containing the SSID (e.g. 'MyHotspot_EXT') does NOT match."""
    import re
    return bool(re.fullmatch(re.escape(configured) + r"( \d+)?", current or "",
                             flags=re.IGNORECASE))


def process_commands(cfg, dry_run):
    """Execute privileged actions the (unelevated) dashboard requested via the
    command channel. Only allowlisted actions run; each writes a result."""
    if dry_run:
        return
    for cmd in commandbus.pending():
        cid, action, cargs = cmd["id"], cmd["action"], cmd.get("args", {})
        try:
            if action == "apply_windows_fixes":
                out = netroute.apply_windows_keepalive_fixes()
                _win_checks["ts"] = 0.0  # force re-check so advice clears
            elif action == "install_task":
                out = netroute.register_task()
            elif action == "uninstall_task":
                out = netroute.unregister_task()
            elif action == "scan_open":
                out = netroute.wlan_scan_open()
            elif action == "join_open":
                openwifi.maybe_join(cfg)  # honours enabled/last-resort gating
                out = openwifi.current_open() or "no open network joined"
            elif action == "forget_open":
                ssid = cargs.get("ssid", "")
                netroute.wlan_remove_profile(ssid)
                out = f"forgot {ssid}"
            elif action == "enable_location_help":
                out = netroute.open_location_settings()
            else:
                raise ValueError(f"unknown action {action}")
            commandbus.complete(cid, True, out)
            log.info("command %s (%s) ok", action, cid)
        except Exception as exc:  # noqa: BLE001 - report to the UI, keep running
            commandbus.complete(cid, False, str(exc))
            log.warning("command %s failed: %s", action, exc)
    commandbus.prune()


def run_cycle(cfg, dry_run):
    process_commands(cfg, dry_run)
    if not openwifi.is_joined():
        maybe_reconnect_wifi(cfg, dry_run)  # openwifi owns the radio when joined
    links = managed_links(cfg)
    openwifi.tag_links(links)               # mark any joined open net untrusted
    refresh_win_checks(cfg)
    maybe_scan_lan(cfg)
    maybe_scan_wifi(cfg)
    maybe_scan_router(cfg)
    if not links:
        log.warning("no managed WAN links found (are the phones connected?)")
        advice = advisor.evaluate([], cfg, _last_seen, _unhealthy_since, _win_checks,
                                  devices=_device_snapshot(), router_findings=_router_scan["findings"])
        toast_advice(advice, cfg)
        write_status([], None, cfg, dry_run, advice, devices=_device_snapshot())
        return links

    ensure_probe_routes(links, dry_run)
    win = cfg["probe"]["loss_window"]
    for lk in links:
        st = _states.setdefault(lk.name, LinkState(win))
        probe_link(lk, cfg, st)
        log.debug("%s: %s %.0f ms loss=%.0f%% metric=%d",
                  lk.name, "UP  " if lk.healthy else "DOWN",
                  lk.latency_ms, st.loss_pct, lk.metric)

    update_advisor_state(links, cfg)
    maybe_recover_tethers(links, dry_run, cfg)

    # Open-Wi-Fi as untrusted last resort: only when NO trusted link is healthy.
    # The moment a trusted link (a phone) is healthy again, drop any open network.
    trusted_healthy = any(lk.healthy and lk.trusted for lk in links)
    if trusted_healthy:
        openwifi.drop_if_joined(cfg, dry_run)
    elif cfg.get("wifi", {}).get("open_join", {}).get("enabled"):
        if openwifi.maybe_join(cfg, dry_run):
            links = managed_links(cfg)          # re-discover to include the open link
            openwifi.tag_links(links)
            for lk in links:
                st = _states.setdefault(lk.name, LinkState(cfg["probe"]["loss_window"]))
                probe_link(lk, cfg, st)

    chosen = choose_link(links, cfg, _current_name)
    apply_choice(chosen, links, cfg, dry_run)
    advice = advisor.evaluate(links, cfg, _last_seen, _unhealthy_since, _win_checks,
                              devices=_device_snapshot(), router_findings=_router_scan["findings"])
    if _metric_fail_count[0] >= 3:
        advice = [{
            "id": "not-elevated", "severity": "crit",
            "title": "Can't change routing — LinkKeeper needs to run as administrator",
            "steps": ["Reinstall the autostart task (runs elevated): .\\install_task.ps1 -Run",
                      "Or run the daemon from an elevated PowerShell"],
            "why": "Set-NetIPInterface is failing, so failover can't actually switch links.",
        }] + advice
    for a in advice:
        if a["id"].startswith("intruder:"):
            store.record_alert(a["id"].split(":", 1)[1], kind="intruder", note=a["title"])
    store.record_link_samples(links, chosen.name if chosen else None,
                              sample=cfg.get("netscan", {}).get("sample_link_quality", True),
                              interval=cfg.get("netscan", {}).get("sample_interval_seconds", 0))
    toast_advice(advice, cfg)
    write_status(links, chosen, cfg, dry_run, advice, devices=_device_snapshot())
    return links


def setup_logging(cfg, verbose):
    log.setLevel(logging.DEBUG if verbose else logging.INFO)
    fmt = logging.Formatter("%(asctime)s %(levelname)-7s %(message)s",
                            "%Y-%m-%d %H:%M:%S")
    logdir = os.path.join(HERE, os.path.dirname(cfg["logging"]["file"]))
    os.makedirs(logdir, exist_ok=True)
    fh = RotatingFileHandler(
        os.path.join(HERE, cfg["logging"]["file"]),
        maxBytes=cfg["logging"]["max_bytes"],
        backupCount=cfg["logging"]["backups"],
        encoding="utf-8",
    )
    fh.setFormatter(fmt)
    log.addHandler(fh)
    if verbose:
        ch = logging.StreamHandler(sys.stdout)
        ch.setFormatter(fmt)
        log.addHandler(ch)


def cmd_status(cfg):
    links = managed_links(cfg)
    win = cfg["probe"]["loss_window"]
    print(f"{'LINK':<16}{'STATE':<7}{'LATENCY':<10}{'METRIC':<8}IP")
    for lk in links:
        st = _states.setdefault(lk.name, LinkState(win))
        probe_link(lk, cfg, st)
        state = "UP" if lk.healthy else "DOWN"
        lat = f"{lk.latency_ms:.0f} ms" if lk.healthy else "-"
        print(f"{lk.name:<16}{state:<7}{lat:<10}{lk.metric:<8}{lk.source_ip}")


def cmd_speedtest(cfg):
    for lk in managed_links(cfg):
        mbps = speed_test(lk, cfg)
        print(f"{lk.name:<16}{mbps:.1f} Mbps" if mbps else f"{lk.name:<16}failed")


def cmd_advise(cfg):
    """Probe once, print live advice for the current situation, then the full
    prevention checklist for every saved device."""
    links = managed_links(cfg)
    win = cfg["probe"]["loss_window"]
    print(f"\n{'LINK':<15}{'TYPE':<9}{'STATE':<7}LATENCY")
    for lk in links:
        st = _states.setdefault(lk.name, LinkState(win))
        probe_link(lk, cfg, st)
        lat = f"{lk.latency_ms:.0f} ms" if lk.healthy else "-"
        print(f"{lk.name:<15}{'wired' if lk.wired else 'Wi-Fi':<9}"
              f"{'UP' if lk.healthy else 'DOWN':<7}{lat}")
    update_advisor_state(links, cfg)
    refresh_win_checks(cfg)
    # look far enough back that missing/unhealthy conditions trigger immediately
    horizon = time.time() - 10 * cfg.get("advisor", {}).get("missing_after_seconds", 90)
    seen = {k: min(v, horizon) if k != "_start" else horizon for k, v in _last_seen.items()}
    seen["_start"] = horizon
    unhealthy = {k: min(v, horizon) for k, v in _unhealthy_since.items()}
    advice = advisor.evaluate(links, cfg, seen, unhealthy, _win_checks)

    print("\n=== CURRENT ISSUES ===")
    if not advice:
        print("  none — all saved connections are healthy")
    for a in advice:
        print(f"\n[{a['severity'].upper()}] {a['title']}")
        print(f"  why: {a['why']}")
        for s in a["steps"]:
            print(f"    - {s}")
    print("\n\n" + advisor.full_checklist())


def main():
    # Windows consoles default to cp1252, which chokes on the arrows in advice
    # text — force UTF-8 (best effort) for CLI output.
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):
        pass
    ap = argparse.ArgumentParser(description="LinkKeeper internet failover daemon")
    ap.add_argument("--verbose", action="store_true", help="log to console too")
    ap.add_argument("--once", action="store_true", help="one cycle then exit")
    ap.add_argument("--dry-run", action="store_true", help="never change metrics")
    ap.add_argument("--status", action="store_true", help="print link health, exit")
    ap.add_argument("--speedtest", action="store_true", help="speed test each link, exit")
    ap.add_argument("--advise", action="store_true",
                    help="print live issues + full prevention checklist, exit")
    args = ap.parse_args()

    cfg = load_config()
    setup_logging(cfg, args.verbose or args.once or args.dry_run)
    try:
        store.init_db()
    except Exception as exc:                       # DB is optional, never fatal
        log.warning("records DB unavailable: %s", exc)

    if args.status:
        cmd_status(cfg)
        return
    if args.speedtest:
        cmd_speedtest(cfg)
        return
    if args.advise:
        cmd_advise(cfg)
        return

    if args.once:
        run_cycle(cfg, args.dry_run)
        return

    log.info("LinkKeeper started (interval %ds, dry_run=%s)",
             cfg["probe"]["interval_seconds"], args.dry_run)
    interval = cfg["probe"]["interval_seconds"]
    good_cfg = cfg  # last config that parsed — survive a bad concurrent write
    while True:
        try:
            try:
                cfg = load_config()  # reload so config edits / manual_pin apply live
                good_cfg = cfg
            except (OSError, ValueError) as exc:
                log.warning("config reload failed (%s) — using last good config", exc)
                cfg = good_cfg
            run_cycle(cfg, args.dry_run)
        except Exception as exc:  # noqa: BLE001 - never let the daemon die
            log.exception("cycle error: %s", exc)
        time.sleep(interval)


if __name__ == "__main__":
    main()
