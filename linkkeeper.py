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
import netroute

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


# ---------------------------------------------------------------------------
# config
# ---------------------------------------------------------------------------

def load_config() -> dict:
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
    if ok:
        state.consecutive_fail = 0
        state.latency_ms = best
        state.latencies.append(best)
    else:
        state.consecutive_fail += 1
        state.latency_ms = float("inf")
    link.healthy = ok
    link.latency_ms = state.latency_ms
    link.jitter_ms = state.jitter_ms
    link.loss_pct = state.loss_pct
    # quality score (lower is better): latency + weighted jitter + loss penalty.
    # Loss is weighted heavily — a 40%-loss link is near-unusable no matter how
    # fast its surviving packets are (observed live: lossy M34 must not beat
    # clean Wi-Fi just because it's wired).
    dec = cfg["decision"]
    jw = dec.get("jitter_weight", 0.5)
    lw = dec.get("loss_weight_ms_per_pct", 20)
    link.score = (state.latency_ms + jw * state.jitter_ms
                  + lw * state.loss_pct) if ok else float("inf")


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

    # Give each managed link its OWN distinct probe target. Assign by sorted
    # link name so it's stable across cycles/discovery-order and never collides
    # (two links must not share a target, or they'd fight over its /32 route).
    pool = cfg["probe"].get("pool", [])
    if pool:
        for i, lk in enumerate(sorted(result, key=lambda l: l.name)):
            lk.probe_target = pool[i % len(pool)]
    return result


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
    if rule.get("ssid") and rule["ssid"].lower() not in lk.ssid.lower():
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
    link's gateway. Re-pins only when a link's gateway/index/target changes."""
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
    """Sort key for 'best link': wired first (if enabled), then quality score,
    then preference as a final tiebreak. Lower is better.

    A wired link only keeps its class privilege while it's CLEAN — once its
    loss crosses wired_degraded_loss_pct it competes on score like everyone
    else (a flapping USB tether must not beat a solid hotspot)."""
    clean = lk.loss_pct < dec.get("wired_degraded_loss_pct", 10)
    wired_rank = 0 if (dec.get("prefer_wired", True) and lk.wired and clean) else 1
    return (wired_rank, lk.score, lk.preference)


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

    # manual override wins if the pinned link is healthy
    pin = cfg.get("manual_pin")
    if pin:
        for lk in healthy:
            if lk.name == pin:
                return lk

    best = min(healthy, key=lambda lk: _rank_key(lk, dec))

    current = next((lk for lk in links if lk.name == current_name), None)
    if current is None or not current.healthy:
        return best  # no current, or current died -> take the best now
    if best.name == current.name:
        return current

    # current still healthy but a rival looks better: require a better class OR
    # a meaningful score win, plus the dwell, before switching (anti-flap).
    better_class = _rank_key(best, dec)[0] < _rank_key(current, dec)[0]
    margin = dec.get("switch_margin_ms", dec.get("latency_margin_ms", 60))
    better_score = current.score - best.score > margin
    dwell_ok = (time.time() - _last_switch_at) > dec["switchback_dwell_seconds"]
    if (better_class or better_score) and dwell_ok:
        return best
    return current


# ---------------------------------------------------------------------------
# applying the choice
# ---------------------------------------------------------------------------

_last_switch_at = 0.0
_current_name = None


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
                netroute.set_interface_metric(lk.if_index, want)
                lk.metric = want

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
    log.debug("win checks: usb_suspend=%s fast_startup=%s hubs=%d",
              _win_checks.get("usb_suspend"), _win_checks.get("fast_startup"),
              len(_win_checks.get("hubs_sleepy") or []))


_last_recovery: dict = {}   # adapter name -> last Restart-NetAdapter attempt


def maybe_recover_tethers(links, dry_run):
    """Self-heal stale USB tethers: if Windows still shows a Remote NDIS
    adapter that isn't routing (classic after suspend/resume or fast startup),
    bounce it with Restart-NetAdapter — the no-replug recovery. Rate-limited
    to once per 5 minutes per adapter."""
    if dry_run:
        return
    active = {lk.if_index for lk in links}
    try:
        stale = netroute.stale_tether_adapters(active)
    except RuntimeError:
        return
    now = time.time()
    for name in stale:
        if now - _last_recovery.get(name, 0) < 300:
            continue
        _last_recovery[name] = now
        log.info("stale tether adapter '%s' — attempting Restart-NetAdapter recovery", name)
        try:
            netroute.restart_adapter(name)
        except RuntimeError as exc:
            log.warning("tether recovery failed for %s: %s", name, exc)


def update_advisor_state(links):
    """Track when each saved link was last seen / went unhealthy."""
    global _wifi_bad_cycles
    now = time.time()
    wireless_bad = False
    for lk in links:
        _last_seen[lk.name] = now
        if lk.healthy:
            _unhealthy_since.pop(lk.name, None)
        else:
            _unhealthy_since.setdefault(lk.name, now)
            if not lk.wired:
                wireless_bad = True
    _wifi_bad_cycles = (_wifi_bad_cycles + 1) if wireless_bad else 0


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


def write_status(links, chosen, cfg, dry_run, advice=None):
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
        on_known = any(s.lower() in current.lower() for s in ssids if s)
        rotate = on_known and _wifi_bad_cycles >= cfg["decision"]["fail_after_bad_probes"]
        if on_known and not rotate:
            return  # on one of our hotspots and it works — leave it
        _last_wifi_attempt = time.time()
        # If the current hotspot is up but has NO internet, rotate to the others
        # first — "keep the PC online from any available connection".
        candidates = ([s for s in ssids if s.lower() not in current.lower()] + ssids) if rotate else ssids
        for ssid in candidates:  # priority order; stop at the first that sticks
            log.info("Wi-Fi on '%s'%s — trying hotspot '%s'",
                     current or "nothing", " (no internet)" if rotate else "", ssid)
            netroute.wifi_connect(ssid, adapter)
            time.sleep(3)
            if ssid.lower() in netroute.wifi_connected_ssid(adapter).lower():
                log.info("Wi-Fi connected to '%s'", ssid)
                break
    except RuntimeError as exc:
        log.warning("wifi reconnect failed: %s", exc)


def run_cycle(cfg, dry_run):
    maybe_reconnect_wifi(cfg, dry_run)
    links = managed_links(cfg)
    refresh_win_checks(cfg)
    if not links:
        log.warning("no managed WAN links found (are the phones connected?)")
        advice = advisor.evaluate([], cfg, _last_seen, _unhealthy_since, _win_checks)
        toast_advice(advice, cfg)
        write_status([], None, cfg, dry_run, advice)
        return links

    ensure_probe_routes(links, dry_run)
    win = cfg["probe"]["loss_window"]
    for lk in links:
        st = _states.setdefault(lk.name, LinkState(win))
        probe_link(lk, cfg, st)
        log.debug("%s: %s %.0f ms loss=%.0f%% metric=%d",
                  lk.name, "UP  " if lk.healthy else "DOWN",
                  lk.latency_ms, st.loss_pct, lk.metric)

    update_advisor_state(links)
    maybe_recover_tethers(links, dry_run)
    chosen = choose_link(links, cfg, _current_name)
    apply_choice(chosen, links, cfg, dry_run)
    advice = advisor.evaluate(links, cfg, _last_seen, _unhealthy_since, _win_checks)
    toast_advice(advice, cfg)
    write_status(links, chosen, cfg, dry_run, advice)
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
    update_advisor_state(links)
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
    while True:
        try:
            cfg = load_config()  # reload so config edits / manual_pin apply live
            run_cycle(cfg, args.dry_run)
        except Exception as exc:  # noqa: BLE001 - never let the daemon die
            log.exception("cycle error: %s", exc)
        time.sleep(interval)


if __name__ == "__main__":
    main()
