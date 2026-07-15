"""
openwifi.py — last-resort, opt-in, UNTRUSTED open-Wi-Fi joining.

Only ever used when the user enables it AND every trusted link (their phones)
is down AND Windows Location is on. It scans for open (password-free) networks,
joins one that passes a captive-portal + real-internet check, exposes it as an
UNTRUSTED link (so it can never outrank a phone and is dropped the instant a
trusted link returns). All OS work is in netroute; this is the policy layer.

Open Wi-Fi is hostile infrastructure — the strict opt-in, last-resort, verify,
auto-drop, blocklist and localhost-only UI are the safety envelope.
"""

from __future__ import annotations

import logging
import time

import netroute

log = logging.getLogger("linkkeeper")

# module state (single Wi-Fi radio, single daemon)
_joined_ssid: str = ""          # the open SSID we deliberately joined, or ""
_last_scan: float = 0.0
_bad: dict[str, float] = {}      # ssid -> time it failed captive/verify (temp block)
_BAD_TTL = 600                   # re-try a failed open network after 10 min


def is_joined() -> bool:
    return bool(_joined_ssid)


def current_open() -> str:
    return _joined_ssid


def tag_links(links):
    """Mark the link we joined as untrusted + rename it, so ranking/UI treat it
    as an open network rather than a friendly hotspot."""
    if not _joined_ssid:
        return
    for lk in links:
        if not lk.wired and _joined_ssid.lower() in (lk.ssid or "").lower():
            lk.trusted = False
            lk.name = f"Open:{_joined_ssid}"


def maybe_join(cfg, dry_run=False):
    """No trusted link is up — try to get online via an open network. Returns
    the joined SSID or ''. Throttled; verifies real internet before trusting."""
    global _joined_ssid, _last_scan
    oc = cfg.get("wifi", {}).get("open_join", {})
    if not oc.get("enabled") or dry_run or _joined_ssid:
        return _joined_ssid
    if netroute.location_services_on() is False:
        return ""                                    # can't scan without Location
    if time.time() - _last_scan < oc.get("scan_interval_seconds", 30):
        return ""
    _last_scan = time.time()

    adapter = cfg.get("wifi", {}).get("adapter", "Wi-Fi")
    blocklist = {s.lower() for s in oc.get("blocklist", [])}
    min_sig = oc.get("min_signal_pct", 55)
    now = time.time()
    for net in netroute.wlan_scan_open():
        ssid, sig = net["ssid"], net["signal"]
        if ssid.lower() in blocklist or sig < min_sig:
            continue
        if now - _bad.get(ssid, 0) < _BAD_TTL:
            continue
        log.info("open-wifi: trying '%s' (%d%%)", ssid, sig)
        try:
            netroute.wlan_add_open_profile(ssid)
            netroute.wifi_connect(ssid, adapter)
        except RuntimeError as exc:
            log.warning("open-wifi: connect '%s' failed: %s", ssid, exc)
            _bad[ssid] = now
            netroute.wlan_remove_profile(ssid)
            continue
        time.sleep(4)
        src = _source_ip_for(ssid)
        if src and netroute.captive_portal_ok(src):
            log.info("open-wifi: joined '%s' (verified internet) — UNTRUSTED", ssid)
            _joined_ssid = ssid
            return ssid
        log.info("open-wifi: '%s' has no real internet (captive/none) — dropping", ssid)
        _bad[ssid] = now
        netroute.wlan_remove_profile(ssid)     # also disconnects
    return ""


def drop_if_joined(cfg, dry_run=False):
    """A trusted link is back (or open-join was disabled) — leave the open
    network and delete its profile so the radio returns to known hotspots."""
    global _joined_ssid
    if not _joined_ssid or dry_run:
        return
    log.info("open-wifi: trusted link restored — dropping open network '%s'", _joined_ssid)
    netroute.wlan_remove_profile(_joined_ssid)
    _joined_ssid = ""


def _source_ip_for(ssid: str) -> str:
    """Find the Wi-Fi link's current source IP after joining (via discovery)."""
    for lk in netroute.discover_wan_interfaces():
        if not lk.wired and ssid.lower() in (lk.ssid or "").lower():
            return lk.source_ip
    return ""
