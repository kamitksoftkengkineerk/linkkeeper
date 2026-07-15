"""
advisor.py — LinkKeeper's diagnostic advisor.

LinkKeeper's goal is to keep the PC online from ANY available connection.
This module watches the saved-connection registry and, when a connection is
missing/unhealthy or the safety margin shrinks (one link left, no carrier
diversity), produces actionable advice: exactly what to change on which
device so connections stop auto-switching off.

The advice appears in status.json (rendered by the dashboard), as toasts,
and via `python linkkeeper.py --advise`. The full researched guide lives in
GUIDE.md. Sources: Samsung/OnePlus community + docs and settings verified
live on this PC (2026-07-15).
"""

from __future__ import annotations

import time

# ---------------------------------------------------------------------------
# Device-specific prevention guides, keyed by link rule name.
# Researched One UI (M34) / OxygenOS (11R) / Windows behavior — see GUIDE.md
# for the long-form version with sources.
# ---------------------------------------------------------------------------

DEVICE_GUIDES: dict = {
    "M34-USB": {
        "device": "Samsung Galaxy M34 (One UI)",
        "prevent": [
            {
                "title": "Make USB tethering turn back ON automatically (the fix for auto switch-off)",
                "steps": [
                    "Enable Developer options: Settings → About phone → Software information → tap 'Build number' 7 times",
                    "Settings → Developer options → 'Default USB configuration' → select 'USB tethering'",
                    "Phone must be UNLOCKED when the cable connects for the default to apply",
                    "Never tap the 'USB for file transfer / MTP' notification while tethered — any USB-mode change kills tethering",
                ],
                "why": "Android turns USB tethering OFF on every cable/USB event by design; this Developer option is the only supported way to make it come back by itself.",
            },
            {
                "title": "Stop One UI from moving/killing mobile data",
                "steps": [
                    "Settings → Connections → SIM manager → Mobile data = SIM 0000 (unlimited 5G)",
                    "SIM manager → turn OFF 'Auto data switching'",
                    "SIM manager → turn OFF 'Switch mobile data during calls' if present",
                    "Settings → Connections → Data usage → turn OFF 'Set data limit' (it hard-cuts data at the threshold)",
                    "Data usage → 'Data saver' OFF (One UI blocks tethering entirely while Data saver is on)",
                ],
                "why": "One UI silently moves data between SIMs, cuts data at a limit, and refuses tethering under Data saver — each looks like 'tethering turned itself off'.",
            },
            {
                "title": "Stop power features from cutting the link",
                "steps": [
                    "Settings → Battery → 'Power saving' OFF (and never accept the low-battery prompt while tethering)",
                    "Settings → Modes and Routines → remove any mode/routine that sets Power saving ON or Mobile data OFF",
                    "Settings → Device care → Auto optimization → 'Auto restart' OFF (a 3 AM reboot leaves tethering off until you unlock)",
                ],
                "why": "Power saving and scheduled auto-restart are the top 'it died overnight' causes on Samsung.",
            },
            {
                "title": "Don't let the phone's own Wi-Fi steal the tether upstream",
                "steps": [
                    "While USB tethering, keep the M34's Wi-Fi OFF (quick tile)",
                    "Or: Settings → Connections → Wi-Fi → gear next to bad saved networks → 'Auto reconnect' OFF",
                ],
                "why": "USB tethering shares the phone's current default network — if the phone auto-joins a dead Wi-Fi, the PC's internet dies while everything still shows ON.",
            },
        ],
    },
    "OnePlus-USB": {
        "device": "OnePlus 11R (OxygenOS)",
        "prevent": [
            {
                "title": "Make USB tethering re-enable automatically",
                "steps": [
                    "Settings → About device → Version → tap 'Build number' 7 times",
                    "Settings → Additional settings → Developer options → 'Default USB configuration' → 'USB tethering'",
                    "Unlock the phone when plugging in; avoid tapping File transfer/MTP while tethered",
                    "Use a data cable into a rear motherboard USB port (hubs/flaky cables cause re-enumeration = tethering off)",
                ],
                "why": "Same Android rule as the M34: every cable event resets the toggle unless the default USB configuration is tethering.",
            },
            {
                "title": "Stop OxygenOS power features cutting data at idle",
                "steps": [
                    "Settings → Battery → More settings → 'Sleep standby optimization' OFF (kills ALL network during learned sleep hours)",
                    "Settings → Battery → Power Saving Mode OFF, and disable 'Turn on automatically at 20%'",
                    "Settings → About device → ⋮ → 'Auto system update' OFF (overnight OTA reboot = tethering off until unlock)",
                ],
                "why": "Sleep standby optimization and auto power-saving are the classic 'hotspot/tether died at 2 AM' causes on OnePlus.",
            },
        ],
    },
    "OnePlus-WiFi": {
        "device": "OnePlus 11R hotspot 'KKKKK'",
        "prevent": [
            {
                "title": "Keep the hotspot broadcasting",
                "steps": [
                    "Settings → Connection & sharing → Personal hotspot → 'Turn off hotspot automatically' OFF (verify it stuck)",
                    "Settings → Battery → More settings → 'Sleep standby optimization' OFF",
                    "Hotspot settings → Band → 2.4 GHz (OnePlus 11-series has known 5 GHz hotspot defects; 2.4 GHz is far more stable)",
                    "Keep the phone's own Wi-Fi OFF while hotspotting (auto-joining a saved Wi-Fi shuts the hotspot down)",
                ],
                "why": "Idle timeout, standby optimization, the 5 GHz defect, and Wi-Fi auto-join are the four OxygenOS hotspot killers.",
            },
        ],
    },
    "M34-WiFi": {
        "device": "Samsung M34 hotspot 'YOUR_HOTSPOT_SSID'",
        "prevent": [
            {
                "title": "Keep the M34 hotspot alive",
                "steps": [
                    "Settings → Connections → Mobile Hotspot and Tethering → Mobile Hotspot → Advanced → 'Turn off when no devices are connected' = Never",
                    "Keep mobile data ON for SIM 0000 (see M34-USB advice — same data rules apply)",
                    "Data saver must be OFF (One UI refuses to run the hotspot with Data saver on)",
                ],
                "why": "One UI hotspots auto-off after idle minutes by default, and Data saver blocks them outright.",
            },
        ],
    },
    "Bluetooth-PAN": {
        "device": "Phone Bluetooth tethering",
        "prevent": [
            {
                "title": "Optional last-resort link: enable Bluetooth tethering",
                "steps": [
                    "Phone: Settings → Connections → Mobile Hotspot and Tethering → Bluetooth tethering ON",
                    "PC: pair the phone, then Bluetooth devices → phone → 'Connect using → Access point'",
                ],
                "why": "Slow (~1-2 Mbps) but survives when USB and Wi-Fi both fail.",
            },
        ],
    },
}

WINDOWS_GUIDE = {
    "usb_suspend": {
        "title": "Windows: disable USB selective suspend (silently suspends the phone tether)",
        "steps": [
            "Elevated PowerShell:",
            "powercfg /setacvalueindex SCHEME_CURRENT 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0",
            "powercfg /setdcvalueindex SCHEME_CURRENT 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0",
            "powercfg /setactive SCHEME_CURRENT",
        ],
        "why": "Windows suspends 'idle' USB ports; a suspended RNDIS tether drops link and the phone turns tethering off — the invisible cable-unplug.",
    },
    "fast_startup": {
        "title": "Windows: disable Fast Startup (tethers come back broken after shutdown)",
        "steps": [
            "Elevated PowerShell:",
            "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Power' -Name HiberbootEnabled -Value 0 -Type DWord",
            "(Takes effect from the next shutdown; plain Restart never uses fast startup)",
        ],
        "why": "Fast Startup resumes stale USB driver state from disk — the tether adapter appears but never gets internet until you replug. This PC currently has it ON.",
    },
    "usb_hub_sleep": {
        "title": "Windows: stop USB hubs powering off (they suspend the phone hanging off them)",
        "steps": [
            "Elevated PowerShell:",
            "Get-CimInstance -Namespace root/wmi -ClassName MSPower_DeviceEnable | Where-Object { $_.InstanceName -like 'USB\\ROOT_HUB*' -or $_.InstanceName -like 'USB\\VID_*' } | Set-CimInstance -Property @{ Enable = $false }",
            "(Equivalent to unticking 'Allow the computer to turn off this device' on each USB hub in Device Manager)",
        ],
        "why": "The RNDIS tether itself has no power checkbox — its parent USB hubs do, and they default to 'may power off', taking the phone down with them.",
    },
}


# ---------------------------------------------------------------------------
# evaluation
# ---------------------------------------------------------------------------

def _advice(aid, severity, title, steps, why):
    return {"id": aid, "severity": severity, "title": title,
            "steps": list(steps), "why": why}


def evaluate(links, cfg, last_seen, unhealthy_since, win_checks, now=None):
    """Return the list of currently-active advice items."""
    now = now or time.time()
    adv_cfg = cfg.get("advisor", {})
    if not adv_cfg.get("enabled", True):
        return []
    missing_after = adv_cfg.get("missing_after_seconds", 90)

    advice = []
    healthy = [lk for lk in links if lk.healthy]
    by_name = {lk.name: lk for lk in links}

    # --- expected link missing entirely (adapter gone) ---
    for rule in cfg.get("links", []):
        name = rule.get("name")
        if not name or not rule.get("expected"):
            continue
        if name in by_name:
            continue
        seen = last_seen.get(name)
        gone_for = (now - seen) if seen else (now - last_seen.get("_start", now))
        if gone_for < missing_after:
            continue
        guide = DEVICE_GUIDES.get(name, {})
        steps = []
        for g in guide.get("prevent", []):
            steps.extend(g["steps"])
        advice.append(_advice(
            f"missing:{name}", "warn",
            f"{name} has disappeared — {guide.get('device', name)} needs attention",
            steps or ["Reconnect the device and re-enable tethering."],
            "The adapter is gone from Windows: cable unplugged, tethering toggled off on the phone, or USB power-saving suspended it.",
        ))

    # --- link present but no internet (gray failure) ---
    for lk in links:
        if lk.healthy:
            continue
        since = unhealthy_since.get(lk.name)
        if not since or now - since < missing_after:
            continue
        guide = DEVICE_GUIDES.get(lk.name, {})
        steps = []
        for g in guide.get("prevent", []):
            steps.extend(g["steps"])
        advice.append(_advice(
            f"unhealthy:{lk.name}", "warn",
            f"{lk.name} is connected but has NO internet",
            steps or ["Check mobile data is on and the SIM has coverage."],
            "The link exists but data isn't flowing — usually mobile data off, a data limit, Data saver, or power saving on the phone.",
        ))

    # --- safety margin ---
    if len(healthy) == 0 and links:
        advice.append(_advice(
            "offline", "crit", "NO working internet connection",
            ["Turn mobile data ON on either phone",
             "Re-enable USB tethering / hotspot",
             "Check cables"],
            "Every known link is down.",
        ))
    elif len(healthy) == 1:
        lone = healthy[0]
        advice.append(_advice(
            "single-link", "warn",
            f"Only ONE live connection ({lone.name}) — one failure = offline",
            ["Bring back a second link (other phone's USB tether or hotspot)",
             "See the per-device advice for why it dropped"],
            "No backup means the next drop takes the PC offline.",
        ))

    # --- carrier diversity ---
    carriers = {}
    for lk in healthy:
        c = _carrier_for(lk.name, cfg)
        if c:
            carriers.setdefault(c, []).append(lk.name)
    if len(healthy) >= 2 and len(carriers) == 1:
        only = next(iter(carriers))
        advice.append(_advice(
            "no-diversity", "info",
            f"All live links ride {only} — a carrier outage kills everything",
            ["Bring up a link on the other carrier "
             "(the other phone's USB tether or hotspot)"],
            "Different carriers fail independently; same-carrier links share one point of failure.",
        ))

    # --- Windows power settings (checked live, cached) ---
    if win_checks.get("usb_suspend") is True:
        g = WINDOWS_GUIDE["usb_suspend"]
        advice.append(_advice("win:usb-suspend", "warn", g["title"], g["steps"], g["why"]))
    if win_checks.get("fast_startup") is True:
        g = WINDOWS_GUIDE["fast_startup"]
        advice.append(_advice("win:fast-startup", "info", g["title"], g["steps"], g["why"]))
    if win_checks.get("hubs_sleepy"):
        g = WINDOWS_GUIDE["usb_hub_sleep"]
        advice.append(_advice("win:hub-sleep", "info", g["title"], g["steps"], g["why"]))

    return advice


def _carrier_for(name, cfg):
    for rule in cfg.get("links", []):
        if rule.get("name") == name:
            return rule.get("carrier", "")
    return ""


def full_checklist() -> str:
    """The complete prevention guide as printable text (for --advise)."""
    lines = ["LinkKeeper prevention checklist — stop devices auto-killing connections",
             "=" * 74]
    for name, guide in DEVICE_GUIDES.items():
        lines.append(f"\n[{name}]  {guide['device']}")
        for g in guide["prevent"]:
            lines.append(f"  * {g['title']}")
            for s in g["steps"]:
                lines.append(f"      - {s}")
            lines.append(f"      why: {g['why']}")
    lines.append("\n[Windows]")
    for g in WINDOWS_GUIDE.values():
        lines.append(f"  * {g['title']}")
        for s in g["steps"]:
            lines.append(f"      - {s}")
        lines.append(f"      why: {g['why']}")
    return "\n".join(lines)
