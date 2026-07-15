"""
netroute.py — thin wrapper over Windows networking cmdlets for LinkKeeper.

All the OS-touching logic lives here so the daemon stays readable:
  * discover_wan_interfaces() -> list of candidate WAN links (default-route ifaces)
  * get_interface_metric() / set_interface_metric()
  * flush_dns()

Everything is done by shelling out to PowerShell's Net* cmdlets and parsing
JSON, so there are no third-party dependencies (stdlib only). Read operations
work unprivileged; set_interface_metric() requires an elevated process.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field


# ---- low-level PowerShell helper -------------------------------------------

# Hide the console window each PowerShell child would otherwise flash on screen
# (matters when the daemon runs headless under pythonw). CREATE_NO_WINDOW = 0x08000000.
_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)

# Force UTF-8 out so non-ASCII SSIDs/adapter names aren't mangled by the OEM
# codepage (cp437) vs Python's cp1252 default. Prefixed to every script.
_UTF8 = "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; "

# Default timeout so one hung PowerShell child (WMI stalls during USB
# re-enumeration, wedged WLAN service) can never freeze the single-threaded
# daemon loop forever.
_PS_TIMEOUT = 15


def ps_quote(value: str) -> str:
    """Escape a value for a single-quoted PowerShell string (double the quotes).
    Single-quoted PS strings have no other metacharacters, so this also blocks
    injection via adapter names / SSIDs / notification text."""
    return str(value).replace("'", "''")


def _ps(script: str, timeout: int = _PS_TIMEOUT) -> str:
    """Run a PowerShell snippet and return stdout (raises on non-zero exit or
    timeout). UTF-8 output; hard timeout so a hung child can't wedge the loop."""
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", _UTF8 + script],
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            creationflags=_NO_WINDOW,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"PowerShell timed out after {timeout}s: {script[:80]}")
    if proc.returncode != 0:
        raise RuntimeError(
            f"PowerShell failed ({proc.returncode}): {(proc.stderr or '').strip() or script}"
        )
    return (proc.stdout or "").strip()


def _ps_json(script: str):
    """Run PowerShell, parse its JSON output. Always returns a list."""
    out = _ps(script + " | ConvertTo-Json -Depth 4 -Compress")
    if not out:
        return []
    data = json.loads(out)
    return data if isinstance(data, list) else [data]


# ---- data model -------------------------------------------------------------

@dataclass
class WanLink:
    if_index: int
    alias: str
    source_ip: str
    gateway: str
    metric: int
    description: str = ""   # adapter hardware description (e.g. "Remote NDIS ...")
    mac: str = ""           # adapter MAC
    vid: str = ""           # USB vendor id (e.g. 04E8 Samsung, distinguishes tethers)
    wired: bool = True      # wired (USB tether / Ethernet) vs wireless (Wi-Fi)
    ssid: str = ""          # for wireless links, the hotspot SSID it's connected to
    # filled in by config matching / probing later
    name: str = ""
    preference: int = 100
    probe_target: str = ""  # dedicated IP this link is health-checked against
    jitter_ms: float = field(default=0.0, compare=False)
    loss_pct: float = field(default=0.0, compare=False)
    score: float = field(default=float("inf"), compare=False)
    healthy: bool = field(default=False, compare=False)
    latency_ms: float = field(default=float("inf"), compare=False)


# ---- discovery --------------------------------------------------------------

# One PowerShell script that gathers everything about every default-route
# interface in a single spawn (route + source IP + metric + description), so a
# probe cycle costs one child process instead of ~7. Runs headless.
_DISCOVER_PS = r"""
$out = foreach ($r in (Get-NetRoute -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4 -ErrorAction SilentlyContinue)) {
  $idx = $r.ifIndex
  $ip = (Get-NetIPAddress -InterfaceIndex $idx -AddressFamily IPv4 -ErrorAction SilentlyContinue |
         Where-Object { $_.IPAddress -notlike '169.254.*' } | Select-Object -First 1).IPAddress
  $mi = (Get-NetIPInterface -InterfaceIndex $idx -AddressFamily IPv4 -ErrorAction SilentlyContinue).InterfaceMetric
  $na = Get-NetAdapter -InterfaceIndex $idx -ErrorAction SilentlyContinue
  $w32 = Get-CimInstance Win32_NetworkAdapter -Filter "InterfaceIndex=$idx" -ErrorAction SilentlyContinue
  $vid = ''
  if ($w32.PNPDeviceID -match 'VID_([0-9A-Fa-f]{4})') { $vid = $Matches[1] }
  $wireless = ($na.PhysicalMediaType -like '*802.11*') -or ($na.MediaType -like '*802.11*') -or ($na.InterfaceDescription -like '*Wi-Fi*') -or ($na.InterfaceDescription -like '*Wireless*') -or ($na.InterfaceDescription -like '*Bluetooth*') -or ($na.PhysicalMediaType -like '*Bluetooth*')
  $ssid = (Get-NetConnectionProfile -InterfaceIndex $idx -ErrorAction SilentlyContinue).Name
  [pscustomobject]@{ ifIndex=$idx; NextHop=$r.NextHop; Alias=$r.InterfaceAlias; IP=$ip; Metric=$mi;
                     Desc=$na.InterfaceDescription; Mac=$na.MacAddress; Vid=$vid; Wired=(-not $wireless); Ssid=$ssid }
}
$out | ConvertTo-Json -Depth 4 -Compress
"""


def discover_wan_interfaces() -> list[WanLink]:
    """
    Return every interface that currently owns an IPv4 default route
    (0.0.0.0/0) — i.e. a real internet-providing link. Loopback and
    interfaces without a usable source IP are skipped. Single PS spawn.
    """
    out = _ps(_DISCOVER_PS, timeout=30)  # CIM per-adapter can be slow
    if not out:
        return []
    data = json.loads(out)
    rows = data if isinstance(data, list) else [data]

    links: list[WanLink] = []
    seen: set[int] = set()
    for r in rows:
        idx = int(r["ifIndex"])
        if idx in seen:
            continue
        gateway = str(r.get("NextHop", "") or "").strip()
        source_ip = str(r.get("IP", "") or "").strip()
        if not gateway or gateway == "0.0.0.0" or not source_ip:
            continue
        links.append(
            WanLink(
                if_index=idx,
                alias=str(r.get("Alias", "") or "").strip(),
                source_ip=source_ip,
                gateway=gateway,
                metric=int(r.get("Metric") or -1),
                description=str(r.get("Desc", "") or "").strip(),
                mac=str(r.get("Mac", "") or "").strip(),
                vid=str(r.get("Vid", "") or "").strip().upper(),
                wired=bool(r.get("Wired", True)),
                ssid=str(r.get("Ssid", "") or "").strip(),
            )
        )
        seen.add(idx)
    return links


# ---- Wi-Fi auto-reconnect + toast notifications -----------------------------

def wifi_connected_ssid(adapter: str = "Wi-Fi") -> str:
    """Return the network name the Wi-Fi adapter is on (= SSID), or ''.
    Uses Get-NetConnectionProfile — unlike netsh it needs neither Location
    services nor elevation. Windows may append ' 2' to duplicate names, so
    callers should match by substring rather than equality."""
    try:
        out = _ps(
            f"(Get-NetConnectionProfile -InterfaceAlias '{ps_quote(adapter)}' "
            "-ErrorAction SilentlyContinue).Name"
        )
    except RuntimeError:
        return ""
    return out.strip()


def wifi_connect(ssid: str, adapter: str = "Wi-Fi") -> bool:
    """Associate the Wi-Fi radio with a saved profile named `ssid`. Calls netsh
    directly (argv list, no PowerShell parsing) so SSIDs with $, backticks or
    quotes are passed literally. Returns True only if netsh reports success;
    logs the reason (e.g. 'no profile') otherwise."""
    try:
        proc = subprocess.run(
            ["netsh", "wlan", "connect", f"name={ssid}",
             f"ssid={ssid}", f"interface={adapter}"],
            capture_output=True, encoding="utf-8", errors="replace",
            creationflags=_NO_WINDOW, timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f"netsh wlan connect failed: {exc}")
    out = (proc.stdout or "").strip()
    ok = proc.returncode == 0 and "request was completed successfully" in out.lower()
    if not ok:
        raise RuntimeError(out or f"netsh exit {proc.returncode}")
    return True


# ---- Windows power-setting checks (things that silently kill tethers) -------
# Findings verified live on this PC 2026-07-15: selective-suspend output must be
# parsed by the last two hex indexes (labels are localized); the RNDIS device
# has no power checkbox but its parent USB hubs do (MSPower_DeviceEnable);
# Get-NetAdapterPowerManagement errors out on this rig, so it is not used.

_USB_SUBGROUP = "2a737441-1930-4402-8d77-b2bebba308a3"
_USB_SUSPEND = "48e6b7a6-50f5-4782-a5d4-53bb8f07e226"


def usb_selective_suspend_enabled() -> bool | None:
    """True if USB selective suspend is enabled on AC or DC (it can suspend an
    idle RNDIS tether, which makes the phone drop USB tethering). None if the
    setting can't be read. Locale-proof: parses the last two hex indexes
    (AC first, DC second) instead of localized label text."""
    try:
        out = _ps(f"powercfg /q SCHEME_CURRENT {_USB_SUBGROUP} {_USB_SUSPEND}")
    except RuntimeError:
        return None
    import re
    vals = re.findall(r"0x[0-9A-Fa-f]{8}", out)
    if len(vals) < 2:
        return None
    ac, dc = int(vals[-2], 16), int(vals[-1], 16)
    return ac == 1 or dc == 1


def fast_startup_enabled() -> bool | None:
    """True if Windows Fast Startup (hiberboot) is on — it resumes stale USB
    driver state after shutdown, leaving tethers 'present but broken'."""
    try:
        out = _ps(
            "(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Power' "
            "-Name HiberbootEnabled -ErrorAction SilentlyContinue).HiberbootEnabled"
        )
    except RuntimeError:
        return None
    out = out.strip()
    return None if not out else out == "1"


def usb_hubs_allowed_to_sleep() -> list[str]:
    """USB hub instances Windows may power off (suspending everything hanging
    off them, including phone tethers). The RNDIS device itself exposes no
    power setting — the hubs above it are what matter."""
    try:
        out = _ps(
            "Get-CimInstance -Namespace root/wmi -ClassName MSPower_DeviceEnable "
            "-ErrorAction SilentlyContinue | Where-Object { $_.Enable -and "
            "($_.InstanceName -like 'USB\\ROOT_HUB*' -or $_.InstanceName -like 'USB\\VID_*') } | "
            "Select-Object -ExpandProperty InstanceName"
        )
    except RuntimeError:
        return []
    return [l.strip() for l in out.splitlines() if l.strip()]


def stale_tether_adapters(active_if_indexes: set) -> list[str]:
    """Names of Remote NDIS adapters Windows can see that are NOT currently
    routing (stale after suspend/resume, or half-enumerated)."""
    try:
        out = _ps(
            "Get-NetAdapter -ErrorAction SilentlyContinue | "
            "Where-Object { $_.InterfaceDescription -match 'Remote NDIS' } | "
            "ForEach-Object { \"$($_.ifIndex)|$($_.Name)|$($_.Status)\" }"
        )
    except RuntimeError:
        return []
    stale = []
    for line in out.splitlines():
        parts = line.strip().split("|")
        if len(parts) != 3:
            continue
        idx, name, status = parts
        if int(idx) not in active_if_indexes and status in ("Up", "Disconnected", "Disabled"):
            stale.append(name)
    return stale


def restart_adapter(name: str) -> None:
    """Bounce a network adapter (Restart-NetAdapter) — recovers a stale RNDIS
    tether without physically replugging the cable. Needs elevation. Real
    failures surface (RuntimeError) instead of being swallowed by 'exit 0'."""
    _ps(
        f"try {{ Restart-NetAdapter -Name '{ps_quote(name)}' -Confirm:$false "
        f"-ErrorAction Stop; exit 0 }} catch {{ Write-Error $_; exit 1 }}"
    )


def notify(message: str, title: str = "LinkKeeper") -> None:
    """Best-effort Windows toast (no third-party modules)."""
    script = (
        "[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType=WindowsRuntime] | Out-Null;"
        "$t=[Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02);"
        "$x=$t.GetElementsByTagName('text');"
        f"$x.Item(0).AppendChild($t.CreateTextNode('{ps_quote(title)}'))|Out-Null;"
        f"$x.Item(1).AppendChild($t.CreateTextNode('{ps_quote(message)}'))|Out-Null;"
        "$n=[Windows.UI.Notifications.ToastNotification]::new($t);"
        "$id='{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\WindowsPowerShell\\v1.0\\powershell.exe';"
        "[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($id).Show($n); exit 0"
    )
    try:
        _ps(script)
    except RuntimeError:
        pass  # notifications are best-effort


def _alias(if_index: int) -> str:
    try:
        rows = _ps_json(
            f"Get-NetIPInterface -InterfaceIndex {if_index} -AddressFamily IPv4 "
            "-ErrorAction SilentlyContinue | Select-Object InterfaceAlias"
        )
    except RuntimeError:
        return str(if_index)  # suppressed pipeline error still exits 1 on Win
    return str(rows[0]["InterfaceAlias"]).strip() if rows else str(if_index)


# ---- metric read / write ----------------------------------------------------

def get_interface_metric(if_index: int) -> int:
    try:
        rows = _ps_json(
            f"Get-NetIPInterface -InterfaceIndex {if_index} -AddressFamily IPv4 "
            "-ErrorAction SilentlyContinue | Select-Object InterfaceMetric"
        )
    except RuntimeError:
        return -1
    return int(rows[0]["InterfaceMetric"]) if rows else -1


def set_interface_metric(if_index: int, metric: int) -> None:
    """Pin an interface's metric (disables Windows' automatic metric).
    Requires an elevated process."""
    _ps(
        f"Set-NetIPInterface -InterfaceIndex {if_index} -AddressFamily IPv4 "
        f"-AutomaticMetric Disabled -InterfaceMetric {metric}"
    )


def flush_dns() -> None:
    try:
        _ps("Clear-DnsClientCache")
    except RuntimeError:
        pass  # non-fatal


# ---- per-link probe routes --------------------------------------------------
# Pinning a /32 host route for a link's probe target via that link's gateway
# forces the health probe out that specific interface, regardless of which
# link is currently the default route. This is what lets us tell whether the
# BACKUP link actually has internet (source-IP binding alone can't, on Windows).
# Routes go in the ActiveStore so they vanish on reboot; the daemon re-pins.

def add_host_route(target: str, if_index: int, gateway: str) -> None:
    # Explicit exit codes: PowerShell otherwise returns 1 whenever the last
    # statement's $? is false (e.g. right after a handled error).
    _ps(
        f"try {{ New-NetRoute -DestinationPrefix '{target}/32' -InterfaceIndex {if_index} "
        f"-NextHop '{gateway}' -PolicyStore ActiveStore -ErrorAction Stop | Out-Null; exit 0 }} "
        f"catch {{ Write-Error $_; exit 1 }}"
    )


def del_host_route(target: str) -> None:
    # Remove this /32 from ALL interfaces; missing route is a no-op. Force exit 0.
    _ps(
        f"try {{ Remove-NetRoute -DestinationPrefix '{target}/32' -Confirm:$false "
        f"-ErrorAction Stop }} catch {{ }}; exit 0"
    )


if __name__ == "__main__":
    # Quick manual check: python netroute.py
    for link in discover_wan_interfaces():
        print(
            f"[{link.if_index:>3}] {link.alias:<28} ip={link.source_ip:<15} "
            f"gw={link.gateway:<15} metric={link.metric}"
        )
