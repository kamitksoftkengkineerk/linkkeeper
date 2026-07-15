# LinkKeeper

Keeps this Windows PC's internet **always on** by riding the best healthy phone
link and failing over automatically when one degrades or dies. No root, no
subscription, stdlib-only Python.

## How it works

1. Discovers every interface that owns a default route (your USB tether + Wi-Fi
   hotspot).
2. Every few seconds, TCP-connects to `1.1.1.1` / `8.8.8.8` / `9.9.9.9`
   **bound to each link's own IP**, measuring latency + loss.
3. Picks the best healthy link (preference, then latency) and points Windows'
   default route at it by rewriting the interface **metric**. Failover away is
   fast; switch-back waits out a dwell time so links don't flap.

## Physical setup

- **Primary — Samsung M34 via USB tether.** Enable *Settings → Connections →
  Mobile Hotspot and Tethering → USB tethering*. Set M34's **active data SIM to
  `0000`** (its only unlimited-5G SIM). Shows up on the PC as an "Ethernet"
  (Remote NDIS) adapter.
- **Secondary — OnePlus 11R Wi-Fi hotspot.** Either SIM (both unlimited 5G).
  Connect the PC's Wi-Fi to it.

Both links live at once = seamless failover. Spare SIMs (OnePlus 2nd SIM, or
M34 `3084`) are manual backups — swap the active data SIM in phone settings if a
live SIM fails hard.

## Run it

```powershell
# read-only checks (no admin needed)
python linkkeeper.py --status        # show each link's health right now
python linkkeeper.py --once --dry-run  # one decide cycle, no changes

# live (needs admin to change metrics)
python linkkeeper.py --verbose       # run in foreground, log to console

# install as a logon service (elevated PowerShell)
.\install_task.ps1 -Run              # register + start
.\install_task.ps1 -Remove           # uninstall
```

Logs: `logs\linkkeeper.log`.

## Config (`config.json`)

- `probe.interval_seconds` / `targets` / `timeout_seconds` — how often / where /
  how patiently it probes.
- `decision.fail_after_bad_probes` — consecutive misses before failing away.
- `decision.switchback_dwell_seconds` — anti-flap hold before switching back.
- `decision.latency_margin_ms` — how much faster a rival must be to steal primary.
- `links[].match_alias` — substring of the Windows adapter name to manage (e.g.
  `Ethernet`, `Wi-Fi`). Leave `links` empty `[]` to auto-manage every default-route
  interface. `preference` — lower = preferred when both are healthy.
- `manual_pin` — set to a link `name` to force it (while healthy); `null` = auto.
- `speedtest.enabled` — OFF by default (active speed tests cost mobile data).

## Per-link health probing (important on Windows)

Windows uses the *weak host model*: binding a socket to a link's source IP does
**not** reliably send traffic out that interface when another link is the
default route. So a naive probe can't tell whether the **backup** link has
internet — it always looks dead. That would break failover for "gray failures"
(link stays connected but its data dies).

Fix: each link gets a dedicated probe target from `probe.pool` (e.g. M34 →
`1.0.0.1`, OnePlus → `9.9.9.9`) and the daemon pins a `/32` host route for that
target via the link's own gateway (`New-NetRoute`, ActiveStore, re-pinned on
reconnect). The health check then reaches each link over *its own* path
regardless of which link is primary. Pool IPs are deliberately not common DNS
(1.1.1.1 / 8.8.8.8) so pinning them doesn't hijack real DNS.

`--status` run un-elevated can't pin routes, so it falls back to shared targets
and may show the backup as down — trust the running daemon's dashboard instead.

## Speed / quality test

`python speedtest.py` (run elevated) measures each link's latency, jitter,
download and upload against speed.cloudflare.com. Because of the weak-host issue
above, it can't measure a backup link by binding — instead it briefly forces
each link to be the sole default route (via interface metrics), measures over
the real route with parallel streams, then restores and restarts the daemon.
Uses mobile data; fine on unlimited 5G for an on-demand check.

## Advisor — it tells you WHY a connection died and how to stop it

The daemon watches the saved-connection registry and raises advice (dashboard
"Advice" panel, toasts, and `python linkkeeper.py --advise`) when:
an expected link vanishes or has no internet · only one link is left · all live
links share one carrier · Windows power settings that kill tethers are enabled
(USB selective suspend, Fast Startup, sleepy USB hubs — all checked live every
30 min). Each item carries exact device steps; the full researched guide is in
[GUIDE.md](GUIDE.md). **The #1 fix:** on both phones set Developer options →
*Default USB configuration = USB tethering* so tethering re-enables itself.

It also **self-heals stale tethers**: a Remote NDIS adapter that's present but
not routing gets bounced with `Restart-NetAdapter` automatically (no replug).

## Best-link selection & extras

- **Any connection technology:** with `manage_unmatched: true` LinkKeeper monitors *every*
  interface that provides internet — USB tether, Ethernet, Wi-Fi, Bluetooth PAN, a new phone,
  whatever — even if no `links` rule names it. The `exclude` list skips virtual/VPN/tunnel
  adapters (TAP, Hyper-V, VMware, WSL, Speedify, Wintun, …). Named `links` rules just add
  friendly names and tell USB tethers apart by `vid`. **Bluetooth PAN** is classified wireless
  and, being slow/high-latency, naturally ranks last — a true last-resort fallback (enable it via
  phone Bluetooth-tethering + PC pair + *Connect using → Access point*).
- **Quality-based auto-pick:** the "best" link is chosen **wired-first** (USB tether /
  Ethernet beat Wi-Fi), then by lowest **quality score = latency + `jitter_weight`×jitter +
  `loss_weight_ms_per_pct`×loss%**. A wired link keeps its class privilege only while its
  loss stays under `wired_degraded_loss_pct` — a flapping USB tether can't beat a solid
  hotspot (this thrashed live until loss-aware ranking was added). It only switches away
  from a healthy primary if a rival is a better class or beats its score by more than
  `decision.switch_margin_ms`, after `switchback_dwell_seconds` (anti-flap).
  Set `decision.prefer_wired: false` to rank purely by score.
- **Multiple USB tethers:** link rules can include `vid` (USB vendor id) and/or `media`
  ("wired"/"wireless") alongside `match_alias`, so two "Remote NDIS" tethers are told apart.
  Samsung = `04E8`. **When you first USB-tether the OnePlus, verify its VID** (the config
  guesses `2A70`): `Get-CimInstance Win32_NetworkAdapter -Filter "InterfaceIndex=<idx>" |
  Select PNPDeviceID` and update the `OnePlus-USB` rule if it differs. Once correct, cabling the
  OnePlus makes it a wired link that auto-wins primary whenever its latency beats M34.
- **Wi-Fi auto-reconnect:** `wifi.autoreconnect` re-associates the PC to `wifi.ssid` (KKKKK)
  via `netsh wlan connect` whenever it's not connected, so the OnePlus backup self-heals.
- **Notifications:** `notify.enabled` pops a Windows toast on every primary switch.

## Notes / limits

- `match_alias: "Ethernet"` also matches a wired LAN named "Ethernet". If you
  ever plug in real Ethernet, tighten the alias (e.g. the exact tether adapter
  name from `Get-NetAdapter`).
- "Fastest" ranking is latency-based by default; enable `speedtest` for true
  throughput ranking at the cost of periodic small downloads.
- Bonding (combining both links' speed) is a separate, later project — see the
  plan (Speedify or self-hosted OpenMPTCProuter on a VPS).
