# LinkKeeper — Keep-Alive Guide

The goal: **the PC stays online from any available connection, wired or wireless.**
LinkKeeper handles monitoring, best-link selection, failover, Wi-Fi reconnection,
and stale-tether recovery automatically. What it *can't* do is change settings on
your phones — this guide is the one-time setup that stops the phones (and Windows)
from auto-killing connections. Researched + verified 2026-07-15; the advisor
(`python linkkeeper.py --advise`, dashboard Advice panel) references these.

---

## Samsung Galaxy M34 (One UI) — the USB-tether workhorse

### 1. THE fix: make USB tethering re-enable itself
Android turns USB tethering OFF on every cable unplug, USB re-enumeration, or
USB-mode change — by design, every time. The only supported way to make it come
back automatically:

1. Settings → About phone → Software information → tap **Build number** 7×
2. Settings → **Developer options** → **Default USB configuration** → **USB tethering**
3. The default only applies if the phone is **unlocked** when the cable connects
4. Never tap the "USB for file transfer / MTP" notification while tethered —
   any mode change kills tethering (don't browse the phone from Explorer)

### 2. Keep mobile data alive on SIM 0000
- SIM manager → **Mobile data = 0000** (the unlimited-5G SIM)
- SIM manager → **Auto data switching OFF** (silently moves data between SIMs;
  every switch drops tethered connections)
- SIM manager → **Switch mobile data during calls OFF** (if present)
- Connections → Data usage → **Set data limit OFF** — when on, One UI *disables
  mobile data entirely* at the threshold and keeps it off till the next cycle
- Data usage → **Data saver OFF** — One UI refuses tethering/hotspot while it's on

### 3. Power features
- Battery → **Power saving OFF**; never accept the low-battery "turn on power
  saving?" prompt while tethering
- **Modes and Routines** → remove any mode/routine that turns Power saving ON,
  Mobile data OFF, or Airplane mode ON (hidden cause of "died at night")
- Device care → Auto optimization → **Auto restart OFF** (a scheduled 3 AM reboot
  leaves tethering off until you unlock the phone)

### 4. Wi-Fi upstream steal
USB tethering shares the phone's *current default network*. If the M34 auto-joins
some saved Wi-Fi with no internet, the PC dies while every toggle still shows ON.
- Keep the M34's own **Wi-Fi OFF** while it's the USB tether, or disable
  Auto-reconnect on bad saved networks
- Hotspot: Mobile Hotspot → Advanced → **Turn off when no devices connected: Never**

---

## OnePlus 11R (OxygenOS) — hotspot + occasional wired

### 1. Same USB fix
- Settings → About device → Version → tap **Build number** 7×
- Settings → Additional settings → **Developer options** → **Default USB
  configuration** → **USB tethering** (unlock at plug-in time)

### 2. Hotspot keep-alive
- Connection & sharing → Personal hotspot → **Turn off hotspot automatically OFF**
- Hotspot settings → **Band: 2.4 GHz** — the OnePlus 11 series has acknowledged
  5 GHz hotspot defects; 2.4 GHz is slower but far more stable
- Keep the phone's own **Wi-Fi OFF** while hotspotting (auto-joining a saved
  network shuts the hotspot down)

### 3. Power features (the "died at 2 AM" causes)
- Battery → More settings → **Sleep standby optimization OFF** — learns your
  sleep hours and cuts ALL network during them; ships enabled
- Battery → **Power Saving Mode OFF** + disable "turn on automatically at 20%"
  (Power Saving Mode kills the hotspot outright)
- About device → ⋮ → **Auto system update OFF** (overnight OTA reboot = hotspot
  and tethering stay off until unlock)

---

## Windows 11 (this PC) — verified live

Run these once from an **elevated PowerShell** (all three were found active/
relevant on this machine):

```powershell
# 1. USB selective suspend OFF (AC + DC) — the invisible cable-unplug
powercfg /setacvalueindex SCHEME_CURRENT 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0
powercfg /setdcvalueindex SCHEME_CURRENT 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0
powercfg /setactive SCHEME_CURRENT

# 2. Fast Startup OFF — tethers otherwise come back broken after a shutdown
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' -Name HiberbootEnabled -Value 0 -Type DWord

# 3. Stop USB hubs powering off (they suspend the phone hanging off them —
#    the RNDIS tether itself has no power checkbox; its parent hubs do)
Get-CimInstance -Namespace root/wmi -ClassName MSPower_DeviceEnable |
  Where-Object { $_.InstanceName -like 'USB\ROOT_HUB*' -or $_.InstanceName -like 'USB\VID_*' } |
  Set-CimInstance -Property @{ Enable = $false }

# 4. Never idle-sleep on AC (sleep suspends the whole USB bus)
powercfg /change standby-timeout-ac 0
```

LinkKeeper's advisor re-checks 1–3 every 30 min and warns on the dashboard if
any regress (e.g. after a Windows update or power-plan switch).

### What LinkKeeper now self-heals (no action needed)
- **Stale tether recovery**: if Windows still shows a Remote NDIS adapter that
  stopped routing (post-sleep/fast-startup state), the daemon bounces it with
  `Restart-NetAdapter` automatically — the no-replug fix (max once/5 min).
- **Wi-Fi**: reconnects to the best saved hotspot (KKKKK → YOUR_HOTSPOT_SSID) and
  rotates to the other hotspot if the current one has no internet.
- **Everything else**: probing, best-link choice, failover, switch-back, toasts.

---

## Physical setup rules of thumb
- Rear-panel USB ports, known **data** cables (charge-only cables = no tether)
- Both phones can USB-tether simultaneously; Bluetooth PAN works as a slow
  last resort; the single Wi-Fi radio holds one hotspot at a time
- Keep the two live links on **different carriers** (Jio + Airtel) so a carrier
  outage can't kill both
