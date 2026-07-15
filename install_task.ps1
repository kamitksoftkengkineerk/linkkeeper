<#
    install_task.ps1 — register (or remove) LinkKeeper as a logon Scheduled Task.

    The task runs the daemon headless (pythonw) at user logon, with highest
    privileges (needed to change interface metrics) and auto-restart on failure.

    Usage (run from an ELEVATED PowerShell):
        .\install_task.ps1              # install / update the task
        .\install_task.ps1 -Remove      # remove the task
        .\install_task.ps1 -Run         # install then start it immediately
#>

param(
    [switch]$Remove,
    [switch]$Run
)

$ErrorActionPreference = "Stop"
$TaskName = "LinkKeeper"
$Here     = Split-Path -Parent $MyInvocation.MyCommand.Definition
$Script   = Join-Path $Here "linkkeeper.py"

# --- admin check ------------------------------------------------------------
$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "Run this from an elevated PowerShell (Run as administrator)."
    exit 1
}

# --- remove path ------------------------------------------------------------
if ($Remove) {
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Host "Removed scheduled task '$TaskName'." -ForegroundColor Yellow
    } else {
        Write-Host "Task '$TaskName' not found." -ForegroundColor Yellow
    }
    exit 0
}

# --- locate pythonw ---------------------------------------------------------
$pythonw = (Get-Command pythonw.exe -ErrorAction SilentlyContinue).Source
if (-not $pythonw) {
    $py = (Get-Command python.exe -ErrorAction SilentlyContinue).Source
    if (-not $py) { Write-Error "Python not found on PATH."; exit 1 }
    $pythonw = Join-Path (Split-Path $py) "pythonw.exe"
    if (-not (Test-Path $pythonw)) { $pythonw = $py }  # fall back to console
}

# --- (re)register -----------------------------------------------------------
if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
}

$action  = New-ScheduledTaskAction -Execute $pythonw `
    -Argument "`"$Script`"" -WorkingDirectory $Here
$trigger = New-ScheduledTaskTrigger -AtLogOn
$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit (New-TimeSpan -Seconds 0)
$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME `
    -LogonType Interactive -RunLevel Highest

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
    -Settings $settings -Principal $principal `
    -Description "Keeps the PC's internet on the best healthy phone link." | Out-Null

Write-Host "Installed scheduled task '$TaskName' (runs $pythonw at logon)." -ForegroundColor Green

if ($Run) {
    Start-ScheduledTask -TaskName $TaskName
    Write-Host "Started '$TaskName'. Logs: $(Join-Path $Here 'logs\linkkeeper.log')" -ForegroundColor Green
}
