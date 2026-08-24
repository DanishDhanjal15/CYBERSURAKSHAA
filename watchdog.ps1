# ================================================================
# CYBERSURAKSHAA — Watchdog / Keep-Alive Script
# ================================================================
# This script:
#   1. Prevents the laptop from sleeping (presentation mode).
#   2. Keeps Flask alive — restarts it if it crashes.
#   3. Keeps Cloudflare tunnel alive — restarts it if it drops.
#   4. Checks Flask health every 30 seconds via /healthz.
#   5. Logs all events with timestamps to watchdog.log.
# ================================================================
# HOW TO START: Right-click → "Run with PowerShell" (or double-click
#               run_watchdog.bat which handles the execution policy).
# HOW TO STOP : Close this window, or press Ctrl+C.
# ================================================================

$AppDir    = Split-Path -Parent $MyInvocation.MyCommand.Path
$LogFile   = Join-Path $AppDir "watchdog.log"
$VenvPy    = Join-Path $AppDir "venv\Scripts\python.exe"
$AppScript = Join-Path $AppDir "app.py"
$CFExe     = "C:\Program Files (x86)\cloudflared\cloudflared.exe"
$HealthURL = "http://127.0.0.1:5000/healthz"

# ── Logging helper ──────────────────────────────────────────────
function Log($msg) {
    $line = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] $msg"
    Write-Host $line -ForegroundColor Cyan
    Add-Content -Path $LogFile -Value $line
}

# ── Prevent Windows sleep using SetThreadExecutionState ─────────
function Set-NeverSleep {
    Add-Type -TypeDefinition @"
    using System;
    using System.Runtime.InteropServices;
    public class SleepPreventer {
        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern uint SetThreadExecutionState(uint esFlags);
        public const uint ES_CONTINUOUS       = 0x80000000;
        public const uint ES_SYSTEM_REQUIRED  = 0x00000001;
        public const uint ES_DISPLAY_REQUIRED = 0x00000002;
    }
"@
    $flags = [SleepPreventer]::ES_CONTINUOUS `
           -bor [SleepPreventer]::ES_SYSTEM_REQUIRED `
           -bor [SleepPreventer]::ES_DISPLAY_REQUIRED
    [SleepPreventer]::SetThreadExecutionState($flags) | Out-Null
    Log "SLEEP PREVENTION: Active. Laptop will not sleep."
}

# ── Check if Flask is healthy ────────────────────────────────────
function Test-Flask {
    try {
        $resp = Invoke-WebRequest -Uri $HealthURL -TimeoutSec 5 -UseBasicParsing
        return ($resp.StatusCode -eq 200)
    } catch {
        return $false
    }
}

# ── Start or restart Flask ───────────────────────────────────────
$FlaskJob = $null
function Start-Flask {
    if ($global:FlaskJob -and $global:FlaskJob.HasExited -eq $false) {
        return  # Already running
    }
    Log "FLASK: Starting..."
    $env:TRUST_PROXY_HEADERS = "1"
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName  = $VenvPy
    $psi.Arguments = "`"$AppScript`""
    $psi.WorkingDirectory = $AppDir
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $p = [System.Diagnostics.Process]::Start($psi)
    $global:FlaskJob = $p
    Log "FLASK: Started (PID $($p.Id))"
}

# ── Start or restart Cloudflare tunnel ──────────────────────────
$TunnelJob = $null
function Start-Tunnel {
    if ($global:TunnelJob -and $global:TunnelJob.HasExited -eq $false) {
        return  # Already running
    }
    Log "TUNNEL: Waiting 60s for Flask to finish loading models..."
    Start-Sleep -Seconds 60
    Log "TUNNEL: Starting Cloudflare tunnel..."
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName  = $CFExe
    $psi.Arguments = "tunnel --url http://127.0.0.1:5000"
    $psi.WorkingDirectory = $AppDir
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $p = [System.Diagnostics.Process]::Start($psi)
    $global:TunnelJob = $p
    Log "TUNNEL: Started (PID $($p.Id))"
}

# ── Main watchdog loop ───────────────────────────────────────────
Log "============================================="
Log "CYBERSURAKSHAA WATCHDOG STARTED"
Log "============================================="

Set-NeverSleep

# Also run powercfg as a belt-and-suspenders backup
try {
    powercfg /change standby-timeout-ac 0 2>$null
    powercfg /change monitor-timeout-ac 0 2>$null
    Log "POWER: powercfg sleep/monitor timeouts set to 0."
} catch {
    Log "POWER: powercfg not available, using SetThreadExecutionState only."
}

Start-Flask
Start-Tunnel

$checkCount = 0
while ($true) {
    Start-Sleep -Seconds 30
    $checkCount++

    # --- Check Flask process ---
    if ($global:FlaskJob -eq $null -or $global:FlaskJob.HasExited) {
        Log "FLASK: Process died! Restarting now..."
        $global:FlaskJob = $null
        $global:TunnelJob = $null  # Tunnel needs Flask, restart it too
        Start-Flask
        Start-Sleep -Seconds 70   # Give models time to reload
        Start-Tunnel
        continue
    }

    # --- Health check Flask over HTTP ---
    $healthy = Test-Flask
    if (-not $healthy) {
        Log "FLASK: Health check FAILED (check #$checkCount). Will retry in 30s..."
        Start-Sleep -Seconds 30
        $healthy = Test-Flask
        if (-not $healthy) {
            Log "FLASK: Still unresponsive after 60s. Killing and restarting..."
            try { $global:FlaskJob.Kill() } catch {}
            $global:FlaskJob = $null
            $global:TunnelJob = $null
            Start-Flask
            Start-Sleep -Seconds 70
            Start-Tunnel
            continue
        }
    }

    # --- Check Cloudflare tunnel process ---
    if ($global:TunnelJob -eq $null -or $global:TunnelJob.HasExited) {
        Log "TUNNEL: Process died! Restarting tunnel..."
        $global:TunnelJob = $null
        Start-Tunnel
        continue
    }

    if ($checkCount % 10 -eq 0) {
        Log "HEARTBEAT: Flask OK | Tunnel OK | Uptime checks: $checkCount"
    }
}
