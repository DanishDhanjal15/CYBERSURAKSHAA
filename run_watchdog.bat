@echo off
REM ============================================================
REM  CYBERSURAKSHAA — WATCHDOG LAUNCHER
REM  Double-click this file to start the watchdog.
REM  It will:
REM    - Keep Flask running (auto-restart on crash)
REM    - Keep Cloudflare tunnel alive (auto-restart on drop)
REM    - Prevent the laptop from sleeping
REM    - Log all events to watchdog.log in this folder
REM ============================================================

cd /d "%~dp0"

echo.
echo  Starting CYBERSURAKSHAA Watchdog...
echo  This window MUST stay open during your presentation.
echo  It will auto-restart Flask and the tunnel if they crash.
echo.

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0watchdog.ps1"

pause
