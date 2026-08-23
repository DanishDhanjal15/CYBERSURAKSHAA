@echo off
REM ============================================================
REM  CYBERSURAKSHAA - one-click demo launcher
REM
REM  Opens TWO windows that keep running on their own:
REM    1. the Flask app on http://127.0.0.1:5000
REM    2. a Cloudflare tunnel giving it a public HTTPS URL
REM
REM  The HTTPS URL is what Web NFC needs on an Android phone, and
REM  it changes every run - read it from the tunnel window.
REM
REM  Close either window to stop that piece.
REM ============================================================

cd /d "%~dp0"

REM Behind the tunnel every visitor arrives from one Cloudflare address, so
REM without this the per-IP rate limit is shared by everybody at once and a
REM few people browsing together 429 each other. This tells the app to read
REM the real client from X-Forwarded-For instead.
set TRUST_PROXY_HEADERS=1

echo.
echo  Starting CYBERSURAKSHAA...
echo.

start "CYBERSURAKSHAA - App" cmd /k "set TRUST_PROXY_HEADERS=1 && venv\Scripts\python.exe app.py"

echo  Waiting for the models to load (about 60 seconds)...
timeout /t 45 /nobreak >nul

start "CYBERSURAKSHAA - Public HTTPS Tunnel" cmd /k ""C:\Program Files (x86)\cloudflared\cloudflared.exe" tunnel --url http://127.0.0.1:5000"

echo.
echo  Two windows opened.
echo.
echo    APP     : http://127.0.0.1:5000        (this laptop)
echo    PHONE   : look in the TUNNEL window for the
echo              https://....trycloudflare.com address
echo.
echo  Open that https address on the Android phone to test NFC.
echo.
pause
