@echo off
title Kaevex Security Platform v1.0 — Admin Console
cd /d "%~dp0\.."

net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [!] Requesting administrative privileges...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

echo ========================================================================
echo   KAEVEX SECURITY PLATFORM v1.0 — SOC ENTERPRISE (ADMIN)
echo ========================================================================
echo.
echo [*] Launching Kaevex Tray Agent...
start "" "%~dp0..\dist\Kaevex-Tray.exe"
timeout /t 1 /nobreak >nul

echo [*] Launching Kaevex SOC Dashboard...
start "" "%~dp0..\dist\Kaevex-GUI.exe"
echo [OK] Kaevex running. Tray icon visible in notification area.
echo.
echo [*] Press any key to open CLI management shell, or close this window.
pause >nul
"%~dp0..\dist\kaevex-cli.exe"
