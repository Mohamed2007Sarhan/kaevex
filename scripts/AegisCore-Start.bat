@echo off
title Starting AegisCore Protection...
cd /d "%~dp0"

echo =========================================================
echo   AegisCore Security Platform — Starting Service...
echo =========================================================
echo.
echo  [*] Launching background protection engine...
echo  [*] System Tray Shield Icon: Initializing...
echo  [*] REST API Server: Port 9009
echo.

start "" "%~dp0AegisCore.exe"

echo  [OK] AegisCore is running actively in the background!
echo  [OK] Check your Windows Taskbar (System Tray) for the Shield Icon.
echo.
echo  To open management console at any time:
echo    - Double-click the Shield Icon in the taskbar
echo    - Or run: AegisCore-Admin.bat
echo.
timeout /t 3 >nul
exit
