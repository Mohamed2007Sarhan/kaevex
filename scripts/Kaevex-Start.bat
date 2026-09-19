@echo off
title Kaevex Security Platform v1.0
cd /d "%~dp0\.."

echo [*] Starting Kaevex Security Platform...

start "" "dist\Kaevex-Tray.exe"
timeout /t 1 /nobreak >nul
start "" "dist\Kaevex-GUI.exe"
exit
