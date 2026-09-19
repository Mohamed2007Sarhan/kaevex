@echo off
title Kaevex Security Platform v1.0
cd /d "%~dp0"

echo [*] Starting Kaevex Security Platform...
echo.

rem Start the Tray Agent in the background (handles icon + background API)
start "" "dist\Kaevex-Tray.exe"

rem Give the tray a moment to initialize
timeout /t 1 /nobreak >nul

rem Launch the GUI (single-instance aware — tray can also open it)
start "" "dist\Kaevex-GUI.exe"

exit
