@echo off
title Kaevex Security Platform - Administrator
cd /d "%~dp0release\windows"
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [!] Requesting administrator rights (needed for firewall, lockdown, logging and fixes)...
    powershell -NoProfile -Command "Start-Process -FilePath '%~dp0release\windows\kaevex.exe' -WorkingDirectory '%~dp0release\windows' -Verb RunAs"
    exit /b
)
start "" "kaevex.exe"
exit
