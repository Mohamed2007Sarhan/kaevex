@echo off
title AegisCore Security Platform — Admin Console
color 0A
cd /d "%~dp0"

echo =========================================================
echo   AegisCore Security Platform — Management Console
echo   (Background Protection remains active in System Tray)
echo =========================================================
echo.

"%~dp0aegiscore-cli.exe"

pause
