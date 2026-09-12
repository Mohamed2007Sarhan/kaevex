@echo off
:: Quick dev-only launcher (no tray, just vite)
title AegisCore Dev Server
cd /d "%~dp0"
echo Starting AegisCore Dashboard on http://localhost:3000
echo Backend API: http://localhost:9009
echo.
npm run dev
