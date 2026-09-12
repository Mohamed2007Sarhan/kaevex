@echo off
title AegisCore v1 — Test Launch
color 0A

echo.
echo  =========================================================
echo   AegisCore Security Platform — v1 Test Build
echo   Copyright (c) 2025 AegisCore Security Systems
echo  =========================================================
echo.

:: Resolve this script's directory
set "BIN=%~dp0"
set "NODE_EXE="

:: Try Node 20 via nvm first
if exist "C:\ProgramData\nvm\v20.19.0\node.exe" (
    set "NODE_EXE=C:\ProgramData\nvm\v20.19.0\node.exe"
    goto :found_node
)

:: Try system node
where node >nul 2>&1
if %errorlevel%==0 (
    for /f "delims=" %%i in ('where node') do set "NODE_EXE=%%i"
    goto :found_node
)

echo  [ERROR] Node.js not found. Install Node.js 20+ from https://nodejs.org
pause
exit /b 1

:found_node
echo  [OK] Node: %NODE_EXE%
echo.

:: Check if real backend is already running on 9009
curl -s --connect-timeout 1 http://127.0.0.1:9009/api/v1/status >nul 2>&1
if %errorlevel%==0 (
    echo  [INFO] Real fire-engine backend detected on port 9009
    echo  [INFO] Skipping mock backend
    set "USE_MOCK=0"
) else (
    echo  [INFO] No backend found - starting mock backend on port 9009
    set "USE_MOCK=1"
    start "AegisCore-MockBackend" /min cmd /c "%NODE_EXE% "%BIN%mock-backend.js" 2>&1 | tee "%BIN%logs\mock-backend.log""
    timeout /t 2 /nobreak >nul
)

:: Start the dashboard static server
echo  [INFO] Starting dashboard on http://localhost:3000
start "AegisCore-Dashboard" /min cmd /c "%NODE_EXE% "%BIN%serve-dashboard.js" 2>&1 | tee "%BIN%logs\dashboard.log""
timeout /t 2 /nobreak >nul

:: Open browser
echo  [INFO] Opening browser...
start "" "http://localhost:3000"

echo.
echo  =========================================================
echo   AegisCore is running!
echo.
echo   Dashboard:   http://localhost:3000
echo   Backend API: http://localhost:9009/api/v1/
echo.
echo   Close this window to stop all services.
echo  =========================================================
echo.
echo  Press any key to STOP all AegisCore services...
pause >nul

:: Cleanup
echo  [INFO] Stopping services...
taskkill /fi "WINDOWTITLE eq AegisCore-MockBackend*" /f >nul 2>&1
taskkill /fi "WINDOWTITLE eq AegisCore-Dashboard*"   /f >nul 2>&1
echo  [INFO] AegisCore stopped.
timeout /t 1 /nobreak >nul
