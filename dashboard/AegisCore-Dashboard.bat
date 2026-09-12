@echo off
title AegisCore Dashboard
color 0B
cls

echo.
echo  ╔══════════════════════════════════════════════════════════╗
echo  ║           AegisCore Security Platform v9.0.0            ║
echo  ║               Web Dashboard Launcher                    ║
echo  ╚══════════════════════════════════════════════════════════╝
echo.

:: Change to dashboard directory
cd /d "%~dp0"

:: ── Activate NVM if available (ensures Node 20+) ──────────────
if exist "%APPDATA%\nvm\nvm.exe" (
    set NVM_HOME=%APPDATA%\nvm
    set NVM_SYMLINK=C:\Program Files\nodejs
) else if exist "%ProgramData%\nvm\nvm.exe" (
    set NVM_HOME=%ProgramData%\nvm
    set NVM_SYMLINK=C:\Program Files\nodejs
)

:: Try to switch to Node 20 if nvm is available
where nvm >nul 2>&1
if %errorlevel% equ 0 (
    echo  [INFO] NVM detected — activating Node 20...
    call nvm use 20 2>nul
    if %errorlevel% neq 0 (
        echo  [WARN] Node 20 not installed. Run: nvm install 20
    )
)

:: Check node version
for /f "tokens=1" %%v in ('node -e "process.stdout.write(process.version)" 2^>nul') do set NODEVER=%%v
echo  [INFO] Node.js: %NODEVER%

:: Check node is available
where node >nul 2>&1
if %errorlevel% neq 0 (
    echo  [ERROR] Node.js is not installed or not in PATH.
    echo  Download from: https://nodejs.org/en/download (LTS)
    pause
    exit /b 1
)

:: Install dependencies if node_modules missing or outdated
if not exist "node_modules\vite" (
    echo  [INFO] Installing dependencies...
    npm install
    if %errorlevel% neq 0 (
        echo  [ERROR] npm install failed.
        pause
        exit /b 1
    )
)

:: Try to install systray2 for tray icon (optional, silent)
if not exist "node_modules\systray2" (
    echo  [INFO] Installing systray2 for tray icon...
    npm install systray2 --save-optional --quiet 2>nul
)

echo.
echo  ┌──────────────────────────────────────────────────────────┐
echo  │  Dashboard URL : http://localhost:3000                   │
echo  │  Backend API   : http://localhost:9009                   │
echo  │  Tray Icon     : Shield icon in Windows taskbar         │
echo  └──────────────────────────────────────────────────────────┘
echo.
echo  Starting AegisCore Dashboard...
echo  Press Ctrl+C to stop.
echo.

:: Start the tray launcher (which starts Vite + opens browser)
node tray.js

:: If tray fails, fall back to plain vite
if %errorlevel% neq 0 (
    echo.
    echo  [WARN] Tray launcher failed — starting plain dev server...
    node node_modules\vite\bin\vite.js --port 3000
)
