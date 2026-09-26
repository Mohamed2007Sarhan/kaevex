@echo off
title Building Kaevex Security Platform v1.0
echo ========================================================================
echo   Kaevex Security Platform v1.0 - Unified Build System
echo ========================================================================
echo.

cd /d "%~dp0"

if not exist C:\GCC\bin\gcc.exe (
    echo [!] C:\GCC junction not found. Creating junction...
    mklink /J C:\GCC F:\9_Programming_language\pcc >nul 2>&1
)

set PATH=C:\GCC\bin;C:\GCC\x86_64-w64-mingw32\bin;C:\Windows\System32;C:\Windows

if not exist dist     mkdir dist
if not exist release  mkdir release
if not exist release\v1 mkdir release\v1

echo.
echo [*] Compiling Unified Master Binary (kaevex.exe) ...
C:\GCC\bin\gcc.exe -mwindows -O2 -w -fno-lto ^
    -I src\engines ^
    -B C:\GCC\x86_64-w64-mingw32\lib ^
    -B C:\GCC\x86_64-w64-mingw32\lib\gcc\x86_64-w64-mingw32\16.2.0 ^
    -L C:\GCC\x86_64-w64-mingw32\lib ^
    -L C:\GCC\x86_64-w64-mingw32\lib\gcc\x86_64-w64-mingw32\16.2.0 ^
    -o dist\kaevex.exe ^
    src\main.c src\gui\kaevex-gui.c src\cli\kaevex-cli.c ^
    -lcomctl32 -lws2_32 -liphlpapi -lshell32 ^
    -lole32 -loleaut32 -lcomdlg32 -lcrypt32 ^
    -lpsapi -ldwmapi -luxtheme -lwinhttp ^
    -lshlwapi -lntdll -ladvapi32 -luser32 -lgdi32 -lwinmm -lwintrust

if errorlevel 1 (
    echo [FAIL] kaevex.exe build failed.
) else (
    echo [OK]   dist\kaevex.exe (Unified Master Binary)
    copy /y dist\kaevex.exe dist\Kaevex-GUI.exe >nul 2>&1
    copy /y dist\kaevex.exe release\kaevex.exe >nul 2>&1
    copy /y dist\kaevex.exe release\Kaevex-GUI.exe >nul 2>&1
    copy /y dist\kaevex.exe release\v1\kaevex.exe >nul 2>&1
    copy /y dist\kaevex.exe release\v1\Kaevex-GUI.exe >nul 2>&1
)

echo.
echo [*] Compiling kaevex-engine.exe ...
C:\GCC\bin\gcc.exe -O2 -w -fno-lto ^
    -I src\engines ^
    -B C:\GCC\x86_64-w64-mingw32\lib ^
    -B C:\GCC\x86_64-w64-mingw32\lib\gcc\x86_64-w64-mingw32\16.2.0 ^
    -L C:\GCC\x86_64-w64-mingw32\lib ^
    -L C:\GCC\x86_64-w64-mingw32\lib\gcc\x86_64-w64-mingw32\16.2.0 ^
    -o dist\kaevex-engine.exe ^
    src\kaevex-engine.c ^
    -lws2_32 -liphlpapi -lpsapi -ladvapi32 -lshell32 -lole32 -lcrypt32 -lwinhttp -lwinmm -lwintrust

if errorlevel 1 (
    echo [FAIL] kaevex-engine build failed.
) else (
    echo [OK]   dist\kaevex-engine.exe
    copy /y dist\kaevex-engine.exe release\kaevex-engine.exe >nul 2>&1
    copy /y dist\kaevex-engine.exe release\v1\kaevex-engine.exe >nul 2>&1
)

echo.
echo [*] Copying assets to dist ...
if exist assets\kaevex.ico (
    copy /y assets\kaevex.ico dist\kaevex.ico >nul 2>&1
    echo [OK]   dist\kaevex.ico
)

echo.
echo ========================================================================
echo   Kaevex v1.0 Build Complete!
echo   Primary: dist\kaevex.exe (Unified GUI + Tray + Engine + CLI)
echo ========================================================================
