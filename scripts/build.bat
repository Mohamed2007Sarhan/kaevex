@echo off
title Building Kaevex Security Platform v1.0
echo ========================================================================
echo   Building Kaevex Security Platform v1.0 (Production Release)
echo ========================================================================
echo.

cd /d "%~dp0\.."

if not exist C:\GCC\bin\gcc.exe (
    echo [!] C:\GCC junction not found. Creating junction...
    mklink /J C:\GCC F:\9_Programming_language\pcc >nul 2>&1
)

set PATH=C:\GCC\bin;C:\GCC\x86_64-w64-mingw32\bin;C:\Windows\System32;C:\Windows

echo [*] Compiling Kaevex-GUI.exe ...
C:\GCC\bin\gcc.exe -mwindows -O2 -w -fno-lto ^
    -I src\engines ^
    -B C:\GCC\x86_64-w64-mingw32\lib ^
    -B C:\GCC\x86_64-w64-mingw32\lib\gcc\x86_64-w64-mingw32\16.2.0 ^
    -L C:\GCC\x86_64-w64-mingw32\lib ^
    -L C:\GCC\x86_64-w64-mingw32\lib\gcc\x86_64-w64-mingw32\16.2.0 ^
    -o dist\Kaevex-GUI.exe ^
    src\gui\kaevex-gui.c ^
    -lcomctl32 -lws2_32 -liphlpapi -lshell32 ^
    -lole32 -loleaut32 -lcomdlg32 -lcrypt32 ^
    -lpsapi -ldwmapi -luxtheme -lwinhttp ^
    -lshlwapi -lntdll -ladvapi32 -luser32 -lgdi32

if errorlevel 1 (
    echo [FAIL] Kaevex-GUI build failed.
    pause
    exit /b 1
) else (
    echo [OK] dist\Kaevex-GUI.exe built successfully.
    copy /y dist\Kaevex-GUI.exe release\Kaevex-GUI.exe >nul 2>&1
)

echo [*] Compiling kaevex-cli.exe ...
C:\GCC\bin\gcc.exe -O2 -w -fno-lto ^
    -I src\engines ^
    -B C:\GCC\x86_64-w64-mingw32\lib ^
    -B C:\GCC\x86_64-w64-mingw32\lib\gcc\x86_64-w64-mingw32\16.2.0 ^
    -L C:\GCC\x86_64-w64-mingw32\lib ^
    -L C:\GCC\x86_64-w64-mingw32\lib\gcc\x86_64-w64-mingw32\16.2.0 ^
    -o dist\kaevex-cli.exe ^
    src\cli\kaevex-cli.c ^
    -lws2_32 -liphlpapi -lpsapi -ladvapi32 -lshell32 -lole32 -lcrypt32 -lwinhttp

if errorlevel 1 (
    echo [FAIL] kaevex-cli build failed.
) else (
    echo [OK] dist\kaevex-cli.exe built successfully.
    copy /y dist\kaevex-cli.exe release\kaevex-cli.exe >nul 2>&1
)

echo.
echo ========================================================================
echo   Kaevex v1.0 Build Complete!
echo ========================================================================
pause
