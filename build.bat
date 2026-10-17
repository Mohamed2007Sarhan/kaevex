@echo off
title Kaevex build (Windows)
cd /d "%~dp0"
echo ============================================================
echo   Kaevex Security Platform - Windows build (MinGW-w64 in C:\GCC)
echo ============================================================
set PATH=C:\GCC\bin;C:\GCC\x86_64-w64-mingw32\bin;C:\Windows\System32;C:\Windows

if not exist release\windows mkdir release\windows
if not exist build mkdir build

echo [*] Compiling resources (icon, manifest with GDI scaling, bitmaps) ...
C:\GCC\bin\windres.exe -I . -i src\kaevex.rc -o build\kaevex_res.o
if errorlevel 1 ( echo [FAIL] resources & exit /b 1 )

echo [*] Compiling kaevex.exe (GUI + CLI + tray in one binary) ...
C:\GCC\bin\gcc.exe -mwindows -O2 -w -fno-lto ^
    -I src\engines ^
    -B C:\GCC\x86_64-w64-mingw32\lib ^
    -B C:\GCC\x86_64-w64-mingw32\lib\gcc\x86_64-w64-mingw32\16.2.0 ^
    -L C:\GCC\x86_64-w64-mingw32\lib ^
    -L C:\GCC\x86_64-w64-mingw32\lib\gcc\x86_64-w64-mingw32\16.2.0 ^
    -o release\windows\kaevex.exe ^
    src\main.c src\gui\kaevex-gui.c src\cli\kaevex-cli.c build\kaevex_res.o ^
    -lcomctl32 -lws2_32 -liphlpapi -licmp -lshell32 ^
    -lole32 -loleaut32 -luuid -lcomdlg32 -lcrypt32 ^
    -lpsapi -ldwmapi -luxtheme -lwinhttp ^
    -lshlwapi -lntdll -ladvapi32 -luser32 -lgdi32 -lwinmm -lwintrust

if errorlevel 1 (
    echo [FAIL] kaevex.exe build failed.
    exit /b 1
)
echo [OK]   release\windows\kaevex.exe
