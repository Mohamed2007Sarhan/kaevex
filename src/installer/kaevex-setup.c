/**
 * =======================================================================
 * Kaevex Security Platform v1.0 - Native Setup Bootstrapper
 * Copyright (c) 2025-2026 Kaevex Cyber Systems. All rights reserved.
 * =======================================================================
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
#include <shlobj.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ole32.lib")

static BOOL is_elevated(void) {
    BOOL elevated = FALSE;
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION el;
        DWORD dwSize = 0;
        if (GetTokenInformation(hToken, TokenElevation, &el, sizeof(el), &dwSize)) {
            elevated = el.TokenIsElevated != 0;
        }
        CloseHandle(hToken);
    }
    return elevated;
}

static void elevate_and_exit(void) {
    char exePath[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, MAX_PATH);

    SHELLEXECUTEINFOA sei = {0};
    sei.cbSize = sizeof(sei);
    sei.lpVerb = "runas";
    sei.lpFile = exePath;
    sei.nShow = SW_NORMAL;

    if (ShellExecuteExA(&sei)) {
        ExitProcess(0);
    }
}

int main(int argc, char *argv[]) {
    SetConsoleTitleA("Kaevex Security Platform v1.0 - Setup Wizard");

    /* Request elevation if not already running as Admin */
    if (!is_elevated()) {
        printf("[*] Elevating setup privileges for Windows Defender & AppContainer...\n");
        elevate_and_exit();
        return 0;
    }

    HANDLE hCon = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hCon, FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);

    printf("\n");
    printf("================================================================================\n");
    printf("        KAEVEX SECURITY PLATFORM v1.0 [SOC ENTERPRISE] - SETUP WIZARD          \n");
    printf("              Native Endpoint, Network & Web Cyber Defense (x64)                \n");
    printf("================================================================================\n\n");

    SetConsoleTextAttribute(hCon, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);

    char dir[MAX_PATH];
    GetModuleFileNameA(NULL, dir, MAX_PATH);
    char *p = strrchr(dir, '\\');
    if (p) *p = '\0';

    char msiPath[MAX_PATH];
    snprintf(msiPath, sizeof(msiPath), "%s\\Kaevex-Setup-v1.0.msi", dir);

    /* If MSI package exists in folder, launch it */
    DWORD attr = GetFileAttributesA(msiPath);
    if (attr != INVALID_FILE_ATTRIBUTES) {
        printf("[*] Launching Windows Installer package: Kaevex-Setup-v1.0.msi\n");
        printf("[*] Target Location: C:\\Program Files\\Kaevex\\\n");

        char cmd[MAX_PATH * 2];
        snprintf(cmd, sizeof(cmd), "/i \"%s\"", msiPath);

        SHELLEXECUTEINFOA sei = {0};
        sei.cbSize = sizeof(sei);
        sei.lpVerb = "open";
        sei.lpFile = "msiexec.exe";
        sei.lpParameters = cmd;
        sei.nShow = SW_SHOWNORMAL;
        sei.fMask = SEE_MASK_NOCLOSEPROCESS;

        if (ShellExecuteExA(&sei)) {
            printf("[*] Windows Installer running in foreground...\n");
            WaitForSingleObject(sei.hProcess, INFINITE);
            CloseHandle(sei.hProcess);
            printf("\n[OK] Kaevex Security Platform v1.0 installed successfully!\n\n");
        } else {
            printf("[!] Failed to invoke Windows Installer (Error %lu)\n", GetLastError());
        }
    } else {
        printf("[*] Direct standalone extraction mode...\n");
        /* Target dir */
        char target[MAX_PATH] = "C:\\Program Files\\Kaevex";
        CreateDirectoryA(target, NULL);

        static const char *files[] = {
            "Kaevex-GUI.exe", "kaevex-cli.exe", "kaevex-engine.exe",
            "kaevex-tray.exe", "kaevex_cve_catalog.json", "Kaevex-Admin.bat",
            "Kaevex-Start.bat", "README.md", NULL
        };

        for (int i = 0; files[i]; i++) {
            char src[MAX_PATH], dst[MAX_PATH];
            snprintf(src, sizeof(src), "%s\\%s", dir, files[i]);
            snprintf(dst, sizeof(dst), "%s\\%s", target, files[i]);
            if (CopyFileA(src, dst, FALSE)) {
                printf("  [+] Installed: %s\n", files[i]);
            }
        }
        printf("\n[OK] All core components deployed to %s\n", target);
    }

    SetConsoleTextAttribute(hCon, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    printf("\n[*] Setup complete! Press any key to launch Kaevex SOC Platform...\n");
    getchar();

    char launch[MAX_PATH] = "C:\\Program Files\\Kaevex\\Kaevex-GUI.exe";
    if (GetFileAttributesA(launch) != INVALID_FILE_ATTRIBUTES) {
        ShellExecuteA(NULL, "open", launch, NULL, "C:\\Program Files\\Kaevex", SW_SHOW);
    }

    return 0;
}
