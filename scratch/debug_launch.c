#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>

int main() {
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    char cmd[] = "dist\\kaevex.exe --gui";
    printf("[*] Launching: %s\n", cmd);
    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        printf("[FAIL] CreateProcess failed, err=%lu\n", GetLastError());
        return 1;
    }
    printf("[*] PID=%lu\n", pi.dwProcessId);

    for (int i = 0; i < 20; i++) {
        Sleep(500);
        DWORD exitCode = 0;
        if (GetExitCodeProcess(pi.hProcess, &exitCode)) {
            if (exitCode != STILL_ACTIVE) {
                printf("[*] Process exited after %d ms with code: 0x%08lX (%lu)\n", (i+1)*500, exitCode, exitCode);
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
                return 0;
            }
        }
        HWND hwnd = FindWindowA("KaevexGUIModern", NULL);
        if (hwnd) {
            printf("[OK] Found KaevexGUIModern after %d ms! hwnd=0x%p\n", (i+1)*500, hwnd);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            return 0;
        }
    }

    printf("[*] Process still active after 10s, but window not found!\n");
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 0;
}
