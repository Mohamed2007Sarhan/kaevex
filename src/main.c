/**
 * ============================================================================
 * Kaevex Security Platform v1.0 — Unified Master Binary Entry Point
 * kaevex.exe
 *
 * Seamlessly consolidates:
 *   1. Windows Search / Double-Click / Shortcut -> Launches Dark SOC GUI
 *   2. System Boot / Autostart (--startup / --tray) -> Silent 24/7 background engine + tray
 *   3. Terminal / Command Prompt -> Attaches to console and executes CLI commands
 *   4. Single-Instance Aware -> Re-opening from Search restores running GUI instantly
 * ============================================================================
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <io.h>
#include <fcntl.h>

/* Forward declarations for unified modules */
int kaevex_cli_main(int argc, char **argv);
int kaevex_gui_main(HINSTANCE hi, HINSTANCE hp, LPSTR lp, int ns, BOOL startMinimized);

static void SetupConsoleIO(void) {
    HANDLE hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
    HANDLE hStdErr = GetStdHandle(STD_ERROR_HANDLE);
    HANDLE hStdIn  = GetStdHandle(STD_INPUT_HANDLE);

    BOOL attached = AttachConsole(ATTACH_PARENT_PROCESS);

    /* Setup STDOUT */
    if (hStdOut != NULL && hStdOut != INVALID_HANDLE_VALUE && GetFileType(hStdOut) != FILE_TYPE_UNKNOWN) {
        int fd = _open_osfhandle((intptr_t)hStdOut, _O_TEXT);
        if (fd >= 0) {
            FILE *fp = _fdopen(fd, "w");
            if (fp) { *stdout = *fp; setvbuf(stdout, NULL, _IONBF, 0); }
        }
    } else if (attached) {
        freopen("CONOUT$", "w", stdout);
    } else {
        AllocConsole();
        freopen("CONOUT$", "w", stdout);
    }

    /* Setup STDERR */
    if (hStdErr != NULL && hStdErr != INVALID_HANDLE_VALUE && GetFileType(hStdErr) != FILE_TYPE_UNKNOWN) {
        int fd = _open_osfhandle((intptr_t)hStdErr, _O_TEXT);
        if (fd >= 0) {
            FILE *fp = _fdopen(fd, "w");
            if (fp) { *stderr = *fp; setvbuf(stderr, NULL, _IONBF, 0); }
        }
    } else {
        freopen("CONOUT$", "w", stderr);
    }

    /* Setup STDIN */
    if (hStdIn != NULL && hStdIn != INVALID_HANDLE_VALUE && GetFileType(hStdIn) != FILE_TYPE_UNKNOWN) {
        int fd = _open_osfhandle((intptr_t)hStdIn, _O_TEXT);
        if (fd >= 0) {
            FILE *fp = _fdopen(fd, "r");
            if (fp) { *stdin = *fp; }
        }
    } else {
        freopen("CONIN$", "r", stdin);
    }
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    (void)hPrevInstance;

    /* Parse Unicode command-line arguments into UTF-8 argv */
    int argc = 0;
    LPWSTR *argvW = CommandLineToArgvW(GetCommandLineW(), &argc);
    char **argv = NULL;

    if (argvW && argc > 0) {
        argv = (char**)malloc(argc * sizeof(char*));
        for (int i = 0; i < argc; i++) {
            int len = WideCharToMultiByte(CP_UTF8, 0, argvW[i], -1, NULL, 0, NULL, NULL);
            argv[i] = (char*)malloc(len ? len : 1);
            if (len) {
                WideCharToMultiByte(CP_UTF8, 0, argvW[i], -1, argv[i], len, NULL, NULL);
            } else {
                argv[i][0] = '\0';
            }
        }
        LocalFree(argvW);
    }

    /* 1. Argument-based execution mode */
    if (argc > 1) {
        const char *arg1 = argv[1];

        /* --- Mode A: Windows Boot / Background Tray Daemon --- */
        if (_stricmp(arg1, "--startup") == 0 || _stricmp(arg1, "-s") == 0 ||
            _stricmp(arg1, "--tray") == 0 || _stricmp(arg1, "-t") == 0 ||
            _stricmp(arg1, "/startup") == 0 || _stricmp(arg1, "/tray") == 0 ||
            _stricmp(arg1, "--background") == 0 || _stricmp(arg1, "-b") == 0 ||
            _stricmp(arg1, "--daemon") == 0 || _stricmp(arg1, "-d") == 0 ||
            _stricmp(arg1, "--service") == 0) {

            /* If an instance is already running, let it manage everything */
            HWND hwExisting = FindWindowA("KaevexGUIModern", NULL);
            if (hwExisting) {
                return 0;
            }
            /* Start all engines, Mobile API, and Tray silently with window hidden */
            return kaevex_gui_main(hInstance, NULL, lpCmdLine, SW_HIDE, TRUE);
        }

        /* --- Mode B: Explicit GUI Flag --- */
        if (_stricmp(arg1, "--gui") == 0 || _stricmp(arg1, "-g") == 0 || _stricmp(arg1, "/gui") == 0) {
            HWND hwExisting = FindWindowA("KaevexGUIModern", NULL);
            if (hwExisting) {
                ShowWindow(hwExisting, SW_SHOW);
                ShowWindow(hwExisting, SW_RESTORE);
                SetForegroundWindow(hwExisting);
                return 0;
            }
            return kaevex_gui_main(hInstance, NULL, lpCmdLine, nCmdShow, FALSE);
        }

        /* --- Mode C: CLI Execution in Console --- */
        SetupConsoleIO();
        int res = kaevex_cli_main(argc, argv);
        return res;
    }

    /* 2. No arguments provided (e.g. Launched from Windows Search, Start Menu, Desktop Shortcut):
     * Check if Kaevex is already running in background/tray.
     * If running: immediately restore & bring the GUI window to the front.
     * If not running: launch the unified platform with GUI visible.
     */
    HWND hwExisting = FindWindowA("KaevexGUIModern", NULL);
    if (hwExisting) {
        ShowWindow(hwExisting, SW_SHOW);
        ShowWindow(hwExisting, SW_RESTORE);
        SetForegroundWindow(hwExisting);
        return 0;
    }

    return kaevex_gui_main(hInstance, NULL, lpCmdLine, nCmdShow, FALSE);
}
