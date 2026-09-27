#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

static void SaveHBITMAPToFile(HBITMAP hbm, HDC hdc, int w, int h, const char *path) {
    BITMAPINFO bi = {0};
    bi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bi.bmiHeader.biWidth = w;
    bi.bmiHeader.biHeight = h;
    bi.bmiHeader.biPlanes = 1;
    bi.bmiHeader.biBitCount = 24;
    bi.bmiHeader.biCompression = BI_RGB;

    int rowSize = ((w * 24 + 31) / 32) * 4;
    int imageSize = rowSize * h;

    BYTE *pBits = (BYTE*)malloc(imageSize);
    if (!pBits) return;

    GetDIBits(hdc, hbm, 0, h, pBits, &bi, DIB_RGB_COLORS);

    BITMAPFILEHEADER bfh = {0};
    bfh.bfType = 0x4D42;
    bfh.bfOffBits = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);
    bfh.bfSize = bfh.bfOffBits + imageSize;

    FILE *fp = fopen(path, "wb");
    if (fp) {
        fwrite(&bfh, sizeof(bfh), 1, fp);
        fwrite(&bi.bmiHeader, sizeof(bi.bmiHeader), 1, fp);
        fwrite(pBits, imageSize, 1, fp);
        fclose(fp);
        printf("[OK] Saved BMP: %s\n", path);
    }
    free(pBits);
}

static void CaptureWindow(HWND hwnd, const char *path) {
    RECT rc;
    GetClientRect(hwnd, &rc);
    int w = rc.right - rc.left;
    int h = rc.bottom - rc.top;

    HDC hdcWin = GetDC(hwnd);
    HDC hdcMem = CreateCompatibleDC(hdcWin);
    HBITMAP hbm = CreateCompatibleBitmap(hdcWin, w, h);
    HBITMAP obm = (HBITMAP)SelectObject(hdcMem, hbm);

    BOOL pwOk = PrintWindow(hwnd, hdcMem, 2);
    if (!pwOk) {
        BitBlt(hdcMem, 0, 0, w, h, hdcWin, 0, 0, SRCCOPY);
    }

    SelectObject(hdcMem, obm);
    SaveHBITMAPToFile(hbm, hdcWin, w, h, path);

    DeleteObject(hbm);
    DeleteDC(hdcMem);
    ReleaseDC(hwnd, hdcWin);
}

int main(int argc, char **argv) {
    system("taskkill /f /im kaevex.exe >nul 2>&1");
    system("taskkill /f /im Kaevex-GUI.exe >nul 2>&1");
    Sleep(500);

    printf("[*] Launching dist\\kaevex.exe ...\n");
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    char cmd[] = "dist\\kaevex.exe";
    if (CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    } else {
        printf("[FAIL] Failed to launch kaevex.exe\n");
        return 1;
    }

    HWND hwnd = NULL;
    for (int i = 0; i < 80; i++) {
        Sleep(250);
        hwnd = FindWindowA("KaevexGUIModern", NULL);
        if (hwnd) break;
    }

    if (!hwnd) {
        printf("[FAIL] Kaevex window not found!\n");
        return 1;
    }

    ShowWindow(hwnd, SW_RESTORE);
    SetForegroundWindow(hwnd);
    Sleep(1500);

    static const char *tabNames[15] = {
        "tab0_dashboard",
        "tab1_defense_engines",
        "tab2_netguard",
        "tab3_webguard_waf",
        "tab4_antivirus",
        "tab5_ransomshield",
        "tab6_smartsandbox",
        "tab7_firewall",
        "tab8_cve_agent",
        "tab9_gaming_threat",
        "tab10_app_hub",
        "tab11_ai_soc",
        "tab12_forensics",
        "tab13_settings",
        "tab14_full_team"
    };

    int startY = 54 + 10;
    int tabH = 38;
    int clickX = 60;

    for (int t = 0; t < 15; t++) {
        int clickY = startY + t * tabH + 19;
        LPARAM lp = MAKELPARAM(clickX, clickY);
        SendMessageA(hwnd, WM_LBUTTONDOWN, MK_LBUTTON, lp);
        SendMessageA(hwnd, WM_LBUTTONUP, 0, lp);
        Sleep(600);

        char bmpPath[MAX_PATH];
        snprintf(bmpPath, sizeof(bmpPath),
                 "C:\\Users\\Moham\\.gemini\\antigravity\\brain\\ea40fe83-cd23-489f-9996-2a73f0e38bc8\\screen_%s.bmp",
                 tabNames[t]);
        CaptureWindow(hwnd, bmpPath);
    }

    /* Tab 9 Sub-tabs */
    static const struct { const char *name; int x; int y; } gSubTabs[4] = {
        { "threat_sub1_protection",  398, 157 },
        { "threat_sub2_performance", 549, 157 },
        { "threat_sub3_rules",       669, 157 },
        { "threat_sub4_profiles",    780, 157 }
    };

    for (int s = 0; s < 4; s++) {
        LPARAM lp = MAKELPARAM(gSubTabs[s].x, gSubTabs[s].y);
        SendMessageA(hwnd, WM_LBUTTONDOWN, MK_LBUTTON, lp);
        SendMessageA(hwnd, WM_LBUTTONUP, 0, lp);
        Sleep(600);

        char bmpPath[MAX_PATH];
        snprintf(bmpPath, sizeof(bmpPath),
                 "C:\\Users\\Moham\\.gemini\\antigravity\\brain\\ea40fe83-cd23-489f-9996-2a73f0e38bc8\\screen_%s.bmp",
                 gSubTabs[s].name);
        CaptureWindow(hwnd, bmpPath);
    }

    PostMessageA(hwnd, WM_CLOSE, 0, 0);
    Sleep(500);
    printf("[DONE] All 10 main tabs and 4 gaming sub-tabs captured!\n");
    return 0;
}
