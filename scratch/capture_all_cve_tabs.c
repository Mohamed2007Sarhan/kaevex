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
    Sleep(500);

    printf("[*] Launching dist\\kaevex.exe ...\n");
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    char cmd[] = "dist\\kaevex.exe";
    if (CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        CloseHandle(pi.hThread);
    } else {
        printf("[FAIL] Failed to launch kaevex.exe\n");
        return 1;
    }

    HWND hwnd = NULL;
    for (int i = 0; i < 40; i++) {
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
    Sleep(1200);

    /* Switch to Tab 8 (TAB_UPD) */
    int clickY = 54 + 10 + 8 * 38 + 19;
    int clickX = 60;
    LPARAM lp = MAKELPARAM(clickX, clickY);
    SendMessageA(hwnd, WM_LBUTTONDOWN, MK_LBUTTON, lp);
    SendMessageA(hwnd, WM_LBUTTONUP, 0, lp);
    Sleep(800);

    /* Exact Pill Centers: Overview=270, Vulns=420, Patches=560, Settings=695, Updates=850, DB=1005, Reports=1135 */
    static const int pillX[7] = { 270, 420, 560, 695, 850, 1005, 1135 };
    int subNavY = 54 + 8 + 68 + 10 + 16; /* ~156 */

    /* 1. Overview (Pill 0) */
    LPARAM lp0 = MAKELPARAM(pillX[0], subNavY);
    SendMessageA(hwnd, WM_LBUTTONDOWN, MK_LBUTTON, lp0);
    SendMessageA(hwnd, WM_LBUTTONUP, 0, lp0);
    Sleep(500);
    CaptureWindow(hwnd, "C:\\Users\\Moham\\.gemini\\antigravity\\brain\\ea40fe83-cd23-489f-9996-2a73f0e38bc8\\screen_cve_overview.bmp");

    /* 2. Vulnerabilities (Pill 1) */
    LPARAM lp1 = MAKELPARAM(pillX[1], subNavY);
    SendMessageA(hwnd, WM_LBUTTONDOWN, MK_LBUTTON, lp1);
    SendMessageA(hwnd, WM_LBUTTONUP, 0, lp1);
    Sleep(500);
    CaptureWindow(hwnd, "C:\\Users\\Moham\\.gemini\\antigravity\\brain\\ea40fe83-cd23-489f-9996-2a73f0e38bc8\\screen_cve_vulnerabilities.bmp");

    /* 2. Patches (Pill 2) */
    LPARAM lp2 = MAKELPARAM(pillX[2], subNavY);
    SendMessageA(hwnd, WM_LBUTTONDOWN, MK_LBUTTON, lp2);
    SendMessageA(hwnd, WM_LBUTTONUP, 0, lp2);
    Sleep(500);
    CaptureWindow(hwnd, "C:\\Users\\Moham\\.gemini\\antigravity\\brain\\ea40fe83-cd23-489f-9996-2a73f0e38bc8\\screen_cve_patches.bmp");

    /* 3. Scan Settings (Pill 3) */
    LPARAM lp3 = MAKELPARAM(pillX[3], subNavY);
    SendMessageA(hwnd, WM_LBUTTONDOWN, MK_LBUTTON, lp3);
    SendMessageA(hwnd, WM_LBUTTONUP, 0, lp3);
    Sleep(500);
    CaptureWindow(hwnd, "C:\\Users\\Moham\\.gemini\\antigravity\\brain\\ea40fe83-cd23-489f-9996-2a73f0e38bc8\\screen_cve_settings.bmp");

    /* 4. Update Center (Pill 4) */
    LPARAM lp4 = MAKELPARAM(pillX[4], subNavY);
    SendMessageA(hwnd, WM_LBUTTONDOWN, MK_LBUTTON, lp4);
    SendMessageA(hwnd, WM_LBUTTONUP, 0, lp4);
    Sleep(500);
    CaptureWindow(hwnd, "C:\\Users\\Moham\\.gemini\\antigravity\\brain\\ea40fe83-cd23-489f-9996-2a73f0e38bc8\\screen_cve_updates.bmp");

    /* 5. CVE Database (Pill 5) */
    LPARAM lp5 = MAKELPARAM(pillX[5], subNavY);
    SendMessageA(hwnd, WM_LBUTTONDOWN, MK_LBUTTON, lp5);
    SendMessageA(hwnd, WM_LBUTTONUP, 0, lp5);
    Sleep(500);
    CaptureWindow(hwnd, "C:\\Users\\Moham\\.gemini\\antigravity\\brain\\ea40fe83-cd23-489f-9996-2a73f0e38bc8\\screen_cve_database.bmp");

    /* 6. Reports (Pill 6) */
    LPARAM lp6 = MAKELPARAM(pillX[6], subNavY);
    SendMessageA(hwnd, WM_LBUTTONDOWN, MK_LBUTTON, lp6);
    SendMessageA(hwnd, WM_LBUTTONUP, 0, lp6);
    Sleep(500);
    CaptureWindow(hwnd, "C:\\Users\\Moham\\.gemini\\antigravity\\brain\\ea40fe83-cd23-489f-9996-2a73f0e38bc8\\screen_cve_reports.bmp");

    PostMessageA(hwnd, WM_CLOSE, 0, 0);
    Sleep(400);
    return 0;
}
