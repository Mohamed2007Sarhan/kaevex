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
    }
    free(pBits);
}

int main() {
    system("taskkill /f /im kaevex.exe >nul 2>&1");
    Sleep(300);

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    char cmd[] = "dist\\kaevex.exe";
    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        printf("Failed to launch kaevex\n");
        return 1;
    }
    CloseHandle(pi.hThread);

    HWND hwnd = NULL;
    for (int i = 0; i < 40; i++) {
        Sleep(200);
        hwnd = FindWindowA("KaevexGUIModern", NULL);
        if (hwnd) break;
    }
    if (!hwnd) {
        printf("Kaevex window not found\n");
        return 1;
    }
    ShowWindow(hwnd, SW_RESTORE);
    SetForegroundWindow(hwnd);
    Sleep(1200);

    RECT rc;
    GetClientRect(hwnd, &rc);
    int rx = rc.right - 260;

    /* 1. Click Bell to open popover */
    LPARAM lp1 = MAKELPARAM(rx + 12, 26);
    SendMessageA(hwnd, WM_LBUTTONDOWN, MK_LBUTTON, lp1);
    SendMessageA(hwnd, WM_LBUTTONUP, 0, lp1);
    Sleep(300);

    /* 2. Click [ Clear All ] inside popover */
    int popW = 340;
    int popX = rx - popW + 36, popY = 54 + 4;
    int clrW = 75, clrH = 22;
    int clrX = popX + popW - clrW - 12, clrY = popY + 9;
    LPARAM lp2 = MAKELPARAM(clrX + 20, clrY + 10);
    SendMessageA(hwnd, WM_LBUTTONDOWN, MK_LBUTTON, lp2);
    SendMessageA(hwnd, WM_LBUTTONUP, 0, lp2);
    Sleep(400);

    /* Capture */
    int w = rc.right - rc.left;
    int h = rc.bottom - rc.top;
    HDC hdcWin = GetDC(hwnd);
    HDC hdcMem = CreateCompatibleDC(hdcWin);
    HBITMAP hbm = CreateCompatibleBitmap(hdcWin, w, h);
    HBITMAP obm = (HBITMAP)SelectObject(hdcMem, hbm);
    PrintWindow(hwnd, hdcMem, 2);
    SelectObject(hdcMem, obm);

    const char *outBmp = "C:\\Users\\Moham\\.gemini\\antigravity\\brain\\ea40fe83-cd23-489f-9996-2a73f0e38bc8\\screen_notif_cleared.bmp";
    SaveHBITMAPToFile(hbm, hdcWin, w, h, outBmp);
    DeleteObject(hbm);
    DeleteDC(hdcMem);
    ReleaseDC(hwnd, hdcWin);

    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hProcess);
    printf("Captured cleared notif BMP successfully!\n");
    return 0;
}
