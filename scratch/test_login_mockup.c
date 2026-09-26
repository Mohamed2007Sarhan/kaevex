#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>

static void SaveHDCtoBMP(HDC hdc, int w, int h, const char *filename) {
    HDC memDC = CreateCompatibleDC(hdc);
    HBITMAP hbm = CreateCompatibleBitmap(hdc, w, h);
    HBITMAP oldBm = (HBITMAP)SelectObject(memDC, hbm);
    BitBlt(memDC, 0, 0, w, h, hdc, 0, 0, SRCCOPY);

    int rowBytes = ((w * 3 + 3) / 4) * 4;
    DWORD imgSize = rowBytes * h;
    BYTE *pixels = (BYTE*)malloc(imgSize);

    BITMAPINFO bi = {0};
    bi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bi.bmiHeader.biWidth = w;
    bi.bmiHeader.biHeight = h;
    bi.bmiHeader.biPlanes = 1;
    bi.bmiHeader.biBitCount = 24;
    bi.bmiHeader.biCompression = BI_RGB;

    GetDIBits(memDC, hbm, 0, h, pixels, &bi, DIB_RGB_COLORS);

    BITMAPFILEHEADER bfh = {0};
    bfh.bfType = 0x4D42;
    bfh.bfOffBits = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);
    bfh.bfSize = bfh.bfOffBits + imgSize;

    BITMAPINFOHEADER bih = bi.bmiHeader;

    FILE *f = fopen(filename, "wb");
    if (f) {
        fwrite(&bfh, sizeof(bfh), 1, f);
        fwrite(&bih, sizeof(bih), 1, f);
        fwrite(pixels, imgSize, 1, f);
        fclose(f);
    }
    free(pixels);
    SelectObject(memDC, oldBm);
    DeleteObject(hbm);
    DeleteDC(memDC);
}

static void DrawRoundRectPanel(HDC dc, int x, int y, int w, int h, int r, COLORREF fill, COLORREF border) {
    HBRUSH b = CreateSolidBrush(fill);
    HPEN p = CreatePen(PS_SOLID, 1, border);
    HBRUSH ob = (HBRUSH)SelectObject(dc, b);
    HPEN op = (HPEN)SelectObject(dc, p);
    RoundRect(dc, x, y, x + w, y + h, r, r);
    SelectObject(dc, ob); SelectObject(dc, op);
    DeleteObject(b); DeleteObject(p);
}

static void DrawGradientH(HDC dc, int x, int y, int w, int h, COLORREF c1, COLORREF c2, int r) {
    HRGN rgn = CreateRoundRectRgn(x, y, x + w + 1, y + h + 1, r, r);
    SelectClipRgn(dc, rgn);
    for (int i = 0; i < w; i++) {
        float t = (float)i / (float)w;
        int red   = (int)(GetRValue(c1) + t * (GetRValue(c2) - GetRValue(c1)));
        int green = (int)(GetGValue(c1) + t * (GetGValue(c2) - GetGValue(c1)));
        int blue  = (int)(GetBValue(c1) + t * (GetBValue(c2) - GetBValue(c1)));
        RECT colR = {x + i, y, x + i + 1, y + h};
        HBRUSH br = CreateSolidBrush(RGB(red, green, blue));
        FillRect(dc, &colR, br);
        DeleteObject(br);
    }
    SelectClipRgn(dc, NULL);
    DeleteObject(rgn);
}

/* Draw elegant flowing cyber ribbons */
static void DrawCyberWaves(HDC dc, int x, int y, int w, int h) {
    /* Background ambient radial glow in the center */
    int gcx = x + w / 2, gcy = y + 270;
    for (int gr = 140; gr >= 20; gr -= 15) {
        float factor = (1.0f - (float)gr / 140.0f);
        int bVal = (int)(25 + factor * 50);
        int cVal = (int)(10 + factor * 25);
        HBRUSH glowB = CreateSolidBrush(RGB(4, cVal, bVal));
        HPEN nullP = (HPEN)GetStockObject(NULL_PEN);
        HBRUSH ob = (HBRUSH)SelectObject(dc, glowB);
        HPEN op = (HPEN)SelectObject(dc, nullP);
        Ellipse(dc, gcx - gr * 13 / 10, gcy - gr, gcx + gr * 13 / 10, gcy + gr);
        SelectObject(dc, ob); SelectObject(dc, op);
        DeleteObject(glowB);
    }

    /* Elegant wavy curves */
    for (int i = 0; i < 7; i++) {
        COLORREF penCol = RGB(10 + i * 4, 28 + i * 9, 65 + i * 16);
        HPEN p = CreatePen(PS_SOLID, 2, penCol);
        HPEN op = (HPEN)SelectObject(dc, p);
        POINT pts[4];
        pts[0].x = x - 30;
        pts[0].y = y + h - 30 - i * 40;
        pts[1].x = x + w * 35 / 100;
        pts[1].y = y + h - 170 - i * 22;
        pts[2].x = x + w * 70 / 100;
        pts[2].y = y + h - 20 - i * 18;
        pts[3].x = x + w + 30;
        pts[3].y = y + h - 140 - i * 12;
        PolyBezier(dc, pts, 4);
        SelectObject(dc, op);
        DeleteObject(p);
    }
}

/* Draw stylized K logo */
static void DrawKLogo(HDC dc, int x, int y, int sz) {
    DrawRoundRectPanel(dc, x, y, sz, sz, 12, RGB(8, 20, 44), RGB(0, 150, 235));
    
    int barW = sz / 5;
    int m = sz / 5;
    DrawGradientH(dc, x + m, y + m, barW, sz - 2 * m, RGB(0, 210, 255), RGB(0, 110, 255), 3);

    POINT w1[3] = {
        { x + m + barW + 2, y + sz / 2 - 2 },
        { x + sz - m, y + m },
        { x + sz - m, y + m + sz / 4 }
    };
    HBRUSH b1 = CreateSolidBrush(RGB(0, 195, 255));
    HPEN pNone = (HPEN)GetStockObject(NULL_PEN);
    HBRUSH ob = (HBRUSH)SelectObject(dc, b1);
    HPEN op = (HPEN)SelectObject(dc, pNone);
    Polygon(dc, w1, 3);

    POINT w2[3] = {
        { x + m + barW + 2, y + sz / 2 - 2 },
        { x + sz - m - 4, y + sz - m },
        { x + sz - m + sz / 6, y + sz - m }
    };
    HBRUSH b2 = CreateSolidBrush(RGB(50, 130, 255));
    SelectObject(dc, b2);
    Polygon(dc, w2, 3);
    SelectObject(dc, ob); SelectObject(dc, op);
    DeleteObject(b1); DeleteObject(b2);
}

/* Draw holographic neon cloud with rings and shield/padlock */
static void DrawNeonCloudGraphic(HDC dc, int cx, int cy, HFONT fIcon) {
    int ringY = cy + 62;

    /* Light rays radiating from rings */
    HPEN rayPen = CreatePen(PS_SOLID, 1, RGB(12, 40, 95));
    HPEN opR = (HPEN)SelectObject(dc, rayPen);
    for (int ang = -70; ang <= 70; ang += 20) {
        float rad = (float)ang * 3.14159f / 180.0f;
        int rx0 = cx + (int)(sin(rad) * 60);
        int ry0 = ringY + (int)(cos(rad) * 16);
        int rx1 = cx + (int)(sin(rad) * 115);
        int ry1 = ringY + (int)(cos(rad) * 28);
        MoveToEx(dc, rx0, ry0, NULL);
        LineTo(dc, rx1, ry1);
    }
    SelectObject(dc, opR);
    DeleteObject(rayPen);

    /* Perspective Concentric Rings */
    for (int r = 4; r >= 1; r--) {
        int rx = 52 + r * 22;
        int ry = 14 + r * 6;
        COLORREF penCol = (r == 1) ? RGB(0, 240, 255) : (r == 2 ? RGB(0, 160, 255) : (r == 3 ? RGB(20, 80, 180) : RGB(25, 25, 80)));
        int penW = (r <= 2) ? 2 : 1;
        HPEN pen = CreatePen(PS_SOLID, penW, penCol);
        HBRUSH nullBr = (HBRUSH)GetStockObject(NULL_BRUSH);
        HPEN op = (HPEN)SelectObject(dc, pen);
        HBRUSH ob = (HBRUSH)SelectObject(dc, nullBr);
        Ellipse(dc, cx - rx, ringY - ry, cx + rx, ringY + ry);
        SelectObject(dc, op); SelectObject(dc, ob);
        DeleteObject(pen);
    }

    /* Floor particle dots */
    HBRUSH dotBr = CreateSolidBrush(RGB(0, 240, 255));
    HPEN nullP = (HPEN)GetStockObject(NULL_PEN);
    HBRUSH ob2 = (HBRUSH)SelectObject(dc, dotBr);
    HPEN op2 = (HPEN)SelectObject(dc, nullP);
    Ellipse(dc, cx - 82, ringY - 8, cx - 78, ringY - 4);
    Ellipse(dc, cx + 86, ringY + 4, cx + 90, ringY + 8);
    Ellipse(dc, cx + 48, ringY - 14, cx + 52, ringY - 10);
    Ellipse(dc, cx - 56, ringY + 12, cx - 52, ringY + 16);
    Ellipse(dc, cx + 10, ringY + 22, cx + 14, ringY + 26);
    SelectObject(dc, ob2); SelectObject(dc, op2); DeleteObject(dotBr);

    /* 2. Floating Cloud Shape */
    int cloudY = cy - 20;

    /* Cloud Multi-pass Soft Glow */
    for (int g = 6; g >= 2; g -= 2) {
        COLORREF glowCol = (g == 6) ? RGB(10, 35, 85) : (g == 4 ? RGB(16, 65, 145) : RGB(22, 105, 205));
        HPEN gPen = CreatePen(PS_SOLID, g, glowCol);
        HBRUSH cBg = CreateSolidBrush(RGB(6, 18, 42));
        HPEN opG = (HPEN)SelectObject(dc, gPen);
        HBRUSH obG = (HBRUSH)SelectObject(dc, cBg);

        RoundRect(dc, cx - 74, cloudY + 10, cx + 74, cloudY + 54, 30, 30);
        Ellipse(dc, cx - 68, cloudY - 10, cx - 10, cloudY + 48);
        Ellipse(dc, cx - 35, cloudY - 38, cx + 35, cloudY + 35);
        Ellipse(dc, cx + 10, cloudY - 12, cx + 68, cloudY + 48);

        SelectObject(dc, opG); SelectObject(dc, obG);
        DeleteObject(gPen); DeleteObject(cBg);
    }

    /* Cloud Inner Neon Outline */
    HPEN neonPen = CreatePen(PS_SOLID, 2, RGB(0, 220, 255));
    HPEN opN = (HPEN)SelectObject(dc, neonPen);
    HBRUSH nullB = (HBRUSH)GetStockObject(NULL_BRUSH);
    HBRUSH obN = (HBRUSH)SelectObject(dc, nullB);

    RoundRect(dc, cx - 74, cloudY + 10, cx + 74, cloudY + 54, 30, 30);
    Ellipse(dc, cx - 68, cloudY - 10, cx - 10, cloudY + 48);
    Ellipse(dc, cx - 35, cloudY - 38, cx + 35, cloudY + 35);
    Ellipse(dc, cx + 10, cloudY - 12, cx + 68, cloudY + 48);

    SelectObject(dc, opN); SelectObject(dc, obN);
    DeleteObject(neonPen);

    /* 3. Shield Badge inside Cloud */
    int shX = cx - 25, shY = cloudY - 12, shW = 50, shH = 56;
    HPEN shPen = CreatePen(PS_SOLID, 2, RGB(0, 220, 255));
    HBRUSH shBr = CreateSolidBrush(RGB(10, 26, 60));
    HPEN op4 = (HPEN)SelectObject(dc, shPen);
    HBRUSH ob4 = (HBRUSH)SelectObject(dc, shBr);
    POINT shPts[5] = {
        {shX, shY},
        {shX + shW, shY},
        {shX + shW, shY + shH * 3 / 5},
        {shX + shW / 2, shY + shH},
        {shX, shY + shH * 3 / 5}
    };
    Polygon(dc, shPts, 5);
    SelectObject(dc, op4); SelectObject(dc, ob4);
    DeleteObject(shPen); DeleteObject(shBr);

    /* Padlock inside shield */
    int lkX = cx - 10, lkY = shY + 20, lkW = 20, lkH = 17;
    HPEN lkPen = CreatePen(PS_SOLID, 2, RGB(165, 215, 255));
    HBRUSH nullB2 = (HBRUSH)GetStockObject(NULL_BRUSH);
    HPEN op5 = (HPEN)SelectObject(dc, lkPen);
    HBRUSH ob5 = (HBRUSH)SelectObject(dc, nullB2);
    Arc(dc, lkX + 2, lkY - 9, lkX + lkW - 2, lkY + 6, lkX + lkW - 2, lkY - 1, lkX + 2, lkY - 1);
    
    HBRUSH lkBody = CreateSolidBrush(RGB(165, 215, 255));
    SelectObject(dc, lkBody);
    RoundRect(dc, lkX, lkY, lkX + lkW, lkY + lkH, 4, 4);
    
    HBRUSH kh = CreateSolidBrush(RGB(10, 26, 60));
    SelectObject(dc, kh);
    Ellipse(dc, cx - 2, lkY + 4, cx + 2, lkY + 8);
    RECT khR = {cx - 1, lkY + 6, cx + 1, lkY + 12};
    FillRect(dc, &khR, kh);
    SelectObject(dc, op5); SelectObject(dc, ob5);
    DeleteObject(lkPen); DeleteObject(lkBody); DeleteObject(kh);
}

static void RenderMockup(int isRegister, const char *bmpName) {
    int W = 940, H = 760;
    HDC scrDC = GetDC(NULL);
    HDC dc = CreateCompatibleDC(scrDC);
    HBITMAP hbm = CreateCompatibleBitmap(scrDC, W, H);
    HBITMAP oldBm = (HBITMAP)SelectObject(dc, hbm);
    ReleaseDC(NULL, scrDC);

    HFONT fTitle = CreateFontA(26, 0, 0, 0, FW_BOLD, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, FF_SWISS, "Segoe UI");
    HFONT fSub   = CreateFontA(13, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, FF_SWISS, "Segoe UI");
    HFONT fLbl   = CreateFontA(14, 0, 0, 0, 600, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, FF_SWISS, "Segoe UI");
    HFONT fBtn   = CreateFontA(15, 0, 0, 0, FW_BOLD, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, FF_SWISS, "Segoe UI");
    HFONT fBtnSm = CreateFontA(14, 0, 0, 0, 600, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, FF_SWISS, "Segoe UI");
    HFONT fIcon  = CreateFontW(16, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, FF_SWISS, L"Segoe MDL2 Assets");
    if (!fIcon) fIcon = CreateFontW(16, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, FF_SWISS, L"Segoe UI Symbol");

    /* ================= 1. Background Fill ================= */
    RECT fullR = {0, 0, W, H};
    HBRUSH bgBr = CreateSolidBrush(RGB(7, 13, 24));
    FillRect(dc, &fullR, bgBr);
    DeleteObject(bgBr);

    /* ================= 2. Left Hero Panel ================= */
    int leftW = 340;
    RECT leftR = {0, 0, leftW, H};
    HBRUSH leftBr = CreateSolidBrush(RGB(5, 11, 22));
    FillRect(dc, &leftR, leftBr);
    DeleteObject(leftBr);

    DrawCyberWaves(dc, 0, 0, leftW, H);

    /* Subtle separator */
    HPEN divPen = CreatePen(PS_SOLID, 1, RGB(18, 30, 52));
    HPEN opD = (HPEN)SelectObject(dc, divPen);
    MoveToEx(dc, leftW, 0, NULL); LineTo(dc, leftW, H);
    SelectObject(dc, opD); DeleteObject(divPen);

    /* Left Top Brand */
    DrawKLogo(dc, 38, 44, 46);

    SetBkMode(dc, TRANSPARENT);
    SetTextColor(dc, RGB(245, 248, 255));
    SelectObject(dc, fTitle);
    TextOutA(dc, 94, 42, "Kaevex", 6);

    SetTextColor(dc, RGB(56, 189, 248));
    SelectObject(dc, fSub);
    TextOutA(dc, 94, 72, "Cloud Identity", 14);

    SetTextColor(dc, RGB(130, 145, 170));
    TextOutA(dc, 38, 108, "Realtime Supabase Security", 26);
    TextOutA(dc, 38, 126, "Synchronization, Fleet Management", 33);

    /* Holographic Cloud */
    DrawNeonCloudGraphic(dc, leftW / 2, 280, fIcon);

    /* Bottom 3 Feature Badges */
    struct { const wchar_t *icon; const char *text; } feats[3] = {
        { L"\uEA18", "Secure Access" },
        { L"\uE895", "Sync in Real-time" },
        { L"\uE7F4", "Fleet Management" }
    };
    int featY = 480;
    for (int i = 0; i < 3; i++) {
        int fy = featY + i * 50;
        DrawRoundRectPanel(dc, 38, fy, 36, 36, 8, RGB(10, 24, 48), RGB(24, 55, 110));
        SetTextColor(dc, RGB(56, 189, 248));
        SelectObject(dc, fIcon);
        RECT icR = {38, fy, 38 + 36, fy + 36};
        DrawTextW(dc, feats[i].icon, -1, &icR, DT_CENTER|DT_VCENTER|DT_SINGLELINE);

        SetTextColor(dc, RGB(185, 200, 225));
        SelectObject(dc, fLbl);
        RECT txR = {86, fy, leftW - 20, fy + 36};
        DrawTextA(dc, feats[i].text, -1, &txR, DT_LEFT|DT_VCENTER|DT_SINGLELINE);
    }

    /* ================= 3. Right Form Panel ================= */
    int formX = leftW + 48;
    int formW = W - formX - 48;

    /* Header */
    SetTextColor(dc, RGB(245, 248, 255));
    SelectObject(dc, fTitle);
    TextOutA(dc, formX, 40, "Welcome to ", 11);
    SIZE szWel; GetTextExtentPoint32A(dc, "Welcome to ", 11, &szWel);

    SetTextColor(dc, RGB(0, 210, 255));
    TextOutA(dc, formX + szWel.cx, 40, "Kaevex ", 7);
    SIZE szKvx; GetTextExtentPoint32A(dc, "Kaevex ", 7, &szKvx);
    SetTextColor(dc, RGB(180, 120, 255));
    TextOutA(dc, formX + szWel.cx + szKvx.cx, 40, "Cloud", 5);

    /* Subtitle */
    SetTextColor(dc, RGB(148, 163, 184));
    SelectObject(dc, fSub);
    if (!isRegister) {
        TextOutA(dc, formX, 78, "Sign in to your Supabase account to access", 42);
        TextOutA(dc, formX, 96, "secure cloud identity and fleet management.", 43);
    } else {
        TextOutA(dc, formX, 78, "Create a Supabase account to access secure cloud identity", 57);
        TextOutA(dc, formX, 96, "and enterprise fleet management.", 32);
    }

    int edH = 44;

    if (!isRegister) {
        /* ==== SIGN IN MODE ==== */
        /* Field 1: Email */
        int emailY = 144;
        SetTextColor(dc, RGB(220, 230, 245));
        SelectObject(dc, fLbl);
        TextOutA(dc, formX, emailY, "Email Address:", 14);

        int emailEdY = emailY + 22;
        DrawRoundRectPanel(dc, formX, emailEdY, formW, edH, 8, RGB(9, 18, 32), RGB(26, 50, 88));

        SetTextColor(dc, RGB(120, 140, 175));
        SelectObject(dc, fIcon);
        RECT mailR = {formX + 14, emailEdY, formX + 40, emailEdY + edH};
        DrawTextW(dc, L"\uE715", -1, &mailR, DT_CENTER|DT_VCENTER|DT_SINGLELINE);

        SetTextColor(dc, RGB(90, 110, 140));
        SelectObject(dc, fSub);
        RECT mailTxR = {formX + 46, emailEdY, formX + formW - 14, emailEdY + edH};
        DrawTextA(dc, "Enter your email address", -1, &mailTxR, DT_LEFT|DT_VCENTER|DT_SINGLELINE);

        /* Field 2: Password */
        int passY = emailEdY + edH + 18;
        SetTextColor(dc, RGB(220, 230, 245));
        SelectObject(dc, fLbl);
        TextOutA(dc, formX, passY, "Password:", 9);

        int passEdY = passY + 22;
        DrawRoundRectPanel(dc, formX, passEdY, formW, edH, 8, RGB(9, 18, 32), RGB(26, 50, 88));

        SetTextColor(dc, RGB(120, 140, 175));
        SelectObject(dc, fIcon);
        RECT lockR = {formX + 14, passEdY, formX + 40, passEdY + edH};
        DrawTextW(dc, L"\uE72E", -1, &lockR, DT_CENTER|DT_VCENTER|DT_SINGLELINE);

        SetTextColor(dc, RGB(90, 110, 140));
        SelectObject(dc, fSub);
        RECT passTxR = {formX + 46, passEdY, formX + formW - 46, passEdY + edH};
        DrawTextA(dc, "Enter your password", -1, &passTxR, DT_LEFT|DT_VCENTER|DT_SINGLELINE);

        /* Eye toggle */
        SetTextColor(dc, RGB(140, 160, 190));
        SelectObject(dc, fIcon);
        RECT eyeR = {formX + formW - 38, passEdY, formX + formW - 12, passEdY + edH};
        DrawTextW(dc, L"\uE7B3", -1, &eyeR, DT_CENTER|DT_VCENTER|DT_SINGLELINE);

        /* Primary Button */
        int btn1Y = passEdY + edH + 32;
        int btn1H = 50;
        DrawGradientH(dc, formX, btn1Y, formW, btn1H, RGB(0, 149, 255), RGB(168, 85, 247), 10);
        SetTextColor(dc, RGB(255, 255, 255));
        SelectObject(dc, fBtn);
        RECT btn1R = {formX, btn1Y, formX + formW, btn1Y + btn1H};
        DrawTextW(dc, L"Sign In to Supabase Cloud  \u2192", -1, &btn1R, DT_CENTER|DT_VCENTER|DT_SINGLELINE);

        /* Secondary Button */
        int btn2Y = btn1Y + btn1H + 16;
        int btn2H = 46;
        DrawRoundRectPanel(dc, formX, btn2Y, formW, btn2H, 10, RGB(9, 18, 34), RGB(28, 56, 104));
        SetTextColor(dc, RGB(210, 225, 245));
        SelectObject(dc, fBtnSm);
        RECT btn2R = {formX, btn2Y, formX + formW, btn2Y + btn2H};
        DrawTextW(dc, L"\uE77B  Register", -1, &btn2R, DT_CENTER|DT_VCENTER|DT_SINGLELINE);

        /* Divider with OR */
        int orY = btn2Y + btn2H + 28;
        int orLineW = (formW - 50) / 2;
        HPEN orPen = CreatePen(PS_SOLID, 1, RGB(26, 40, 64));
        HPEN opO = (HPEN)SelectObject(dc, orPen);
        MoveToEx(dc, formX, orY, NULL); LineTo(dc, formX + orLineW, orY);
        MoveToEx(dc, formX + formW - orLineW, orY, NULL); LineTo(dc, formX + formW, orY);
        SelectObject(dc, opO); DeleteObject(orPen);

        SetTextColor(dc, RGB(110, 130, 160));
        SelectObject(dc, fSub);
        RECT orR = {formX + orLineW, orY - 9, formX + formW - orLineW, orY + 9};
        DrawTextA(dc, "OR", -1, &orR, DT_CENTER|DT_VCENTER|DT_SINGLELINE);

        /* Close Button */
        int closeW = 130, closeH = 36;
        int closeX = formX + (formW - closeW) / 2;
        int closeY = orY + 22;
        DrawRoundRectPanel(dc, closeX, closeY, closeW, closeH, 8, RGB(11, 20, 36), RGB(30, 52, 85));
        SetTextColor(dc, RGB(180, 200, 225));
        SelectObject(dc, fBtnSm);
        RECT closeR = {closeX, closeY, closeX + closeW, closeY + closeH};
        DrawTextW(dc, L"\uE711  Close", -1, &closeR, DT_CENTER|DT_VCENTER|DT_SINGLELINE);

    } else {
        /* ==== REGISTER MODE ==== */
        /* Field 1: Full Name */
        int nameY = 126;
        SetTextColor(dc, RGB(220, 230, 245));
        SelectObject(dc, fLbl);
        TextOutA(dc, formX, nameY, "Full Name:", 10);

        int nameEdY = nameY + 20;
        DrawRoundRectPanel(dc, formX, nameEdY, formW, 40, 8, RGB(9, 18, 32), RGB(26, 50, 88));
        SetTextColor(dc, RGB(120, 140, 175));
        SelectObject(dc, fIcon);
        RECT nameIcR = {formX + 14, nameEdY, formX + 40, nameEdY + 40};
        DrawTextW(dc, L"\uE77B", -1, &nameIcR, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
        SetTextColor(dc, RGB(90, 110, 140));
        SelectObject(dc, fSub);
        RECT nameTxR = {formX + 46, nameEdY, formX + formW - 14, nameEdY + 40};
        DrawTextA(dc, "Enter your full name", -1, &nameTxR, DT_LEFT|DT_VCENTER|DT_SINGLELINE);

        /* Field 2: Email */
        int emailY = nameEdY + 40 + 10;
        SetTextColor(dc, RGB(220, 230, 245));
        SelectObject(dc, fLbl);
        TextOutA(dc, formX, emailY, "Email Address:", 14);

        int emailEdY = emailY + 20;
        DrawRoundRectPanel(dc, formX, emailEdY, formW, 40, 8, RGB(9, 18, 32), RGB(26, 50, 88));
        SetTextColor(dc, RGB(120, 140, 175));
        SelectObject(dc, fIcon);
        RECT mailR = {formX + 14, emailEdY, formX + 40, emailEdY + 40};
        DrawTextW(dc, L"\uE715", -1, &mailR, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
        SetTextColor(dc, RGB(90, 110, 140));
        SelectObject(dc, fSub);
        RECT mailTxR = {formX + 46, emailEdY, formX + formW - 14, emailEdY + 40};
        DrawTextA(dc, "Enter your email address", -1, &mailTxR, DT_LEFT|DT_VCENTER|DT_SINGLELINE);

        /* Field 3: Password */
        int passY = emailEdY + 40 + 10;
        SetTextColor(dc, RGB(220, 230, 245));
        SelectObject(dc, fLbl);
        TextOutA(dc, formX, passY, "Password:", 9);

        int passEdY = passY + 20;
        DrawRoundRectPanel(dc, formX, passEdY, formW, 40, 8, RGB(9, 18, 32), RGB(26, 50, 88));
        SetTextColor(dc, RGB(120, 140, 175));
        SelectObject(dc, fIcon);
        RECT lockR = {formX + 14, passEdY, formX + 40, passEdY + 40};
        DrawTextW(dc, L"\uE72E", -1, &lockR, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
        SetTextColor(dc, RGB(90, 110, 140));
        SelectObject(dc, fSub);
        RECT passTxR = {formX + 46, passEdY, formX + formW - 46, passEdY + 40};
        DrawTextA(dc, "Create a password", -1, &passTxR, DT_LEFT|DT_VCENTER|DT_SINGLELINE);

        /* Field 4: Confirm Password */
        int pass2Y = passEdY + 40 + 10;
        SetTextColor(dc, RGB(220, 230, 245));
        SelectObject(dc, fLbl);
        TextOutA(dc, formX, pass2Y, "Confirm Password:", 17);

        int pass2EdY = pass2Y + 20;
        DrawRoundRectPanel(dc, formX, pass2EdY, formW, 40, 8, RGB(9, 18, 32), RGB(26, 50, 88));
        SetTextColor(dc, RGB(120, 140, 175));
        SelectObject(dc, fIcon);
        RECT lock2R = {formX + 14, pass2EdY, formX + 40, pass2EdY + 40};
        DrawTextW(dc, L"\uE72E", -1, &lock2R, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
        SetTextColor(dc, RGB(90, 110, 140));
        SelectObject(dc, fSub);
        RECT pass2TxR = {formX + 46, pass2EdY, formX + formW - 46, pass2EdY + 40};
        DrawTextA(dc, "Confirm your password", -1, &pass2TxR, DT_LEFT|DT_VCENTER|DT_SINGLELINE);

        /* Primary Button: Register */
        int btn1Y = pass2EdY + 40 + 20;
        int btn1H = 48;
        DrawGradientH(dc, formX, btn1Y, formW, btn1H, RGB(0, 149, 255), RGB(168, 85, 247), 10);
        SetTextColor(dc, RGB(255, 255, 255));
        SelectObject(dc, fBtn);
        RECT btn1R = {formX, btn1Y, formX + formW, btn1Y + btn1H};
        DrawTextW(dc, L"Create Supabase Cloud Account  \u2192", -1, &btn1R, DT_CENTER|DT_VCENTER|DT_SINGLELINE);

        /* Secondary Button: Back to Sign In */
        int btn2Y = btn1Y + btn1H + 12;
        int btn2H = 42;
        DrawRoundRectPanel(dc, formX, btn2Y, formW, btn2H, 10, RGB(9, 18, 34), RGB(28, 56, 104));
        SetTextColor(dc, RGB(210, 225, 245));
        SelectObject(dc, fBtnSm);
        RECT btn2R = {formX, btn2Y, formX + formW, btn2Y + btn2H};
        DrawTextW(dc, L"\uE72B  Back to Sign In", -1, &btn2R, DT_CENTER|DT_VCENTER|DT_SINGLELINE);

        /* Divider with OR */
        int orY = btn2Y + btn2H + 20;
        int orLineW = (formW - 50) / 2;
        HPEN orPen = CreatePen(PS_SOLID, 1, RGB(26, 40, 64));
        HPEN opO = (HPEN)SelectObject(dc, orPen);
        MoveToEx(dc, formX, orY, NULL); LineTo(dc, formX + orLineW, orY);
        MoveToEx(dc, formX + formW - orLineW, orY, NULL); LineTo(dc, formX + formW, orY);
        SelectObject(dc, opO); DeleteObject(orPen);

        SetTextColor(dc, RGB(110, 130, 160));
        SelectObject(dc, fSub);
        RECT orR = {formX + orLineW, orY - 9, formX + formW - orLineW, orY + 9};
        DrawTextA(dc, "OR", -1, &orR, DT_CENTER|DT_VCENTER|DT_SINGLELINE);

        /* Close Button */
        int closeW = 130, closeH = 34;
        int closeX = formX + (formW - closeW) / 2;
        int closeY = orY + 16;
        DrawRoundRectPanel(dc, closeX, closeY, closeW, closeH, 8, RGB(11, 20, 36), RGB(30, 52, 85));
        SetTextColor(dc, RGB(180, 200, 225));
        SelectObject(dc, fBtnSm);
        RECT closeR = {closeX, closeY, closeX + closeW, closeY + closeH};
        DrawTextW(dc, L"\uE711  Close", -1, &closeR, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
    }

    SaveHDCtoBMP(dc, W, H, bmpName);

    SelectObject(dc, oldBm);
    DeleteObject(hbm);
    DeleteDC(dc);
    DeleteObject(fTitle); DeleteObject(fSub); DeleteObject(fLbl);
    DeleteObject(fBtn); DeleteObject(fBtnSm); DeleteObject(fIcon);
}

int main() {
    RenderMockup(0, "scratch\\test_login_mockup.bmp");
    RenderMockup(1, "scratch\\test_register_mockup.bmp");
    printf("Generated both Login and Register bitmaps!\n");
    return 0;
}
