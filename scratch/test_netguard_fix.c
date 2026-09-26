#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#define C_BG        RGB( 5,   9,  18)
#define C_CARD      RGB( 9,  15,  28)
#define C_CARD2     RGB(12,  20,  36)
#define C_PANEL     RGB(10,  18,  34)
#define C_BORDER    RGB(20,  38,  70)
#define C_BORDER2   RGB(16,  28,  52)
#define C_TEXT      RGB(240, 246, 255)
#define C_TEXT2     RGB(180, 195, 220)
#define C_DIM       RGB(110, 130, 160)
#define C_DIM2      RGB( 70,  90, 120)
#define C_CYAN      RGB(  0, 210, 255)
#define C_BLUE      RGB( 37,  99, 235)
#define C_GREEN     RGB( 16, 185, 129)
#define C_AMBER     RGB(245, 158,  11)
#define C_RED       RGB(239,  68,  68)
#define C_PURPLE    RGB(168,  85, 247)

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

static void Txt(HDC dc, const char *txt, int x, int y, int w, int h, COLORREF col, HFONT font, UINT align) {
    SetBkMode(dc, TRANSPARENT);
    SetTextColor(dc, col);
    HFONT of = (HFONT)SelectObject(dc, font);
    RECT r = {x, y, x + w, y + h};
    DrawTextA(dc, txt, -1, &r, align | DT_NOPREFIX);
    SelectObject(dc, of);
}

/* Draw custom brand vector icons */
static void DrawBrandIcon(HDC dc, int x, int y, int sz, int type) {
    HPEN nullP = (HPEN)GetStockObject(NULL_PEN);
    HBRUSH nullB = (HBRUSH)GetStockObject(NULL_BRUSH);

    if (type == 1) { /* Android Studio - Green bug */
        HBRUSH br = CreateSolidBrush(RGB(61, 220, 132));
        HBRUSH ob = (HBRUSH)SelectObject(dc, br);
        HPEN op = (HPEN)SelectObject(dc, nullP);
        /* Head dome */
        Chord(dc, x+2, y+4, x+sz-2, y+sz-2, x+sz-2, y+sz/2, x+2, y+sz/2);
        /* Eyes */
        HBRUSH eyeBr = CreateSolidBrush(RGB(9, 15, 28));
        SelectObject(dc, eyeBr);
        Ellipse(dc, x+sz/4, y+sz/3, x+sz/4+3, y+sz/3+3);
        Ellipse(dc, x+sz*3/4-3, y+sz/3, x+sz*3/4, y+sz/3+3);
        SelectObject(dc, ob); SelectObject(dc, op);
        DeleteObject(br); DeleteObject(eyeBr);
    }
    else if (type == 2) { /* Git - Red/orange rotated square */
        HBRUSH br = CreateSolidBrush(RGB(240, 80, 51));
        HBRUSH ob = (HBRUSH)SelectObject(dc, br);
        HPEN op = (HPEN)SelectObject(dc, nullP);
        POINT diamond[4] = {
            { x + sz/2, y + 2 },
            { x + sz - 2, y + sz/2 },
            { x + sz/2, y + sz - 2 },
            { x + 2, y + sz/2 }
        };
        Polygon(dc, diamond, 4);
        /* Branch white line */
        HPEN wPen = CreatePen(PS_SOLID, 2, RGB(255, 255, 255));
        SelectObject(dc, wPen);
        MoveToEx(dc, x + sz/3, y + sz*2/3, NULL);
        LineTo(dc, x + sz*2/3, y + sz/3);
        SelectObject(dc, ob); SelectObject(dc, op);
        DeleteObject(br); DeleteObject(wPen);
    }
    else if (type == 3) { /* Firefox - Orange/purple fox */
        HBRUSH br = CreateSolidBrush(RGB(255, 113, 57));
        HBRUSH ob = (HBRUSH)SelectObject(dc, br);
        HPEN op = (HPEN)SelectObject(dc, nullP);
        Ellipse(dc, x+2, y+2, x+sz-2, y+sz-2);
        /* Purple globe core */
        HBRUSH pBr = CreateSolidBrush(RGB(144, 89, 255));
        SelectObject(dc, pBr);
        Ellipse(dc, x+sz/4, y+sz/4, x+sz*3/4, y+sz*3/4);
        SelectObject(dc, ob); SelectObject(dc, op);
        DeleteObject(br); DeleteObject(pBr);
    }
    else if (type == 4) { /* Spotify - Green circle with sound waves */
        HBRUSH br = CreateSolidBrush(RGB(30, 215, 96));
        HBRUSH ob = (HBRUSH)SelectObject(dc, br);
        HPEN op = (HPEN)SelectObject(dc, nullP);
        Ellipse(dc, x+2, y+2, x+sz-2, y+sz-2);
        /* 3 black curved lines */
        HPEN arcP = CreatePen(PS_SOLID, 2, RGB(10, 16, 26));
        SelectObject(dc, arcP); SelectObject(dc, nullB);
        Arc(dc, x+4, y+4, x+sz-4, y+sz/2+2, x+sz-6, y+sz/3, x+6, y+sz/3);
        Arc(dc, x+6, y+7, x+sz-6, y+sz/2+5, x+sz-8, y+sz/2, x+8, y+sz/2);
        SelectObject(dc, ob); SelectObject(dc, op);
        DeleteObject(br); DeleteObject(arcP);
    }
    else if (type == 5) { /* Microsoft 365 - 4 colored squares */
        HBRUSH r1 = CreateSolidBrush(RGB(242, 80, 34));  /* Orange */
        HBRUSH r2 = CreateSolidBrush(RGB(127, 186, 0));  /* Green */
        HBRUSH r3 = CreateSolidBrush(RGB(0, 164, 239));  /* Blue */
        HBRUSH r4 = CreateSolidBrush(RGB(255, 185, 0));  /* Yellow */
        HPEN op = (HPEN)SelectObject(dc, nullP);
        int m = sz / 2;
        RECT q1 = {x+2, y+2, x+m-1, y+m-1};
        RECT q2 = {x+m+1, y+2, x+sz-2, y+m-1};
        RECT q3 = {x+2, y+m+1, x+m-1, y+sz-2};
        RECT q4 = {x+m+1, y+m+1, x+sz-2, y+sz-2};
        FillRect(dc, &q1, r1); FillRect(dc, &q2, r2);
        FillRect(dc, &q3, r3); FillRect(dc, &q4, r4);
        SelectObject(dc, op);
        DeleteObject(r1); DeleteObject(r2); DeleteObject(r3); DeleteObject(r4);
    }
    else if (type == 6) { /* Windows Push Notifications - 4 cyan/blue squares */
        HBRUSH br = CreateSolidBrush(RGB(0, 164, 239));
        HPEN op = (HPEN)SelectObject(dc, nullP);
        int m = sz / 2;
        RECT q1 = {x+2, y+2, x+m-1, y+m-1};
        RECT q2 = {x+m+1, y+2, x+sz-2, y+m-1};
        RECT q3 = {x+2, y+m+1, x+m-1, y+sz-2};
        RECT q4 = {x+m+1, y+m+1, x+sz-2, y+sz-2};
        FillRect(dc, &q1, br); FillRect(dc, &q2, br);
        FillRect(dc, &q3, br); FillRect(dc, &q4, br);
        SelectObject(dc, op); DeleteObject(br);
    }
    else if (type == 7) { /* OneDrive - Cloud */
        HBRUSH br = CreateSolidBrush(RGB(14, 114, 236));
        HBRUSH ob = (HBRUSH)SelectObject(dc, br);
        HPEN op = (HPEN)SelectObject(dc, nullP);
        RoundRect(dc, x+3, y+sz/3, x+sz-3, y+sz-3, 6, 6);
        Ellipse(dc, x+sz/4, y+3, x+sz*3/4, y+sz*3/4);
        Ellipse(dc, x+3, y+sz/4, x+sz/2, y+sz*3/4);
        SelectObject(dc, ob); SelectObject(dc, op); DeleteObject(br);
    }
    else if (type == 8) { /* WinRAR - Books stack */
        HBRUSH b1 = CreateSolidBrush(RGB(80, 60, 180));
        HBRUSH b2 = CreateSolidBrush(RGB(0, 150, 220));
        HBRUSH b3 = CreateSolidBrush(RGB(220, 50, 80));
        HPEN op = (HPEN)SelectObject(dc, nullP);
        RECT r1 = {x+2, y+3, x+sz-2, y+sz/3};
        RECT r2 = {x+2, y+sz/3+1, x+sz-2, y+sz*2/3-1};
        RECT r3 = {x+2, y+sz*2/3, x+sz-2, y+sz-3};
        FillRect(dc, &r1, b1); FillRect(dc, &r2, b2); FillRect(dc, &r3, b3);
        SelectObject(dc, op);
        DeleteObject(b1); DeleteObject(b2); DeleteObject(b3);
    }
    else if (type == 9) { /* XAMPP - Orange box with bone */
        DrawRoundRectPanel(dc, x+2, y+2, sz-4, sz-4, 6, RGB(251, 140, 0), RGB(255, 179, 0));
        HPEN wP = CreatePen(PS_SOLID, 2, RGB(255, 255, 255));
        HPEN op = (HPEN)SelectObject(dc, wP);
        MoveToEx(dc, x+6, y+6, NULL); LineTo(dc, x+sz-6, y+sz-6);
        MoveToEx(dc, x+sz-6, y+6, NULL); LineTo(dc, x+6, y+sz-6);
        SelectObject(dc, op); DeleteObject(wP);
    }
    else if (type == 10) { /* Brave Browser - Orange lion shield */
        HBRUSH br = CreateSolidBrush(RGB(251, 84, 43));
        HBRUSH ob = (HBRUSH)SelectObject(dc, br);
        HPEN op = (HPEN)SelectObject(dc, nullP);
        POINT sh[5] = {
            {x+3, y+3}, {x+sz-3, y+3},
            {x+sz-3, y+sz*3/5}, {x+sz/2, y+sz-2}, {x+3, y+sz*3/5}
        };
        Polygon(dc, sh, 5);
        SelectObject(dc, ob); SelectObject(dc, op); DeleteObject(br);
    }
    else if (type == 11) { /* Visual Studio / C++ - Purple ribbon */
        DrawRoundRectPanel(dc, x+2, y+2, sz-4, sz-4, 6, RGB(104, 33, 122), RGB(168, 85, 247));
        HPEN wP = CreatePen(PS_SOLID, 2, RGB(255, 255, 255));
        HPEN op = (HPEN)SelectObject(dc, wP);
        POINT rib[4] = {
            {x+sz-6, y+5}, {x+6, y+sz/2}, {x+sz-6, y+sz-5}, {x+sz/2, y+sz/2}
        };
        Polyline(dc, rib, 4);
        SelectObject(dc, op); DeleteObject(wP);
    }
    else { /* Generic Process */
        DrawRoundRectPanel(dc, x+2, y+2, sz-4, sz-4, 6, RGB(16, 36, 70), RGB(0, 180, 255));
        HBRUSH dBr = CreateSolidBrush(RGB(0, 210, 255));
        HPEN op = (HPEN)SelectObject(dc, nullP);
        HBRUSH ob = (HBRUSH)SelectObject(dc, dBr);
        Ellipse(dc, x+sz/2-3, y+sz/2-3, x+sz/2+3, y+sz/2+3);
        SelectObject(dc, ob); SelectObject(dc, op); DeleteObject(dBr);
    }
}

int main() {
    int W = 1140, H = 760;
    HDC scrDC = GetDC(NULL);
    HDC dc = CreateCompatibleDC(scrDC);
    HBITMAP hbm = CreateCompatibleBitmap(scrDC, W, H);
    HBITMAP oldBm = (HBITMAP)SelectObject(dc, hbm);
    ReleaseDC(NULL, scrDC);

    HFONT fHdr   = CreateFontA(22, 0, 0, 0, FW_BOLD, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, FF_SWISS, "Segoe UI");
    HFONT fBig   = CreateFontA(24, 0, 0, 0, FW_BOLD, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, FF_SWISS, "Segoe UI");
    HFONT fStatV = CreateFontA(20, 0, 0, 0, FW_BOLD, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, FF_SWISS, "Segoe UI");
    HFONT fMed   = CreateFontA(14, 0, 0, 0, 600,     0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, FF_SWISS, "Segoe UI");
    HFONT fSm    = CreateFontA(12, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, FF_SWISS, "Segoe UI");
    HFONT fMini  = CreateFontA(10, 0, 0, 0, 600,     0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, FF_SWISS, "Segoe UI");
    HFONT fMono  = CreateFontA(12, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, FF_MODERN, "Consolas");
    HFONT fIcon  = CreateFontW(14, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, FF_SWISS, L"Segoe MDL2 Assets");
    if (!fIcon) fIcon = CreateFontW(14, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, FF_SWISS, L"Segoe UI Symbol");
    HFONT fIconBig = CreateFontW(22, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, FF_SWISS, L"Segoe MDL2 Assets");
    if (!fIconBig) fIconBig = CreateFontW(22, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, FF_SWISS, L"Segoe UI Symbol");

    /* Base Fill */
    RECT bgR = {0, 0, W, H};
    HBRUSH bgBr = CreateSolidBrush(C_BG);
    FillRect(dc, &bgR, bgBr);
    DeleteObject(bgBr);

    int MRG = 16;
    int cx = 0, cy = 0, cw = W;

    /* ================= 1. Top Header Banner Card ================= */
    int bannerY = cy + 12;
    int bannerH = 76;
    int bannerW = cw - MRG * 2;
    DrawRoundRectPanel(dc, cx + MRG, bannerY, bannerW, bannerH, 10, C_PANEL, C_BORDER);

    /* Left Shield Badge */
    int shX = cx + MRG + 16, shY = bannerY + 16, shSz = 44;
    DrawRoundRectPanel(dc, shX, shY, shSz, shSz, 10, RGB(16, 38, 78), C_BLUE);
    SetBkMode(dc, TRANSPARENT);
    SetTextColor(dc, RGB(56, 189, 248));
    SelectObject(dc, fIconBig);
    RECT shR = {shX, shY, shX + shSz, shY + shSz};
    DrawTextW(dc, L"\uEA18", -1, &shR, DT_CENTER|DT_VCENTER|DT_SINGLELINE);

    /* Title & Subtitle */
    Txt(dc, "NetGuard ", shX + shSz + 14, bannerY + 14, 100, 24, C_TEXT, fBig, DT_LEFT|DT_SINGLELINE);
    Txt(dc, "Traffic",   shX + shSz + 114, bannerY + 14, 100, 24, C_CYAN, fBig, DT_LEFT|DT_SINGLELINE);
    Txt(dc, "Monitor, analyze and control network traffic in real time.",
        shX + shSz + 14, bannerY + 42, 380, 16, C_DIM, fSm, DT_LEFT|DT_SINGLELINE);

    /* Right 4 Stat Cards inside banner */
    int cardY = bannerY + 11;
    int cardH = 54;
    int rightEdge = cx + cw - MRG - 12;

    /* Card 4: Traffic Overview (Sparkline) */
    int card4W = 150;
    int card4X = rightEdge - card4W;
    DrawRoundRectPanel(dc, card4X, cardY, card4W, cardH, 8, C_CARD2, C_BORDER2);
    Txt(dc, "Traffic Overview", card4X + 10, cardY + 8, 90, 14, C_DIM, fMini, DT_LEFT|DT_SINGLELINE);
    /* Live dot + text */
    HBRUSH grnB = CreateSolidBrush(C_GREEN);
    HPEN nullP = (HPEN)GetStockObject(NULL_PEN);
    HBRUSH ob = (HBRUSH)SelectObject(dc, grnB);
    HPEN op = (HPEN)SelectObject(dc, nullP);
    Ellipse(dc, card4X + card4W - 42, cardY + 12, card4X + card4W - 36, cardY + 18);
    SelectObject(dc, ob); SelectObject(dc, op); DeleteObject(grnB);
    Txt(dc, "Live", card4X + card4W - 32, cardY + 7, 30, 14, C_GREEN, fMini, DT_LEFT|DT_SINGLELINE);

    /* Sparkline wave */
    HPEN spPen = CreatePen(PS_SOLID, 2, RGB(0, 200, 255));
    HPEN spGlow = CreatePen(PS_SOLID, 4, RGB(10, 45, 90));
    SelectObject(dc, spGlow);
    POINT spPts[6] = {
        { card4X + 12, cardY + 38 },
        { card4X + 42, cardY + 30 },
        { card4X + 72, cardY + 44 },
        { card4X + 102, cardY + 32 },
        { card4X + 125, cardY + 40 },
        { card4X + 140, cardY + 34 }
    };
    Polyline(dc, spPts, 6);
    SelectObject(dc, spPen);
    Polyline(dc, spPts, 6);
    SelectObject(dc, op);
    DeleteObject(spPen); DeleteObject(spGlow);

    /* Card 3: Blocked */
    int card3W = 125;
    int card3X = card4X - card3W - 8;
    DrawRoundRectPanel(dc, card3X, cardY, card3W, cardH, 8, C_CARD2, C_BORDER2);
    /* Target icon badge */
    DrawRoundRectPanel(dc, card3X + 10, cardY + 12, 30, 30, 8, RGB(16, 38, 76), RGB(0, 180, 255));
    SetTextColor(dc, C_CYAN); SelectObject(dc, fIcon);
    RECT c3ir = {card3X + 10, cardY + 12, card3X + 40, cardY + 42};
    DrawTextW(dc, L"\uE72E", -1, &c3ir, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
    Txt(dc, "Blocked", card3X + 46, cardY + 6, 70, 14, C_DIM, fMini, DT_LEFT|DT_SINGLELINE);
    Txt(dc, "3", card3X + 46, cardY + 20, 30, 20, C_TEXT, fStatV, DT_LEFT|DT_SINGLELINE);
    Txt(dc, "\x19 25%", card3X + 72, cardY + 24, 46, 14, C_CYAN, fMini, DT_LEFT|DT_SINGLELINE);

    /* Card 2: Open Ports */
    int card2W = 130;
    int card2X = card3X - card2W - 8;
    DrawRoundRectPanel(dc, card2X, cardY, card2W, cardH, 8, C_CARD2, C_BORDER2);
    /* Purple port badge */
    DrawRoundRectPanel(dc, card2X + 10, cardY + 12, 30, 30, 8, RGB(36, 22, 60), RGB(168, 85, 247));
    SetTextColor(dc, C_PURPLE); SelectObject(dc, fIcon);
    RECT c2ir = {card2X + 10, cardY + 12, card2X + 40, cardY + 42};
    DrawTextW(dc, L"\uE74C", -1, &c2ir, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
    Txt(dc, "Open Ports", card2X + 46, cardY + 6, 75, 14, C_DIM, fMini, DT_LEFT|DT_SINGLELINE);
    Txt(dc, "48", card2X + 46, cardY + 20, 30, 20, C_TEXT, fStatV, DT_LEFT|DT_SINGLELINE);
    Txt(dc, "\x18 6%", card2X + 76, cardY + 24, 46, 14, C_PURPLE, fMini, DT_LEFT|DT_SINGLELINE);

    /* Card 1: Active Connections */
    int card1W = 140;
    int card1X = card2X - card1W - 8;
    DrawRoundRectPanel(dc, card1X, cardY, card1W, cardH, 8, C_CARD2, C_BORDER2);
    /* Green network nodes badge */
    DrawRoundRectPanel(dc, card1X + 10, cardY + 12, 30, 30, 8, RGB(12, 42, 32), RGB(16, 185, 129));
    SetTextColor(dc, C_GREEN); SelectObject(dc, fIcon);
    RECT c1ir = {card1X + 10, cardY + 12, card1X + 40, cardY + 42};
    DrawTextW(dc, L"\uE968", -1, &c1ir, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
    Txt(dc, "Active Connections", card1X + 46, cardY + 6, 90, 14, C_DIM, fMini, DT_LEFT|DT_SINGLELINE);
    Txt(dc, "312", card1X + 46, cardY + 20, 40, 20, C_TEXT, fStatV, DT_LEFT|DT_SINGLELINE);
    Txt(dc, "\x18 12%", card1X + 88, cardY + 24, 46, 14, C_GREEN, fMini, DT_LEFT|DT_SINGLELINE);

    /* ================= 2. Action Controls / Toolbar Row ================= */
    int toolY = bannerY + bannerH + 12;
    int toolH = 32;

    /* Button 1: Scan Connections (Green action button) */
    int btn1W = 150;
    DrawRoundRectPanel(dc, cx + MRG, toolY, btn1W, toolH, 8, RGB(10, 48, 36), RGB(16, 185, 129));
    SetTextColor(dc, RGB(52, 211, 153)); SelectObject(dc, fMed);
    RECT b1r = {cx + MRG, toolY, cx + MRG + btn1W, toolY + toolH};
    DrawTextW(dc, L"\uE768  Scan Connections", -1, &b1r, DT_CENTER|DT_VCENTER|DT_SINGLELINE);

    /* Button 2: Scan Open Ports */
    int btn2W = 140;
    int btn2X = cx + MRG + btn1W + 10;
    DrawRoundRectPanel(dc, btn2X, toolY, btn2W, toolH, 8, C_CARD2, C_BORDER);
    SetTextColor(dc, C_TEXT2);
    RECT b2r = {btn2X, toolY, btn2X + btn2W, toolY + toolH};
    DrawTextW(dc, L"\uE774  Scan Open Ports", -1, &b2r, DT_CENTER|DT_VCENTER|DT_SINGLELINE);

    /* Button 3: Close Port */
    int btn3W = 110;
    int btn3X = btn2X + btn2W + 10;
    DrawRoundRectPanel(dc, btn3X, toolY, btn3W, toolH, 8, C_CARD2, C_BORDER);
    SetTextColor(dc, C_TEXT2);
    RECT b3r = {btn3X, toolY, btn3X + btn3W, toolY + toolH};
    DrawTextW(dc, L"\uE711  Close Port", -1, &b3r, DT_CENTER|DT_VCENTER|DT_SINGLELINE);

    /* Right: Kill PID (Red button) */
    int btnKillW = 85;
    int btnKillX = cx + cw - MRG - btnKillW;
    DrawRoundRectPanel(dc, btnKillX, toolY, btnKillW, toolH, 8, RGB(80, 16, 26), RGB(239, 68, 68));
    SetTextColor(dc, RGB(255, 150, 160));
    RECT bKr = {btnKillX, toolY, btnKillX + btnKillW, toolY + toolH};
    DrawTextW(dc, L"\uE74D  Kill PID", -1, &bKr, DT_CENTER|DT_VCENTER|DT_SINGLELINE);

    /* Sort By Pill */
    int sortW = 130;
    int sortX = btnKillX - sortW - 10;
    DrawRoundRectPanel(dc, sortX, toolY, sortW, toolH, 8, C_CARD2, C_BORDER2);
    Txt(dc, "Sort by: Latest  \x76", sortX, toolY, sortW, toolH, C_TEXT2, fSm, DT_CENTER|DT_VCENTER|DT_SINGLELINE);

    /* ================= 3. Search & Filter Bar ================= */
    int srchY = toolY + toolH + 10;
    int srchH = 34;
    DrawRoundRectPanel(dc, cx + MRG, srchY, bannerW, srchH, 8, C_CARD, C_BORDER2);

    /* Magnifier */
    SetTextColor(dc, C_DIM); SelectObject(dc, fIcon);
    RECT magR = {cx + MRG + 10, srchY, cx + MRG + 34, srchY + srchH};
    DrawTextW(dc, L"\uE721", -1, &magR, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
    Txt(dc, "Search by process, IP, port, or application...", cx + MRG + 36, srchY, 400, srchH, C_DIM, fSm, DT_LEFT|DT_VCENTER|DT_SINGLELINE);

    /* Snort/DNS toggle button on right of search bar */
    int snortW = 100;
    int snortX = cx + MRG + bannerW - snortW - 8;
    DrawRoundRectPanel(dc, snortX, srchY + 4, snortW, srchH - 8, 6, RGB(14, 28, 54), RGB(30, 68, 130));
    SetTextColor(dc, RGB(0, 195, 255)); SelectObject(dc, fSm);
    RECT snR = {snortX, srchY + 4, snortX + snortW, srchY + srchH - 4};
    DrawTextW(dc, L"\uE968  Snort/DNS", -1, &snR, DT_CENTER|DT_VCENTER|DT_SINGLELINE);

    /* ================= 4. Connections Table Container ================= */
    int tblY = srchY + srchH + 10;
    int tblH = H - tblY - 14;
    DrawRoundRectPanel(dc, cx + MRG, tblY, bannerW, tblH, 8, C_CARD, C_BORDER);

    /* Column Headers at tblY + 6 */
    int thY = tblY + 6;
    int thH = 24;

    int colX1 = cx + MRG + 14;  /* # */
    int colX2 = cx + MRG + 44;  /* App / Process */
    int colX3 = cx + MRG + 230; /* Local Address */
    int colX4 = cx + MRG + 380; /* Remote Endpoint */
    int colX5 = cx + MRG + 510; /* Category */
    int colX6 = cx + MRG + 660; /* Reverse DNS / Host */
    int colX7 = cx + MRG + 840; /* State */
    int colX8 = cx + MRG + bannerW - 40; /* Action */

    Txt(dc, "#", colX1, thY, 24, thH, C_DIM, fMini, DT_LEFT|DT_VCENTER|DT_SINGLELINE);
    Txt(dc, "Application / Process", colX2 + 18, thY, 160, thH, C_DIM, fMini, DT_LEFT|DT_VCENTER|DT_SINGLELINE);
    Txt(dc, "Local Address", colX3 + 18, thY, 130, thH, C_DIM, fMini, DT_LEFT|DT_VCENTER|DT_SINGLELINE);
    Txt(dc, "Remote Endpoint", colX4 + 18, thY, 120, thH, C_DIM, fMini, DT_LEFT|DT_VCENTER|DT_SINGLELINE);
    Txt(dc, "Category", colX5 + 18, thY, 130, thH, C_DIM, fMini, DT_LEFT|DT_VCENTER|DT_SINGLELINE);
    Txt(dc, "Reverse DNS / Host", colX6 + 18, thY, 160, thH, C_DIM, fMini, DT_LEFT|DT_VCENTER|DT_SINGLELINE);
    Txt(dc, "State", colX7 + 14, thY, 60, thH, C_DIM, fMini, DT_LEFT|DT_VCENTER|DT_SINGLELINE);
    Txt(dc, "Action", colX8 - 6, thY, 40, thH, C_DIM, fMini, DT_LEFT|DT_VCENTER|DT_SINGLELINE);

    /* Tiny header icons */
    SetTextColor(dc, C_DIM); SelectObject(dc, fIcon);
    RECT iApp = {colX2, thY, colX2+16, thY+thH}; DrawTextW(dc, L"\uE71D", -1, &iApp, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
    RECT iLoc = {colX3, thY, colX3+16, thY+thH}; DrawTextW(dc, L"\uE839", -1, &iLoc, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
    RECT iRem = {colX4, thY, colX4+16, thY+thH}; DrawTextW(dc, L"\uE774", -1, &iRem, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
    RECT iCat = {colX5, thY, colX5+16, thY+thH}; DrawTextW(dc, L"\uEA18", -1, &iCat, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
    RECT iDns = {colX6, thY, colX6+16, thY+thH}; DrawTextW(dc, L"\uE7F4", -1, &iDns, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
    RECT iSt  = {colX7, thY, colX7+14, thY+thH}; DrawTextW(dc, L"\uE9D9", -1, &iSt,  DT_CENTER|DT_VCENTER|DT_SINGLELINE);

    /* Divider under header */
    HPEN pDiv = CreatePen(PS_SOLID, 1, C_BORDER2);
    HPEN opD = (HPEN)SelectObject(dc, pDiv);
    MoveToEx(dc, cx + MRG + 4, thY + thH + 2, NULL);
    LineTo(dc, cx + MRG + bannerW - 4, thY + thH + 2);
    SelectObject(dc, opD); DeleteObject(pDiv);

    /* 12 Rows Table Data with Risk Levels (0=Safe/Green, 1=Suspicious/Yellow, 2=Threat/Red) */
    struct {
        int iconType;
        const char *name;
        const char *proc;
        const char *local;
        const char *remote;
        const char *cat;
        const char *rdns;
        const char *state;
        int riskLevel;
    } rows[12] = {
        { 1, "Android Studio",             "svchost.exe",      "0.0.0.0:0",          "Loopback",             "Localhost",              "-",                          "ESTABLISHED", 0 },
        { 2, "Git",                        "git.exe",          "0.0.0.0:0",          "Loopback",             "Localhost",              "-",                          "ESTABLISHED", 0 },
        { 3, "Mozilla Firefox",            "firefox.exe",      "0.0.0.0:0",          "Loopback",             "Localhost",              "-",                          "ESTABLISHED", 0 },
        { 4, "Spotify",                    "spotify.exe",      "0.0.0.0:0",          "Loopback",             "Localhost",              "-",                          "ESTABLISHED", 0 },
        { 5, "Microsoft 365",              "msedge.exe",       "0.0.0.0:0",          "Loopback",             "Localhost",              "-",                          "ESTABLISHED", 0 },
        { 6, "Remote Device Link",         "svchost.exe",      "192.168.1.105:51240","98.66.133.184:8088",   "Unverified Device / IP", "Raw Socket [98.66.133.184]", "SUSPICIOUS",  1 },
        { 7, "Microsoft OneDrive",         "onedrive.exe",     "40.0.0.0:0",         "Loopback",             "Localhost",              "-",                          "ESTABLISHED", 0 },
        { 8, "WinRAR",                     "winrar.exe",       "0.0.0.0:0",          "Loopback",             "Localhost",              "-",                          "ESTABLISHED", 0 },
        { 9, "XAMPP",                      "xampp-control.exe","0.0.0.0:0",          "Loopback",             "Localhost",              "-",                          "ESTABLISHED", 0 },
        { 10,"Brave Browser",              "brave.exe",        "140.82.112.26:443",  "Web / Cloud",          "Encrypted TLS Web Host", "brave.com",                  "ESTABLISHED", 0 },
        { 11,"External C2 Beacon",         "powershell.exe",   "192.168.1.105:49812","185.220.101.44:4444",  "C2 / Threat",            "Blacklisted C2 [185.220.101.44]","THREAT",     2 },
        { 12,"Microsoft Visual C++",       "brave.exe",        "172.64.149.246:443", "Web / Cloud",          "Cloud Edge / HTTPS",     "edge.brave.com",             "ESTABLISHED", 0 }
    };

    int rowStartY = thY + thH + 4;
    int rowH = 40;

    for (int r = 0; r < 12; r++) {
        int ry = rowStartY + r * rowH;
        if (ry + rowH > tblY + tblH) break;

        /* Row background tint based on risk */
        COLORREF bg;
        if (rows[r].riskLevel == 2) {
            bg = (r % 2 == 1) ? RGB(34, 10, 16) : RGB(26, 8, 12);
        } else if (rows[r].riskLevel == 1) {
            bg = (r % 2 == 1) ? RGB(30, 22, 8) : RGB(24, 18, 6);
        } else {
            bg = (r % 2 == 1) ? RGB(11, 19, 34) : RGB(9, 15, 28);
        }
        RECT rowRc = {cx + MRG + 2, ry, cx + MRG + bannerW - 2, ry + rowH};
        HBRUSH zBr = CreateSolidBrush(bg);
        FillRect(dc, &rowRc, zBr);
        DeleteObject(zBr);

        /* Left indicator bar for risk */
        if (rows[r].riskLevel > 0) {
            RECT indR = {cx + MRG + 2, ry + 4, cx + MRG + 5, ry + rowH - 4};
            HBRUSH indB = CreateSolidBrush(rows[r].riskLevel == 2 ? RGB(239, 68, 68) : RGB(245, 158, 11));
            FillRect(dc, &indR, indB);
            DeleteObject(indB);
        }

        /* 1. Row # */
        char numStr[8]; snprintf(numStr, sizeof(numStr), "%d", r + 1);
        Txt(dc, numStr, colX1, ry, 24, rowH, C_TEXT2, fSm, DT_LEFT|DT_VCENTER|DT_SINGLELINE);

        /* 2. Brand Icon */
        DrawBrandIcon(dc, colX2, ry + (rowH - 24)/2, 24, rows[r].iconType);

        /* App Name & Process */
        Txt(dc, rows[r].name, colX2 + 30, ry + 4, 160, 16, C_TEXT, fMed, DT_LEFT|DT_SINGLELINE);
        Txt(dc, rows[r].proc, colX2 + 30, ry + 22, 160, 14, C_DIM, fSm, DT_LEFT|DT_SINGLELINE);

        /* 3. Local Address */
        Txt(dc, rows[r].local, colX3, ry, 140, rowH, C_TEXT2, fSm, DT_LEFT|DT_VCENTER|DT_SINGLELINE);

        /* 4. Remote Endpoint */
        COLORREF remCol;
        if (rows[r].riskLevel == 2)      remCol = RGB(248, 113, 113);
        else if (rows[r].riskLevel == 1) remCol = RGB(251, 191, 36);
        else if (strcmp(rows[r].remote, "Loopback") == 0) remCol = C_TEXT2;
        else remCol = RGB(140, 200, 255);
        Txt(dc, rows[r].remote, colX4, ry, 120, rowH, remCol, fSm, DT_LEFT|DT_VCENTER|DT_SINGLELINE);

        /* 5. Category */
        COLORREF catCol = (rows[r].riskLevel == 2) ? RGB(248, 113, 113) :
                          (rows[r].riskLevel == 1) ? RGB(251, 191, 36) : C_DIM;
        Txt(dc, rows[r].cat, colX5, ry, 140, rowH, catCol, fSm, DT_LEFT|DT_VCENTER|DT_SINGLELINE);

        /* 6. Reverse DNS */
        COLORREF rdnsCol = (rows[r].riskLevel == 2) ? RGB(255, 140, 140) :
                           (rows[r].riskLevel == 1) ? RGB(255, 210, 120) :
                           (strcmp(rows[r].rdns, "-") == 0 ? C_DIM2 : RGB(170, 195, 230));
        Txt(dc, rows[r].rdns, colX6, ry, 170, rowH, rdnsCol, fSm, DT_LEFT|DT_VCENTER|DT_SINGLELINE);

        /* 7. State Pill: Color-coded by risk! */
        int stPillW = 88, stPillH = 20;
        int stPillY = ry + (rowH - stPillH) / 2;
        COLORREF stBg, stBdr, stFg;
        if (rows[r].riskLevel == 2) {
            stBg  = RGB(55, 12, 18);
            stBdr = RGB(239, 68, 68);
            stFg  = RGB(255, 110, 110);
        } else if (rows[r].riskLevel == 1) {
            stBg  = RGB(48, 34, 6);
            stBdr = RGB(245, 158, 11);
            stFg  = RGB(251, 191, 36);
        } else {
            stBg  = RGB(8, 36, 26);
            stBdr = RGB(16, 185, 129);
            stFg  = RGB(52, 211, 153);
        }
        DrawRoundRectPanel(dc, colX7, stPillY, stPillW, stPillH, 10, stBg, stBdr);
        Txt(dc, rows[r].state, colX7, stPillY, stPillW, stPillH, stFg, fMini, DT_CENTER|DT_VCENTER|DT_SINGLELINE);

        /* 8. Action Dots: 3 vector dots */
        int adX = colX8 + 4;
        int adY = ry + rowH / 2;
        COLORREF dotCol = (rows[r].riskLevel == 2) ? RGB(239, 68, 68) :
                          (rows[r].riskLevel == 1) ? RGB(245, 158, 11) : C_DIM;
        HBRUSH bDot3 = CreateSolidBrush(dotCol);
        HPEN pNone2 = (HPEN)GetStockObject(NULL_PEN);
        HBRUSH obDot3 = (HBRUSH)SelectObject(dc, bDot3);
        HPEN opNone2 = (HPEN)SelectObject(dc, pNone2);
        Ellipse(dc, adX - 6, adY - 2, adX - 2, adY + 2);
        Ellipse(dc, adX - 1, adY - 2, adX + 3, adY + 2);
        Ellipse(dc, adX + 4, adY - 2, adX + 8, adY + 2);
        SelectObject(dc, obDot3); SelectObject(dc, opNone2);
        DeleteObject(bDot3);
    }

    SaveHDCtoBMP(dc, W, H, "scratch\\test_netguard_fix.bmp");

    SelectObject(dc, oldBm);
    DeleteObject(hbm);
    DeleteDC(dc);
    DeleteObject(fHdr); DeleteObject(fBig); DeleteObject(fStatV);
    DeleteObject(fMed); DeleteObject(fSm); DeleteObject(fMini);
    DeleteObject(fMono); DeleteObject(fIcon); DeleteObject(fIconBig);

    printf("Generated scratch\\test_netguard_fix.bmp\n");
    return 0;
}
