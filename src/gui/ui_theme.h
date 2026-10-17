/*===========================================================================
 * Kaevex dark theme for the native tool windows (Firewall Pro, CVE Intelligence, Self-Test)
 * so they match the main dashboard: dark title bar, dark lists/trees/edits/buttons, Segoe UI.
 *===========================================================================*/
#pragma once
#ifndef UI_THEME_H
#define UI_THEME_H
#include <uxtheme.h>
#include <dwmapi.h>

#define KV_BG     RGB(9, 13, 24)
#define KV_PANEL  RGB(15, 22, 38)
#define KV_TEXT   RGB(220, 232, 250)
#define KV_DIM    RGB(140, 160, 190)
#define KV_ACCENT RGB(59, 130, 246)

static HBRUSH g_kvBrushBg = NULL, g_kvBrushPanel = NULL; static HFONT g_kvFontUi = NULL;
static void kv_theme_init(void) {
    if (g_kvBrushBg) return;
    g_kvBrushBg = CreateSolidBrush(KV_BG); g_kvBrushPanel = CreateSolidBrush(KV_PANEL);
    g_kvFontUi = CreateFontA(-13, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, "Segoe UI");
}
static BOOL CALLBACK kv_theme_child(HWND h, LPARAM lp) {
    (void)lp; char cls[40]; GetClassNameA(h, cls, sizeof cls);
    SendMessageA(h, WM_SETFONT, (WPARAM)g_kvFontUi, TRUE);
    if (!_stricmp(cls, "SysListView32")) {
        SetWindowTheme(h, L"DarkMode_Explorer", NULL);
        SendMessageA(h, LVM_SETBKCOLOR, 0, KV_PANEL); SendMessageA(h, LVM_SETTEXTBKCOLOR, 0, KV_PANEL); SendMessageA(h, LVM_SETTEXTCOLOR, 0, KV_TEXT);
        HWND hdr = (HWND)SendMessageA(h, LVM_GETHEADER, 0, 0); if (hdr) SetWindowTheme(hdr, L"DarkMode_ItemsView", NULL);
    } else if (!_stricmp(cls, "SysTreeView32")) {
        SetWindowTheme(h, L"DarkMode_Explorer", NULL); SendMessageA(h, TVM_SETBKCOLOR, 0, KV_PANEL); SendMessageA(h, TVM_SETTEXTCOLOR, 0, KV_TEXT); SendMessageA(h, TVM_SETLINECOLOR, 0, RGB(60, 80, 120));
    } else if (!_stricmp(cls, "Button") || !_stricmp(cls, "Edit") || !_stricmp(cls, "ListBox") || !_stricmp(cls, "SysTabControl32")) {
        SetWindowTheme(h, L"DarkMode_Explorer", NULL);
    }
    return TRUE;
}
/* call once after the window and its children exist */
static void kv_theme_apply(HWND hw) {
    kv_theme_init(); BOOL on = TRUE;
    DwmSetWindowAttribute(hw, 20 /*DWMWA_USE_IMMERSIVE_DARK_MODE*/, &on, sizeof on);
    EnumChildWindows(hw, kv_theme_child, 0);
    InvalidateRect(hw, NULL, TRUE);
}
/* WM_CTLCOLOR* handler body: returns the brush, sets text/background colours */
static LRESULT kv_ctlcolor(HDC dc, BOOL editLike) {
    kv_theme_init(); SetTextColor(dc, KV_TEXT); SetBkColor(dc, editLike ? KV_PANEL : KV_BG); SetBkMode(dc, OPAQUE);
    return (LRESULT)(editLike ? g_kvBrushPanel : g_kvBrushBg);
}
#define KV_CTLCOLOR_CASES \
    case WM_CTLCOLORSTATIC: return kv_ctlcolor((HDC)wp, FALSE); \
    case WM_CTLCOLOREDIT:   return kv_ctlcolor((HDC)wp, TRUE);  \
    case WM_CTLCOLORLISTBOX:return kv_ctlcolor((HDC)wp, TRUE);  \
    case WM_CTLCOLORBTN:    return kv_ctlcolor((HDC)wp, FALSE);
#endif
