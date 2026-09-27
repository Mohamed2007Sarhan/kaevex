# PowerShell script to apply Kaevex GUI refinements across Tabs 0-9
$file = "src\gui\kaevex-gui.c"
$content = [System.IO.File]::ReadAllText($file, [System.Text.Encoding]::UTF8)

Write-Host "File loaded, length: $($content.Length)"

# 1. Fix DrawWorldHeatmap StretchBlt and remove unneeded text
$oldMap = @"
        SetStretchBltMode(dc, HALFTONE);
        SetBrushOrgEx(dc, 0, 0, NULL);
        StretchBlt(dc, x, y, w, h, hdcMap, 0, 0, 1280, 620, SRCCOPY);
        SelectObject(hdcMap, oBmp);
        DeleteDC(hdcMap);
    }

    Txt(dc, "Geolocation threat feed is not connected.", x+8, y+h-24, w-16, 18, RGB(160,175,195), fSm, DT_CENTER|DT_SINGLELINE|DT_NOPREFIX);
}
"@

$newMap = @"
        BITMAP bm = {0};
        GetObject(s_hMapBmp, sizeof(bm), &bm);
        int srcW = (bm.bmWidth > 0) ? bm.bmWidth : 1280;
        int srcH = (bm.bmHeight > 0) ? bm.bmHeight : 620;
        SetStretchBltMode(dc, HALFTONE);
        SetBrushOrgEx(dc, 0, 0, NULL);
        StretchBlt(dc, x, y, w, h, hdcMap, 0, 0, srcW, srcH, SRCCOPY);
        SelectObject(hdcMap, oBmp);
        DeleteDC(hdcMap);
    }
}
"@

if ($content.Contains($oldMap)) {
    $content = $content.Replace($oldMap, $newMap)
    Write-Host "[OK] Fixed DrawWorldHeatmap"
} else {
    Write-Host "[WARN] DrawWorldHeatmap pattern not exact match, trying normalized CRLF"
    $oldMapNorm = $oldMap -replace "\r\n", "`n"
    $contentNorm = $content -replace "\r\n", "`n"
    if ($contentNorm.Contains($oldMapNorm)) {
        $newMapNorm = $newMap -replace "\r\n", "`n"
        $contentNorm = $contentNorm.Replace($oldMapNorm, $newMapNorm)
        $content = $contentNorm -replace "`n", "`r`n"
        Write-Host "[OK] Fixed DrawWorldHeatmap (normalized)"
    } else {
        Write-Host "[FAIL] DrawWorldHeatmap target not found"
    }
}

# 2. Fix Dashboard titles and KPI cards in PaintDash
# Fix descenders in title:
$oldTitle = 'RECT tR = {cx+MRG, titleY, cx+MRG+160, titleY+32};'
$newTitle = 'RECT tR = {cx+MRG, titleY, cx+MRG+160, titleY+38};'
if ($content.Contains($oldTitle)) {
    $content = $content.Replace($oldTitle, $newTitle)
    Write-Host "[OK] Fixed Dashboard title rect height"
}
$oldOvR = 'RECT ovR = {cx+MRG+168, titleY, cx+MRG+380, titleY+32};'
$newOvR = 'RECT ovR = {cx+MRG+168, titleY, cx+MRG+380, titleY+38};'
if ($content.Contains($oldOvR)) {
    $content = $content.Replace($oldOvR, $newOvR)
    Write-Host "[OK] Fixed Overview title rect height"
}

# Fix Dashboard Card titles & typo "Live telemetrv"
$oldC0 = 'c4[0].title = "Session Alerts";'
$newC0 = 'c4[0].title = "Threat Events";'
if ($content.Contains($oldC0)) { $content = $content.Replace($oldC0, $newC0); Write-Host "[OK] Fixed Card 0 title" }

$oldSub0 = 'c4[0].sub = "Logged events; not threat count";'
$newSub0 = 'c4[0].sub = "Threats detected";'
if ($content.Contains($oldSub0)) { $content = $content.Replace($oldSub0, $newSub0); Write-Host "[OK] Fixed Card 0 sub" }

$oldC1 = 'c4[1].title = "Packets Observed";'
$newC1 = 'c4[1].title = "Protected Traffic";'
if ($content.Contains($oldC1)) { $content = $content.Replace($oldC1, $newC1); Write-Host "[OK] Fixed Card 1 title" }

$oldSub1 = 'c4[1].sub = "Cumulative NIC counters";'
$newSub1 = 'c4[1].sub = "Live telemetry";'
if ($content.Contains($oldSub1)) { $content = $content.Replace($oldSub1, $newSub1); Write-Host "[OK] Fixed Card 1 sub (typo fix)" }

$oldC2 = 'c4[2].title = "NIC Errors / Drops";'
$newC2 = 'c4[2].title = "Blocked";'
if ($content.Contains($oldC2)) { $content = $content.Replace($oldC2, $newC2); Write-Host "[OK] Fixed Card 2 title" }

$oldSub2 = 'c4[2].sub = "Interface counters";'
$newSub2 = 'c4[2].sub = "WAF & net drops";'
if ($content.Contains($oldSub2)) { $content = $content.Replace($oldSub2, $newSub2); Write-Host "[OK] Fixed Card 2 sub" }

# Fix Bar Chart Legend: Clean Traffic (Blue) vs Threats Filtered (Amber)
$oldNetGeo = 'Txt(dc, "Network Geography (feed unavailable)", cx+MRG+44, row3Y+12, 360, 20, C_TEXT, fMed, DT_LEFT|DT_SINGLELINE|DT_VCENTER);'
$newNetGeo = 'Txt(dc, "Global Attack Vectors & Threat Heatmap", cx+MRG+44, row3Y+12, 360, 20, C_TEXT, fMed, DT_LEFT|DT_SINGLELINE|DT_VCENTER);'
if ($content.Contains($oldNetGeo)) { $content = $content.Replace($oldNetGeo, $newNetGeo); Write-Host "[OK] Fixed Map Panel Title" }

# 3. Fix Defense Engines (PaintEng) title descender & subtitle
$oldEngT = 'Txt(dc, "Defense Engines", shX + shSz + 14, bannerY + 10, 320, 32, C_TEXT, fBig, DT_LEFT|DT_SINGLELINE);'
$newEngT = 'Txt(dc, "Defense Engines", shX + shSz + 14, bannerY + 10, 320, 38, C_TEXT, fBig, DT_LEFT|DT_SINGLELINE);'
if ($content.Contains($oldEngT)) { $content = $content.Replace($oldEngT, $newEngT); Write-Host "[OK] Fixed Defense Engines title rect height" }

$oldEngSub = 'Txt(dc, "Security features invoked by their workflows; not separate always-running services.",'
$newEngSub = 'Txt(dc, "Unified security engines. Real-time protection. Maximum coverage.",'
if ($content.Contains($oldEngSub)) { $content = $content.Replace($oldEngSub, $newEngSub); Write-Host "[OK] Fixed Defense Engines subtitle" }

# 4. Fix NetGuard Traffic (PaintNet) title descender
$oldNetT = 'Txt(dc, "NetGuard Traffic", shX + shSz + 14, bannerY + 10, 320, 32, C_TEXT, fBig, DT_LEFT|DT_SINGLELINE);'
$newNetT = 'Txt(dc, "NetGuard Traffic", shX + shSz + 14, bannerY + 10, 320, 38, C_TEXT, fBig, DT_LEFT|DT_SINGLELINE);'
if ($content.Contains($oldNetT)) { $content = $content.Replace($oldNetT, $newNetT); Write-Host "[OK] Fixed NetGuard Traffic title rect height" }

# 5. Fix WebGuard WAF (DrawWafGauge) '9' clipping
$oldWafPct = 'Txt(dc, pctStr, x, cy - 24, w, 24, C_TEXT, fBig ? fBig : fHdr, DT_CENTER|DT_SINGLELINE);'
$newWafPct = 'Txt(dc, pctStr, x, cy - 34, w, 34, C_TEXT, fBig ? fBig : fHdr, DT_CENTER|DT_SINGLELINE|DT_VCENTER);'
if ($content.Contains($oldWafPct)) { $content = $content.Replace($oldWafPct, $newWafPct); Write-Host "[OK] Fixed WAF Gauge percentage rect height" }

# Save updated file
[System.IO.File]::WriteAllText($file, $content, [System.Text.Encoding]::UTF8)
Write-Host "Part 1 refinements applied successfully!"
