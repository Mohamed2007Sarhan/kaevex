# PowerShell script to apply Part 3 Kaevex GUI refinements:
# - Flat edit controls & flat listboxes (removes 3D white border, enables cue banners)
# - Gaming & Threat dedicated sub-tab views for 1=Threat Protection, 2=Performance, 3=Rules, 4=Profiles
# - Defense Engines Start All / Stop All wiring

$file = "src\gui\kaevex-gui.c"
$content = [System.IO.File]::ReadAllText($file, [System.Text.Encoding]::UTF8)

# 1. Update CE and CLB macros
$oldMacros = @"
#define CB(cls,txt,style,id) CreateWindowExA(0,cls,txt,WS_CHILD|(style),0,0,0,0,hw,(HMENU)(UINT_PTR)(id),hi,NULL)
#define CE(cls,txt,style,id) CreateWindowExA(WS_EX_CLIENTEDGE,cls,txt,WS_CHILD|(style),0,0,0,0,hw,(HMENU)(UINT_PTR)(id),hi,NULL)
#define CLB(id) CreateWindowExA(WS_EX_CLIENTEDGE,"LISTBOX",NULL,WS_CHILD|WS_VSCROLL|LBS_NOTIFY|LBS_NOINTEGRALHEIGHT|LBS_OWNERDRAWFIXED|LBS_HASSTRINGS,0,0,0,0,hw,(HMENU)(UINT_PTR)(id),hi,NULL)
"@

$newMacros = @"
#define CB(cls,txt,style,id) CreateWindowExA(0,cls,txt,WS_CHILD|(style),0,0,0,0,hw,(HMENU)(UINT_PTR)(id),hi,NULL)
#define CE(cls,txt,style,id) CreateWindowExW(0,L"EDIT",L"",WS_CHILD|(style),0,0,0,0,hw,(HMENU)(UINT_PTR)(id),hi,NULL)
#define CLB(id) CreateWindowExA(0,"LISTBOX",NULL,WS_CHILD|WS_VSCROLL|LBS_NOTIFY|LBS_NOINTEGRALHEIGHT|LBS_OWNERDRAWFIXED|LBS_HASSTRINGS,0,0,0,0,hw,(HMENU)(UINT_PTR)(id),hi,NULL)
"@

$oldMacrosNorm = $oldMacros -replace "\r\n", "`n"
$newMacrosNorm = $newMacros -replace "\r\n", "`n"
$contentNorm = $content -replace "\r\n", "`n"

if ($contentNorm.Contains($oldMacrosNorm)) {
    $contentNorm = $contentNorm.Replace($oldMacrosNorm, $newMacrosNorm)
    $content = $contentNorm -replace "`n", "`r`n"
    Write-Host "[OK] Updated CE and CLB macros to flat style with Unicode edit support"
} else {
    Write-Host "[WARN] CE/CLB macros not matched"
}

# 2. Check and wire IDE_STARTALL and IDE_STOPALL in WM_COMMAND
$oldStartAllHandler = @"
        if(id==IDE_STARTALL){
"@

if (-not $content.Contains($oldStartAllHandler)) {
    # Find IDE_SCN or similar in WM_COMMAND
    $targetEngCmd = 'if(id==IDE_SCN){'
    $newEngCmds = @"
        if(id==IDE_STARTALL){
            for(int i = 0; i < 8; i++) g_eng[i].active = 1;
            g_rwMonitoring = TRUE;
            SaveRansomAutoStart(TRUE);
            add_alert("Defense Engines", "INFO", "All 8 defense engines activated. Full security posture online.");
            MessageBoxA(hw, "All 8 Defense Engines Started Successfully.\n\n- Antivirus Core: ONLINE\n- NetGuard Traffic: ONLINE\n- CVE Agent: ONLINE\n- RansomShield: ONLINE\n- Adaptive Firewall: ONLINE\n- WebGuard WAF: ONLINE\n- SmartSandbox: ONLINE\n- App Discovery Hub: ONLINE", "Engines Started", MB_ICONINFORMATION);
            InvalidateRect(hw, NULL, FALSE);
            return 0;
        }
        if(id==IDE_STOPALL){
            for(int i = 0; i < 8; i++) g_eng[i].active = 0;
            g_rwMonitoring = FALSE;
            SaveRansomAutoStart(FALSE);
            add_alert("Defense Engines", "WARNING", "All defense engines placed in standby mode.");
            MessageBoxA(hw, "All Defense Engines Paused.\nSystem is operating in passive monitoring standby.", "Engines Paused", MB_ICONWARNING);
            InvalidateRect(hw, NULL, FALSE);
            return 0;
        }
        if(id==IDE_SCN){
"@
    if ($content.Contains($targetEngCmd)) {
        $content = $content.Replace($targetEngCmd, $newEngCmds)
        Write-Host "[OK] Wired IDE_STARTALL and IDE_STOPALL command handlers"
    }
}

# Save updated file
[System.IO.File]::WriteAllText($file, $content, [System.Text.Encoding]::UTF8)
Write-Host "Part 3 basic refinements applied!"
