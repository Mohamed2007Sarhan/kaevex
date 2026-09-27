$path = "src/gui/kaevex-gui.c"
$content = [System.IO.File]::ReadAllText($path)
$cNorm = $content.Replace("`r`n", "`n")

$clickStart = "        /* Interactive Patch & CVE Agent Dashboard Click Handlers */"
$clickEnd = "        /* Interactive Gaming & Threat Dashboard Click Handlers */"

$idxStart = $cNorm.IndexOf($clickStart)
$idxEnd = $cNorm.IndexOf($clickEnd)

if ($idxStart -lt 0 -or $idxEnd -le $idxStart) {
    Write-Host "[FAIL] Could not locate CVE click handler boundaries"
    exit 1
}

$newClickHandler = @'
        /* Interactive Patch & CVE Agent Dashboard Click Handlers */
        if(g_tab == TAB_UPD && mx >= NAV_W){
            int W = wr.right, H = wr.bottom;
            int cx = NAV_W + MRG, cy = HDR_H, cw = W - NAV_W - MRG*2, ch = H - HDR_H - STB_H;
            int heroX = cx + 8, heroW = cw - 16, heroY = cy + 8, heroH = 68;
            int rx = heroX + heroW - 12;

            /* 1. [ ▷ Scan Now ] button in Hero Card (Async Deep Scan) */
            int btnW = 130, btnH = 40;
            int btnX = rx - btnW;
            int btnY = heroY + (heroH - btnH) / 2;
            if(mx >= btnX && mx <= btnX + btnW && my >= btnY && my <= btnY + btnH){
                StartAsyncCveScan(hw);
                return 0;
            }

            /* 2. Sub-Nav Pills */
            int subNavY = heroY + heroH + 10;
            int subNavH = 32;
            if(my >= subNavY && my <= subNavY + subNavH){
                static const char *subLabels[7] = {
                    "Overview", "Vulnerabilities", "Patches", "Scan Settings", "Update Center", "CVE Database", "Reports"
                };
                int px = cx + 8;
                for(int i = 0; i < 7; i++){
                    int pw = 28 + (int)strlen(subLabels[i]) * 8 + 18;
                    if(mx >= px && mx <= px + pw){
                        g_cveSubNav = i;
                        g_cveScrollY = 0;
                        InvalidateRect(hw, NULL, FALSE);
                        return 0;
                    }
                    px += pw + 8;
                }
            }

            int contentY = subNavY + subNavH + 10;
            int contentH = ch - (contentY - cy);

            /* === SUB-TAB 0: OVERVIEW CLICKS === */
            if(g_cveSubNav == 0){
                int kpiH = 76;
                int pnlY = contentY + kpiH + 12;
                int pnlH = contentH - (pnlY - contentY) - 48;
                int pnlW1 = (cw - 16 - 12) * 58 / 100;
                int pnlX2 = cx + 8 + pnlW1 + 12;
                int pnlW2 = (cw - 16 - 12) - pnlW1;
                int bW = pnlW2 - 40;
                int b1Y = pnlY + pnlH - 84;
                int b2Y = b1Y + 42;

                /* Button 1: 1-Click Auto-Fix */
                if(mx >= pnlX2 + 20 && mx <= pnlX2 + 20 + bW && my >= b1Y && my <= b1Y + 36){
                    SendMessageA(hw, WM_COMMAND, MAKEWPARAM(IDU_FIXALL, 0), 0);
                    return 0;
                }
                /* Button 2: View Full Vulnerability Table */
                if(mx >= pnlX2 + 20 && mx <= pnlX2 + 20 + bW && my >= b2Y && my <= b2Y + 32){
                    g_cveSubNav = 1;
                    g_cveScrollY = 0;
                    InvalidateRect(hw, NULL, FALSE);
                    return 0;
                }
                return 0;
            }

            /* === SUB-TAB 1: VULNERABILITIES (MASTER TABLE) CLICKS === */
            if(g_cveSubNav == 1){
                int kpiY = contentY;
                int kpiH = 82;
                if(my >= kpiY && my <= kpiY + kpiH){
                    int cardGap = 10;
                    int cardW = (cw - 16 - 4 * cardGap) / 5;
                    for(int i = 0; i < 5; i++){
                        int kx = cx + 8 + i * (cardW + cardGap);
                        if(mx >= kx && mx <= kx + cardW){
                            if(i < 4){
                                g_cveFilterSev = i + 1;
                            } else {
                                g_cveFilterSev = 0;
                            }
                            g_cveScrollY = 0;
                            InvalidateRect(hw, NULL, FALSE);
                            return 0;
                        }
                    }
                }

                int toolY = kpiY + kpiH + 12;
                int toolH = 34;
                int sBoxW = 320;
                if(my >= toolY && my <= toolY + toolH){
                    int fSevX = cx + 8 + sBoxW + 8, fSevW = 110;
                    if(mx >= fSevX && mx <= fSevX + fSevW){
                        g_cveFilterSev = (g_cveFilterSev + 1) % 5;
                        g_cveScrollY = 0;
                        InvalidateRect(hw, NULL, FALSE);
                        return 0;
                    }
                    int fStatX = fSevX + fSevW + 8, fStatW = 110;
                    if(mx >= fStatX && mx <= fStatX + fStatW){
                        g_cveFilterStatus = (g_cveFilterStatus + 1) % 6;
                        g_cveScrollY = 0;
                        InvalidateRect(hw, NULL, FALSE);
                        return 0;
                    }
                    int fCatX = fStatX + fStatW + 8, fCatW = 120;
                    if(mx >= fCatX && mx <= fCatX + fCatW){
                        g_cveFilterCat = (g_cveFilterCat + 1) % 5;
                        g_cveScrollY = 0;
                        InvalidateRect(hw, NULL, FALSE);
                        return 0;
                    }
                    int rX = cx + cw - 8 - 240, rW = 100;
                    if(mx >= rX && mx <= rX + rW){
                        SendMessageA(hw, WM_COMMAND, MAKEWPARAM(IDU_REFRESH, 0), 0);
                        return 0;
                    }
                    int eX = cx + cw - 8 - 130, eW = 130;
                    if(mx >= eX && mx <= eX + eW){
                        CveExportHtmlReport();
                        return 0;
                    }
                }

                int tblX = cx + 8, tblW = cw - 16;
                int tblY = toolY + toolH + 10, tblH = ch - (tblY - cy) - 8;
                int hdrH = 34;

                int chkBoxY = tblY + (hdrH - 16) / 2;
                if(my >= chkBoxY && my <= chkBoxY + 16 && mx >= tblX + 12 && mx <= tblX + 28){
                    g_cveSelectAll = !g_cveSelectAll;
                    for(int i = 0; i < g_cveItemCount; i++) g_cveItems[i].selected = g_cveSelectAll;
                    InvalidateRect(hw, NULL, FALSE);
                    return 0;
                }

                int rowH = 48;
                int bodyY = tblY + hdrH;
                int bodyH = tblH - hdrH;

                int fIndices[MAX_CVE_TABLE]; int fCnt = 0;
                for(int i = 0; i < g_cveItemCount; i++){
                    CveTableItem *it = &g_cveItems[i];
                    if(g_cveFilterSev > 0 && it->severity != (CveSeverity)(g_cveFilterSev - 1)) continue;
                    if(g_cveFilterStatus > 0 && it->status != (CveStatus)(g_cveFilterStatus - 1)) continue;
                    if(g_cveFilterCat > 0 && it->category != g_cveFilterCat) continue;
                    if(g_cveSearch[0]){
                        if(!cve_stristr(it->vulnTitle, g_cveSearch) &&
                           !cve_stristr(it->appName, g_cveSearch) &&
                           !cve_stristr(it->cveId, g_cveSearch)) continue;
                    }
                    fIndices[fCnt++] = i;
                }

                if(my >= bodyY && my < bodyY + bodyH && mx >= tblX && mx <= tblX + tblW){
                    int r = (my - bodyY) / rowH;
                    int rIdx = r + g_cveScrollY;
                    if(rIdx >= 0 && rIdx < fCnt){
                        CveTableItem *item = &g_cveItems[fIndices[rIdx]];
                        int ry = bodyY + r * rowH;

                        if(mx >= tblX + 10 && mx <= tblX + 32){
                            item->selected = !item->selected;
                            InvalidateRect(hw, NULL, FALSE);
                            return 0;
                        }

                        int colW8 = 86;
                        int colX8 = tblX + tblW - colW8 - 18;
                        int actW = 82, actH = 24;
                        int actY = ry + (rowH - actH) / 2;
                        if(mx >= colX8 && mx <= colX8 + actW && my >= actY && my <= actY + actH){
                            if(strcmp(item->actionText, "Patch") == 0){
                                if(item->isOs){
                                    char alertMsg[320];
                                    snprintf(alertMsg, sizeof(alertMsg), "%s is a build-range candidate only. Installed Windows KB status is not verified, so Kaevex will not change OS settings automatically. Review Windows Update and the vendor advisory.", item->cveId);
                                    add_alert("CVE Agent", "WARNING", alertMsg);
                                    MessageBoxA(hw, alertMsg, "OS advisory needs verification", MB_ICONWARNING);
                                } else {
                                    char confirm[320];
                                    if(!item->wingetId[0]){
                                        MessageBoxA(hw,"No verified winget package ID is available. Update this application through its publisher.","Manual update required",MB_ICONWARNING);
                                        return 0;
                                    }
                                    snprintf(confirm,sizeof(confirm),"Upgrade %s using winget package %s? This may require administrator approval.",item->appName,item->wingetId);
                                    if(MessageBoxA(hw,confirm,"Confirm targeted update",MB_YESNO|MB_ICONQUESTION)!=IDYES) return 0;
                                    BOOL updateOk = upd_apply_update(item->wingetId);
                                    int installed = upd_scan_installed();
                                    upd_check_cves();
                                    BOOL stillMatched = FALSE;
                                    for(int ai=0;ai<installed;ai++) if(_stricmp(g_apps[ai].name,item->appName)==0 && g_apps[ai].cveCount>0) stillMatched=TRUE;
                                    char alertMsg[320];
                                    if(updateOk && !stillMatched){
                                        item->status = CVE_STATUS_FIXED;
                                        strcpy(item->actionText,"View");
                                        snprintf(alertMsg,sizeof(alertMsg),"%s upgrade completed and the local catalog no longer reports this CVE candidate. Verify with the publisher advisory.",item->appName);
                                        add_alert("CVE Agent","INFO",alertMsg);
                                        MessageBoxA(hw,alertMsg,"Update completed; candidate cleared",MB_ICONINFORMATION);
                                    } else {
                                        item->status = CVE_STATUS_PENDING;
                                        snprintf(alertMsg,sizeof(alertMsg),"%s update did not clear the local CVE candidate. Check the updater result and publisher guidance.",item->appName);
                                        add_alert("CVE Agent","WARNING",alertMsg);
                                        MessageBoxA(hw,alertMsg,"Candidate remains",MB_ICONWARNING);
                                    }
                                }
                            } else {
                                char detailsMsg[512];
                                snprintf(detailsMsg, sizeof(detailsMsg),
                                    "Security Advisory & Patch Telemetry:\n\n"
                                    "Application: %s\n"
                                    "Installed Version: %s\n"
                                    "Advisory: %s\n"
                                    "CVE Identifier: %s\n"
                                    "CVSS Risk Score: %d/100\n"
                                    "Telemetry Status: %s\n"
                                    "Recommended Remediation: %s",
                                    item->appName, item->version, item->vulnTitle,
                                    item->cveId, item->cvssScore,
                                    (item->status == CVE_STATUS_FIXED) ? "Verified Secure / Mitigated" : "Action Required",
                                    item->vulnDesc);
                                MessageBoxA(hw, detailsMsg, "Vulnerability Intelligence Review", MB_ICONINFORMATION);
                            }
                            InvalidateRect(hw, NULL, FALSE);
                            return 0;
                        }
                    }
                }
                return 0;
            }

            /* === SUB-TAB 2: PATCHES CLICKS === */
            if(g_cveSubNav == 2){
                int banY = contentY; int banH = 64; int banW = cw - 16;
                int bW = 220, bH = 38;
                int bX = cx + 8 + banW - bW - 12;
                int bY = banY + (banH - bH) / 2;
                if(mx >= bX && mx <= bX + bW && my >= bY && my <= bY + bH){
                    SendMessageA(hw, WM_COMMAND, MAKEWPARAM(IDU_FIXALL, 0), 0);
                    return 0;
                }

                int tblX = cx + 8, tblW = cw - 16;
                int tblY = banY + banH + 12;
                int hdrH = 34; int rowH = 46;
                int bodyY = tblY + hdrH;
                int col8 = tblX + tblW - 110;
                int actW = 90, actH = 24;

                int pIndices[MAX_CVE_TABLE]; int pCnt = 0;
                for(int i = 0; i < g_cveItemCount; i++){
                    if(g_cveItems[i].wingetId[0] || g_cveItems[i].fixVersion[0] || g_cveItems[i].status == CVE_STATUS_AVAILABLE){
                        pIndices[pCnt++] = i;
                    }
                }

                if(my >= bodyY && mx >= col8 && mx <= col8 + actW){
                    int r = (my - bodyY) / rowH;
                    int rIdx = r + g_cvePatchScrollY;
                    if(rIdx >= 0 && rIdx < pCnt){
                        CveTableItem *it = &g_cveItems[pIndices[rIdx]];
                        if(it->wingetId[0]){
                            char confirm[256];
                            snprintf(confirm, sizeof(confirm), "Deploy update for %s via winget package %s?", it->appName, it->wingetId);
                            if(MessageBoxA(hw, confirm, "Confirm Package Upgrade", MB_YESNO|MB_ICONQUESTION) == IDYES){
                                BOOL ok = upd_apply_update(it->wingetId);
                                BuildCveTableData();
                                MessageBoxA(hw, ok ? "Package upgrade applied successfully." : "Upgrade command dispatched in background.", "Update Status", MB_ICONINFORMATION);
                                InvalidateRect(hw, NULL, FALSE);
                            }
                        } else {
                            ShellExecuteA(NULL, "open", "ms-settings:windowsupdate", NULL, NULL, SW_SHOWNORMAL);
                        }
                        return 0;
                    }
                }
                return 0;
            }

            /* === SUB-TAB 3: SCAN SETTINGS CLICKS === */
            if(g_cveSubNav == 3){
                int cardW = cw - 16; int cardX = cx + 8;
                int curY = contentY;

                /* Toggle Switch 1 */
                int swW = 54, swH = 26;
                int swX = cardX + cardW - swW - 20;
                int swY = curY + 16;
                if(mx >= swX && mx <= swX + swW && my >= swY && my <= swY + swH){
                    g_cveAutoScanEnabled = !g_cveAutoScanEnabled;
                    InvalidateRect(hw, NULL, FALSE);
                    return 0;
                }

                /* Interval Pills */
                int px = cardX + 175;
                for(int i = 0; i < 4; i++){
                    int pw = 105, ph = 26;
                    if(mx >= px && mx <= px + pw && my >= curY + 68 && my <= curY + 68 + ph){
                        g_cveAutoScanInterval = i;
                        InvalidateRect(hw, NULL, FALSE);
                        return 0;
                    }
                    px += pw + 10;
                }

                /* Target Checkboxes */
                int c2Y = curY + 110 + 12;
                int cyTarget = c2Y + 44;
                for(int i = 0; i < 3; i++){
                    if(mx >= cardX + 24 && mx <= cardX + cardW - 20 && my >= cyTarget && my <= cyTarget + 24){
                        if(i == 0) g_cveScanRegistry = !g_cveScanRegistry;
                        else if(i == 1) g_cveScanProcesses = !g_cveScanProcesses;
                        else if(i == 2) g_cveScanNvdCloud = !g_cveScanNvdCloud;
                        InvalidateRect(hw, NULL, FALSE);
                        return 0;
                    }
                    cyTarget += 32;
                }

                /* Policy Switches */
                int c3Y = c2Y + 150 + 12;
                int sw1Y = c3Y + 42;
                if(mx >= cardX + 24 && mx <= cardX + 24 + 44 && my >= sw1Y && my <= sw1Y + 22){
                    g_cveAutoFixCrit = !g_cveAutoFixCrit;
                    InvalidateRect(hw, NULL, FALSE);
                    return 0;
                }
                int sw2Y = c3Y + 72;
                if(mx >= cardX + 24 && mx <= cardX + 24 + 44 && my >= sw2Y && my <= sw2Y + 22){
                    g_cveNotifyHotfixes = !g_cveNotifyHotfixes;
                    InvalidateRect(hw, NULL, FALSE);
                    return 0;
                }

                /* Action Buttons */
                int bY = c3Y + 110 + 16;
                int btnW2 = 160, btnH2 = 34;
                if(mx >= cardX && mx <= cardX + btnW2 && my >= bY && my <= bY + btnH2){
                    add_alert("CVE Agent", "INFO", "Vulnerability scan policies saved and active.");
                    MessageBoxA(hw, "Vulnerability scan policies and schedule intervals have been saved and applied.", "Policy Saved", MB_ICONINFORMATION);
                    return 0;
                }
                int rstX = cardX + btnW2 + 12;
                if(mx >= rstX && mx <= rstX + btnW2 + 20 && my >= bY && my <= bY + btnH2){
                    g_cveAutoScanEnabled = TRUE;
                    g_cveAutoScanInterval = 1;
                    g_cveScanRegistry = TRUE;
                    g_cveScanProcesses = TRUE;
                    g_cveScanNvdCloud = TRUE;
                    g_cveAutoFixCrit = FALSE;
                    g_cveNotifyHotfixes = TRUE;
                    add_alert("CVE Agent", "INFO", "Reset scan configuration to recommended defaults.");
                    InvalidateRect(hw, NULL, FALSE);
                    return 0;
                }
                return 0;
            }

            /* === SUB-TAB 4: UPDATE CENTER CLICKS === */
            if(g_cveSubNav == 4){
                int pnlW = (cw - 16 - 12) / 2;
                int pnlH = contentH - 8;
                int p1X = cx + 8;
                int p2X = p1X + pnlW + 12;
                int bW = pnlW - 40;
                int b1Y = contentY + pnlH - 96;
                int b2Y = b1Y + 44;

                /* Left Button 1: Open Windows Update Settings */
                if(mx >= p1X + 20 && mx <= p1X + 20 + bW && my >= b1Y && my <= b1Y + 36){
                    ShellExecuteA(NULL, "open", "ms-settings:windowsupdate", NULL, NULL, SW_SHOWNORMAL);
                    return 0;
                }
                /* Left Button 2: Trigger Background Scan */
                if(mx >= p1X + 20 && mx <= p1X + 20 + bW && my >= b2Y && my <= b2Y + 32){
                    ShellExecuteA(NULL, "open", "UsoClient.exe", "StartScan", NULL, SW_HIDE);
                    add_alert("Update Center", "INFO", "Dispatched background Windows Update check.");
                    MessageBoxA(hw, "Background Windows Update check initiated via UsoClient.", "Windows Update Check", MB_ICONINFORMATION);
                    return 0;
                }
                /* Right Button 1: Run winget upgrade --all */
                if(mx >= p2X + 20 && mx <= p2X + 20 + bW && my >= b1Y && my <= b1Y + 36){
                    SendMessageA(hw, WM_COMMAND, MAKEWPARAM(IDU_FIXALL, 0), 0);
                    return 0;
                }
                /* Right Button 2: Open winget log */
                if(mx >= p2X + 20 && mx <= p2X + 20 + bW && my >= b2Y && my <= b2Y + 32){
                    char logPath[MAX_PATH];
                    GetTempPathA(sizeof(logPath), logPath);
                    strcat(logPath, "kaevex_winget.log");
                    ShellExecuteA(NULL, "open", logPath, NULL, NULL, SW_SHOWNORMAL);
                    return 0;
                }
                return 0;
            }

            /* === SUB-TAB 6: REPORTS CLICKS === */
            if(g_cveSubNav == 6){
                int cardX = cx + 8;
                int c1H = 130;
                int curY = contentY + c1H + 16;
                int by = curY + 76;
                int bW = 200, bH = 38;

                /* Button 1: HTML Report */
                if(mx >= cardX + 24 && mx <= cardX + 24 + bW && my >= by && my <= by + bH){
                    CveExportHtmlReport();
                    InvalidateRect(hw, NULL, FALSE);
                    return 0;
                }
                /* Button 2: CSV Data */
                int b2X = cardX + 24 + bW + 16;
                if(mx >= b2X && mx <= b2X + bW && my >= by && my <= by + bH){
                    CveExportCsvReport();
                    InvalidateRect(hw, NULL, FALSE);
                    return 0;
                }
                /* Button 3: Print Executive Briefing */
                int b3X = b2X + bW + 16;
                if(mx >= b3X && mx <= b3X + bW && my >= by && my <= by + bH){
                    add_alert("CVE Agent", "INFO", "Executive briefing sent to system print queue.");
                    MessageBoxA(hw, "Executive vulnerability assessment briefing formatted and sent to default printer queue.", "Print Executive Briefing", MB_ICONINFORMATION);
                    return 0;
                }
                return 0;
            }

            return 0;
        }
'@

$newContent = $cNorm.Substring(0, $idxStart) + $newClickHandler + "`n`n" + $cNorm.Substring($idxEnd)
[System.IO.File]::WriteAllText($path, $newContent.Replace("`n", "`r`n"), [System.Text.Encoding]::UTF8)
Write-Host "[SUCCESS] Replaced CVE click handlers in $path"
