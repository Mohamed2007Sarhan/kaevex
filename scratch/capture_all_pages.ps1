Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Windows.Forms

# Win32 API Definitions
$sig = @"
[DllImport("user32.dll", SetLastError = true)]
public static extern IntPtr FindWindow(string lpClassName, string lpWindowName);

[DllImport("user32.dll")]
public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

[DllImport("user32.dll")]
public static extern bool SetForegroundWindow(IntPtr hWnd);

[DllImport("user32.dll")]
public static extern bool GetClientRect(IntPtr hWnd, out RECT lpRect);

[DllImport("user32.dll")]
public static extern IntPtr GetDC(IntPtr hWnd);

[DllImport("user32.dll")]
public static extern int ReleaseDC(IntPtr hWnd, IntPtr hDC);

[DllImport("gdi32.dll")]
public static extern IntPtr CreateCompatibleDC(IntPtr hdc);

[DllImport("gdi32.dll")]
public static extern IntPtr CreateCompatibleBitmap(IntPtr hdc, int nWidth, int nHeight);

[DllImport("gdi32.dll")]
public static extern IntPtr SelectObject(IntPtr hdc, IntPtr hgdiobj);

[DllImport("gdi32.dll")]
public static extern bool DeleteDC(IntPtr hdc);

[DllImport("gdi32.dll")]
public static extern bool DeleteObject(IntPtr hObject);

[DllImport("gdi32.dll")]
public static extern bool BitBlt(IntPtr hdcDest, int nXDest, int nYDest, int nWidth, int nHeight, IntPtr hdcSrc, int nXSrc, int nYSrc, uint dwRop);

[DllImport("user32.dll")]
public static extern bool PrintWindow(IntPtr hwnd, IntPtr hdcBlt, uint nFlags);

[DllImport("user32.dll", CharSet = CharSet.Auto)]
public static extern IntPtr SendMessage(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);

[DllImport("user32.dll", CharSet = CharSet.Auto)]
public static extern bool PostMessage(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);

[StructLayout(LayoutKind.Sequential)]
public struct RECT {
    public int Left;
    public int Top;
    public int Right;
    public int Bottom;
}
"@

Add-Type -MemberDefinition $sig -Name "Win32Util" -Namespace "KaevexCapture"

function MakeLParam($x, $y) {
    return [IntPtr](($y -shl 16) -bor ($x -band 0xFFFF))
}

function Capture-Window($hwnd, $outputPath) {
    $rect = New-Object KaevexCapture.Win32Util+RECT
    [KaevexCapture.Win32Util]::GetClientRect($hwnd, [ref]$rect)
    $w = $rect.Right - $rect.Left
    $h = $rect.Bottom - $rect.Top

    $hdcWin = [KaevexCapture.Win32Util]::GetDC($hwnd)
    $hdcMem = [KaevexCapture.Win32Util]::CreateCompatibleDC($hdcWin)
    $hbm = [KaevexCapture.Win32Util]::CreateCompatibleBitmap($hdcWin, $w, $h)
    $obm = [KaevexCapture.Win32Util]::SelectObject($hdcMem, $hbm)

    $ok = [KaevexCapture.Win32Util]::PrintWindow($hwnd, $hdcMem, 2)
    if (-not $ok) {
        [KaevexCapture.Win32Util]::BitBlt($hdcMem, 0, 0, $w, $h, $hdcWin, 0, 0, 0x00CC0020)
    }

    $bmp = [System.Drawing.Image]::FromHbitmap($hbm)
    $bmp.Save($outputPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()

    [KaevexCapture.Win32Util]::SelectObject($hdcMem, $obm)
    [KaevexCapture.Win32Util]::DeleteObject($hbm)
    [KaevexCapture.Win32Util]::DeleteDC($hdcMem)
    [KaevexCapture.Win32Util]::ReleaseDC($hwnd, $hdcWin)
    Write-Host "[OK] Saved $outputPath"
}

# 1. Kill any existing kaevex
Stop-Process -Name "kaevex" -ErrorAction SilentlyContinue
Stop-Process -Name "Kaevex-GUI" -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 600

# 2. Launch kaevex.exe with --gui flag
Write-Host "[*] Launching dist\kaevex.exe --gui ..."
$proc = Start-Process -FilePath "c:\Users\Moham\Desktop\keavex\github\dist\kaevex.exe" -ArgumentList "--gui" -PassThru -WorkingDirectory "c:\Users\Moham\Desktop\keavex\github"

# 3. Find window
$hwnd = [IntPtr]::Zero
for ($i = 0; $i -lt 50; $i++) {
    Start-Sleep -Milliseconds 200
    $hwnd = [KaevexCapture.Win32Util]::FindWindow("KaevexGUIModern", $null)
    if ($hwnd -ne [IntPtr]::Zero) { break }
}

if ($hwnd -eq [IntPtr]::Zero) {
    Write-Host "[FAIL] Could not find KaevexGUIModern window"
    exit 1
}

Write-Host "[OK] Window found: $hwnd"
[KaevexCapture.Win32Util]::ShowWindow($hwnd, 9) # SW_RESTORE
[KaevexCapture.Win32Util]::SetForegroundWindow($hwnd)
Start-Sleep -Milliseconds 1200

$outDir = "C:\Users\Moham\.gemini\antigravity\brain\ea40fe83-cd23-489f-9996-2a73f0e38bc8"

$tabNames = @(
    "tab0_dashboard",
    "tab1_defense_engines",
    "tab2_netguard",
    "tab3_webguard_waf",
    "tab4_antivirus",
    "tab5_ransomshield",
    "tab6_smartsandbox",
    "tab7_firewall",
    "tab8_cve_agent",
    "tab9_gaming_threat"
)

$startY = 54 + 10
$tabH = 38
$clickX = 60

$WM_LBUTTONDOWN = 0x0201
$WM_LBUTTONUP   = 0x0202

for ($t = 0; $t -lt 10; $t++) {
    $clickY = $startY + $t * $tabH + 19
    $lp = MakeLParam $clickX $clickY
    [KaevexCapture.Win32Util]::SendMessage($hwnd, $WM_LBUTTONDOWN, [IntPtr]1, $lp)
    [KaevexCapture.Win32Util]::SendMessage($hwnd, $WM_LBUTTONUP, [IntPtr]0, $lp)
    Start-Sleep -Milliseconds 600

    $path = "$outDir\screen_$($tabNames[$t]).png"
    Capture-Window $hwnd $path
}

# Now in Tab 9, capture the remaining sub-tabs:
# SubTabs X positions relative to cx (which is 170):
# HeroX = cx + 8 = 178
# SubTabs: 0=178, 1=178+143=321, 2=321+163=484, 3=484+138=622, 4=622+103=725
# Y = 54 + 6 + 70 + 10 + 17 = 157
$gamingSubTabs = @(
    @{ name = "threat_sub1_protection"; x = 330; y = 157 },
    @{ name = "threat_sub2_performance"; x = 490; y = 157 },
    @{ name = "threat_sub3_rules";       x = 630; y = 157 },
    @{ name = "threat_sub4_profiles";    x = 735; y = 157 }
)

foreach ($st in $gamingSubTabs) {
    $lp = MakeLParam $st.x $st.y
    [KaevexCapture.Win32Util]::SendMessage($hwnd, $WM_LBUTTONDOWN, [IntPtr]1, $lp)
    [KaevexCapture.Win32Util]::SendMessage($hwnd, $WM_LBUTTONUP, [IntPtr]0, $lp)
    Start-Sleep -Milliseconds 600
    $path = "$outDir\screen_$($st.name).png"
    Capture-Window $hwnd $path
}

# Close window
[KaevexCapture.Win32Util]::PostMessage($hwnd, 0x0010, [IntPtr]0, [IntPtr]0) # WM_CLOSE
Start-Sleep -Milliseconds 500
Write-Host "[DONE] All tabs and sub-tabs captured successfully!"
