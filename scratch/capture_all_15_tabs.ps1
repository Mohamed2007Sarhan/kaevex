Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Windows.Forms

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

if (-not ([System.Management.Automation.PSTypeName]'KvxFullCapture.Win32Util').Type) {
    Add-Type -MemberDefinition $sig -Name "Win32Util" -Namespace "KvxFullCapture"
}

function MakeLParam($x, $y) {
    return [IntPtr](($y -shl 16) -bor ($x -band 0xFFFF))
}

function Capture-Window($hwnd, $outputPath) {
    $rect = New-Object KvxFullCapture.Win32Util+RECT
    [KvxFullCapture.Win32Util]::GetClientRect($hwnd, [ref]$rect)
    $w = $rect.Right - $rect.Left
    $h = $rect.Bottom - $rect.Top

    $hdcWin = [KvxFullCapture.Win32Util]::GetDC($hwnd)
    $hdcMem = [KvxFullCapture.Win32Util]::CreateCompatibleDC($hdcWin)
    $hbm = [KvxFullCapture.Win32Util]::CreateCompatibleBitmap($hdcWin, $w, $h)
    $obm = [KvxFullCapture.Win32Util]::SelectObject($hdcMem, $hbm)

    $ok = [KvxFullCapture.Win32Util]::PrintWindow($hwnd, $hdcMem, 2)
    if (-not $ok) {
        [KvxFullCapture.Win32Util]::BitBlt($hdcMem, 0, 0, $w, $h, $hdcWin, 0, 0, 0x00CC0020)
    }

    $bmp = [System.Drawing.Image]::FromHbitmap($hbm)
    $bmp.Save($outputPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()

    [KvxFullCapture.Win32Util]::SelectObject($hdcMem, $obm)
    [KvxFullCapture.Win32Util]::DeleteObject($hbm)
    [KvxFullCapture.Win32Util]::DeleteDC($hdcMem)
    [KvxFullCapture.Win32Util]::ReleaseDC($hwnd, $hdcWin)
    Write-Host "[OK] $outputPath"
}

function Click-Tab($hwnd, $tabIdx) {
    $startY = 54 + 10
    $tabH = 38
    $clickX = 60
    $clickY = $startY + $tabIdx * $tabH + 19
    $lp = MakeLParam $clickX $clickY
    [KvxFullCapture.Win32Util]::SendMessage($hwnd, 0x0201, [IntPtr]1, $lp)
    [KvxFullCapture.Win32Util]::SendMessage($hwnd, 0x0202, [IntPtr]0, $lp)
}

# Kill existing
Stop-Process -Name "kaevex" -ErrorAction SilentlyContinue
Stop-Process -Name "Kaevex-GUI" -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 600

Write-Host "[*] Launching kaevex.exe..."
$proc = Start-Process -FilePath "c:\Users\Moham\Desktop\keavex\github\dist\kaevex.exe" -PassThru -WorkingDirectory "c:\Users\Moham\Desktop\keavex\github"

$hwnd = [IntPtr]::Zero
for ($i = 0; $i -lt 60; $i++) {
    Start-Sleep -Milliseconds 300
    $p = Get-Process kaevex -ErrorAction SilentlyContinue
    if ($p -and $p.MainWindowHandle -ne [IntPtr]::Zero) {
        $hwnd = $p.MainWindowHandle
        break
    }
}

if ($hwnd -eq [IntPtr]::Zero) {
    Write-Host "[FAIL] Could not find Kaevex window"
    exit 1
}

Write-Host "[OK] Window: $hwnd"
[KvxFullCapture.Win32Util]::ShowWindow($hwnd, 9)
[KvxFullCapture.Win32Util]::SetForegroundWindow($hwnd)
Start-Sleep -Milliseconds 1500

$outDir = "C:\Users\Moham\.gemini\antigravity\brain\ea40fe83-cd23-489f-9996-2a73f0e38bc8"

$tabs = @(
    @{ name="tab00_dashboard";        idx=0;  wait=800 },
    @{ name="tab01_defense_engines";  idx=1;  wait=600 },
    @{ name="tab02_netguard";         idx=2;  wait=1200 },
    @{ name="tab03_webguard_waf";     idx=3;  wait=600 },
    @{ name="tab04_antivirus";        idx=4;  wait=600 },
    @{ name="tab05_ransomshield";     idx=5;  wait=800 },
    @{ name="tab06_smartsandbox";     idx=6;  wait=600 },
    @{ name="tab07_firewall";         idx=7;  wait=1000 },
    @{ name="tab08_cve_agent";        idx=8;  wait=2000 },
    @{ name="tab09_gaming_threat";    idx=9;  wait=1200 },
    @{ name="tab10_app_hub";          idx=10; wait=2500 },
    @{ name="tab11_ai_soc";           idx=11; wait=600 },
    @{ name="tab12_forensics";        idx=12; wait=1200 },
    @{ name="tab13_settings";         idx=13; wait=600 },
    @{ name="tab14_full_team";        idx=14; wait=600 }
)

foreach ($tab in $tabs) {
    Write-Host "[*] Capturing $($tab.name)..."
    Click-Tab $hwnd $tab.idx
    Start-Sleep -Milliseconds $tab.wait
    $path = "$outDir\fulltest_$($tab.name).png"
    Capture-Window $hwnd $path
}

Write-Host ""
Write-Host "[DONE] All 15 tabs captured!"

[KvxFullCapture.Win32Util]::PostMessage($hwnd, 0x0010, [IntPtr]0, [IntPtr]0)
