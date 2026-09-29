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

if (-not ([System.Management.Automation.PSTypeName]'KaevexAppHubCapture.Win32Util').Type) {
    Add-Type -MemberDefinition $sig -Name "Win32Util" -Namespace "KaevexAppHubCapture"
}

function MakeLParam($x, $y) {
    return [IntPtr](($y -shl 16) -bor ($x -band 0xFFFF))
}

function Capture-Window($hwnd, $outputPath) {
    $rect = New-Object KaevexAppHubCapture.Win32Util+RECT
    [KaevexAppHubCapture.Win32Util]::GetClientRect($hwnd, [ref]$rect)
    $w = $rect.Right - $rect.Left
    $h = $rect.Bottom - $rect.Top

    $hdcWin = [KaevexAppHubCapture.Win32Util]::GetDC($hwnd)
    $hdcMem = [KaevexAppHubCapture.Win32Util]::CreateCompatibleDC($hdcWin)
    $hbm = [KaevexAppHubCapture.Win32Util]::CreateCompatibleBitmap($hdcWin, $w, $h)
    $obm = [KaevexAppHubCapture.Win32Util]::SelectObject($hdcMem, $hbm)

    $ok = [KaevexAppHubCapture.Win32Util]::PrintWindow($hwnd, $hdcMem, 2)
    if (-not $ok) {
        [KaevexAppHubCapture.Win32Util]::BitBlt($hdcMem, 0, 0, $w, $h, $hdcWin, 0, 0, 0x00CC0020)
    }

    $bmp = [System.Drawing.Image]::FromHbitmap($hbm)
    $bmp.Save($outputPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()

    [KaevexAppHubCapture.Win32Util]::SelectObject($hdcMem, $obm)
    [KaevexAppHubCapture.Win32Util]::DeleteObject($hbm)
    [KaevexAppHubCapture.Win32Util]::DeleteDC($hdcMem)
    [KaevexAppHubCapture.Win32Util]::ReleaseDC($hwnd, $hdcWin)
    Write-Host "[OK] Saved $outputPath"
}

# 1. Kill existing
Stop-Process -Name "kaevex" -ErrorAction SilentlyContinue
Stop-Process -Name "Kaevex-GUI" -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 600

# 2. Launch
Write-Host "[*] Launching dist\kaevex.exe --gui ..."
$proc = Start-Process -FilePath "c:\Users\Moham\Desktop\keavex\github\dist\kaevex.exe" -ArgumentList "--gui" -PassThru -WorkingDirectory "c:\Users\Moham\Desktop\keavex\github"

# 3. Find window
$hwnd = [IntPtr]::Zero
for ($i = 0; $i -lt 50; $i++) {
    Start-Sleep -Milliseconds 200
    $p = Get-Process kaevex -ErrorAction SilentlyContinue
    if ($p -and $p.MainWindowHandle -ne [IntPtr]::Zero) {
        $hwnd = $p.MainWindowHandle
        break
    }
}

if ($hwnd -eq [IntPtr]::Zero) {
    Write-Host "[FAIL] Could not find Kaevex window handle"
    exit 1
}

Write-Host "[OK] Window found: $hwnd"
[KaevexAppHubCapture.Win32Util]::ShowWindow($hwnd, 9) # SW_RESTORE
[KaevexAppHubCapture.Win32Util]::SetForegroundWindow($hwnd)
Start-Sleep -Milliseconds 1500

$outDir = "C:\Users\Moham\.gemini\antigravity\brain\ea40fe83-cd23-489f-9996-2a73f0e38bc8"

# Click Tab 10 (App Hub)
# Tab index 10:
$startY = 54 + 10
$tabH = 38
$clickX = 60
$clickY = $startY + 10 * $tabH + 19
$lp = MakeLParam $clickX $clickY
$WM_LBUTTONDOWN = 0x0201
$WM_LBUTTONUP   = 0x0202

Write-Host "[*] Clicking Tab 10 (App Hub) at ($clickX, $clickY)..."
[KaevexAppHubCapture.Win32Util]::SendMessage($hwnd, $WM_LBUTTONDOWN, [IntPtr]1, $lp)
[KaevexAppHubCapture.Win32Util]::SendMessage($hwnd, $WM_LBUTTONUP, [IntPtr]0, $lp)
Start-Sleep -Milliseconds 1500

$path = "$outDir\screen_tab10_app_hub.png"
Capture-Window $hwnd $path

# Close window
[KaevexAppHubCapture.Win32Util]::PostMessage($hwnd, 0x0010, [IntPtr]0, [IntPtr]0) # WM_CLOSE
Start-Sleep -Milliseconds 600
Write-Host "[DONE] App Hub screen captured successfully!"
