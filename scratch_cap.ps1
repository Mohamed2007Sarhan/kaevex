Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$csharp = @'
using System;
using System.Runtime.InteropServices;

namespace Win32 {
    public struct RECT {
        public int Left;
        public int Top;
        public int Right;
        public int Bottom;
    }

    public static class Native {
        [DllImport("user32.dll")]
        public static extern bool SetForegroundWindow(IntPtr hWnd);
        [DllImport("user32.dll")]
        public static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);
        [DllImport("user32.dll")]
        public static extern bool PrintWindow(IntPtr hWnd, IntPtr hdcBlt, uint nFlags);
        [DllImport("user32.dll")]
        public static extern IntPtr SendMessage(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);
        [DllImport("user32.dll", EntryPoint="FindWindowA")]
        public static extern IntPtr FindWindow(string lpClassName, string lpWindowName);
    }
}
'@

Add-Type -TypeDefinition $csharp

$hwnd = [Win32.Native]::FindWindow("KaevexGUIModern", $null)
if ($hwnd -eq [IntPtr]::Zero) {
    Write-Host "Window not found yet!"
    exit 1
}

Write-Host "Found KaevexGUIModern Window: $hwnd"

[Win32.Native]::SetForegroundWindow($hwnd)
Start-Sleep -Milliseconds 300

# Click Tab 9 (Gaming & Threat): x = 60, y = 64 + 9*40 + 20 = 444
$lParam = [IntPtr]((444 -shl 16) -bor 60)
[Win32.Native]::SendMessage($hwnd, 0x0201, [IntPtr]1, $lParam) # WM_LBUTTONDOWN
Start-Sleep -Milliseconds 100
[Win32.Native]::SendMessage($hwnd, 0x0202, [IntPtr]0, $lParam) # WM_LBUTTONUP
Start-Sleep -Seconds 1

$rect = New-Object Win32.RECT
[Win32.Native]::GetWindowRect($hwnd, [ref]$rect)
$w = $rect.Right - $rect.Left
$h = $rect.Bottom - $rect.Top
Write-Host "Window Dimensions: $w x $h"

if ($w -gt 100 -and $h -gt 100) {
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $gfx = [System.Drawing.Graphics]::FromImage($bmp)
    $hdc = $gfx.GetHdc()
    [Win32.Native]::PrintWindow($hwnd, $hdc, 2)
    $gfx.ReleaseHdc($hdc)
    $gfx.Dispose()
    $outPath = 'C:\Users\Moham\.gemini\antigravity\brain\ea40fe83-cd23-489f-9996-2a73f0e38bc8\screen_gaming.png'
    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    Write-Host "SAVED_SCREENSHOT: $outPath"
}
