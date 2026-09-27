Add-Type -AssemblyName System.Drawing
$dir = "C:\Users\Moham\.gemini\antigravity\brain\ea40fe83-cd23-489f-9996-2a73f0e38bc8"
$tabs = @("overview", "vulnerabilities", "patches", "settings", "updates", "database", "reports")

foreach ($t in $tabs) {
    $src = "$dir\screen_cve_$t.bmp"
    $dst = "$dir\screen_cve_$t.png"
    if (Test-Path $src) {
        $b = [System.Drawing.Image]::FromFile($src)
        $b.Save($dst, [System.Drawing.Imaging.ImageFormat]::Png)
        $b.Dispose()
        Write-Host "[OK] Converted $src -> $dst"
    }
}
