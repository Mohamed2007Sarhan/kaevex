Add-Type -AssemblyName System.Drawing
$dir = "C:\Users\Moham\.gemini\antigravity\brain\ea40fe83-cd23-489f-9996-2a73f0e38bc8"
Get-ChildItem "$dir\screen_tab*.bmp" | ForEach-Object {
    $dst = $_.FullName -replace '\.bmp$', '.png'
    $img = [System.Drawing.Image]::FromFile($_.FullName)
    $img.Save($dst, [System.Drawing.Imaging.ImageFormat]::Png)
    $img.Dispose()
    Write-Host "[OK] Converted $dst"
}
