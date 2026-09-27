Add-Type -AssemblyName System.Drawing
$path = "C:\Users\Moham\.gemini\antigravity\brain\ea40fe83-cd23-489f-9996-2a73f0e38bc8\screen_tab1_defense_engines.png"
$img = [System.Drawing.Bitmap]::FromFile($path)
for ($x = 1250; $x -lt 1276; $x++) {
    $c = $img.GetPixel($x, 134)
    Write-Host "x=$x : R=$($c.R) G=$($c.G) B=$($c.B)"
}
$img.Dispose()
