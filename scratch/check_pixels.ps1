Add-Type -AssemblyName System.Drawing
$img = [System.Drawing.Bitmap]::FromFile("C:\Users\Moham\Desktop\keavex\github\scratch\check_screen.bmp")
# if check_screen doesn't exist, use artifact
$path = "C:\Users\Moham\.gemini\antigravity\brain\ea40fe83-cd23-489f-9996-2a73f0e38bc8\screen_tab1_defense_engines.png"
$img = [System.Drawing.Bitmap]::FromFile($path)
Write-Host "Scanning for pill (R<60, G>30, B>120) between y=60..200, x=800..1280"
for ($y = 60; $y -lt 200; $y += 5) {
    for ($x = 800; $x -lt 1280; $x += 5) {
        $c = $img.GetPixel($x, $y)
        if ($c.B -gt 150 -and $c.R -lt 100) {
            Write-Host "Found pill pixel at x=$x y=$y : R=$($c.R) G=$($c.G) B=$($c.B)"
            break
        }
    }
}
$img.Dispose()
