Add-Type -AssemblyName System.Drawing
$bmp = New-Object System.Drawing.Bitmap('C:\Users\Moham\.gemini\antigravity\brain\ea40fe83-cd23-489f-9996-2a73f0e38bc8\.user_uploaded\media_1790372536043.jpg')
Write-Host "Image is $($bmp.Width) x $($bmp.Height)"

# Sample colors at several points
# Window title bar is around y=60
$cTitle = $bmp.GetPixel(100, 65)
Write-Host "Titlebar sample: R=$($cTitle.R), G=$($cTitle.G), B=$($cTitle.B)"

# Left panel at x=200, y=300
$cLeft = $bmp.GetPixel(200, 300)
Write-Host "Left panel sample: R=$($cLeft.R), G=$($cLeft.G), B=$($cLeft.B)"

# Right panel at x=600, y=300
$cRight = $bmp.GetPixel(600, 300)
Write-Host "Right panel sample: R=$($cRight.R), G=$($cRight.G), B=$($cRight.B)"

# CTA button at x=600, y=620
$cBtn = $bmp.GetPixel(600, 620)
Write-Host "Button sample: R=$($cBtn.R), G=$($cBtn.G), B=$($cBtn.B)"

# Find window bounding box by scanning from corners
$minX = 1000; $maxX = 0; $minY = 1000; $maxY = 0;
for ($y = 20; $y -lt 900; $y += 5) {
    for ($x = 20; $x -lt 1000; $x += 5) {
        $c = $bmp.GetPixel($x, $y)
        # Check if pixel belongs to the inner window (dark navy or blue border)
        if ($c.R -gt 15 -or $c.G -gt 25 -or $c.B -gt 45) {
            if ($x -lt $minX) { $minX = $x }
            if ($x -gt $maxX) { $maxX = $x }
            if ($y -lt $minY) { $minY = $y }
            if ($y -gt $maxY) { $maxY = $y }
        }
    }
}
Write-Host "Window bounds roughly: X=$minX..$maxX (W=$($maxX-$minX)), Y=$minY..$maxY (H=$($maxY-$minY))"
$bmp.Dispose()
