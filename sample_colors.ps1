Add-Type -AssemblyName System.Drawing
$imgPath = "C:\Users\Moham\.gemini\antigravity\brain\ea40fe83-cd23-489f-9996-2a73f0e38bc8\.user_uploaded\media_1790389623297.jpg"
$img = [System.Drawing.Bitmap]::FromFile($imgPath)
$w = $img.Width
$h = $img.Height
Write-Host "Image Size: $w x $h"

function SampleNorm($fx, $fy, $desc) {
    $x = [int]($fx * $w)
    $y = [int]($fy * $h)
    if ($x -ge $w) { $x = $w - 1 }
    if ($y -ge $h) { $y = $h - 1 }
    $c = $img.GetPixel($x, $y)
    Write-Host "$desc at ($x, $y) [${fx}, ${fy}]: R=$($c.R), G=$($c.G), B=$($c.B) | Hex=#$($c.R.ToString('X2'))$($c.G.ToString('X2'))$($c.B.ToString('X2'))"
}

SampleNorm 0.10 0.04 "Top Header BG"
SampleNorm 0.35 0.04 "Search Bar Inside"
SampleNorm 0.35 0.02 "Search Bar Top Border"
SampleNorm 0.88 0.04 "User Avatar Chip BG"
SampleNorm 0.08 0.12 "Sidebar Active Tab (Dashboard) center"
SampleNorm 0.08 0.20 "Sidebar Inactive Tab center"
SampleNorm 0.08 0.85 "Sidebar Bottom Wave blue glow"
SampleNorm 0.25 0.12 "Main Area Background"
SampleNorm 0.25 0.23 "Card 1 (Threat Events) Center BG"
SampleNorm 0.45 0.23 "Card 2 (Protected Traffic) Center BG"
SampleNorm 0.65 0.23 "Card 3 (Blocked) Center BG"
SampleNorm 0.85 0.23 "Card 4 (Active Sessions) Center BG"
SampleNorm 0.35 0.45 "Left Chart (Threat Activity) Panel BG"
SampleNorm 0.75 0.45 "Right Chart (Traffic by Time) Panel BG"
SampleNorm 0.30 0.75 "World Map Panel BG"
SampleNorm 0.35 0.75 "World Map Continent color"
SampleNorm 0.75 0.70 "Right Threat Panel Outer BG"
SampleNorm 0.85 0.73 "Cluster Mesh Red Inner Box BG"
SampleNorm 0.85 0.86 "System Status Card BG"

$img.Dispose()
