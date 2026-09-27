Add-Type -AssemblyName System.Drawing
$path = "C:\Users\Moham\.gemini\antigravity\brain\ea40fe83-cd23-489f-9996-2a73f0e38bc8\screen_tab1_defense_engines.png"
$img = [System.Drawing.Bitmap]::FromFile($path)
# Let's find all pixels with border color of card (C_BORDER or pill border)
# C_BORDER is RGB(26, 42, 72)
# Pill border is RGB(40, 110, 230)
$minX = 9999; $maxX = 0; $minY = 9999; $maxY = 0;
for ($y = 50; $y -lt 250; $y++) {
    for ($x = 1000; $x -lt 1280; $x++) {
        $c = $img.GetPixel($x, $y)
        # Check for pill text color RGB(147, 197, 253)
        if ($c.R -gt 130 -and $c.R -lt 165 -and $c.G -gt 180 -and $c.G -lt 210 -and $c.B -gt 240) {
            if ($x -lt $minX) { $minX = $x }
            if ($x -gt $maxX) { $maxX = $x }
            if ($y -lt $minY) { $minY = $y }
            if ($y -gt $maxY) { $maxY = $y }
        }
    }
}
Write-Host "Pill text bbox: x=[$minX..$maxX], y=[$minY..$maxY]"
$img.Dispose()
