Add-Type -AssemblyName System.Drawing

$srcPath = "C:\Users\Moham\.gemini\antigravity\brain\ea40fe83-cd23-489f-9996-2a73f0e38bc8\.user_uploaded\media_1790365107019.jpg"
$dstBmp = "c:\Users\Moham\Desktop\keavex\github\assets\world_map_cyber.bmp"

$src = [System.Drawing.Image]::FromFile($srcPath)
Write-Host "Source dimensions: $($src.Width)x$($src.Height)"

# In media_1790365107019.jpg (1024x683):
# The Global Attack Vectors card is at bottom-left:
# X starts around 190, Y starts around 430, width around 600, height around 210.
# The map itself inside the card is from X=196, Y=458 to X=580, Y=630 (width ~384, height ~172)
$cropX = 196
$cropY = 458
$cropW = 390
$cropH = 176

$bmp = New-Object System.Drawing.Bitmap($cropW, $cropH, [System.Drawing.Imaging.PixelFormat]::Format24bppRgb)
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
$g.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
$srcRect = New-Object System.Drawing.Rectangle($cropX, $cropY, $cropW, $cropH)
$dstRect = New-Object System.Drawing.Rectangle(0, 0, $cropW, $cropH)

$g.DrawImage($src, $dstRect, $srcRect, [System.Drawing.GraphicsUnit]::Pixel)
$g.Dispose()
$src.Dispose()

# Save as 24bpp BMP
$bmp.Save($dstBmp, [System.Drawing.Imaging.ImageFormat]::Bmp)
$bmp.Dispose()
Write-Host "[OK] Saved cropped map to $dstBmp"

# Also copy to dist and release
Copy-Item $dstBmp "c:\Users\Moham\Desktop\keavex\github\dist\world_map_cyber.bmp" -Force
Copy-Item $dstBmp "c:\Users\Moham\Desktop\keavex\github\release\world_map_cyber.bmp" -Force
Copy-Item $dstBmp "c:\Users\Moham\Desktop\keavex\github\release\v1\world_map_cyber.bmp" -Force
Write-Host "[OK] Copied world_map_cyber.bmp to dist and release"
