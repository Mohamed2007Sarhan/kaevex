Add-Type -AssemblyName System.Drawing
$img = [System.Drawing.Image]::FromFile('C:\Users\Moham\.gemini\antigravity\brain\ea40fe83-cd23-489f-9996-2a73f0e38bc8\.user_uploaded\media_1790372536043.jpg')
Write-Host "Width: $($img.Width), Height: $($img.Height)"
$img.Dispose()
