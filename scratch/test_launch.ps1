$p = Start-Process -FilePath "dist\kaevex.exe" -PassThru
Start-Sleep -Milliseconds 1500
Write-Host "Process ID: $($p.Id), HasExited: $($p.HasExited)"
if (-not $p.HasExited) {
    Stop-Process -Id $p.Id -Force
}
