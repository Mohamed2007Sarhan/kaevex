$p = Start-Process -FilePath "c:\Users\Moham\Desktop\keavex\github\dist\kaevex.exe" -ArgumentList "--gui" -PassThru -WorkingDirectory "c:\Users\Moham\Desktop\keavex\github"

for ($i = 0; $i -lt 30; $i++) {
    Start-Sleep -Milliseconds 500
    $p.Refresh()
    if ($p.HasExited) {
        Write-Host "Process exited early with code $($p.ExitCode)"
        break
    }
    if ($p.MainWindowHandle -ne 0) {
        Write-Host "Window found after $($i * 500) ms! Handle: $($p.MainWindowHandle), Title: '$($p.MainWindowTitle)'"
        break
    }
}

if (-not $p.HasExited) {
    Start-Sleep -Seconds 2
    Stop-Process -Id $p.Id -Force
}
