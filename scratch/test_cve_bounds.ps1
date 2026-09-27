$path = "src/gui/kaevex-gui.c"
$content = [System.IO.File]::ReadAllText($path)

# Let's inspect where PaintUpd starts and ends
$paintUpdStart = "static void PaintUpd(HDC dc, int cx, int cy, int cw, int ch) {"
$paintUpdEnd = "/* ============================================================" + "`n" + " * SOC CLUSTER MULTI-SERVER PAIRING HELPERS"

Write-Host "Checking if PaintUpd can be located..."
$cNorm = $content.Replace("`r`n", "`n")
$idxStart = $cNorm.IndexOf($paintUpdStart)
$idxEnd = $cNorm.IndexOf($paintUpdEnd)

if ($idxStart -ge 0 -and $idxEnd -gt $idxStart) {
    Write-Host "[OK] Found PaintUpd at $idxStart..$idxEnd (length: $($idxEnd - $idxStart))"
} else {
    Write-Host "[FAIL] Could not locate PaintUpd boundaries"
}
