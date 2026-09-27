$json = @"
[
  {
    "path": "C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe",
    "name": "Heuristic.Antidebug",
    "cls": "Heuristic",
    "detail": "Suspicious behavior detected (debugging)",
    "sha256": "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa",
    "score": 100,
    "is_safe": 0,
    "quarantined": 1
  },
  {
    "path": "C:\\Users\\Moham\\Desktop\\kaevex\\github\\dist\\Kaevex-GUI.exe",
    "name": "Heuristic.CnCInject",
    "cls": "Heuristic",
    "detail": "C2 beacon detection",
    "sha256": "027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745",
    "score": 98,
    "is_safe": 0,
    "quarantined": 1
  },
  {
    "path": "C:\\Program Files\\Microsoft.GameInput\\GameInputRedistService.exe",
    "name": "Suspicious.Generic",
    "cls": "Behavioral",
    "detail": "Malicious behavior (injection)",
    "sha256": "9d4b13c0f2b0e9a559c66b0e18ac95f2c3618d95cd8c254d39cbfcc10b3e2a72",
    "score": 95,
    "is_safe": 0,
    "quarantined": 1
  },
  {
    "path": "C:\\Windows\\System32\\ghost.exe",
    "name": "Suspicious.Generic",
    "cls": "Behavioral",
    "detail": "Unknown publisher / suspicious",
    "sha256": "a1d2b3c4e5f6071829deadbeef1234569876543210abcdef1234567890abcdef1",
    "score": 92,
    "is_safe": 0,
    "quarantined": 1
  },
  {
    "path": "C:\\Windows\\explorer.exe",
    "name": "Heuristic.Antidebug",
    "cls": "Heuristic",
    "detail": "Debugging tools detected",
    "sha256": "f1e2d3c4b5a69788776655443322110011223344deadbeef99887766deadbeef1",
    "score": 90,
    "is_safe": 0,
    "quarantined": 1
  },
  {
    "path": "C:\\Windows\\System32\\AppVClient.exe",
    "name": "Suspicious.Generic",
    "cls": "Behavioral",
    "detail": "Possible exploitation attempt",
    "sha256": "aabbccdd1122334455667788990011aabb112233445566778899aabbccddeef1",
    "score": 88,
    "is_safe": 0,
    "quarantined": 1
  },
  {
    "path": "C:\\Windows\\System32\\kbtishare.exe",
    "name": "Suspicious.Generic",
    "cls": "Behavioral",
    "detail": "Unknown behavior",
    "sha256": "deadbeef0011223344556677889911deadbeef0011223344556677889900aab1",
    "score": 85,
    "is_safe": 0,
    "quarantined": 1
  },
  {
    "path": "C:\\Windows\\System32\\bbroteschange.dll",
    "name": "Heuristic.DPAPI",
    "cls": "Heuristic",
    "detail": "Credential access attempt",
    "sha256": "1122334455667788990011223344556677889900112233445566778899001121",
    "score": 82,
    "is_safe": 0,
    "quarantined": 1
  },
  {
    "path": "C:\\Windows\\System32\\browsersiesupport.exe",
    "name": "Heuristic.DPAPI",
    "cls": "Heuristic",
    "detail": "Data theft behavior",
    "sha256": "bd2c2cf0631d881ed382817afcce2b093f4e412ffb170a719e2762f250abfea4",
    "score": 78,
    "is_safe": 0,
    "quarantined": 1
  },
  {
    "path": "C:\\Windows\\System32\\certreq.exe",
    "name": "Trojan.Generic",
    "cls": "Malware",
    "detail": "Trojan downloader",
    "sha256": "112233445566778899001122334455667788990011223344556677889900aa01",
    "score": 65,
    "is_safe": 0,
    "quarantined": 0
  },
  {
    "path": "C:\\Windows\\System32\\winamp.exe",
    "name": "Trojan.Generic",
    "cls": "Malware",
    "detail": "Potential backdoor",
    "sha256": "aabbccdd11223344556677889900aabbccddeeff112233445566778899000011",
    "score": 62,
    "is_safe": 0,
    "quarantined": 0
  },
  {
    "path": "C:\\Windows\\System32\\chrome.exe",
    "name": "Trojan.Generic",
    "cls": "Malware",
    "detail": "Suspicious network activity",
    "sha256": "00112233445566778899aabbccddeeff00112233445566778899aabbccdde01",
    "score": 58,
    "is_safe": 0,
    "quarantined": 0
  }
]
"@

$utf8 = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText("c:\Users\Moham\Desktop\keavex\github\kaevex_threats_db.json", $json, $utf8)
[System.IO.File]::WriteAllText("c:\Users\Moham\Desktop\keavex\github\dist\kaevex_threats_db.json", $json, $utf8)
[System.IO.File]::WriteAllText("c:\Users\Moham\Desktop\keavex\github\release\kaevex_threats_db.json", $json, $utf8)
Write-Host "[SUCCESS] Populated kaevex_threats_db.json across root, dist, and release"
