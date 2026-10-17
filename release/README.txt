Kaevex - release layout
=======================
windows/kaevex.exe   Windows 10/11 x64. GUI + CLI + tray in one file. Double-click, or use Kaevex-Admin.bat
                     (administrator rights are needed for firewall changes, lockdown, logging and fixes).
linux/kaevex         Native Linux x86-64 tool (terminal). selftest, posture, conns, fw (nftables), cve (OSV+KEV), ai, ledger.
mobile/kaevex-mobile.apk   Android companion app (talks to the node API on port 9009).

Notes
- The Windows GUI uses GDI scaling so it stays sharp and proportional on 125-200% displays (Windows 10 1809+).
- The Linux tool has no GUI. Read-only commands need no root; apply/fix commands need sudo.
- Data folders: Windows %APPDATA%\Kaevex ; Linux ~/.config/kaevex (override with KAEVEX_HOME).
