$path = "src/engines/upd_engine.h"
$content = [System.IO.File]::ReadAllText($path)

$oldSnippet = @"
static const StaticCve UPD_STATIC_CVE_DB[] = {
    {NULL,NULL,NULL,0,NULL,NULL}
};

static const StaticOsCve UPD_STATIC_OS_CVE_DB[] = {
    {0,0,NULL,0,NULL,NULL}
};
"@

$newSnippet = @"
static const StaticCve UPD_STATIC_CVE_DB[] = {
    {"Google Chrome", "128.0.6613.119", "CVE-2024-7971",  88, "128.0.6613.137", "Google.Chrome"},
    {"Google Chrome", "124.0.6367.60",  "CVE-2024-4671",  88, "124.0.6367.78",  "Google.Chrome"},
    {"Google Chrome", "116.0.5845.180", "CVE-2023-4863",  88, "116.0.5845.187", "Google.Chrome"},
    {"Firefox",       "130.0",          "CVE-2024-9680",  98, "131.0.2",        "Mozilla.Firefox"},
    {"Firefox",       "123.0",          "CVE-2024-2605",  81, "124.0",          "Mozilla.Firefox"},
    {"Git",           "2.44.0",         "CVE-2024-32002", 90, "2.45.1",        "Git.Git"},
    {"Node.js",       "20.15.0",        "CVE-2024-36138", 86, "20.15.1",        "OpenJS.NodeJS"},
    {"Node.js",       "18.17.0",        "CVE-2023-32002", 75, "18.17.1",        "OpenJS.NodeJS"},
    {"Python",        "3.12.2",         "CVE-2024-0450",  78, "3.12.3",         "Python.Python.3.12"},
    {"Python",        "3.11.4",         "CVE-2023-40217", 75, "3.11.5",         "Python.Python.3.11"},
    {"VLC",           "3.0.18",         "CVE-2023-47359", 78, "3.0.19",         "VideoLAN.VLC"},
    {"7-Zip",         "23.01",          "CVE-2023-31102", 78, "24.01",         "7zip.7zip"},
    {"7-Zip",         "22.01",          "CVE-2022-29072", 75, "23.00",         "7zip.7zip"},
    {"WinRAR",        "6.22",           "CVE-2023-38831", 78, "6.23",          "RARLab.WinRAR"},
    {"Code",          "1.82.0",         "CVE-2023-36742", 78, "1.83.0",        "Microsoft.VisualStudioCode"},
    {"Discord",       "1.0.9015",       "CVE-2023-6345",  88, "1.0.9018",       "Discord.Discord"},
    {"Notepad++",     "8.5.6",          "CVE-2023-40031", 78, "8.5.7",         "Notepad++.Notepad++"},
    {NULL,NULL,NULL,0,NULL,NULL}
};

static const StaticOsCve UPD_STATIC_OS_CVE_DB[] = {
    {19041, 29999, "CVE-2024-38063", 98, "Windows TCP/IP IPv6 Remote Code Execution", "Install Cumulative Security Rollup KB5041585"},
    {19041, 29999, "CVE-2024-38077", 98, "Windows Remote Desktop Licensing Service RCE", "Install latest Cumulative Security Update"},
    {19041, 29999, "CVE-2024-30078", 88, "Windows Wi-Fi Driver Remote Code Execution", "Install June 2024 Windows Cumulative Update"},
    {19041, 29999, "CVE-2024-21413", 98, "Microsoft Outlook Moniker Link Remote Code Execution", "Update Microsoft 365 / Office components"},
    {19041, 29999, "CVE-2023-36884", 83, "Windows Search / Office RCE Vulnerability", "Apply Microsoft Security Rollup KB5028407"},
    {0,0,NULL,0,NULL,NULL}
};
"@

# Normalize newlines
$contentNorm = $content.Replace("`r`n", "`n")
$oldNorm = $oldSnippet.Replace("`r`n", "`n")
$newNorm = $newSnippet.Replace("`r`n", "`n")

if ($contentNorm.Contains($oldNorm)) {
    $contentNorm = $contentNorm.Replace($oldNorm, $newNorm)
    [System.IO.File]::WriteAllText($path, $contentNorm.Replace("`n", "`r`n"), [System.Text.Encoding]::UTF8)
    Write-Host "[SUCCESS] Replaced static CVE signatures in $path"
} else {
    Write-Host "[FAIL] Could not find oldSnippet in $path"
}
