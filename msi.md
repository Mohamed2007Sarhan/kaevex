# Kaevex v1.0 - MSI Installer Architecture & Build Engineering Guide

This document provides a comprehensive technical breakdown of how the **Windows Installer Package (`Kaevex-Setup-v1.0.msi`)** was constructed for **Kaevex Security Platform v1.0 [SOC Enterprise]**.

---

## 1. Executive Summary & Design Constraints

- **Package Format**: Microsoft Windows Installer Database (`.msi`).
- **Target Platform**: Windows 10, Windows 11, Windows Server 2016+ (64-bit).
- **Default Installation Target**: `C:\Program Files\Kaevex\`
- **Zero External Dependencies**: Created purely using native Windows system facilities and Windows Installer COM APIs (`WindowsInstaller.Installer`), requiring no third-party package managers or Linux emulation layers (`wixl`).
- **Web Components Excluded**: Per architecture specifications, the optional web frontend (`web-dashboard`) was explicitly excluded to produce a lightweight, closed-source, pure native Win32/C production payload.

---

## 2. Packaged Closed-Source Production Artifacts

The installer bundles and extracts the following production binaries and configuration files:

| Artifact | Type | Description |
|:---|:---:|:---|
| `Kaevex-GUI.exe` | Win32 GUI | Primary 15-tab SOC Enterprise defense dashboard. |
| `kaevex-cli.exe` | Console | Standalone management shell & REST API engine (port 9009). |
| `kaevex-engine.exe` | Service | Background continuous defense engine daemon. |
| `kaevex-tray.exe` | Win32 Tray | System tray monitor and notification controller. |
| `kaevex_cve_catalog.json` | JSON Data | Embedded 2024–2026 CVE intelligence database. |
| `Kaevex-Admin.bat` | Script | UAC-elevated launcher for full kernel/VSS operations. |
| `Kaevex-Start.bat` | Script | Quick launch shortcut for desktop environments. |
| `README.md` | Markdown | Complete technical documentation for Kaevex v1.0. |

---

## 3. Step-by-Step Engineering Process

### Step 1: Staging Production Files in `release\v1\`
All verified, 64-bit production binaries and runtime configurations were copied from `dist\` into a clean staging directory:

```cmd
if not exist release\v1 mkdir release\v1
copy /y dist\Kaevex-GUI.exe release\v1\
copy /y dist\kaevex-cli.exe release\v1\
copy /y dist\kaevex-engine.exe release\v1\
copy /y dist\kaevex-tray.exe release\v1\
copy /y dist\kaevex_cve_catalog.json release\v1\
copy /y README.md release\v1\
copy /y Kaevex-Admin.bat release\v1\
copy /y Kaevex-Start.bat release\v1\
```

### Step 2: Generating the Compressed Binary Payload
To achieve an ultra-compact, single-file MSI distribution, all staged artifacts were compressed into a deterministic zip archive:

```powershell
Compress-Archive -Path 'release\v1\Kaevex-GUI.exe', `
                       'release\v1\kaevex-cli.exe', `
                       'release\v1\kaevex-engine.exe', `
                       'release\v1\kaevex-tray.exe', `
                       'release\v1\kaevex_cve_catalog.json', `
                       'release\v1\Kaevex-Admin.bat', `
                       'release\v1\Kaevex-Start.bat', `
                       'release\v1\README.md' `
                 -DestinationPath 'release\v1\Kaevex-v1.0-Production-x64.zip' -Force
```
*Resulting Payload Size*: **~186 KB** (compressed from ~550 KB raw binaries).

### Step 3: Initializing the Windows Installer Database
A clean Microsoft Windows Installer database template was cloned and opened in Transact Mode (`1`) using the native Windows COM interface `WindowsInstaller.Installer`:

```powershell
$inst = New-Object -ComObject WindowsInstaller.Installer
$db = $inst.OpenDatabase('release\v1\Kaevex-Setup-v1.0.msi', 1) # Mode 1 = Transact
```

### Step 4: Configuring Product Identity & Metadata
Standard Windows Installer database properties were configured via SQL execution:

```sql
INSERT INTO `Property` (`Property`, `Value`) VALUES ('ProductName', 'Kaevex Security Platform v1.0 [SOC Enterprise]');
INSERT INTO `Property` (`Property`, `Value`) VALUES ('ProductVersion', '1.0.0');
INSERT INTO `Property` (`Property`, `Value`) VALUES ('Manufacturer', 'Kaevex Cyber Systems');
INSERT INTO `Property` (`Property`, `Value`) VALUES ('ProductCode', '{A7F8E9D0-1234-5678-9ABC-DEF012345678}');
INSERT INTO `Property` (`Property`, `Value`) VALUES ('UpgradeCode', '{B8E9D0C1-2345-6789-ABCD-EF0123456789}');
INSERT INTO `Property` (`Property`, `Value`) VALUES ('ALLUSERS', '1');
INSERT INTO `Property` (`Property`, `Value`) VALUES ('ARPHELPLINK', 'https://github.com/kaevex/fire');
INSERT INTO `Property` (`Property`, `Value`) VALUES ('ARPCOMMENTS', 'Enterprise Endpoint, Network & Web Defense SOC Platform');
```

*Crucial Note on Add/Remove Programs Visibility*:
The system flag `ARPSYSTEMCOMPONENT = 1` was deleted from the `Property` table so that Windows displays **Kaevex Security Platform v1.0** cleanly inside **Windows Settings > Apps > Installed Apps** and the legacy **Control Panel > Programs and Features**.

### Step 5: Embedding the Payload into the `Binary` Table
Using the `SetStream` COM method, the compressed zip payload was embedded directly as an OLE binary stream inside the MSI database under the key `KaevexPayload`:

```powershell
$rec = $inst.CreateRecord(2)
$rec.StringData(1) = 'KaevexPayload'
$rec.SetStream(2, 'release\v1\Kaevex-v1.0-Production-x64.zip')

$v = $db.OpenView("INSERT INTO `Binary` (`Name`, `Data`) VALUES (?, ?)")
$v.Execute($rec)
$v.Close()
```

### Step 6: Implementing the Self-Extracting Custom Action
A specialized Custom Action (`Type 38` = embedded script executed in system context) was inserted into the `CustomAction` table. 

The custom action handles both **Installation** and **Uninstallation**:

#### Installation Phase:
1. Resolves `%ProgramFiles%\Kaevex`.
2. Creates the target directory if absent.
3. Queries `SELECT Data FROM Binary WHERE Name = 'KaevexPayload'`.
4. Streams the binary data into `%TEMP%\Kaevex-v1.0-Payload.zip` via `ADODB.Stream`.
5. Calls `Shell.Application.NameSpace.CopyHere` to decompress all core binaries into `C:\Program Files\Kaevex\`.
6. Purges the temporary zip file.
7. Creates desktop and start menu shortcuts (`.lnk` files) with correct working directories and metadata.

#### Uninstallation Phase (`REMOVE="ALL"`):
1. Safely terminates any running `Kaevex-GUI.exe`, `kaevex-cli.exe`, or `kaevex-engine.exe` instances.
2. Removes all desktop and Start Menu shortcuts.
3. Deletes `C:\Program Files\Kaevex\` cleanly.

### Step 7: Scheduling the Custom Action in `InstallExecuteSequence`
The action `KaevexSetupAction` was inserted into the installation sequence table just before `InstallFinalize` (Sequence `6500`):

```sql
INSERT INTO `InstallExecuteSequence` (`Action`, `Condition`, `Sequence`)
VALUES ('KaevexSetupAction', 'NOT Installed OR REMOVE="ALL"', 6500);
```

### Step 8: Building the Companion Native C Bootstrapper
To provide an optional graphical/terminal setup wizard with automated UAC privilege elevation, a native C launcher [`src\installer\kaevex-setup.c`](file:///c:/Users/Moham/Desktop/keavex/fire/src/installer/kaevex-setup.c) was compiled into [`release\v1\Kaevex-Setup-v1.0.exe`](file:///c:/Users/Moham/Desktop/keavex/fire/release/v1/Kaevex-Setup-v1.0.exe):

- Uses `OpenProcessToken` and `TokenElevation` to check administrative rights.
- Triggers automatic UAC elevation via `ShellExecuteExA` with `"runas"`.
- Automatically calls `msiexec.exe /i "Kaevex-Setup-v1.0.msi"` in the foreground and launches the platform upon completion.

---

## 4. Deployment Instructions

### Interactive Installation (Double-Click)
Double-click [`Kaevex-Setup-v1.0.msi`](file:///c:/Users/Moham/Desktop/keavex/fire/release/v1/Kaevex-Setup-v1.0.msi) or [`Kaevex-Setup-v1.0.exe`](file:///c:/Users/Moham/Desktop/keavex/fire/release/v1/Kaevex-Setup-v1.0.exe). Accept the standard Windows UAC prompt.

### Enterprise Silent / Automated Deployment (GPO, Intune, SCCM)
To deploy silently across Windows domains without user interaction:

```cmd
msiexec.exe /i "Kaevex-Setup-v1.0.msi" /qn /norestart
```

### Clean Uninstallation
Uninstallation can be performed through **Windows Settings > Installed Apps** or via command line:

```cmd
msiexec.exe /x "Kaevex-Setup-v1.0.msi" /qn
```
Or via Product Code:
```cmd
msiexec.exe /x "{A7F8E9D0-1234-5678-9ABC-DEF012345678}" /qn
```

---

## 5. Verification Checklist

- [x] **File Format**: Valid Windows Installer Compound Document (`.msi`).
- [x] **Payload Integrity**: Embedded closed-source production binaries (`Kaevex-GUI.exe`, `kaevex-cli.exe`, `kaevex-engine.exe`, `kaevex-tray.exe`, `kaevex_cve_catalog.json`).
- [x] **Web Assets Excluded**: Verified zero HTML/JS/CSS web dashboard files in MSI.
- [x] **Shortcut Creation**: Generates Desktop and Start Menu links dynamically.
- [x] **Registry & ARP**: Full registration in Windows Add/Remove Programs.
- [x] **Clean Removal**: Complete cleanup on uninstallation.
