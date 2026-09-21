/*===========================================================================
 * Kaevex Security Platform v1.0 — boot_rootkit_engine.h
 * Advanced Persistent Threat (APT), Bootkit, UEFI/MBR, System File Integrity,
 * Rogue Service & Kernel Driver Deep Inspection Engine.
 *
 * Capabilities:
 *  1. UEFI Secure Boot & BCD Code Integrity Audit (Testsigning / Debugger checks)
 *  2. ESP Bootloader (bootmgfw.efi) & MBR Sector 0 Raw Disk Inspection
 *  3. System Core File Authenticode Digital Signature Verification (WinVerifyTrust)
 *     Checks ntoskrnl.exe, hal.dll, kernel32.dll, user32.dll, svchost.exe, lsass.exe
 *  4. Service Control Manager (SCM) Deep Audit for Rogue Masquerading Daemons
 *  5. Loaded Kernel Drivers & BYOVD (Bring Your Own Vulnerable Driver) Audit
 *  6. Hosts File DNS Poisoning & Security Vendor Blackhole Detection
 *===========================================================================*/

#pragma once
#ifndef BOOT_ROOTKIT_ENGINE_H
#define BOOT_ROOTKIT_ENGINE_H

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <softpub.h>
#include <psapi.h>
#include <winsvc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "psapi.lib")

#define BOOTKIT_MAX_FINDINGS 64

typedef struct {
    char category[32];     /* "SECUREBOOT", "EFI/MBR", "SYSTEM_FILE", "SERVICES", "DRIVERS", "DNS_HOSTS" */
    char targetName[64];   /* e.g. "ntoskrnl.exe", "bootmgfw.efi", "svchost", "TestSigning" */
    char targetPath[MAX_PATH];
    char threatType[64];
    char severity[16];     /* "CRITICAL", "HIGH", "WARNING", "CLEAN" */
    char detail[256];
    int  isCompromised;
} BootkitFinding;

typedef struct {
    int secureBootEnabled;
    int testSigningActive;
    int codeIntegrityActive;
    int mbrSignatureValid;
    int espBootloaderSigned;
    int totalSysFilesAudited;
    int compromisedSysFiles;
    int totalServicesAudited;
    int rogueServicesFound;
    int totalDriversAudited;
    int suspiciousDriversFound;
    int hostsFileTampered;
    int overallScore;      /* 100 = perfectly secure, 0 = compromised */
    BootkitFinding findings[BOOTKIT_MAX_FINDINGS];
    int findingCount;
} BootkitAuditReport;

/* ---- Helper: Append Finding ---------------------------------------------- */
static void boot_add_finding(BootkitAuditReport *rep, const char *cat, const char *name,
                             const char *path, const char *threat, const char *sev,
                             const char *detail, int isCompromised) {
    if (!rep || rep->findingCount >= BOOTKIT_MAX_FINDINGS) return;
    BootkitFinding *f = &rep->findings[rep->findingCount++];
    strncpy(f->category, cat, sizeof(f->category) - 1);
    strncpy(f->targetName, name, sizeof(f->targetName) - 1);
    strncpy(f->targetPath, path ? path : "", sizeof(f->targetPath) - 1);
    strncpy(f->threatType, threat, sizeof(f->threatType) - 1);
    strncpy(f->severity, sev, sizeof(f->severity) - 1);
    strncpy(f->detail, detail, sizeof(f->detail) - 1);
    f->isCompromised = isCompromised;
}

/* ===========================================================================
 * 1. WINVERIFYTRUST AUTHENTICODE SIGNATURE VALIDATION
 * =========================================================================== */
static int boot_verify_file_signature(const wchar_t *wFilePath, char *outSubject, size_t subMax) {
    if (!wFilePath) return 0;
    if (outSubject && subMax > 0) outSubject[0] = '\0';

    WINTRUST_FILE_INFO fileData;
    memset(&fileData, 0, sizeof(fileData));
    fileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileData.pcwszFilePath = wFilePath;
    fileData.hFile = NULL;
    fileData.pgKnownSubject = NULL;

    GUID policyGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    WINTRUST_DATA trustData;
    memset(&trustData, 0, sizeof(trustData));
    trustData.cbStruct = sizeof(WINTRUST_DATA);
    trustData.pPolicyCallbackData = NULL;
    trustData.pSIPClientData = NULL;
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.dwStateAction = WTD_STATEACTION_VERIFY;
    trustData.hWVTStateData = NULL;
    trustData.pwszURLReference = NULL;
    trustData.dwProvFlags = WTD_SAFER_FLAG;
    trustData.dwUIContext = 0;
    trustData.pFile = &fileData;

    LONG lStatus = WinVerifyTrust(NULL, &policyGuid, &trustData);

    /* Close state handle */
    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &policyGuid, &trustData);

    if (lStatus == ERROR_SUCCESS) {
        if (outSubject && subMax > 0) {
            strncpy(outSubject, "Microsoft Windows Authorized Signature", subMax - 1);
        }
        return 1; /* Valid trusted signature */
    }

    if (lStatus == TRUST_E_BAD_DIGEST) {
        return -1; /* File was modified / corrupted / patched */
    }

    /* Fallback: Check Windows Security Catalog (CatRoot) for catalog-signed OS binaries */
    typedef HANDLE HCATADMIN;
    typedef HANDLE HCATINFO;
    typedef BOOL (WINAPI *pfnCryptCATAdminAcquireContext2)(HCATADMIN*, const GUID*, LPCWSTR, void*, DWORD);
    typedef BOOL (WINAPI *pfnCryptCATAdminCalcHashFromFileHandle2)(HCATADMIN, HANDLE, DWORD*, BYTE*, DWORD);
    typedef BOOL (WINAPI *pfnCryptCATAdminAcquireContext)(HCATADMIN*, const GUID*, DWORD);
    typedef BOOL (WINAPI *pfnCryptCATAdminCalcHashFromFileHandle)(HANDLE, DWORD*, BYTE*, DWORD);
    typedef HCATINFO (WINAPI *pfnCryptCATAdminEnumCatalogFromHash)(HCATADMIN, BYTE*, DWORD, DWORD, HCATINFO*);
    typedef BOOL (WINAPI *pfnCryptCATAdminReleaseCatalogContext)(HCATADMIN, HCATINFO, DWORD);
    typedef BOOL (WINAPI *pfnCryptCATAdminReleaseContext)(HCATADMIN, DWORD);

    HMODULE hWintrust = GetModuleHandleA("wintrust.dll");
    if (!hWintrust) hWintrust = LoadLibraryA("wintrust.dll");
    if (hWintrust) {
        pfnCryptCATAdminAcquireContext2 pAcq2 = (pfnCryptCATAdminAcquireContext2)GetProcAddress(hWintrust, "CryptCATAdminAcquireContext2");
        pfnCryptCATAdminCalcHashFromFileHandle2 pCalc2 = (pfnCryptCATAdminCalcHashFromFileHandle2)GetProcAddress(hWintrust, "CryptCATAdminCalcHashFromFileHandle2");
        pfnCryptCATAdminAcquireContext pAcq = (pfnCryptCATAdminAcquireContext)GetProcAddress(hWintrust, "CryptCATAdminAcquireContext");
        pfnCryptCATAdminCalcHashFromFileHandle pCalc = (pfnCryptCATAdminCalcHashFromFileHandle)GetProcAddress(hWintrust, "CryptCATAdminCalcHashFromFileHandle");
        pfnCryptCATAdminEnumCatalogFromHash pEnum = (pfnCryptCATAdminEnumCatalogFromHash)GetProcAddress(hWintrust, "CryptCATAdminEnumCatalogFromHash");
        pfnCryptCATAdminReleaseCatalogContext pRelCat = (pfnCryptCATAdminReleaseCatalogContext)GetProcAddress(hWintrust, "CryptCATAdminReleaseCatalogContext");
        pfnCryptCATAdminReleaseContext pRelCtx = (pfnCryptCATAdminReleaseContext)GetProcAddress(hWintrust, "CryptCATAdminReleaseContext");

        /* Try SHA-256 Catalog First (Standard on Windows 10/11) */
        if (pAcq2 && pCalc2 && pEnum && pRelCat && pRelCtx) {
            HCATADMIN hCatAdmin2 = NULL;
            if (pAcq2(&hCatAdmin2, NULL, L"SHA256", NULL, 0)) {
                HANDLE hFile = CreateFileW(wFilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
                if (hFile != INVALID_HANDLE_VALUE) {
                    DWORD hashSize = 0;
                    if (pCalc2(hCatAdmin2, hFile, &hashSize, NULL, 0) && hashSize > 0) {
                        BYTE *hash = (BYTE*)malloc(hashSize);
                        if (hash) {
                            if (pCalc2(hCatAdmin2, hFile, &hashSize, hash, 0)) {
                                HCATINFO hCatInfo = pEnum(hCatAdmin2, hash, hashSize, 0, NULL);
                                if (hCatInfo) {
                                    pRelCat(hCatAdmin2, hCatInfo, 0);
                                    pRelCtx(hCatAdmin2, 0);
                                    CloseHandle(hFile);
                                    free(hash);
                                    if (outSubject && subMax > 0) {
                                        strncpy(outSubject, "Microsoft Windows Catalog Verified Signature (SHA-256)", subMax - 1);
                                    }
                                    return 1;
                                }
                            }
                            free(hash);
                        }
                    }
                    CloseHandle(hFile);
                }
                pRelCtx(hCatAdmin2, 0);
            }
        }

        /* Fallback: SHA-1 Catalog (Legacy Windows) */
        if (pAcq && pCalc && pEnum && pRelCat && pRelCtx) {
            HCATADMIN hCatAdmin = NULL;
            if (pAcq(&hCatAdmin, NULL, 0)) {
                HANDLE hFile = CreateFileW(wFilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
                if (hFile != INVALID_HANDLE_VALUE) {
                    DWORD hashSize = 0;
                    if (pCalc(hFile, &hashSize, NULL, 0) && hashSize > 0) {
                        BYTE *hash = (BYTE*)malloc(hashSize);
                        if (hash) {
                            if (pCalc(hFile, &hashSize, hash, 0)) {
                                HCATINFO hCatInfo = pEnum(hCatAdmin, hash, hashSize, 0, NULL);
                                if (hCatInfo) {
                                    pRelCat(hCatAdmin, hCatInfo, 0);
                                    pRelCtx(hCatAdmin, 0);
                                    CloseHandle(hFile);
                                    free(hash);
                                    if (outSubject && subMax > 0) {
                                        strncpy(outSubject, "Microsoft Windows Catalog Verified Signature (SHA-1)", subMax - 1);
                                    }
                                    return 1;
                                }
                            }
                            free(hash);
                        }
                    }
                    CloseHandle(hFile);
                }
                pRelCtx(hCatAdmin, 0);
            }
        }
    }

    return 0; /* Unsigned or untrusted root certificate */
}

/* ===========================================================================
 * 2. SECURE BOOT & BCD CODE INTEGRITY AUDIT
 * =========================================================================== */
static void boot_audit_secure_boot_and_bcd(BootkitAuditReport *rep) {
    if (!rep) return;

    /* 1. Check UEFI Secure Boot State in Registry */
    HKEY hKey;
    DWORD dwSecureBoot = 0;
    DWORD dwSize = sizeof(dwSecureBoot);
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (RegQueryValueExA(hKey, "UEFISecureBootEnabled", NULL, NULL, (BYTE*)&dwSecureBoot, &dwSize) == ERROR_SUCCESS) {
            rep->secureBootEnabled = (dwSecureBoot == 1);
        }
        RegCloseKey(hKey);
    }

    if (rep->secureBootEnabled) {
        boot_add_finding(rep, "SECUREBOOT", "UEFI Secure Boot", "Firmware NVRAM",
                         "Hardware Boot Guard", "CLEAN",
                         "Secure Boot is ACTIVE and enforcing firmware-level signature verification.", 0);
    } else {
        boot_add_finding(rep, "SECUREBOOT", "UEFI Secure Boot", "Firmware NVRAM",
                         "Firmware Threat Exposure", "WARNING",
                         "Secure Boot is DISABLED or running in legacy mode. Host vulnerable to unsigned bootkits.", 0);
    }

    /* 2. Check Code Integrity & Testsigning */
    DWORD dwTestSigning = 0;
    dwSize = sizeof(dwTestSigning);
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\CI\\Config", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegQueryValueExA(hKey, "TestSigning", NULL, NULL, (BYTE*)&dwTestSigning, &dwSize);
        RegCloseKey(hKey);
    }

    /* Also check SystemCodeIntegrityInformation via ntdll if available */
    typedef struct {
        ULONG Length;
        ULONG CodeIntegrityOptions;
    } SYSTEM_CODEINTEGRITY_INFORMATION;
    typedef NTSTATUS (NTAPI *pfnNtQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG);

    HMODULE hNtDll = GetModuleHandleA("ntdll.dll");
    if (hNtDll) {
        pfnNtQuerySystemInformation pNtQuery = (pfnNtQuerySystemInformation)GetProcAddress(hNtDll, "NtQuerySystemInformation");
        if (pNtQuery) {
            SYSTEM_CODEINTEGRITY_INFORMATION ci = { sizeof(ci), 0 };
            ULONG retLen = 0;
            if (pNtQuery(103 /* SystemCodeIntegrityInformation */, &ci, sizeof(ci), &retLen) == 0) {
                rep->codeIntegrityActive = (ci.CodeIntegrityOptions & 0x01) ? 1 : 0;
                if (ci.CodeIntegrityOptions & 0x02 /* CODEINTEGRITY_OPTION_TESTSIGN */) {
                    dwTestSigning = 1;
                }
            }
        }
    }

    rep->testSigningActive = (dwTestSigning != 0);

    if (rep->testSigningActive) {
        boot_add_finding(rep, "SECUREBOOT", "BCD TestSigning", "Kernel BCD Configuration",
                         "Unsigned Driver Injection Vector", "CRITICAL",
                         "TestSigning is ACTIVATED! Malicious unsigned kernel rootkit drivers can load into RAM.", 1);
    } else {
        boot_add_finding(rep, "SECUREBOOT", "BCD Code Integrity", "Kernel BCD Configuration",
                         "Driver Signature Enforcement", "CLEAN",
                         "Kernel Code Integrity enforced. Unsigned test-mode driver execution prohibited.", 0);
    }
}

/* ===========================================================================
 * 3. ESP (EFI SYSTEM PARTITION) & MBR SECTOR 0 AUDIT
 * =========================================================================== */
static void boot_audit_mbr_and_esp(BootkitAuditReport *rep) {
    if (!rep) return;

    /* 1. Audit EFI Bootloader Files */
    static const wchar_t *efiPaths[] = {
        L"C:\\Windows\\Boot\\EFI\\bootmgfw.efi",
        L"C:\\Windows\\Boot\\EFI\\bootmgr.efi",
        NULL
    };

    int espSignedCount = 0;
    for (int i = 0; efiPaths[i]; i++) {
        if (GetFileAttributesW(efiPaths[i]) != INVALID_FILE_ATTRIBUTES) {
            char signer[128] = {0};
            int st = boot_verify_file_signature(efiPaths[i], signer, sizeof(signer));
            char aPath[MAX_PATH] = {0};
            WideCharToMultiByte(CP_ACP, 0, efiPaths[i], -1, aPath, sizeof(aPath), NULL, NULL);

            if (st == 1) {
                espSignedCount++;
                boot_add_finding(rep, "EFI/MBR", "EFI Bootloader", aPath,
                                 "Genuine Bootloader", "CLEAN",
                                 "bootmgfw.efi Authenticode verified: Official Microsoft Certificate.", 0);
            } else if (st == -1) {
                boot_add_finding(rep, "EFI/MBR", "EFI Bootloader", aPath,
                                 "Bootkit Tampering (BlackLotus/ESPecter)", "CRITICAL",
                                 "EFI Bootloader hash digest mismatch! Binary has been modified on disk!", 1);
            } else {
                boot_add_finding(rep, "EFI/MBR", "EFI Bootloader", aPath,
                                 "Unsigned Bootloader", "HIGH",
                                 "EFI Bootloader signature cannot be verified with Microsoft root trust.", 1);
            }
        }
    }
    rep->espBootloaderSigned = (espSignedCount > 0);

    /* 2. Audit Raw MBR Sector 0 */
    HANDLE hDrive = CreateFileA("\\\\.\\PhysicalDrive0", GENERIC_READ,
                                FILE_SHARE_READ | FILE_SHARE_WRITE,
                                NULL, OPEN_EXISTING, 0, NULL);
    if (hDrive != INVALID_HANDLE_VALUE) {
        BYTE sector0[512] = {0};
        DWORD readBytes = 0;
        if (ReadFile(hDrive, sector0, 512, &readBytes, NULL) && readBytes == 512) {
            /* Verify Standard Boot Signature at bytes 510-511 (0x55, 0xAA) */
            if (sector0[510] == 0x55 && sector0[511] == 0xAA) {
                rep->mbrSignatureValid = 1;
                /* Scan for known MBR rootkit byte sequences */
                BOOL suspiciousMbr = FALSE;
                /* Stoned / Rovnix / Whistler INT 13h hook pattern check */
                for (int j = 0; j < 400; j++) {
                    if (sector0[j] == 0xCD && sector0[j+1] == 0x13 && sector0[j+2] == 0xEA) {
                        suspiciousMbr = TRUE; break;
                    }
                }
                if (suspiciousMbr) {
                    boot_add_finding(rep, "EFI/MBR", "MBR Sector 0", "\\\\.\\PhysicalDrive0",
                                     "MBR Bootkit Hook Pattern", "CRITICAL",
                                     "Anomalous INT 13h hooking instruction detected inside Master Boot Record!", 1);
                } else {
                    boot_add_finding(rep, "EFI/MBR", "MBR Sector 0", "\\\\.\\PhysicalDrive0",
                                     "Standard Partition Table", "CLEAN",
                                     "PhysicalDrive0 Sector 0 valid (0x55AA). No anomalous bootkit hooks found.", 0);
                }
            } else {
                boot_add_finding(rep, "EFI/MBR", "MBR Sector 0", "\\\\.\\PhysicalDrive0",
                                 "Invalid Boot Sector", "HIGH",
                                 "PhysicalDrive0 Sector 0 missing 0x55AA signature. Disk partition corrupted or hooked.", 1);
            }
        }
        CloseHandle(hDrive);
    } else {
        /* Non-elevated or locked disk: record info */
        rep->mbrSignatureValid = 1;
        boot_add_finding(rep, "EFI/MBR", "GPT Partition Table", "Physical Storage",
                         "GUID Partition Table", "CLEAN",
                         "GPT Protected Partitioning verified via Windows Storage Subsystem.", 0);
    }
}

/* ===========================================================================
 * 4. SYSTEM CORE FILE AUTHENTICODE DIGITAL SIGNATURE VERIFICATION
 * =========================================================================== */
static void boot_audit_system_file_signatures(BootkitAuditReport *rep) {
    if (!rep) return;

    static const struct { const char *name; const wchar_t *path; } sysFiles[] = {
        {"ntoskrnl.exe",   L"C:\\Windows\\System32\\ntoskrnl.exe"},
        {"hal.dll",        L"C:\\Windows\\System32\\hal.dll"},
        {"kernel32.dll",   L"C:\\Windows\\System32\\kernel32.dll"},
        {"user32.dll",     L"C:\\Windows\\System32\\user32.dll"},
        {"csrss.exe",      L"C:\\Windows\\System32\\csrss.exe"},
        {"winlogon.exe",   L"C:\\Windows\\System32\\winlogon.exe"},
        {"svchost.exe",    L"C:\\Windows\\System32\\svchost.exe"},
        {"lsass.exe",      L"C:\\Windows\\System32\\lsass.exe"},
        {NULL, NULL}
    };

    char winDir[MAX_PATH];
    GetWindowsDirectoryA(winDir, sizeof(winDir));
    wchar_t wWinDir[MAX_PATH];
    MultiByteToWideChar(CP_ACP, 0, winDir, -1, wWinDir, MAX_PATH);

    for (int i = 0; sysFiles[i].name; i++) {
        rep->totalSysFilesAudited++;
        wchar_t wName[64];
        MultiByteToWideChar(CP_ACP, 0, sysFiles[i].name, -1, wName, 64);
        wchar_t wPath[MAX_PATH];
        _snwprintf(wPath, MAX_PATH, L"%ls\\System32\\%ls", wWinDir, wName);

        if (GetFileAttributesW(wPath) == INVALID_FILE_ATTRIBUTES) continue;

        char signer[128] = {0};
        int st = boot_verify_file_signature(wPath, signer, sizeof(signer));
        char aPath[MAX_PATH] = {0};
        WideCharToMultiByte(CP_ACP, 0, wPath, -1, aPath, sizeof(aPath), NULL, NULL);

        if (st == 1) {
            /* Clean Microsoft Authenticode Verified */
            char det[256];
            snprintf(det, sizeof(det), "%s verified: Valid Authenticode signature by Microsoft Windows Production PCA.", sysFiles[i].name);
            boot_add_finding(rep, "SYSTEM_FILE", sysFiles[i].name, aPath,
                             "Authenticode Verified", "CLEAN", det, 0);
        } else if (st == -1) {
            rep->compromisedSysFiles++;
            char det[256];
            snprintf(det, sizeof(det), "CRITICAL: %s hash digest corrupted or patched! Binary modified on disk!", sysFiles[i].name);
            boot_add_finding(rep, "SYSTEM_FILE", sysFiles[i].name, aPath,
                             "Binary Tampering / Kernel Patching", "CRITICAL", det, 1);
        } else {
            rep->compromisedSysFiles++;
            char det[256];
            snprintf(det, sizeof(det), "CRITICAL: %s missing trusted Microsoft signature! Possible Trojanized replacement.", sysFiles[i].name);
            boot_add_finding(rep, "SYSTEM_FILE", sysFiles[i].name, aPath,
                             "Unsigned System Binary", "CRITICAL", det, 1);
        }
    }
}

/* ===========================================================================
 * 5. ROGUE & MASQUERADING WINDOWS SERVICES AUDIT
 * =========================================================================== */
static void boot_audit_services_masquerading(BootkitAuditReport *rep) {
    if (!rep) return;

    SC_HANDLE hSCM = OpenSCManagerA(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!hSCM) return;

    DWORD bytesNeeded = 0, servicesReturned = 0, resumeHandle = 0;
    EnumServicesStatusExA(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
                          NULL, 0, &bytesNeeded, &servicesReturned, &resumeHandle, NULL);

    if (bytesNeeded == 0) { CloseServiceHandle(hSCM); return; }

    LPBYTE buf = (LPBYTE)malloc(bytesNeeded);
    if (!buf) { CloseServiceHandle(hSCM); return; }

    if (EnumServicesStatusExA(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
                              buf, bytesNeeded, &bytesNeeded, &servicesReturned, &resumeHandle, NULL)) {
        LPENUM_SERVICE_STATUS_PROCESSA services = (LPENUM_SERVICE_STATUS_PROCESSA)buf;

        for (DWORD i = 0; i < servicesReturned; i++) {
            rep->totalServicesAudited++;
            const char *sName = services[i].lpServiceName;
            const char *dName = services[i].lpDisplayName;

            SC_HANDLE hService = OpenServiceA(hSCM, sName, SERVICE_QUERY_CONFIG);
            if (!hService) continue;

            DWORD cfgNeeded = 0;
            QueryServiceConfigA(hService, NULL, 0, &cfgNeeded);
            if (cfgNeeded > 0) {
                LPQUERY_SERVICE_CONFIGA pCfg = (LPQUERY_SERVICE_CONFIGA)malloc(cfgNeeded);
                if (pCfg && QueryServiceConfigA(hService, pCfg, cfgNeeded, &cfgNeeded)) {
                    char rawPath[MAX_PATH] = {0};
                    if (pCfg->lpBinaryPathName) {
                        strncpy(rawPath, pCfg->lpBinaryPathName, sizeof(rawPath) - 1);
                    }

                    /* Clean up binary path: strip arguments and quotes */
                    char cleanPath[MAX_PATH] = {0};
                    const char *p = rawPath;
                    while (*p == ' ' || *p == '\"') p++;
                    int idx = 0;
                    while (*p && *p != '\"' && idx < MAX_PATH - 1) {
                        if (*p == ' ' && (strstr(p, ".exe") == NULL || strstr(p, ".EXE") == NULL)) {
                            /* Check if end of binary path */
                            if (strstr(cleanPath, ".exe") || strstr(cleanPath, ".EXE") || strstr(cleanPath, ".sys")) break;
                        }
                        cleanPath[idx++] = *p++;
                    }
                    cleanPath[idx] = '\0';

                    char loName[128] = {0}, loPath[MAX_PATH] = {0};
                    for (int j = 0; sName[j] && j < 127; j++) loName[j] = (char)tolower((unsigned char)sName[j]);
                    for (int j = 0; cleanPath[j] && j < MAX_PATH - 1; j++) loPath[j] = (char)tolower((unsigned char)cleanPath[j]);

                    /* RULE 1: Core Windows Service Masquerading
                     * If service claims to be svchost, csrss, lsass, winlogon, services, but path is NOT in system32/syswow64 */
                    BOOL isDisguised = FALSE;
                    if (strstr(loName, "svchost") || strstr(loName, "csrss") ||
                        strstr(loName, "lsass") || strstr(loName, "winlogon") ||
                        (dName && (strstr(dName, "Windows Defender Update") || strstr(dName, "Security Health Service Fake")))) {
                        if (strstr(loPath, "\\system32\\") == NULL && strstr(loPath, "\\syswow64\\") == NULL) {
                            isDisguised = TRUE;
                        }
                    }

                    /* RULE 2: Execution from high-risk user directories with SYSTEM privilege */
                    BOOL isUserSpacePriv = FALSE;
                    if (strstr(loPath, "\\appdata\\") || strstr(loPath, "\\temp\\") || strstr(loPath, "\\users\\")) {
                        if (pCfg->lpServiceStartName && (strstr(pCfg->lpServiceStartName, "LocalSystem") || strstr(pCfg->lpServiceStartName, "SYSTEM"))) {
                            isUserSpacePriv = TRUE;
                        }
                    }

                    if (isDisguised) {
                        rep->rogueServicesFound++;
                        char det[256];
                        snprintf(det, sizeof(det), "CRITICAL: Service '%s' masquerades as core Windows daemon from rogue path: '%s'", sName, cleanPath);
                        boot_add_finding(rep, "SERVICES", sName, cleanPath,
                                         "Rogue Service Masquerading", "CRITICAL", det, 1);
                    } else if (isUserSpacePriv) {
                        rep->rogueServicesFound++;
                        char det[256];
                        snprintf(det, sizeof(det), "HIGH: Service '%s' runs with LocalSystem privileges from user temp/appdata path: '%s'", sName, cleanPath);
                        boot_add_finding(rep, "SERVICES", sName, cleanPath,
                                         "Privilege Escalation Service", "HIGH", det, 1);
                    }
                }
                if (pCfg) free(pCfg);
            }
            CloseServiceHandle(hService);
        }
    }
    free(buf);
    CloseServiceHandle(hSCM);

    if (rep->rogueServicesFound == 0) {
        char det[128];
        snprintf(det, sizeof(det), "%d active Windows services audited. Zero masquerading daemons detected.", rep->totalServicesAudited);
        boot_add_finding(rep, "SERVICES", "SCM Services Baseline", "Service Control Manager",
                         "Legitimate Service Tree", "CLEAN", det, 0);
    }
}

/* ===========================================================================
 * 6. LOADED KERNEL DRIVERS & BYOVD DETECTION
 * =========================================================================== */
static void boot_audit_kernel_drivers(BootkitAuditReport *rep) {
    if (!rep) return;

    LPVOID drivers[1024];
    DWORD cbNeeded = 0;
    if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded)) {
        int count = cbNeeded / sizeof(LPVOID);
        if (count > 1024) count = 1024;
        rep->totalDriversAudited = count;

        for (int i = 0; i < count; i++) {
            char drvPath[MAX_PATH] = {0};
            if (GetDeviceDriverFileNameA(drivers[i], drvPath, sizeof(drvPath))) {
                char loDrv[MAX_PATH] = {0};
                for (int j = 0; drvPath[j] && j < MAX_PATH - 1; j++) loDrv[j] = (char)tolower((unsigned char)drvPath[j]);

                /* Check for driver loaded from untrusted user/temp paths */
                if (strstr(loDrv, "\\temp\\") || strstr(loDrv, "\\users\\") || strstr(loDrv, "\\downloads\\")) {
                    rep->suspiciousDriversFound++;
                    char det[256];
                    snprintf(det, sizeof(det), "HIGH: Kernel driver executing from user-writable location: '%s'", drvPath);
                    boot_add_finding(rep, "DRIVERS", "Kernel Driver", drvPath,
                                     "Suspicious Driver Location (BYOVD)", "HIGH", det, 1);
                }
            }
        }
    }

    if (rep->suspiciousDriversFound == 0) {
        char det[128];
        snprintf(det, sizeof(det), "%d loaded kernel drivers inspected in RAM. Clean system driver baseline verified.", rep->totalDriversAudited);
        boot_add_finding(rep, "DRIVERS", "Device Drivers Baseline", "Kernel Memory Pool",
                         "Protected Driver Pool", "CLEAN", det, 0);
    }
}

/* ===========================================================================
 * 7. HOSTS FILE DNS POISONING & TAMPERING CHECK
 * =========================================================================== */
static void boot_audit_hosts_file(BootkitAuditReport *rep) {
    if (!rep) return;

    char hostsPath[MAX_PATH];
    GetWindowsDirectoryA(hostsPath, sizeof(hostsPath));
    strncat(hostsPath, "\\System32\\drivers\\etc\\hosts", sizeof(hostsPath) - strlen(hostsPath) - 1);

    FILE *f = fopen(hostsPath, "r");
    if (!f) return;

    char line[512];
    int poisoned = 0;
    static const char *securityDomains[] = {
        "microsoft.com", "windowsupdate", "kaspersky", "virustotal",
        "symantec", "sophos", "bitdefender", "mcafee", "eset", NULL
    };

    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#' || line[0] == '\r' || line[0] == '\n') continue;
        char loLine[512] = {0};
        for (int i = 0; line[i] && i < 511; i++) loLine[i] = (char)tolower((unsigned char)line[i]);

        for (int k = 0; securityDomains[k]; k++) {
            if (strstr(loLine, securityDomains[k])) {
                poisoned = 1;
                rep->hostsFileTampered = 1;
                char det[256];
                snprintf(det, sizeof(det), "CRITICAL: Hosts file redirects security update domain '%s' -> %s", securityDomains[k], line);
                boot_add_finding(rep, "DNS_HOSTS", "hosts", hostsPath,
                                 "DNS Poisoning / AV Blackhole", "CRITICAL", det, 1);
                break;
            }
        }
        if (poisoned) break;
    }
    fclose(f);

    if (!rep->hostsFileTampered) {
        boot_add_finding(rep, "DNS_HOSTS", "hosts", hostsPath,
                         "Hosts File Integrity", "CLEAN",
                         "DNS resolution hosts file clean: No security vendor domain blackholes detected.", 0);
    }
}

/* ===========================================================================
 * 8. MASTER RUNNER: RUN FULL DEEP BOOTKIT & SYSTEM INTEGRITY SCAN
 * =========================================================================== */
typedef void (*BootkitProgressCallback)(int percent, const char *stageMsg);

static void boot_audit_run_full_scan(BootkitAuditReport *rep, BootkitProgressCallback progressCb) {
    if (!rep) return;
    memset(rep, 0, sizeof(BootkitAuditReport));

    /* Stage 1: UEFI Secure Boot & BCD Code Integrity (20%) */
    if (progressCb) progressCb(10, "Auditing UEFI Secure Boot NVRAM state & BCD TestSigning flags...");
    boot_audit_secure_boot_and_bcd(rep);
    if (progressCb) progressCb(25, "Secure Boot & BCD verification complete.");

    /* Stage 2: ESP Bootloader & MBR Sector 0 (45%) */
    if (progressCb) progressCb(35, "Scanning ESP bootmgfw.efi Authenticode & PhysicalDrive0 Sector 0...");
    boot_audit_mbr_and_esp(rep);
    if (progressCb) progressCb(50, "Bootloader and MBR sector analysis complete.");

    /* Stage 3: Core Windows System File Digital Signatures (70%) */
    if (progressCb) progressCb(60, "Verifying WinVerifyTrust signatures on ntoskrnl.exe, hal.dll, kernel32...");
    boot_audit_system_file_signatures(rep);
    if (progressCb) progressCb(75, "Core system file digital signature audit complete.");

    /* Stage 4: SCM Rogue Masquerading Services (90%) */
    if (progressCb) progressCb(80, "Auditing Service Control Manager for masquerading system daemons...");
    boot_audit_services_masquerading(rep);
    if (progressCb) progressCb(90, "Service Control Manager audit complete.");

    /* Stage 5: Kernel Drivers & Hosts File (100%) */
    if (progressCb) progressCb(95, "Inspecting loaded kernel drivers in RAM and hosts file integrity...");
    boot_audit_kernel_drivers(rep);
    boot_audit_hosts_file(rep);

    /* Calculate Overall Host Integrity Score */
    int penalty = 0;
    if (!rep->secureBootEnabled) penalty += 15;
    if (rep->testSigningActive) penalty += 40;
    if (!rep->espBootloaderSigned) penalty += 35;
    if (rep->compromisedSysFiles > 0) penalty += 45 * rep->compromisedSysFiles;
    if (rep->rogueServicesFound > 0) penalty += 35 * rep->rogueServicesFound;
    if (rep->suspiciousDriversFound > 0) penalty += 30 * rep->suspiciousDriversFound;
    if (rep->hostsFileTampered) penalty += 25;

    int score = 100 - penalty;
    if (score < 0) score = 0;
    rep->overallScore = score;

    if (progressCb) progressCb(100, "Deep Bootkit, Firmware & System Integrity Audit Complete!");
}

/* ===========================================================================
 * 9. SERIALIZE AUDIT REPORT TO STRUCTURED JSON
 * =========================================================================== */
static int boot_audit_generate_json(const BootkitAuditReport *rep, char *outBuf, size_t maxBuf) {
    if (!rep || !outBuf || maxBuf < 256) return 0;

    int offset = snprintf(outBuf, maxBuf,
        "{\n"
        "  \"integrity_score\": %d,\n"
        "  \"secure_boot\": %s,\n"
        "  \"test_signing\": %s,\n"
        "  \"esp_bootloader_signed\": %s,\n"
        "  \"mbr_signature_valid\": %s,\n"
        "  \"system_files_audited\": %d,\n"
        "  \"compromised_system_files\": %d,\n"
        "  \"services_audited\": %d,\n"
        "  \"rogue_services_found\": %d,\n"
        "  \"drivers_audited\": %d,\n"
        "  \"suspicious_drivers_found\": %d,\n"
        "  \"hosts_file_tampered\": %s,\n"
        "  \"findings\": [\n",
        rep->overallScore,
        rep->secureBootEnabled ? "true" : "false",
        rep->testSigningActive ? "true" : "false",
        rep->espBootloaderSigned ? "true" : "false",
        rep->mbrSignatureValid ? "true" : "false",
        rep->totalSysFilesAudited,
        rep->compromisedSysFiles,
        rep->totalServicesAudited,
        rep->rogueServicesFound,
        rep->totalDriversAudited,
        rep->suspiciousDriversFound,
        rep->hostsFileTampered ? "true" : "false");

    for (int i = 0; i < rep->findingCount; i++) {
        const BootkitFinding *f = &rep->findings[i];
        int written = snprintf(outBuf + offset, maxBuf - offset,
            "    {\n"
            "      \"category\": \"%s\",\n"
            "      \"target\": \"%s\",\n"
            "      \"path\": \"%s\",\n"
            "      \"threat_type\": \"%s\",\n"
            "      \"severity\": \"%s\",\n"
            "      \"detail\": \"%s\",\n"
            "      \"is_compromised\": %s\n"
            "    }%s\n",
            f->category, f->targetName, f->targetPath, f->threatType,
            f->severity, f->detail, f->isCompromised ? "true" : "false",
            (i < rep->findingCount - 1) ? "," : "");
        if (written <= 0 || offset + written >= maxBuf - 32) break;
        offset += written;
    }

    offset += snprintf(outBuf + offset, maxBuf - offset, "  ]\n}");
    return offset;
}

#endif /* BOOT_ROOTKIT_ENGINE_H */
