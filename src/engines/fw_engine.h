/*===========================================================================
 * Kaevex Firewall Engine ??? fw_engine.h
 * Windows Firewall integration via netsh + INetFwPolicy2 COM
 *===========================================================================*/
#pragma once
#ifndef FW_ENGINE_H
#define FW_ENGINE_H

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include <shlwapi.h>
#define FW_MAX_RULES 4096

typedef struct {
    char name[128];
    char program[MAX_PATH];
    char direction[16];   /* "In" / "Out" / "Both" */
    char action[16];      /* "Allow" / "Block" */
    char protocol[16];    /* "TCP" / "UDP" / "Any" */
    char localPort[32];
    char remotePort[32];
    char remoteIP[64];
    char enabled[8];      /* "Yes" / "No" */
    char profile[32];     /* "Domain,Private,Public" */
    unsigned long hits;
} FwRule;

static FwRule   g_fwRules[FW_MAX_RULES];
static int      g_fwRuleCount = 0;

/* --- Run a command and capture its stdout --------------------------------- */
static int fw_run_capture(const char *cmd, char *out, int outLen) {
    HANDLE hRead = NULL, hWrite = NULL;
    SECURITY_ATTRIBUTES sa = {sizeof(sa), NULL, TRUE};
    if(!CreatePipe(&hRead, &hWrite, &sa, 0)) return 0;
    SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si; ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.hStdOutput = hWrite;
    si.hStdError  = hWrite;
    si.dwFlags    = STARTF_USESTDHANDLES;

    PROCESS_INFORMATION pi; ZeroMemory(&pi, sizeof(pi));
    char cmdBuf[1024];
    snprintf(cmdBuf, sizeof(cmdBuf), "cmd.exe /c %s", cmd);

    if(!CreateProcessA(NULL, cmdBuf, NULL, NULL, TRUE,
                       CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        CloseHandle(hRead); CloseHandle(hWrite); return 0;
    }
    CloseHandle(hWrite);

    DWORD rd = 0, total = 0;
    while(total < (DWORD)outLen - 1 &&
          ReadFile(hRead, out + total, outLen - total - 1, &rd, NULL) && rd)
        total += rd;
    out[total] = '\0';
    CloseHandle(hRead);
    WaitForSingleObject(pi.hProcess, 15000);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    return (int)total;
}

/* --- Run a netsh command with UAC elevation ------------------------------- */
static BOOL fw_run_elevated(const char *netshArgs) {
    SHELLEXECUTEINFOA sei; ZeroMemory(&sei, sizeof(sei));
    sei.cbSize      = sizeof(sei);
    sei.lpVerb      = "runas";
    sei.lpFile      = "netsh";
    sei.lpParameters= netshArgs;
    sei.fMask       = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NO_CONSOLE;
    sei.nShow       = SW_HIDE;
    if(!ShellExecuteExA(&sei) || !sei.hProcess) return FALSE;
    DWORD wait = WaitForSingleObject(sei.hProcess, 15000);
    DWORD code = 1;
    if(wait == WAIT_OBJECT_0) GetExitCodeProcess(sei.hProcess, &code);
    else TerminateProcess(sei.hProcess, 1);
    CloseHandle(sei.hProcess);
    return wait == WAIT_OBJECT_0 && code == 0;
}

static BOOL fw_safe_rule_text(const char *s, BOOL allowSpace) {
    if(!s || !*s) return FALSE;
    for(const unsigned char *p=(const unsigned char*)s; *p; ++p) {
        if(isalnum(*p) || *p=='_' || *p=='-' || *p=='.' || *p=='\\' || *p==':' ||
           (allowSpace && *p==' ')) continue;
        return FALSE;
    }
    return TRUE;
}

/* --- Fallback: Read real firewall rules from Windows Registry --- */
static int fw_load_from_registry(void) {
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\FirewallRules",
        0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        return 0;
    }

    DWORD dwValues = 0, dwMaxValueNameLen = 0, dwMaxValueLen = 0;
    if (RegQueryInfoKeyA(hKey, NULL, NULL, NULL, NULL, NULL, NULL, &dwValues,
                         &dwMaxValueNameLen, &dwMaxValueLen, NULL, NULL) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return 0;
    }

    char *valName = (char*)malloc(dwMaxValueNameLen + 4);
    char *valData = (char*)malloc(dwMaxValueLen + 4);
    if (!valName || !valData) {
        if (valName) free(valName);
        if (valData) free(valData);
        RegCloseKey(hKey);
        return 0;
    }

    for (DWORD i = 0; i < dwValues && g_fwRuleCount < FW_MAX_RULES; i++) {
        DWORD nameLen = dwMaxValueNameLen + 2;
        DWORD dataLen = dwMaxValueLen + 2;
        DWORD type = 0;
        if (RegEnumValueA(hKey, i, valName, &nameLen, NULL, &type, (LPBYTE)valData, &dataLen) == ERROR_SUCCESS) {
            if (type == REG_SZ && dataLen > 0) {
                valData[dataLen] = '\0';
                FwRule *cur = &g_fwRules[g_fwRuleCount++];
                ZeroMemory(cur, sizeof(*cur));
                strcpy(cur->remoteIP, "*");
                strcpy(cur->remotePort, "*");
                strcpy(cur->localPort, "*");
                strcpy(cur->profile, "All");
                strcpy(cur->enabled, "Yes");
                strcpy(cur->action, "Allow");
                strcpy(cur->direction, "Inbound");
                strcpy(cur->protocol, "TCP");

                /* Parse registry rule string format */
                char *token = strtok(valData, "|");
                while (token) {
                    if (strncmp(token, "Action=", 7) == 0) {
                        strncpy(cur->action, token + 7, sizeof(cur->action) - 1);
                    } else if (strncmp(token, "Active=", 7) == 0) {
                        strcpy(cur->enabled, (_stricmp(token + 7, "TRUE") == 0) ? "Yes" : "No");
                    } else if (strncmp(token, "Dir=", 4) == 0) {
                        strcpy(cur->direction, (_stricmp(token + 4, "In") == 0) ? "Inbound" : "Outbound");
                    } else if (strncmp(token, "Protocol=", 9) == 0) {
                        int protoNum = atoi(token + 9);
                        if (protoNum == 6) strcpy(cur->protocol, "TCP");
                        else if (protoNum == 17) strcpy(cur->protocol, "UDP");
                        else if (protoNum == 256) strcpy(cur->protocol, "Any");
                        else snprintf(cur->protocol, sizeof(cur->protocol), "%d", protoNum);
                    } else if (strncmp(token, "LPort=", 6) == 0) {
                        strncpy(cur->localPort, token + 6, sizeof(cur->localPort) - 1);
                    } else if (strncmp(token, "RPort=", 6) == 0) {
                        strncpy(cur->remotePort, token + 6, sizeof(cur->remotePort) - 1);
                    } else if (strncmp(token, "RA4=", 4) == 0 || strncmp(token, "RA6=", 4) == 0) {
                        strncpy(cur->remoteIP, token + 4, sizeof(cur->remoteIP) - 1);
                    } else if (strncmp(token, "Name=", 5) == 0) {
                        strncpy(cur->name, token + 5, sizeof(cur->name) - 1);
                    } else if (strncmp(token, "App=", 4) == 0) {
                        strncpy(cur->program, token + 4, sizeof(cur->program) - 1);
                    } else if (strncmp(token, "Profile=", 8) == 0) {
                        strncpy(cur->profile, token + 8, sizeof(cur->profile) - 1);
                    }
                    token = strtok(NULL, "|");
                }
                if (!cur->name[0]) {
                    strncpy(cur->name, valName, sizeof(cur->name) - 1);
                }
            }
        }
    }

    free(valName);
    free(valData);
    RegCloseKey(hKey);
    return g_fwRuleCount;
}

/* --- Correlate real live socket activity and network interface throughput --- */
static void fw_correlate_traffic(void) {
    DWORD totalInPkts = 0, totalOutPkts = 0;
    DWORD ifSz = 0;
    GetIfTable(NULL, &ifSz, FALSE);
    if (ifSz > 0) {
        MIB_IFTABLE *ifTable = (MIB_IFTABLE*)malloc(ifSz);
        if (ifTable && GetIfTable(ifTable, &ifSz, FALSE) == NO_ERROR) {
            for (DWORD i = 0; i < ifTable->dwNumEntries; i++) {
                if (ifTable->table[i].dwType == IF_TYPE_ETHERNET_CSMACD ||
                    ifTable->table[i].dwType == IF_TYPE_IEEE80211) {
                    totalInPkts += ifTable->table[i].dwInUcastPkts;
                    totalOutPkts += ifTable->table[i].dwOutUcastPkts;
                }
            }
            free(ifTable);
        }
    }

    DWORD tcpSz = 0;
    GetExtendedTcpTable(NULL, &tcpSz, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    MIB_TCPTABLE_OWNER_PID *tcpTable = NULL;
    if (tcpSz > 0) {
        tcpTable = (MIB_TCPTABLE_OWNER_PID*)malloc(tcpSz);
        if (tcpTable && GetExtendedTcpTable(tcpTable, &tcpSz, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR) {
            free(tcpTable);
            tcpTable = NULL;
        }
    }

    DWORD udpSz = 0;
    GetExtendedUdpTable(NULL, &udpSz, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    MIB_UDPTABLE_OWNER_PID *udpTable = NULL;
    if (udpSz > 0) {
        udpTable = (MIB_UDPTABLE_OWNER_PID*)malloc(udpSz);
        if (udpTable && GetExtendedUdpTable(udpTable, &udpSz, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) != NO_ERROR) {
            free(udpTable);
            udpTable = NULL;
        }
    }

    for (int i = 0; i < g_fwRuleCount; i++) {
        FwRule *r = &g_fwRules[i];
        r->hits = 0;

        int portNum = atoi(r->localPort);
        int activeSockets = 0;

        if (tcpTable && portNum > 0) {
            for (DWORD t = 0; t < tcpTable->dwNumEntries; t++) {
                if (ntohs((USHORT)tcpTable->table[t].dwLocalPort) == portNum) {
                    activeSockets++;
                }
            }
        }
        if (udpTable && portNum > 0) {
            for (DWORD u = 0; u < udpTable->dwNumEntries; u++) {
                if (ntohs((USHORT)udpTable->table[u].dwLocalPort) == portNum) {
                    activeSockets++;
                }
            }
        }

        /* "hits" = live sockets currently using this rule's local port. A real number; the old code
           invented packet counts by dividing interface totals by arbitrary constants. */
        r->hits = (unsigned long)activeSockets;
    }

    if (tcpTable) free(tcpTable);
    if (udpTable) free(udpTable);
}

/* --- Load all firewall rules ---------------------------------------------- */
/* Fast and language independent: rules are read from the firewall policy in the registry (no netsh, no cmd.exe).
 * The old code ran "netsh ... show rule name=all" on the UI thread: 10-60 s on PCs with thousands of rules, and its
 * English text parser found nothing on non-English Windows. */
static int fw_load_rules(void) {
    g_fwRuleCount = 0;
    fw_load_from_registry();
    fw_correlate_traffic();
    return g_fwRuleCount;
}

/* Names such as "@FirewallAPI.dll,-80201" are resource references; resolve them to readable text (call from a worker thread). */
static void fw_resolve_names(void) {
    for (int i = 0; i < g_fwRuleCount; i++) {
        if (g_fwRules[i].name[0] != '@') continue;
        wchar_t in[256], out[256];
        if (!MultiByteToWideChar(CP_ACP, 0, g_fwRules[i].name, -1, in, 256)) continue;
        if (SUCCEEDED(SHLoadIndirectString(in, out, 256, NULL)) && out[0])
            WideCharToMultiByte(CP_ACP, 0, out, -1, g_fwRules[i].name, (int)sizeof(g_fwRules[i].name), "?", NULL);
    }
}

/* ?????? Add a firewall rule ????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????? */
static BOOL fw_add_rule(const char *name, const char *program,
                        const char *dir, const char *action,
                        const char *protocol, const char *port) {
    if(!fw_safe_rule_text(name, TRUE) ||
       (program && *program && (!fw_safe_rule_text(program, TRUE) || !strchr(program, ':'))) ||
       (!dir || (_stricmp(dir,"in") && _stricmp(dir,"out"))) ||
       (!action || (_stricmp(action,"allow") && _stricmp(action,"block"))) ||
       (protocol && *protocol && _stricmp(protocol,"tcp") && _stricmp(protocol,"udp") && _stricmp(protocol,"any")) ||
       (port && *port && !fw_safe_rule_text(port, FALSE))) return FALSE;
    char args[1024];
    if(program && strlen(program) > 0) {
        snprintf(args, sizeof(args),
            "advfirewall firewall add rule name=\"%s\" "
            "program=\"%s\" dir=%s action=%s enable=yes "
            "protocol=%s profile=any",
            name, program, dir, action,
            (protocol && *protocol) ? protocol : "any");
    } else {
        snprintf(args, sizeof(args),
            "advfirewall firewall add rule name=\"%s\" "
            "dir=%s action=%s enable=yes protocol=%s "
            "localport=%s profile=any",
            name, dir, action,
            (protocol && *protocol) ? protocol : "tcp",
            (port && *port) ? port : "any");
    }
    return fw_run_elevated(args);
}

static BOOL fw_add_remote_port_block(const char *name, const char *protocol, const char *port) {
    if(!fw_safe_rule_text(name, TRUE) || !protocol ||
       (_stricmp(protocol,"tcp") && _stricmp(protocol,"udp")) ||
       !fw_safe_rule_text(port, FALSE)) return FALSE;
    for(const char *p=port; *p; ++p)
        if(!isdigit((unsigned char)*p) && *p!='-' && *p!=',') return FALSE;
    char args[512];
    if(snprintf(args,sizeof(args),
        "advfirewall firewall add rule name=\"%s\" dir=out action=block enable=yes protocol=%s remoteport=%s profile=any",
        name,protocol,port) >= (int)sizeof(args)) return FALSE;
    return fw_run_elevated(args);
}

/* Emergency containment: deny all network traffic for one verified executable. */
static void fw_delete_rule(const char *name);
static BOOL fw_block_program(const char *program) {
    if(!program || !fw_safe_rule_text(program, TRUE) || !strchr(program, ':')) return FALSE;
    DWORD attrs=GetFileAttributesA(program);
    if(attrs==INVALID_FILE_ATTRIBUTES || (attrs&FILE_ATTRIBUTE_DIRECTORY)) return FALSE;
    char inName[64], outName[64];
    unsigned long hash=2166136261u;
    for(const unsigned char *p=(const unsigned char*)program; *p; ++p) hash=(hash^*p)*16777619u;
    snprintf(inName,sizeof(inName),"Kaevex-CVE-%08lX-In",hash);
    snprintf(outName,sizeof(outName),"Kaevex-CVE-%08lX-Out",hash);
    BOOL inOk=fw_add_rule(inName,program,"in","block","any",NULL);
    BOOL outOk=fw_add_rule(outName,program,"out","block","any",NULL);
    if(inOk != outOk) fw_delete_rule(inOk?inName:outName);
    return inOk && outOk;
}

/* ?????? Block a process completely (in + out) ??????????????????????????????????????????????????????????????????????????????????????????????????? */
static void fw_block_process(const char *exePath) {
    const char *bn = strrchr(exePath, '\\');
    bn = bn ? bn + 1 : exePath;
    char ruleName[192];
    snprintf(ruleName, sizeof(ruleName), "Kaevex-Block-%s", bn);

    char args[1024];
    /* Block outbound */
    snprintf(args, sizeof(args),
        "advfirewall firewall add rule name=\"%s-Out\" "
        "program=\"%s\" dir=out action=block enable=yes profile=any",
        ruleName, exePath);
    fw_run_elevated(args);
    /* Block inbound */
    snprintf(args, sizeof(args),
        "advfirewall firewall add rule name=\"%s-In\" "
        "program=\"%s\" dir=in action=block enable=yes profile=any",
        ruleName, exePath);
    fw_run_elevated(args);
}

/* ?????? Delete a rule by name ??????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????? */
static void fw_delete_rule(const char *name) {
    char args[512];
    snprintf(args, sizeof(args),
             "advfirewall firewall delete rule name=\"%s\"", name);
    fw_run_elevated(args);
}

/* ?????? Emergency lockdown ??? blocks ALL inbound+outbound ??????????????????????????????????????????????????????????????? */
static void fw_emergency_lockdown(BOOL enable) {
    if(enable) {
        fw_run_elevated("advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound");
        fw_run_elevated("advfirewall set allprofiles state on");
    } else {
        fw_run_elevated("advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound");
    }
}

/* ?????? Enable/disable Windows Firewall ????????????????????????????????????????????????????????????????????????????????????????????????????????????????????? */
static void fw_set_enabled(BOOL enable) {
    fw_run_elevated(enable
        ? "advfirewall set allprofiles state on"
        : "advfirewall set allprofiles state off");
}

/* ?????? Get current firewall state ???????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????? */
/* Registry based (netsh prints translated text, e.g. on Arabic Windows "ON" never matches). TRUE if any profile is on. */
static BOOL fw_is_enabled_raw(void) {
    static const char *prof[3] = { "DomainProfile", "StandardProfile", "PublicProfile" };
    for (int i = 0; i < 3; i++) {
        char k[256]; snprintf(k, sizeof k, "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\%s", prof[i]);
        HKEY h; DWORD v = 0, sz = sizeof v;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, k, 0, KEY_READ, &h) == ERROR_SUCCESS) {
            LONG rc = RegQueryValueExA(h, "EnableFirewall", NULL, NULL, (BYTE *)&v, &sz);
            RegCloseKey(h);
            if (rc == ERROR_SUCCESS && v) return TRUE;
        }
    }
    return FALSE;
}
/* cached for 2 s: it is called from paint code */
static BOOL fw_is_enabled(void) {
    static DWORD t = 0; static BOOL v = FALSE;
    DWORD now = GetTickCount(); if (!t || now - t > 2000) { v = fw_is_enabled_raw(); t = now; }
    return v;
}

/* ?????? Add Kaevex default protection rules ???????????????????????????????????????????????????????????????????????????????????????????????? */
static void fw_apply_aegis_defaults(void) {
    /* Block common attack ports inbound */
    fw_add_rule("Kaevex-Block-Telnet",    NULL, "in", "block", "tcp", "23");
    fw_add_rule("Kaevex-Block-RDP-Ext",   NULL, "in", "block", "tcp", "3389");
    fw_add_rule("Kaevex-Block-SMB",       NULL, "in", "block", "tcp", "445");
    fw_add_rule("Kaevex-Block-NetBIOS",   NULL, "in", "block", "tcp", "137-139");
    fw_add_rule("Kaevex-Block-WinRM",     NULL, "in", "block", "tcp", "5985");
    fw_add_rule("Kaevex-Block-VNC",       NULL, "in", "block", "tcp", "5900");
}

/* ?????? Remove all Kaevex rules ???????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????? */
static void fw_remove_aegis_rules(void) {
    fw_run_elevated("advfirewall firewall delete rule name=\"Kaevex-Block-Telnet\"");
    fw_run_elevated("advfirewall firewall delete rule name=\"Kaevex-Block-RDP-Ext\"");
    fw_run_elevated("advfirewall firewall delete rule name=\"Kaevex-Block-SMB\"");
    fw_run_elevated("advfirewall firewall delete rule name=\"Kaevex-Block-NetBIOS\"");
    fw_run_elevated("advfirewall firewall delete rule name=\"Kaevex-Block-WinRM\"");
    fw_run_elevated("advfirewall firewall delete rule name=\"Kaevex-Block-VNC\"");
}

#endif /* FW_ENGINE_H */
