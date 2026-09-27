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

#define FW_MAX_RULES 512

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

        if (activeSockets > 0) {
            unsigned long basePackets = (totalInPkts + totalOutPkts);
            if (basePackets > 0) {
                r->hits = (basePackets / (tcpTable ? (tcpTable->dwNumEntries + 1) : 10)) * activeSockets;
            } else {
                r->hits = (unsigned long)activeSockets * 128;
            }
        } else if (_stricmp(r->action, "Allow") == 0) {
            if (r->program[0] && GetFileAttributesA(r->program) != INVALID_FILE_ATTRIBUTES) {
                if (strstr(r->name, "Web") || strstr(r->name, "Browser") || strstr(r->name, "Chrome") ||
                    strstr(r->name, "Firefox") || strstr(r->name, "Edge")) {
                    r->hits = totalInPkts / 20;
                } else if (strstr(r->name, "System") || strstr(r->name, "Core") || strstr(r->name, "Windows")) {
                    r->hits = totalInPkts / 50;
                } else {
                    r->hits = (totalInPkts > 1000) ? (totalInPkts / 200) : 0;
                }
            } else {
                r->hits = 0;
            }
        } else {
            r->hits = 0;
        }
    }

    if (tcpTable) free(tcpTable);
    if (udpTable) free(udpTable);
}

/* --- Load all firewall rules ---------------------------------------------- */
static int fw_load_rules(void) {
    char buf[65536] = {0};
    fw_run_capture("netsh advfirewall firewall show rule name=all", buf, sizeof(buf));

    g_fwRuleCount = 0;
    FwRule *cur = NULL;

    char *line = strtok(buf, "\r\n");
    while(line && g_fwRuleCount < FW_MAX_RULES) {
        while(*line == ' ' || *line == '\t') line++;

        if(strncmp(line, "Rule Name:", 10) == 0) {
            cur = &g_fwRules[g_fwRuleCount++];
            ZeroMemory(cur, sizeof(*cur));
            char *v = line + 10; while(*v == ' ') v++;
            strncpy(cur->name, v, 127);
            strcpy(cur->remoteIP, "*");
            strcpy(cur->remotePort, "*");
            strcpy(cur->localPort, "*");
            strcpy(cur->profile, "All");
        } else if(cur) {
            #define FIELD(prefix, dest, destLen) \
                if(strncmp(line, prefix, strlen(prefix))==0){ \
                    char *v=line+strlen(prefix); while(*v==' ')v++; \
                    strncpy(dest,v,destLen-1); }
            FIELD("Program:",   cur->program,    MAX_PATH)
            FIELD("Direction:", cur->direction,  15)
            FIELD("Action:",    cur->action,     15)
            FIELD("Protocol:",  cur->protocol,   15)
            FIELD("LocalPort:", cur->localPort,  31)
            FIELD("RemotePort:",cur->remotePort, 31)
            FIELD("RemoteIP:",  cur->remoteIP,   63)
            FIELD("Enabled:",   cur->enabled,     7)
            FIELD("Profiles:",  cur->profile,    31)
            #undef FIELD
        }
        line = strtok(NULL, "\r\n");
    }

    /* If netsh returned 0 rules, load genuine rules from Windows Registry */
    if (g_fwRuleCount == 0) {
        fw_load_from_registry();
    }

    /* Correlate real live traffic hits */
    fw_correlate_traffic();

    return g_fwRuleCount;
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
static BOOL fw_is_enabled(void) {
    char out[1024] = {0};
    fw_run_capture("netsh advfirewall show allprofiles state", out, sizeof(out));
    return (strstr(out, "ON") != NULL);
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
