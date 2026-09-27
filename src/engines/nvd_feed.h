#ifndef KAEVEX_NVD_FEED_H
#define KAEVEX_NVD_FEED_H

#include <windows.h>
#include <winhttp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NVD_RECENT_LIMIT 512
#define NVD_BODY_LIMIT (32u * 1024u * 1024u)
#define NVD_PAGE_SIZE 2000
#define NVD_MAX_PAGES 10

typedef struct {
    char id[24];
    char published[32];
    char severity[16];
    int score10;
    char summary[256];
} NvdRecentEntry;

static NvdRecentEntry g_nvdRecent[NVD_RECENT_LIMIT];
static int g_nvdRecentCount = 0;
static int g_nvdTotalResults = 0;
static int g_nvdParsedCount = 0;
static int g_nvdLoadedResults = 0;
static BOOL g_nvdPartial = FALSE;
static BOOL g_nvdRefreshOk = FALSE;
static char g_nvdRefreshMessage[256] = "Not refreshed";
static char g_nvdRefreshUtc[32] = "";

static char *nvd_json_key(char *obj, char *end, const char *key) {
    char needle[64];
    if (snprintf(needle, sizeof(needle), "\"%s\"", key) >= (int)sizeof(needle)) return NULL;
    char *p = obj;
    while ((p = strstr(p, needle)) != NULL && p < end) {
        char *q = p + strlen(needle);
        while (q < end && (*q == ' ' || *q == '\t' || *q == '\r' || *q == '\n')) ++q;
        if (q < end && *q == ':') return q + 1;
        p += strlen(needle);
    }
    return NULL;
}

static BOOL nvd_json_string(char *obj, char *end, const char *key, char *out, size_t cap) {
    if (!out || cap < 2) return FALSE;
    out[0] = '\0';
    char *p = nvd_json_key(obj, end, key);
    if (!p) return FALSE;
    while (p < end && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')) ++p;
    if (p >= end || *p++ != '"') return FALSE;
    size_t n = 0;
    while (p < end && *p != '"' && n + 1 < cap) {
        if (*p == '\\' && p + 1 < end) {
            ++p;
            if (*p == 'n' || *p == 'r' || *p == 't') out[n++] = ' ';
            else if (*p == 'u') {
                if (p + 4 < end) p += 4;
                out[n++] = ' ';
            } else out[n++] = *p;
            ++p;
        } else out[n++] = *p++;
    }
    out[n] = '\0';
    return n > 0;
}

static BOOL nvd_json_number(char *obj, char *end, const char *key, double *value) {
    char *p = nvd_json_key(obj, end, key);
    if (!p) return FALSE;
    while (p < end && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')) ++p;
    if (p >= end || ((*p < '0' || *p > '9') && *p != '.')) return FALSE;
    *value = strtod(p, NULL);
    return TRUE;
}

static BOOL nvd_object_end(char *start, char **endOut) {
    int depth = 0, inString = 0, escaped = 0;
    for (char *p = start; *p; ++p) {
        if (inString) {
            if (escaped) escaped = 0;
            else if (*p == '\\') escaped = 1;
            else if (*p == '"') inString = 0;
            continue;
        }
        if (*p == '"') inString = 1;
        else if (*p == '{') ++depth;
        else if (*p == '}' && --depth == 0) { *endOut = p + 1; return TRUE; }
    }
    return FALSE;
}

static void nvd_store_object(char *obj, char *end) {
    NvdRecentEntry entry; ZeroMemory(&entry, sizeof(entry));
    if (!nvd_json_string(obj, end, "id", entry.id, sizeof(entry.id)) ||
        strncmp(entry.id, "CVE-", 4) != 0 ||
        !nvd_json_string(obj, end, "published", entry.published, sizeof(entry.published))) return;

    char *descList = nvd_json_key(obj, end, "descriptions");
    if (!descList) return;
    char *lang = strstr(descList, "\"lang\"");
    if (!lang || lang >= end) return;
    char *langEnd = strchr(lang, '}');
    if (!langEnd || langEnd >= end) return;
    char langValue[8];
    if (!nvd_json_string(lang, langEnd + 1, "lang", langValue, sizeof(langValue)) || strcmp(langValue, "en") != 0 ||
        !nvd_json_string(lang, langEnd + 1, "value", entry.summary, sizeof(entry.summary))) return;
    ++g_nvdParsedCount;

    double score = 0.0;
    if (nvd_json_number(obj, end, "baseScore", &score))
        entry.score10 = (int)(score * 10.0 + 0.5);
    nvd_json_string(obj, end, "baseSeverity", entry.severity, sizeof(entry.severity));

    if (g_nvdRecentCount < NVD_RECENT_LIMIT) {
        g_nvdRecent[g_nvdRecentCount++] = entry;
        return;
    }
    int oldest = 0;
    for (int i = 1; i < g_nvdRecentCount; ++i)
        if (strcmp(g_nvdRecent[i].published, g_nvdRecent[oldest].published) < 0) oldest = i;
    if (strcmp(entry.published, g_nvdRecent[oldest].published) > 0) g_nvdRecent[oldest] = entry;
    g_nvdPartial = TRUE;
}

static int __cdecl nvd_recent_compare(const void *a, const void *b) {
    const NvdRecentEntry *x = (const NvdRecentEntry*)a;
    const NvdRecentEntry *y = (const NvdRecentEntry*)b;
    return strcmp(y->published, x->published);
}

static BOOL nvd_parse_body(char *body, BOOL firstPage) {
    if(firstPage) { g_nvdRecentCount = 0; g_nvdTotalResults = 0; g_nvdParsedCount = 0; g_nvdLoadedResults = 0; g_nvdPartial = FALSE; }
    double total = 0;
    if (nvd_json_number(body, body + strlen(body), "totalResults", &total))
        g_nvdTotalResults = (int)total;
    g_nvdPartial = g_nvdTotalResults > NVD_RECENT_LIMIT;
    char *p = body;
    while ((p = strstr(p, "\"cve\"")) != NULL) {
        char *brace = strchr(p, '{');
        if (!brace) break;
        char *end = NULL;
        if (!nvd_object_end(brace, &end)) break;
        nvd_store_object(brace, end);
        p = end;
    }
    if (g_nvdRecentCount > 1)
        qsort(g_nvdRecent, g_nvdRecentCount, sizeof(g_nvdRecent[0]), nvd_recent_compare);
    return g_nvdRecentCount > 0 || g_nvdTotalResults == 0;
}

static BOOL nvd_fetch_page(HINTERNET conn, const wchar_t *path, const wchar_t *apiHeader, char **bodyOut, size_t *sizeOut, DWORD *httpStatus) {
    *bodyOut=NULL; *sizeOut=0; *httpStatus=0;
    HINTERNET req=WinHttpOpenRequest(conn,L"GET",path,NULL,WINHTTP_NO_REFERER,WINHTTP_DEFAULT_ACCEPT_TYPES,WINHTTP_FLAG_SECURE);
    if(!req) return FALSE;
    if(apiHeader && apiHeader[0]) WinHttpAddRequestHeaders(req,apiHeader,(DWORD)-1,WINHTTP_ADDREQ_FLAG_ADD|WINHTTP_ADDREQ_FLAG_REPLACE);
    BOOL sent=WinHttpSendRequest(req,WINHTTP_NO_ADDITIONAL_HEADERS,0,WINHTTP_NO_REQUEST_DATA,0,0,0) && WinHttpReceiveResponse(req,NULL);
    DWORD statusSize=sizeof(*httpStatus);
    if(!sent || !WinHttpQueryHeaders(req,WINHTTP_QUERY_STATUS_CODE|WINHTTP_QUERY_FLAG_NUMBER,WINHTTP_HEADER_NAME_BY_INDEX,httpStatus,&statusSize,WINHTTP_NO_HEADER_INDEX) || *httpStatus!=200) {
        WinHttpCloseHandle(req); return FALSE;
    }
    size_t used=0,cap=1024*1024; char *body=(char*)malloc(cap+1);
    if(!body){WinHttpCloseHandle(req);return FALSE;}
    BOOL readOk=TRUE;
    for(;;){
        DWORD available=0;
        if(!WinHttpQueryDataAvailable(req,&available)){readOk=FALSE;break;}
        if(available==0) break;
        if(used+available>NVD_BODY_LIMIT){readOk=FALSE;break;}
        if(used+available>cap){size_t next=cap;while(next<used+available && next<NVD_BODY_LIMIT)next*=2;if(next>NVD_BODY_LIMIT)next=NVD_BODY_LIMIT;char *grown=(char*)realloc(body,next+1);if(!grown){readOk=FALSE;break;}body=grown;cap=next;}
        DWORD got=0;if(!WinHttpReadData(req,body+used,available,&got)||got==0){readOk=FALSE;break;}used+=got;
    }
    WinHttpCloseHandle(req);
    if(!readOk||used==0){free(body);return FALSE;}
    body[used]='\0'; *bodyOut=body; *sizeOut=used; return TRUE;
}

static BOOL nvd_refresh_recent(void) {
    g_nvdRefreshOk = FALSE;
    SYSTEMTIME nowUtc, startUtc;
    FILETIME nowFt, startFt;
    GetSystemTime(&nowUtc);
    if (!SystemTimeToFileTime(&nowUtc, &nowFt)) goto failed;
    ULARGE_INTEGER ticks; ticks.LowPart = nowFt.dwLowDateTime; ticks.HighPart = nowFt.dwHighDateTime;
    ticks.QuadPart -= 7ULL * 24ULL * 60ULL * 60ULL * 10000000ULL;
    startFt.dwLowDateTime = ticks.LowPart; startFt.dwHighDateTime = ticks.HighPart;
    if (!FileTimeToSystemTime(&startFt, &startUtc)) goto failed;

    wchar_t path[448];
    HINTERNET session = WinHttpOpen(L"Kaevex-NVD/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                    WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) goto failed;
    WinHttpSetTimeouts(session, 8000, 8000, 15000, 30000);
    HINTERNET conn = WinHttpConnect(session, L"services.nvd.nist.gov", INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!conn) { WinHttpCloseHandle(session); goto failed; }
    char apiKey[256] = {0};
    DWORD keyLen = GetEnvironmentVariableA("NVD_API_KEY",apiKey,sizeof(apiKey));
    wchar_t apiHeader[320]={0};
    if (keyLen > 0 && keyLen < sizeof(apiKey)) {
        wchar_t keyWide[256];
        if (MultiByteToWideChar(CP_UTF8,0,apiKey,-1,keyWide,256) > 0) {
            swprintf(apiHeader,320,L"apiKey: %s",keyWide);
        }
        SecureZeroMemory(keyWide,sizeof(keyWide));
    }
    SecureZeroMemory(apiKey,sizeof(apiKey));
    NvdRecentEntry *saved = (NvdRecentEntry*)malloc(sizeof(g_nvdRecent));
    if(!saved) { WinHttpCloseHandle(conn); WinHttpCloseHandle(session); goto failed; }
    int savedCount=g_nvdRecentCount, savedTotal=g_nvdTotalResults;
    int savedParsed=g_nvdParsedCount,savedLoaded=g_nvdLoadedResults; BOOL savedPartial=g_nvdPartial;
    memcpy(saved,g_nvdRecent,sizeof(g_nvdRecent));
    DWORD nextIndex=0,pageNo=0; BOOL parsed=TRUE; DWORD status=0;
    for(;;){
        char pathA[448];
        int n=snprintf(pathA,sizeof(pathA),"/rest/json/cves/2.0?pubStartDate=%04u-%02u-%02uT%02u%%3A%02u%%3A%02u.000&pubEndDate=%04u-%02u-%02uT%02u%%3A%02u%%3A%02u.000&resultsPerPage=%u&startIndex=%lu&noRejected",
            startUtc.wYear,startUtc.wMonth,startUtc.wDay,startUtc.wHour,startUtc.wMinute,startUtc.wSecond,
            nowUtc.wYear,nowUtc.wMonth,nowUtc.wDay,nowUtc.wHour,nowUtc.wMinute,nowUtc.wSecond,NVD_PAGE_SIZE,(unsigned long)nextIndex);
        if(n<=0||n>=(int)sizeof(pathA)||MultiByteToWideChar(CP_UTF8,0,pathA,-1,path,(int)(sizeof(path)/sizeof(path[0])))<=0){parsed=FALSE;break;}
        char *body=NULL; size_t bodySize=0;
        if(!nvd_fetch_page(conn,path,apiHeader,&body,&bodySize,&status)){parsed=FALSE;break;}
        double pageRows=0; nvd_json_number(body,body+bodySize,"resultsPerPage",&pageRows);
        if(!nvd_parse_body(body,nextIndex==0)){free(body);parsed=FALSE;break;}
        free(body);
        ++pageNo;
        DWORD step=(DWORD)pageRows;
        if(step==0){if(nextIndex<(DWORD)g_nvdTotalResults)parsed=FALSE;break;}
        nextIndex+=step; g_nvdLoadedResults=(int)nextIndex;
        if(nextIndex >= (DWORD)g_nvdTotalResults) break;
        if(pageNo>=NVD_MAX_PAGES){g_nvdPartial=TRUE;break;}
        if(keyLen==0 || keyLen>=sizeof(apiKey)) Sleep(6500);
    }
    WinHttpCloseHandle(conn); WinHttpCloseHandle(session);
    SecureZeroMemory(apiHeader,sizeof(apiHeader));
    if(!parsed){
        memcpy(g_nvdRecent,saved,sizeof(g_nvdRecent));g_nvdRecentCount=savedCount;g_nvdTotalResults=savedTotal;g_nvdParsedCount=savedParsed;g_nvdLoadedResults=savedLoaded;g_nvdPartial=savedPartial;
        free(saved);goto failed;
    }
    free(saved);

    g_nvdRefreshOk = TRUE;
    GetSystemTime(&nowUtc);
    snprintf(g_nvdRefreshUtc,sizeof(g_nvdRefreshUtc),"%04u-%02u-%02uT%02u:%02uZ",
             nowUtc.wYear,nowUtc.wMonth,nowUtc.wDay,nowUtc.wHour,nowUtc.wMinute);
    snprintf(g_nvdRefreshMessage,sizeof(g_nvdRefreshMessage),
             "NVD refreshed: %d CVEs from the last 7 days; downloaded %d%s",g_nvdTotalResults,g_nvdLoadedResults,
             g_nvdPartial ? " (showing newest available subset)" : "");
    return TRUE;

failed:
    g_nvdRefreshOk = FALSE;
    snprintf(g_nvdRefreshMessage,sizeof(g_nvdRefreshMessage),
             "NVD refresh failed (network/API response unavailable); last successful data was not replaced.");
    return FALSE;
}

#endif
