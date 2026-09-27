#include <windows.h>
#include <stdio.h>

int main() {
    HANDLE h = CreateMutexA(NULL, TRUE, "KaevexMasterMutex");
    DWORD err = GetLastError();
    printf("CreateMutex error: %lu (ALREADY_EXISTS=%d)\n", err, err == ERROR_ALREADY_EXISTS);
    if (h) CloseHandle(h);
    return 0;
}
