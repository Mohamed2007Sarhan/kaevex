#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>

int main() {
    HANDLE hFile = CreateFileA("dist\\kaevex.exe", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) { printf("Failed to open kaevex.exe\n"); return 1; }
    DWORD size = GetFileSize(hFile, NULL);
    HANDLE hMap = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    BYTE *base = (BYTE*)MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);

    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER*)base;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    DWORD importRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

    /* Find section containing importRva */
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
    DWORD importOffset = 0;
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (importRva >= sec[i].VirtualAddress && importRva < sec[i].VirtualAddress + sec[i].Misc.VirtualSize) {
            importOffset = importRva - sec[i].VirtualAddress + sec[i].PointerToRawData;
            break;
        }
    }

    IMAGE_IMPORT_DESCRIPTOR *desc = (IMAGE_IMPORT_DESCRIPTOR*)(base + importOffset);
    int missingCount = 0;
    while (desc->Name) {
        /* Convert Name RVA to raw offset */
        DWORD nameOff = 0;
        for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
            if (desc->Name >= sec[i].VirtualAddress && desc->Name < sec[i].VirtualAddress + sec[i].Misc.VirtualSize) {
                nameOff = desc->Name - sec[i].VirtualAddress + sec[i].PointerToRawData;
                break;
            }
        }
        const char *dllName = (const char*)(base + nameOff);
        HMODULE hMod = LoadLibraryA(dllName);
        if (!hMod) {
            printf("[MISSING DLL] %s\n", dllName);
            missingCount++;
        } else {
            /* Check thunks */
            DWORD thunkRva = desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk;
            DWORD thunkOff = 0;
            for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
                if (thunkRva >= sec[i].VirtualAddress && thunkRva < sec[i].VirtualAddress + sec[i].Misc.VirtualSize) {
                    thunkOff = thunkRva - sec[i].VirtualAddress + sec[i].PointerToRawData;
                    break;
                }
            }
            IMAGE_THUNK_DATA64 *thunk = (IMAGE_THUNK_DATA64*)(base + thunkOff);
            while (thunk->u1.AddressOfData) {
                if (!(thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64)) {
                    DWORD dataRva = (DWORD)thunk->u1.AddressOfData;
                    DWORD dataOff = 0;
                    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
                        if (dataRva >= sec[i].VirtualAddress && dataRva < sec[i].VirtualAddress + sec[i].Misc.VirtualSize) {
                            dataOff = dataRva - sec[i].VirtualAddress + sec[i].PointerToRawData;
                            break;
                        }
                    }
                    IMAGE_IMPORT_BY_NAME *ibn = (IMAGE_IMPORT_BY_NAME*)(base + dataOff);
                    FARPROC proc = GetProcAddress(hMod, ibn->Name);
                    if (!proc) {
                        printf("[MISSING FUNC] %s -> %s\n", dllName, ibn->Name);
                        missingCount++;
                    }
                }
                thunk++;
            }
        }
        desc++;
    }

    if (!missingCount) printf("[OK] All DLLs and functions are present!\n");
    UnmapViewOfFile(base);
    CloseHandle(hMap);
    CloseHandle(hFile);
    return 0;
}
