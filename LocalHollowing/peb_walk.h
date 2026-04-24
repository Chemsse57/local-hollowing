#pragma once
#include <Windows.h>
#include <winternl.h>

// Full LDR_DATA_TABLE_ENTRY - winternl.h only exposes a partial definition
typedef struct _MY_LDR_ENTRY {
    LIST_ENTRY     InLoadOrderLinks;
    LIST_ENTRY     InMemoryOrderLinks;
    LIST_ENTRY     InInitializationOrderLinks;
    PVOID          DllBase;
    PVOID          EntryPoint;
    ULONG          SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} MY_LDR_ENTRY;

// Compare UNICODE_STRING (PEB, wide) with narrow ASCII - case-insensitive
static inline int _peb_wstrcmpi_a(UNICODE_STRING* ws, const char* s) {
    USHORT wlen = ws->Length / sizeof(WCHAR);
    USHORT slen = (USHORT)strlen(s);
    if (wlen != slen) return 1;
    for (USHORT i = 0; i < wlen; i++) {
        WCHAR wc = (ws->Buffer[i] >= L'A' && ws->Buffer[i] <= L'Z')
                   ? ws->Buffer[i] + 32 : ws->Buffer[i];
        char  sc = (s[i] >= 'A' && s[i] <= 'Z') ? s[i] + 32 : s[i];
        if (wc != (WCHAR)sc) return 1;
    }
    return 0;
}

// Walk PEB InMemoryOrderModuleList - replaces GetModuleHandleA
static PVOID PebGetModuleBase(const char* modName) {
    PPEB peb = (PPEB)__readgsqword(0x60);
    PLIST_ENTRY head = &peb->Ldr->InMemoryOrderModuleList;
    for (PLIST_ENTRY e = head->Flink; e != head; e = e->Flink) {
        MY_LDR_ENTRY* entry = CONTAINING_RECORD(e, MY_LDR_ENTRY, InMemoryOrderLinks);
        if (entry->BaseDllName.Buffer &&
            _peb_wstrcmpi_a(&entry->BaseDllName, modName) == 0)
            return entry->DllBase;
    }
    return NULL;
}

// Walk PE export table by name - replaces GetProcAddress
static PVOID PebGetExportAddr(PVOID base, const char* funcName) {
    BYTE* b = (BYTE*)base;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)b;
    PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)(b + dos->e_lfanew);
    DWORD expRVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!expRVA) return NULL;
    PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)(b + expRVA);
    DWORD* names     = (DWORD*)(b + exp->AddressOfNames);
    WORD*  ordinals  = (WORD*) (b + exp->AddressOfNameOrdinals);
    DWORD* functions = (DWORD*)(b + exp->AddressOfFunctions);
    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        if (strcmp((char*)(b + names[i]), funcName) == 0)
            return (PVOID)(b + functions[ordinals[i]]);
    }
    return NULL;
}
