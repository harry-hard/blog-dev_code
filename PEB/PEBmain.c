#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <wchar.h>
#ifdef _WIN64
DWORD LDR_OFFSET = 0x10;
#elif
DWORD LDR_OFFSET = 0x8;
#endif // _WIN64
PBYTE getDllAddress(wchar_t* dllName);
PBYTE getFuncAddress(const char* funcName,PBYTE kernel32dllAddr);
int main() {
	PBYTE kernel32dllAddr = getDllAddress(L"KernelBase.dll");

	PBYTE pLoadLibraryA =  getFuncAddress("LoadLibraryA", kernel32dllAddr);
	printf("LoadLibraryA address at:%p\n", pLoadLibraryA);
	
	return 0;
}

PBYTE getDllAddress(wchar_t* dllName) {
	//通过PEB结构获取dll地址
	PPEB  pPeb = __readgsqword(0x60);
	PPEB_LDR_DATA ldr = pPeb->Ldr;
	PLIST_ENTRY head = &ldr->InMemoryOrderModuleList;
	PLIST_ENTRY flink = head->Flink;
	PBYTE kernel32dllAddr = NULL;
	while (flink != head) {
		PLDR_DATA_TABLE_ENTRY entry = (ULONG_PTR)flink - LDR_OFFSET;
		//AI写的
		PWSTR filename = wcsrchr(entry->FullDllName.Buffer, L'\\');
		filename = filename ? filename + 1 : entry->FullDllName.Buffer;
		//AI结束
		if (_wcsicmp(filename, dllName) == 0) {
			kernel32dllAddr = entry->DllBase;
			break;
		}
		else
			flink = flink->Flink;
	}
	if (!kernel32dllAddr) {
		printf("Failed to find kernel32.dll\n");
		return (PVOID)0;
	}
	return kernel32dllAddr;
}

PBYTE getFuncAddress(const char* funcName,PBYTE kernel32dllAddr) {
	//根据获取到的dll寻找函数导出表
	PIMAGE_DOS_HEADER imgPe = (PIMAGE_DOS_HEADER)kernel32dllAddr;
	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(kernel32dllAddr + imgPe->e_lfanew);
	//PIMAGE_SECTION_HEADER sec = (PIMAGE_SECTION_HEADER)IMAGE_FIRST_SECTION(nt);
	/*IMAGE_OPTIONAL_HEADER opt = nt->OptionalHeader;*/
	PIMAGE_DATA_DIRECTORY dataDir = &nt->OptionalHeader.DataDirectory[0];
	PIMAGE_EXPORT_DIRECTORY exp = kernel32dllAddr + dataDir->VirtualAddress;
	PDWORD nameFunc = kernel32dllAddr + exp->AddressOfNames;
	PDWORD addrFunc = kernel32dllAddr + exp->AddressOfFunctions;
	PWORD ordinals = kernel32dllAddr + exp->AddressOfNameOrdinals;
	for (int i = 0; i < exp->NumberOfNames; i++) {
		DWORD name_rva = nameFunc[i];
		if (name_rva == 0 || name_rva >= nt->OptionalHeader.SizeOfImage) {
			printf("Invalid RVA: 0x%08X\n", name_rva);
			continue;
		}
		if (strcmp(funcName, kernel32dllAddr + (DWORD)nameFunc[i]) == 0) {
			return kernel32dllAddr + (DWORD)addrFunc[ordinals[i]];
		}
	}
}