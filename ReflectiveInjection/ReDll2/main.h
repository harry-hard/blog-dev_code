#pragma once
#include <Windows.h>
#include <winternl.h>
#ifdef _WIN64
#define LDR_OFFSET  0x10
#else
#define LDR_OFFSET  0x8
#endif // _WIN64
#define DLLEXPORT __declspec(dllexport) 

#define LoadLibraryA_CRC32				0x3FC1BD8D
#define VirtualAlloc_CRC32				0x09CE0D4A
#define VirtualProtect_CRC32			0x10066F2F
#define RtlAddFunctionTable_CRC32       0x4C3CB59B
#define NtFlushInstructionCache_CRC32   0x85BF2F9C

#define kernel32dll_CRC32				0x6AE69F02
#define ntdlldll_CRC32					0x84C05E40

typedef BOOL(WINAPI* fnDllMain)(HINSTANCE, DWORD, LPVOID);

HMODULE GetModuleHandleH(IN UINT32 uModuleHash);
FARPROC GetProcAddressH(IN HMODULE hModule, IN UINT32 uApiHash);
typedef LPVOID(WINAPI* fnVirtualAlloc)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
typedef BOOL(WINAPI* fnVirtualProtect)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
typedef BOOLEAN(WINAPI* fnRtlAddFunctionTable)(PRUNTIME_FUNCTION FunctionTable, DWORD EntryCount, DWORD64 BaseAddress);
typedef NTSTATUS(NTAPI* fnNtFlushInstructionCache)(HANDLE hProcess, PVOID BaseAddress, ULONG NumberOfBytesToFlush);
typedef HMODULE(WINAPI* fnLoadLibraryA)(LPCSTR lpLibFileName);
