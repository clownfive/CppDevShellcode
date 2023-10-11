#include "shellcode64.h"

#include <stdio.h>

//这是shellcode的入口函数
void ShellCodeEntry()
{
	SCENV env;
	InitEnv(&env);

	char sz_hello[] = { 'h','e','l','l','o','\0' };
	env.m_pfnMessageBoxA(NULL, sz_hello, sz_hello, MB_OK);
	//代码冲这开始写


}

void InitEnv(PSCENV pEnv)
{
	char sz_MessageBoxA[] = { 'M','e','s','s','a','g','e','B','o','x','A','\0' };
	char sz_LoadLibraryA[] = { 'L','o','a','d','L','i','b','r','a','r','y','A','\0' };
	char sz_GetProcAddress[] = { 'G','e','t','P','r','o','c','A','d','d','r','e','s','s','\0' };
	char sz_user32[] = { 'u','s','e','r','3','2','\0' };

	//拿kernel32的地址
	HMODULE hKernel32 = GetModuleKernel();
	pEnv->m_pfnGetProcAddress = (PFN_GetProcAddress)MyGetProcAddress(hKernel32, sz_GetProcAddress);
	pEnv->m_pfnLoadLibraryA = (PFN_LoadLibraryA)pEnv->m_pfnGetProcAddress(hKernel32, sz_LoadLibraryA);
	
	
	HMODULE hUser32 = pEnv->m_pfnLoadLibraryA(sz_user32);
	pEnv->m_pfnMessageBoxA = (PFN_MessageBoxA)pEnv->m_pfnGetProcAddress(hUser32, sz_MessageBoxA);



}

int MyStrCmp(char* pDst, char* pSrc)
{
	char* pDstTmp = pDst;
	char* pSrcTmp = pSrc;
	while (*pSrcTmp && *pDstTmp)
	{
		if (*pSrcTmp != *pDstTmp)
		{
			return *pDstTmp - *pSrcTmp;
		}
		pSrcTmp++;
		pDstTmp++;
	}

	return *pDstTmp - *pSrcTmp;
}

FARPROC MyGetProcAddress(HMODULE hModule, char* lpProcName) {
	IMAGE_DOS_HEADER* pDosHeader = (IMAGE_DOS_HEADER*)hModule;
	IMAGE_NT_HEADERS64* pNtHeaders = (IMAGE_NT_HEADERS64*)((char*)pDosHeader + pDosHeader->e_lfanew);

	//LPVOID exports1 = (LPVOID)&(pNtHeaders->OptionalHeader.DataDirectory[0]);
	//DWORD exports2 =  pNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress;

	IMAGE_EXPORT_DIRECTORY* pExportDir = (IMAGE_EXPORT_DIRECTORY*)((char*)pDosHeader + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	DWORD* pAddressOfNames = (DWORD*)((char*)pDosHeader + pExportDir->AddressOfNames);
	WORD* pAddressOfOrdinals = (WORD*)((char*)pDosHeader + pExportDir->AddressOfNameOrdinals);
	DWORD* pAddressOfFunctions = (DWORD*)((char*)pDosHeader + pExportDir->AddressOfFunctions);

	for (DWORD i = 0; i < pExportDir->NumberOfNames; i++) {
		LPCSTR pProcName = (LPCSTR)((char*)pDosHeader + pAddressOfNames[i]);
		if (MyStrCmp((char*)pProcName, lpProcName) == 0) {
			WORD ordinal = pAddressOfOrdinals[i];
			DWORD functionRVA = pAddressOfFunctions[ordinal];
			FARPROC functionPtr = (FARPROC)((char*)hModule + functionRVA);
			return functionPtr;
		}
	}
	return NULL;
}