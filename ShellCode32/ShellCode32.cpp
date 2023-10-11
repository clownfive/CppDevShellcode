#include "shellcode.h"


//函数入口点
void ShellCodeOEP()
{
	SCENV env;
	InitEnv(&env);

	char sz_hello[] = { 'h','e','l','l','o','\0' };
	env.m_pfnMessageBoxA(NULL, sz_hello, sz_hello, MB_OK);

}

void InitEnv(PSCENV pEnv)
{
	char sz_MessageBoxA[] = { 'M','e','s','s','a','g','e','B','o','x','A','\0' };
	char sz_LoadLibraryA[] = { 'L','o','a','d','L','i','b','r','a','r','y','A','\0' };
	char sz_GetProcAddress[] = { 'G','e','t','P','r','o','c','A','d','d','r','e','s','s','\0' };
	char sz_user32[] = { 'u','s','e','r','3','2','\0' };



	//拿kernel32的地址
	HMODULE hKernel32 = GetKernel32Base();
	pEnv->m_pfnGetProcAddress = (PFN_GetProcAddress)MyGetProcAddress(hKernel32, sz_GetProcAddress);
	pEnv->m_pfnLoadLibraryA = (PFN_LoadLibraryA)pEnv->m_pfnGetProcAddress(hKernel32, sz_LoadLibraryA);

	HMODULE hUser32 = pEnv->m_pfnLoadLibraryA(sz_user32);
	pEnv->m_pfnMessageBoxA = (PFN_MessageBoxA)pEnv->m_pfnGetProcAddress(hUser32, sz_MessageBoxA);



}

//拿kernel32模块基址
HMODULE GetKernel32Base()
{

	HMODULE hKer32 = NULL;
	__asm
	{
		mov eax, fs: [0x18] ; //TEB
		mov eax, [eax + 0x30]; //PEB
		mov eax, [eax + 0x0C];//_PEB_LDR_DATA
		mov eax, [eax + 0x0C];  // _LIST_ENTRY 主模块
		mov eax, [eax]
		mov eax, [eax]
		mov eax, dword ptr[eax + 0x18];// KERNEL32基址
		mov hKer32, eax

	}
	return hKer32;
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


FARPROC MyGetProcAddress(HMODULE hDll, char* szFuncName)
{
	if (hDll == NULL || szFuncName == NULL)
	{
		return NULL;
	}

	//处理pe头
	PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)hDll;
	PIMAGE_NT_HEADERS pNtHdr = (PIMAGE_NT_HEADERS)((int)hDll + (int)pDosHdr->e_lfanew);
	PIMAGE_OPTIONAL_HEADER pOptionHeader = (PIMAGE_OPTIONAL_HEADER)&pNtHdr->OptionalHeader; //可选头


	PIMAGE_DATA_DIRECTORY pExportDir = (PIMAGE_DATA_DIRECTORY)pOptionHeader->DataDirectory + IMAGE_DIRECTORY_ENTRY_EXPORT;

	PIMAGE_EXPORT_DIRECTORY pExportTable = (PIMAGE_EXPORT_DIRECTORY)(int)(pOptionHeader->DataDirectory[0].VirtualAddress + (int)hDll);


	PDWORD pdwAddressofNames = (PDWORD)(pExportTable->AddressOfNames + (int)hDll); //二级名称指针
	PWORD pdwAddressofNameOrdinals = (PWORD)(pExportTable->AddressOfNameOrdinals + (int)hDll);
	PDWORD pdwAddressOfFunc = (PDWORD)(pExportTable->AddressOfFunctions + (int)hDll);
	DWORD dwFuncCount = pExportTable->NumberOfFunctions;

		//名称获取函数地址
		for (int i = 0; i < (int)dwFuncCount; i++)
		{
			//获取名称地址
			char* pszName = (char*)(pdwAddressofNames[i] + (int)hDll);
			if (MyStrCmp(pszName, szFuncName) == 0)
			{
				DWORD dwIdx = pdwAddressofNameOrdinals[i]; // + pExportTable->Base
				//找到函数地址
				DWORD dwFunAddr = pdwAddressOfFunc[dwIdx] + (int)hDll;
				return FARPROC(dwFunAddr);

			}
		}
	return NULL;
}