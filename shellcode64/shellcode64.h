#pragma once
#include <Windows.h>
#include <stdio.h>
//函数指针声明
typedef int (WINAPI* PFN_MessageBoxA)(HWND, LPCSTR, LPCSTR, UINT);
typedef HMODULE(WINAPI* PFN_LoadLibraryA)(LPCSTR);
typedef FARPROC(WINAPI* PFN_GetProcAddress)(HMODULE, LPCSTR);



typedef	struct SellcodeEvn
{
	PFN_MessageBoxA m_pfnMessageBoxA;
	PFN_LoadLibraryA m_pfnLoadLibraryA;
	PFN_GetProcAddress m_pfnGetProcAddress;


}SCENV, * PSCENV;

//自己的函数声明

void InitEnv(PSCENV pEnv);
EXTERN_C ULONG numadd(ULONG a, ULONG b);
EXTERN_C HMODULE GetModuleKernel();
int MyStrCmp(char* pDst, char* pSrc);
FARPROC MyGetProcAddress(HMODULE hModule, char* lpProcName);