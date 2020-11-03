// dllmain.cpp : Определяет точку входа для приложения DLL.
#include "pch.h"
#include "MemoryLib.h"
#include <Windows.h>

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
	char target[] = "Hello";
	char replace[] = "olleH";
	int result;

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		result = VirtualMemorySwapEx(target, replace);
		break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

