// dllmain.cpp : Определяет точку входа для приложения DLL.
#include "pch.h"
#include "MemoryLib.h"
#include <Windows.h>

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
	HANDLE hProc = NULL;
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		/*hProc = OpenProcess(PROCESS_ALL_ACCESS, 0, GetCurrentProcessId());
		if (hProc) {
			VirtualMemorySwap("Hello", "OraOr", hProc);
		}*/
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

