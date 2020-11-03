// MemoryLib.h - Contains declarations of memory functions
#pragma once

#ifdef MEMORYLIB_EXPORTS
#define MEMORYLIB_API __declspec(dllexport)
#else
#define MEMORYLIB_API __declspec(dllimport)
#endif

extern "C" MEMORYLIB_API int VirtualMemorySwap(
	const char* target, const char* replace, HANDLE hProc);

extern "C" MEMORYLIB_API int VirtualMemorySwapEx(const char* target, const char* replace);
