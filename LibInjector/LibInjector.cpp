#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>

#define DLL_NAME "D:\\Semester 5\\OSaSP\\Lab3_2\\MemoryLib\\Debug\\MemoryLib.dll"
#define PROC_NAME "VirtualMemorySwapEx"

typedef int VMSwapEx(PVOID param);

BOOL	WINAPI InjectLib(DWORD dwProcId, PCWSTR libFile);
BOOL	WINAPI EjectLib(DWORD dwProcessId, PCWSTR pszLibFile);
BOOL	WINAPI CallFunc(DWORD dwProcId, std::string target, std::string replace);

int main() {
	HWND hWnd = FindWindow(0, TEXT("TextOutApp"));

	if (hWnd == 0) {
		std::cerr << "Cannot find window." << std::endl;
		return -1;
	}

	DWORD pId;
	GetWindowThreadProcessId(hWnd, &pId);
	/*std::cout << "Enter Process ID:\n";
	std::cin >> pId;*/

	if (InjectLib(pId, TEXT(DLL_NAME))) {
		std::cout << "Dll Injection successful.\n";

		/*
		if (CallFunc(pId, target, replace))
			std::cout << "Function called successfully.";
		else
			std::cout << "Function call failed.";*/

		/*if (EjectLib(pId, TEXT("D:\Semester 5\OSaSP\Lab3_2\MemoryLib\Debug\MemoryLib.dll"))) 
			std::cout << "Dll Ejection successful";
		else 
			std::cout << "Dll Ejection failed";*/
		
	}
	else {
		std::cout << "Dll Injection failed.\n";
	}

	std::string str;
	std::cin >> str;
}


BOOL WINAPI InjectLib(DWORD dwProcId, PCWSTR libFile) {
	BOOL result = FALSE;
	HANDLE hProc = NULL;
	HANDLE hThread = NULL;
	PWSTR libFileRemote = NULL;

	__try {
		hProc = OpenProcess(
			PROCESS_CREATE_THREAD |
			PROCESS_VM_OPERATION |
			PROCESS_VM_WRITE,
			FALSE,
			dwProcId
		);

		if (hProc == NULL) __leave;

		/* lnSize - lib name size (in bytes) */
		int lnSize = (lstrlenW(libFile) + 1) * sizeof(WCHAR);

		/* VirtualAllocEx
		(
			HANDLE hProcess			- The handle to a process
			LPVOID lpAddress		- The pointer that specifies a desired starting address
									  for the region of pages that you want to allocate.
									  If NULL, the function determines where to allocate the region.
			SIZE_T dwSize			- The size of memory to allocate, in bytes.
			DWORD  flAllocationType - The type of memory allocation.
			DWORD  flProtect		- The memory protection.
		)
		*/
		libFileRemote = (PWSTR)VirtualAllocEx(hProc, NULL, lnSize, MEM_COMMIT, PAGE_READWRITE);
		if (libFileRemote == NULL) __leave;

		if (!WriteProcessMemory(hProc, libFileRemote, (PVOID)libFile, lnSize, NULL))
			__leave;

		PTHREAD_START_ROUTINE pfnThreadRtn = (PTHREAD_START_ROUTINE)
			GetProcAddress(GetModuleHandle(TEXT("Kernel32")), "LoadLibraryW");
		if (pfnThreadRtn == NULL) __leave;

		hThread = CreateRemoteThread(hProc, NULL, 0,
			pfnThreadRtn, libFileRemote, 0, NULL);
		if (hThread == NULL) __leave;

		WaitForSingleObject(hThread, INFINITE);
		CloseHandle(hThread);

		result = TRUE;
	}
	__finally {
		/* Clear resourses*/
		if (libFileRemote != NULL)
			VirtualFreeEx(hProc, libFileRemote, 0, MEM_RELEASE);
		
		/*if (hThread != NULL)
			CloseHandle(hThread);*/
		
		if (hProc != NULL)
			CloseHandle(hProc);
	}

	return result;
}

BOOL WINAPI CallFunc(DWORD dwProcId, std::string target, std::string replace) {
	HANDLE hProc = NULL, hThread = NULL;

	hProc = OpenProcess(
		PROCESS_CREATE_THREAD |
		PROCESS_VM_OPERATION |
		PROCESS_VM_WRITE,
		FALSE,
		dwProcId
	);
	if (hProc == NULL) return FALSE;

	HINSTANCE hModule = LoadLibrary(TEXT(DLL_NAME));
	if (hModule == NULL) return FALSE;

	VMSwapEx* pVMSwap = (VMSwapEx*)GetProcAddress(hModule, "VirtualMemorySwapEx");
	if (pVMSwap == NULL) return FALSE;

	struct PARAMETER {
		std::string target;
		std::string replace;
		int pId;
	};

	PARAMETER m_parameter;

	m_parameter.target = target;
	m_parameter.replace = replace;
	m_parameter.pId = dwProcId;

	LPVOID alloc = VirtualAllocEx(hProc, NULL, sizeof PARAMETER, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	if (alloc == NULL) return FALSE;

	if (!WriteProcessMemory(hProc, alloc, &m_parameter, sizeof(m_parameter), NULL))
		return NULL;

	hThread = CreateRemoteThread(hProc, 0, 0, (LPTHREAD_START_ROUTINE)pVMSwap, (LPVOID)alloc, 0, 0);
	if (hThread == NULL) return FALSE;

	CloseHandle(hProc);
	WaitForSingleObject(hThread, INFINITE);
	CloseHandle(hThread);
	FreeLibrary(hModule);

	return TRUE;
}

BOOL WINAPI EjectLib(DWORD dwProcessId, PCWSTR pszLibFile) {
	BOOL result = FALSE; 
	HANDLE hthSnapshot = NULL;
	HANDLE hProcess = NULL, hThread = NULL;
	__try {

		hthSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwProcessId);
		if (hthSnapshot == NULL) __leave;

		MODULEENTRY32W me = { sizeof(me) };
		BOOL fFound = FALSE;
		BOOL fMoreMods = Module32FirstW(hthSnapshot, &me);
		for (; fMoreMods && !fFound; fMoreMods = Module32NextW(hthSnapshot, &me)) {
			fFound = (lstrcmpiW(me.szModule, pszLibFile) == 0) ||
				(lstrcmpiW(me.szExePath, pszLibFile) == 0);
		}
		if (!fFound) __leave;

		hProcess = OpenProcess(
			PROCESS_CREATE_THREAD |
			PROCESS_VM_OPERATION,
			FALSE, dwProcessId);
		if (hProcess == NULL) __leave;
		
		PTHREAD_START_ROUTINE pfnThreadRtn = (PTHREAD_START_ROUTINE)
			GetProcAddress(GetModuleHandle(TEXT("Kernel32")), "FreeLibrary");
		if (pfnThreadRtn == NULL) __leave;
		
		hThread = CreateRemoteThread(hProcess, NULL, 0,
			pfnThreadRtn, me.modBaseAddr, 0, NULL);
		if (hThread == NULL) __leave;
		
		WaitForSingleObject(hThread, INFINITE);
		result = TRUE; 
	}
	__finally { 
		if (hthSnapshot != NULL)
			CloseHandle(hthSnapshot);

		if (hThread != NULL)
			CloseHandle(hThread);

		if (hProcess != NULL)
			CloseHandle(hProcess);
	}
	return result;
}