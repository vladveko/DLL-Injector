#include <iostream>
#include <Windows.h>

bool InjectLib(DWORD dwProcId, PCWSTR libFile);

int main() {
	DWORD pId;
	std::cin >> pId;

	if (InjectLib(pId, TEXT("D:\Semester 5\OSaSP\Lab3_2\MemoryLib\Debug\MemoryLib.dll"))) {
		std::cout << "Dll Injection successful.";
	}
	else {
		std::cout << "Dll Injection failed.";
	}
}


bool InjectLib(DWORD dwProcId, PCWSTR libFile) {
	bool result = FALSE;
	HANDLE hProc = NULL, hThread = NULL;
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
			return FALSE;

		PTHREAD_START_ROUTINE pfnThreadRtn = (PTHREAD_START_ROUTINE)
			GetProcAddress(GetModuleHandle(TEXT("Kernel32")), "LoadLibraryW");
		if (pfnThreadRtn == NULL) __leave;

		hThread = CreateRemoteThread(hProc, NULL, 0,
			pfnThreadRtn, libFileRemote, 0, NULL);
		if (hThread == NULL) __leave;

		WaitForSingleObject(hThread, INFINITE);

		result = TRUE;
	}
	__finally {
		/* Clear resourses*/
		if (libFileRemote != NULL)
			VirtualFreeEx(hProc, libFileRemote, 0, MEM_RELEASE);
		
		if (hThread != NULL)
			CloseHandle(hThread);
		
		if (hProc != NULL)
			CloseHandle(hProc);
	}

	return result;
}