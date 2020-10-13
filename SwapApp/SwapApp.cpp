#include <iostream>
#include <Windows.h>
#include <cstring>
#define BUFF_SIZE 65536

char buffer[BUFF_SIZE];

int Find(char* buf, int bufLen, const char* target) {
	int tLen = strlen(target);
	int tIndex = 0;
	bool match = FALSE;

	for (int i = 0;
		i < bufLen && tIndex < tLen;
		i++) {
		if (buf[i] == target[tIndex]) {
			match = TRUE;
			tIndex++;
		}
		else if (match) {
			match = FALSE;
			tIndex = 0;
		}

		if (tIndex >= tLen && match) {
			return i - tLen + 1;
		}
	}

	return -1;
}

int VirtualMemorySwap(const char* target, const char* replace, HANDLE hProc) {
	unsigned char* p = NULL;
	MEMORY_BASIC_INFORMATION info;
	SIZE_T bRead = 0;

	for (p = NULL;
		VirtualQueryEx(hProc, p, &info, sizeof(info)) == sizeof(info);
		p += info.RegionSize) {
		if (info.State == MEM_COMMIT && info.AllocationProtect == PAGE_READWRITE && !(info.Protect == PAGE_NOACCESS))
		{

			if (ReadProcessMemory(hProc, (LPCVOID)p, buffer, info.RegionSize, &bRead)) {
				int offset = Find(buffer, bRead, target);

				if (offset != -1) {
					size_t len = strlen(replace);
					SIZE_T bWritten = 0;

					if (WriteProcessMemory(hProc, (LPVOID)(p + offset), (LPCVOID)replace, len, &bWritten))
						return TRUE;
					else
						return FALSE;
				}
			}

		}
	}
	return FALSE;
}

unsigned long usage;

void showModules(HANDLE hProc) {

	unsigned char* p = NULL;
	MEMORY_BASIC_INFORMATION info;

	for (p = NULL;
		VirtualQueryEx(hProc, p, &info, sizeof(info)) == sizeof(info);
		p += info.RegionSize)
	{
		printf("%#10.10x (%6uK)\t", info.BaseAddress, info.RegionSize / 1024);

		switch (info.State) {
		case MEM_COMMIT:
			printf("Committed");
			break;
		case MEM_RESERVE:
			printf("Reserved");
			break;
		case MEM_FREE:
			printf("Free");
			break;
		}
		printf("\t");
		switch (info.Type) {
		case MEM_IMAGE:
			printf("Code Module");
			break;
		case MEM_MAPPED:
			printf("Mapped     ");
			break;
		case MEM_PRIVATE:
			printf("Private    ");
		}
		printf("\t");

		if ((info.State == MEM_COMMIT) && (info.Type == MEM_PRIVATE))
			usage += info.RegionSize;

		int guard = 0, nocache = 0;

		if (info.AllocationProtect & PAGE_NOCACHE)
			nocache = 1;
		if (info.AllocationProtect & PAGE_GUARD)
			guard = 1;

		info.AllocationProtect &= ~(PAGE_GUARD | PAGE_NOCACHE);

		switch (info.AllocationProtect) {
		case PAGE_READONLY:
			printf("Read Only");
			break;
		case PAGE_READWRITE:
			printf("Read/Write");
			break;
		case PAGE_WRITECOPY:
			printf("Copy on Write");
			break;
		case PAGE_EXECUTE:
			printf("Execute only");
			break;
		case PAGE_EXECUTE_READ:
			printf("Execute/Read");
			break;
		case PAGE_EXECUTE_READWRITE:
			printf("Execute/Read/Write");
			break;
		case PAGE_EXECUTE_WRITECOPY:
			printf("COW Executable");
			break;
		}

		if (guard)
			printf("\tguard page");
		if (nocache)
			printf("\tnon-cachable");
		printf("\n");
	}
}

int main() {
	/*int pid = GetCurrentProcessId();

	HANDLE hProc = OpenProcess(
		PROCESS_ALL_ACCESS | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
		false,
		pid);*/

	HWND hWnd = FindWindow(0, TEXT("TextOutApp"));
	if (hWnd == 0) {
		std::cerr << "Cannot find window." << std::endl;
	}
	else {
		DWORD pId, currpId;
		GetWindowThreadProcessId(hWnd, &pId);
		currpId = GetCurrentProcessId();
		HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pId);
		if (hProc) {
			char target[] = "Hello";
			char replace[] = "olleH";

			int res = VirtualMemorySwap(target, replace, hProc);

			std::cerr << res << std::endl;


			/*show_modules(hProc);
			printf("Total memory used: %luKB\n", usage / 1024);*/
		}

	}
}