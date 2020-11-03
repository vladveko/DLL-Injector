#include "pch.h" // use stdafx.h in Visual Studio 2017 and earlier
#include <utility>
#include <limits.h>
#include <string.h>
#include <string>
#include "MemoryLib.h"


#define BUFF_SIZE 65536

typedef struct Params {
	HANDLE hProc;
	std::string target;
	std::string replace;
} FuncParams;

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

int VirtualMemorySwapEx(PVOID param) {
	struct PARAMETER {
		std::string target;
		std::string replace;
		int pId;
	};

	PARAMETER* p_parameter = (PARAMETER*)param;

	const char* target = (*p_parameter).target.c_str();
	const char* replace = (*p_parameter).replace.c_str();
	int pId = (*p_parameter).pId;

	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pId);
	if (!hProc) return FALSE;

	return VirtualMemorySwap(target, replace, hProc);
}