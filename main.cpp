#define _CRT_SECURE_NO_WARNINGS

#include <iostream>
#include <Windows.h>
int main()
{
	const char* processTitle = "Counter-Strike: Global Offensive";

	char DLL_PATH[MAX_PATH];
	char filePath[MAX_PATH];
	GetCurrentDirectoryA(sizeof(filePath), filePath);
	const char* DLL_NAME = "\\cheat.dll";
	strncpy(DLL_PATH, filePath, sizeof(DLL_PATH));
	strncat(DLL_PATH, DLL_NAME, sizeof(DLL_PATH));

	DWORD dwProcessID = 0;
	HWND ProcessWindow = FindWindowA(0, processTitle);
	GetWindowThreadProcessId(ProcessWindow, &dwProcessID);

	HANDLE pHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessID);

	LPVOID DllFile = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
	LPVOID remoteData = (LPVOID)VirtualAllocEx(pHandle, NULL, strlen(DLL_PATH), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	WriteProcessMemory(pHandle, remoteData, DLL_PATH, strlen(DLL_PATH), NULL);
	CreateRemoteThread(pHandle, NULL, NULL, (LPTHREAD_START_ROUTINE)DllFile, (LPVOID)remoteData, NULL, NULL);
	CloseHandle(pHandle);

	printf("Injecting Done!\n");
	
	getchar(); getchar();

	return 0;
}
