#include <Windows.h>
#include <stdio.h>
#include <Psapi.h>

#define PATH "E:\\Programming\\Windows\\IAT_Hooking\\Debug\\dll_iat-hook.dll"

HANDLE findProc(const wchar_t* proc_name);
void handleError(DWORD num);

int main()
{
	HANDLE h;
	do 
	{
		h = findProc(L"Misery.exe");
	} while (h == NULL);

	int size = strlen(PATH) * sizeof(char);

	LPVOID mem = (LPVOID)VirtualAllocEx(h, NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (mem == NULL)
	{
		handleError(GetLastError());
	}

	LPVOID func = GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "LoadLibraryA");

	if (!WriteProcessMemory(h, mem, PATH, strlen(PATH) * sizeof(char), NULL))
	{
		handleError(GetLastError());
	}
	HANDLE thread = CreateRemoteThread(h, NULL, 0, (LPTHREAD_START_ROUTINE)func, mem, 0, NULL);
	CloseHandle(thread);
	return 0;
}

HANDLE findProc(const wchar_t* proc_name)
{
	const DWORD array_size = 1024;
	DWORD proc_array[array_size];
	DWORD actual_size;
	wchar_t name[MAX_PATH];
	HANDLE h;
	EnumProcesses(proc_array, array_size * sizeof(DWORD), &actual_size);
	for (int i = 0; i < actual_size / sizeof(DWORD); i++)
	{
		h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD, TRUE, proc_array[i]);
		GetModuleBaseName(h, NULL, name, MAX_PATH);
		if (!wcscmp(name, proc_name))
		{
			return h;
		}
		CloseHandle(h);
	}
	return NULL;
}

void handleError(DWORD num)
{
	printf("Error accured, code: %d\n", num);
}
