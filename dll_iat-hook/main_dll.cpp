#include <Windows.h>
#include <stdio.h>
//wow64win.dll+0x10014
#define FUNC_NAME "Sleep"
#define DLL_NAME "KERNEL32.dll"
typedef void (*PFunc)(void);

DWORD saved_adress;

DWORD hook(const char* orfunc, const char* lib, PFunc hofunc);
void showMsg();

BOOL WINAPI DllMain(HINSTANCE handle, DWORD reason, LPVOID reserved)
{
	switch (reason)
	{
	case DLL_PROCESS_ATTACH:
		MessageBoxA(NULL, "Injection success", "Damn boi", MB_OK);
		if (!hook(FUNC_NAME, DLL_NAME, showMsg))
			MessageBoxA(NULL, "Hook failed", "Damn boi", MB_OK);
		break;
	case DLL_PROCESS_DETACH:
		if (reserved == NULL)
			printf("");
		else
			printf("");
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	}
	return TRUE;
}

DWORD hook(const char* orfunc, const char* lib, PFunc hofunc)
{
	PIMAGE_DOS_HEADER dosHeader;
	PIMAGE_NT_HEADERS ntHeader;
	PIMAGE_OPTIONAL_HEADER opHeader;
	PIMAGE_DATA_DIRECTORY dataDir;
	PIMAGE_IMPORT_DESCRIPTOR impDes;

	DWORD baseAdress = (DWORD)GetModuleHandle(L"E:\\Programming\\Windows\\IAT_Hooking\\Debug\\Misery.exe");
	dosHeader = PIMAGE_DOS_HEADER(baseAdress);
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return 0;
	}
	ntHeader = PIMAGE_NT_HEADERS(baseAdress + dosHeader->e_lfanew);
	if (ntHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		return 0;
	}
	opHeader = &(ntHeader->OptionalHeader);
	dataDir = &(opHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]);
	DWORD importRVA = dataDir->VirtualAddress;
	impDes = PIMAGE_IMPORT_DESCRIPTOR(baseAdress + importRVA);

	DWORD index = 0;
	while (impDes->Characteristics != 0)
	{
		char* name = (char*)baseAdress + impDes[index].Name;
		if (strcmp(name, lib) == 0)
		{
			break;
		}
		index++;
	}
	if (impDes[index].Characteristics == 0)
	{
		return 0;
	}

	PIMAGE_THUNK_DATA ilt;
	PIMAGE_THUNK_DATA iat;
	PIMAGE_IMPORT_BY_NAME name;
	ilt = (PIMAGE_THUNK_DATA)(impDes[index].OriginalFirstThunk + baseAdress);
	iat = (PIMAGE_THUNK_DATA)(impDes[index].FirstThunk + baseAdress);

	while (ilt->u1.AddressOfData != 0 && iat->u1.Function != 0)
	{
		name = (PIMAGE_IMPORT_BY_NAME)(ilt->u1.AddressOfData + baseAdress);
		if (strcmp((char*)name->Name, orfunc) == 0)
		{
			break;
		}
		ilt++;
		iat++;
	}
	if (ilt->u1.AddressOfData == 0 && iat->u1.Function == 0)
	{
		return 0;
	}
	DWORD size = NULL;
	saved_adress = iat->u1.Function;
	LPVOID a = & (iat->u1.Function);
	if (!VirtualProtect(a, sizeof(DWORD), PAGE_READWRITE, &size))
	{
		return 0;
	}
	iat->u1.Function = DWORD_PTR(hofunc);
	if (!VirtualProtect(a, sizeof(DWORD), size, &index))
	{
		return 0;
	}
	return 1;
}

void showMsg()
{
	MessageBoxA(NULL, "Hook success", "Damn boi", MB_OK);
	_asm
	{
		pop edi
		pop esi
		pop ebx
		add esp, 0C0h
		mov	esp, ebp
		pop	ebp
		jmp saved_adress
	}
}