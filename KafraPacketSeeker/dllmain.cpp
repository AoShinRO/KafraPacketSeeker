#include "stdafx.h"
#include "config.h"
#include <iostream>
#include <vector>
#include <fstream>

typedef int (WINAPI* PSEND)(SOCKET s, const char* buf, int len, int flags);
typedef int (WINAPI* PRECV)(SOCKET s, const char* buf, int len, int flags);

typedef int (WINAPI* PCLOSESOCKET) (SOCKET s);

PRECV OrigRecv;
PSEND OrigSend;

//===========================DEBUGER===========================
void attach_console() {
#if defined USE_CONSOLE_LOG
	AllocConsole();
	freopen("CONOUT$", "w", stdout); // redireciona printf ao console
#endif
}

void debug_log(std::string log, int len) {
#if defined USE_CONSOLE_LOG
	printf("Packet Header: %s /Size: %d\n", log.c_str(), len);
#else
	FILE* fp;

	fp = fopen("log.txt", "ab");

	std::string finallog = "Packet Header: " + log + " /Size: " + len;
	fwrite(finallog.c_str(), finallog.size(), 1, fp);
	fputc(0x0d, fp);
	fputc(0x0a, fp);
	fclose(fp);
#endif
}

//===========================RECV===========================
int WINAPI __stdcall MyRecv(SOCKET s, const char* buf, int len, int flags)
{
	int RecvedBytes = OrigRecv(s, buf, len, flags);
	if (RecvedBytes == SOCKET_ERROR) return RecvedBytes;

	unsigned short packetHeader;
	memcpy(&packetHeader, buf, sizeof(packetHeader));
	char hexString[10];
	snprintf(hexString, sizeof(hexString), "0x%04X", packetHeader);
	debug_log(hexString, len);

	return RecvedBytes;
}

//===========================RECV===========================
int WINAPI __stdcall MySend(SOCKET s, const char* buf, int len, int flags)
{
	int SendBytes = OrigSend(s, buf, len, flags); 
	if (SendBytes == SOCKET_ERROR) return SendBytes;

	unsigned short packetHeader;
	memcpy(&packetHeader, buf, sizeof(packetHeader));
	char hexString[10];
	snprintf(hexString, sizeof(hexString), "0x%04X", packetHeader);
	debug_log(hexString, len);

	return SendBytes;
}

//===========================DLL===========================
HMODULE LoadDllFromSystemDirectory(const std::wstring& dllname) {
	wchar_t systemdir[MAX_PATH];
	::GetSystemDirectoryW(systemdir, MAX_PATH);

	wchar_t fullpath[MAX_PATH];
	::PathCombineW(fullpath, systemdir, dllname.c_str());

	return ::LoadLibraryW(fullpath);
}

//===========================HOOK===========================
BOOL InstallProxyFunction(LPCTSTR dllname, LPCSTR exportname, VOID* ProxyFunction, LPVOID* pOriginalFunction)
{
	BOOL result = FALSE;

	HMODULE hDll;

	hDll = LoadDllFromSystemDirectory(dllname);

	if (!hDll)
		return result;

	BYTE* p = (BYTE*)::GetProcAddress(hDll, exportname);

	if (p)
	{
		if (p[0] == 0x8b && p[1] == 0xff && ((p[-5] == 0x90 && p[-4] == 0x90 && p[-3] == 0x90 && p[-2] == 0x90 && p[-1] == 0x90) || (p[-5] == 0xcc && p[-4] == 0xcc && p[-3] == 0xcc && p[-2] == 0xcc && p[-1] == 0xcc))) {

			// find hotpatch structure.
			//
			// 9090909090 nop  x 5
			// 8bff       mov  edi,edi
			//       or
			// cccccccccc int 3 x 5
			// 8bff       mov edi,edi
			DWORD flOldProtect, flDontCare;
			if (::VirtualProtect((LPVOID)&p[-5], 7, PAGE_READWRITE, &flOldProtect))
			{
				p[-5] = 0xe9;              // jmp
				p[0] = 0xeb; p[1] = 0xf9;// jmp short [pc-7]

				*pOriginalFunction = (void*)&p[2];
				*((DWORD*)&p[-4]) = (DWORD)ProxyFunction - (DWORD)&p[-5] - 5;

				::VirtualProtect((LPVOID)&p[-5], 7, flOldProtect, &flDontCare);
				result = TRUE;
			}
		}
		else if (p[-5] == 0xe9 && p[0] == 0xeb && p[1] == 0xf9) {

			// find hotpached function.
			// jmp ****
			// jmp short [pc -7]
			DWORD flOldProtect, flDontCare;
			if (::VirtualProtect((LPVOID)&p[-5], 7, PAGE_READWRITE, &flOldProtect))
			{
				*pOriginalFunction = (LPVOID)(*((DWORD*)&p[-4]) + (DWORD)&p[-5] + 5);
				*((DWORD*)&p[-4]) = (DWORD)ProxyFunction - (DWORD)&p[-5] - 5;

				::VirtualProtect((LPVOID)&p[-5], 7, flOldProtect, &flDontCare);
				result = TRUE;
			}
		}
		else if (p[0] == 0xe9 && ((p[-5] == 0x90 && p[-4] == 0x90 && p[-3] == 0x90 && p[-2] == 0x90 && p[-1] == 0x90) || (p[-5] == 0xcc && p[-4] == 0xcc && p[-3] == 0xcc && p[-2] == 0xcc && p[-1] == 0xcc))) {

			// find irregular hook code. case by iro
			//
			// 9090909090 nop  x 5
			// e9******** jmp  im4byte
			//       or
			// cccccccccc int 3 x 5
			// e9******** jmp  im4byte
			DWORD flOldProtect, flDontCare;
			if (::VirtualProtect((LPVOID)&p[0], 5, PAGE_READWRITE, &flOldProtect))
			{
				*pOriginalFunction = (LPVOID)(*((DWORD*)&p[1]) + (DWORD)&p[0] + 5);

				*((DWORD*)&p[1]) = (DWORD)ProxyFunction - (DWORD)&p[0] - 5;

				::VirtualProtect((LPVOID)&p[0], 5, flOldProtect, &flDontCare);
				result = TRUE;
			}
		}
	}

	::FreeLibrary(hDll);
	return result;
}

//===========================MAINHOOK===========================
void WINAPI WinsockHook(void)
{
#if defined HOOK_RECEIVED || defined HOOK_BOTH
	InstallProxyFunction(L"ws2_32.dll", "recv", MyRecv, (LPVOID*)&OrigRecv);
#endif
#if defined HOOK_SEND || defined HOOK_BOTH
	InstallProxyFunction(L"ws2_32.dll", "send", MySend, (LPVOID*)&OrigSend);
#endif
#if defined HOOK_RECEIVED || defined HOOK_BOTH
	ReadProcessMemory(GetCurrentProcess(), (void*)GetProcAddress(GetModuleHandle(L"WS2_32.dll"), "recv"), bHookedRecv, 6, nullptr);
#endif
#if defined HOOK_SEND || defined HOOK_BOTH
	ReadProcessMemory(GetCurrentProcess(), (void*)GetProcAddress(GetModuleHandle(L"WS2_32.dll"), "send"), bHookedSend, 6, nullptr);
#endif
}

//===========================MAINDLLFUNC===========================
BOOL WINAPI DllMain(HINSTANCE hDll, DWORD dwReason, LPVOID lpReserved)
{
	switch (dwReason)
	{
	case DLL_PROCESS_ATTACH:
		::DisableThreadLibraryCalls(hDll);
		attach_console();
		WinsockHook();
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:// Manipulação de inicialização/destruição específica da thread
		break;
	case DLL_PROCESS_DETACH:// Limpeza na saída do processo
		break;
	}
	return TRUE;
}
