#include "stdafx.h"
#include "config.h"

//===========================PACKAGE PREDICTOR===========================
void generate_struct_suggestion(unsigned short header, const PacketAnalysis& analysis) {
	printf("\n=== STRUCT SUGESTION TO 0x%04X ===\n", header);
	printf("Sended: %d | len: ", analysis.sample_count);

	if (analysis.min_size == analysis.max_size) {
		printf("fixed (%d bytes)\n", analysis.min_size);
	}
	else {
		printf("variable (%d-%d bytes)\n", analysis.min_size, analysis.max_size);
	}

	printf("struct PACKET_0x%04X {\n", header);
	printf("    uint16 packetType;  // 0x%04X\n", header);

	int current_offset = 2;
	if (analysis.has_length_field) {
		printf("    uint16 packetLength;\n");
		current_offset += 2;
	}
	int count = 1;
	for (const auto& field : analysis.detected_fields) {
		if (field.offset >= current_offset) {
			if (field.type_hint == "string") {
				printf("    char[%d] va_%d;  // offset %d", field.size, count, field.offset);
			}
			else if (field.type_hint == "uint8") {
				printf("    uint8 va_%d;  // offset %d", count, field.offset);
			}
			else if (field.type_hint == "uint16") {
				printf("    uint16 va_%d;  // offset %d", count, field.offset);
			}
			else {
				printf("    uint32 va_%d;  // offset %d [unknown]", count, field.offset);
			}

			if (!field.is_constant) {
				printf(" [variable]");
			}
			printf("\n");

			current_offset = field.offset + field.size;
			count++;
		}
	}

	printf("} __attribute__((packed));\n");
	printf("=====================================\n\n");
}

bool is_printable_string(const char* data, int max_len, int& out_len) {
	if (max_len < 2) {
		out_len = 0;
		return false;
	}

	out_len = 0;

	
	for (int i = 0; i < max_len && i < 128; i++) {  // max 128 chars  
		if (data[i] == 0) { //null terminated
			out_len = i + 1;
			return i > 0; 
		}

		 
		if (data[i] < 32 || data[i] > 126) {
			if (i >= 3) {
				out_len = i;
				return true;
			}
			out_len = 0;
			return false;
		}
	}
 
	if (max_len >= 3) {
		out_len = max_len;
		return true;
	}

	out_len = 0;
	return false;
}

bool looks_like_uint8(const char* data) {
	uint32_t val;
	memcpy(&val, data, 1);

	return val < 0xFF && val >= 0;
}

bool looks_like_uint16(const char* data) {
	uint32_t val;
	memcpy(&val, data, 2);

	return val < 0xFFFF && val >= 0;
}

void analyze_fields(const char* buf, int len, PacketAnalysis& analysis) {
	int offset = analysis.has_length_field ? 4 : 2;  // skip header 

	while (offset < len) {
		PacketField field;
		field.offset = offset;

		int str_len = 0;
		if (is_printable_string(buf + offset, len - offset, str_len)) {
			field.type_hint = "string";
			field.size = str_len;
			offset += str_len;
		}
		else if (offset + 1 <= len && looks_like_uint8(buf + offset)) {
			field.type_hint = "uint8";
			field.size = 1;
			offset += 1;
		}
		else if (offset + 2 <= len && looks_like_uint16(buf + offset)) {
			field.type_hint = "uint16";
			field.size = 2;
			offset += 2;
		}
		else {
			field.type_hint = "unknown";
			field.size = min(4, len - offset);
			offset += field.size;
		}

		if (field.values.size() > 1) {
			field.is_constant = false;
		}

		analysis.detected_fields.push_back(field);
	}
}

void analyze_packet(const char* buf, int len, bool is_send) {
#if defined USE_CONSOLE_LOG
	if (len < 2) return;

	unsigned short header;
	memcpy(&header, buf, sizeof(header));

	PacketAnalysis& analysis = packet_db[header];
	analysis.sample_count++;
	analysis.observed_sizes.push_back(len);
	analysis.size_frequency[len]++;
	analysis.min_size = min(analysis.min_size, len);
	analysis.max_size = max(analysis.max_size, len);

	if (len >= 4) { //skip header
		uint16_t packet_len;
		memcpy(&packet_len, buf + 2, sizeof(packet_len));
		if (packet_len == len) {
			analysis.has_length_field = true;
		}
	}
 
	analyze_fields(buf, len, analysis);
  
	if (analysis.sample_count % 10 == 0) { // generate a suggestion
		generate_struct_suggestion(header, analysis);
	}
#endif
}

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
	analyze_packet(buf, RecvedBytes, false);

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
	analyze_packet(buf, SendBytes, true);

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
	ReadProcessMemory(GetCurrentProcess(), (void*)GetProcAddress(GetModuleHandle(L"WS2_32.dll"), "recv"), bHookedRecv, 6, nullptr);
#endif
#if defined HOOK_SEND || defined HOOK_BOTH
	InstallProxyFunction(L"ws2_32.dll", "send", MySend, (LPVOID*)&OrigSend);
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
