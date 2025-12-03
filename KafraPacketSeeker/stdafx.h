// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
#pragma once

// Exclude rarely-used stuff from Windows headers
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <memory>
#include <stdio.h>
#include <thread>
#include <TlHelp32.h>
#include <string>
#include <iostream>
#include <shlwapi.h>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "OpenGL32.lib")

#include <winsock2.h>
#include <stdio.h>
#include <ws2tcpip.h>
#include <Iphlpapi.h>
#include <Assert.h>
#include <process.h>

SYSTEMTIME st;

// The Winsock Hook Main Function
void WINAPI WinsockHook(void);
int WINAPI __stdcall MySend(SOCKET s, const char* buf, int len, int flags);
int WINAPI __stdcall MyRecv(SOCKET s, const char* buf, int len, int flags);
#define CONVIP(ip) ((ip)>>24)&0xFF,((ip)>>16)&0xFF,((ip)>>8)&0xFF,((ip)>>0)&0xFF
#define ARRAYLENGTH(A) ( sizeof(A)/sizeof((A)[0]) )

unsigned char bHookedRecv[6]; // Bytes após o hook de Recv
unsigned char bHookedSend[6]; // Bytes após o hook de Send