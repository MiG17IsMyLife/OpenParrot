#include <StdInc.h>
#pragma optimize("", off)
#include <iphlpapi.h>
#include <winsock2.h>
#include <sysinfoapi.h>
#include "Utility/InitFunction.h"
#include "Functions/Global.h"
#include <tlhelp32.h>
#include "AmAuthGame64_Config/AMConfig.cpp"
#include "AmAuthGame64_Config/WritableConfig.cpp"

#ifndef _M_IX86
u_short HttpPort = 80;
//const char* powerOn = "http://x/allnet/poweron";
//const char* dlOrder = "http://x/allnet/downloadorder";
//const char* localhost = "x";

linb::ini myconfig;

static char gatewayAddressStr[256];

bool (WINAPI* orig_SetSystemTime)(const SYSTEMTIME* lpSystemTime);

static bool SetSystemTimeHook(const SYSTEMTIME* lpSystemTime)
{
	return 1;
}

u_short(PASCAL FAR* htons_orig)(u_short hostshort);

static u_short htonsHook(u_short hostshort)
{
	std::string ports = config["Network"]["Port"];
	if (!ports.empty())
	{
		HttpPort = std::atoi(ports.c_str());
	}


#if _DEBUG
	info(true, "htons: %i", hostshort);
#endif

	if (hostshort == 80) {
#ifdef _DEBUG
		info(true, "replacing port...");
#endif
		return htons_orig(HttpPort);
	}
	else {
		return htons_orig(hostshort);
	}
}

int(WSAAPI* g_origgetaddrinfoo)(PCSTR pNodeName, PCSTR pServiceName, const ADDRINFOA* pHints, PADDRINFOA* ppResult);

/*int WSAAPI getaddrinfoHookAMAuth(PCSTR pNodeName, PCSTR pServiceName, const ADDRINFOA* pHints, PADDRINFOA* ppResult)
{
#if _DEBUG
	info(true, "getaddrinfo: %s, %s", pNodeName, pServiceName);
#endif
	if (strcmp(pNodeName, "tenporouter.loc") == 0)
	{
		return g_origgetaddrinfoo(config["General"]["NetworkAdapterIP"].c_str(), pServiceName, pHints, ppResult);
	}
	else if (strcmp(pNodeName, "bbrouter.loc") == 0)
	{
		return g_origgetaddrinfoo(config["General"]["NetworkAdapterIP"].c_str(), pServiceName, pHints, ppResult);
	}
	else if (strcmp(pNodeName, "naominet.jp") == 0)
	{
		return g_origgetaddrinfoo(config["Network"]["ServerIP"].c_str(), pServiceName, pHints, ppResult);
	}
	else {
		return g_origgetaddrinfoo(pNodeName, pServiceName, pHints, ppResult);
	}
}*/

int WSAAPI getaddrinfoHookAMAuth(PCSTR pNodeName, PCSTR pServiceName, const ADDRINFOA* pHints, PADDRINFOA* ppResult)
{
#if _DEBUG
	info(true, "getaddrinfo: %s, %s", pNodeName, pServiceName);
#endif
	if (strcmp(pNodeName, "tenporouter.loc") == 0)
	{
		return g_origgetaddrinfoo(config["General"]["NetworkAdapterIP"].c_str(), pServiceName, pHints, ppResult);
	}
	else if (strcmp(pNodeName, "bbrouter.loc") == 0)
	{
		return g_origgetaddrinfoo(config["General"]["NetworkAdapterIP"].c_str(), pServiceName, pHints, ppResult);
	}
	else if (strcmp(pNodeName, "naominet.jp") == 0)
	{
		return g_origgetaddrinfoo("wangan.network", pServiceName, pHints, ppResult);
	}
	else {
		return g_origgetaddrinfoo(pNodeName, pServiceName, pHints, ppResult);
	}
}

static int WINAPI GetRTTAndHopCountStubAM(_In_ uint32_t DestIpAddress, _Out_ PULONG HopCount, _In_ ULONG MaxHops, _Out_ PULONG RTT)
{
	return 1;
}

static std::string getProfileString(LPCSTR name, LPCSTR key, LPCSTR def, LPCSTR filename)
{
	char temp[1024];
	int result = GetPrivateProfileStringA(name, key, def, temp, sizeof(temp), filename);
	return std::string(temp, result);
}

static void prepareWMMT()
{
	static char newCrc[0x400];

	// Check AMConfig.ini.orig
	if (FILE* file = fopen("AMConfig.ini.orig", "r")) 
	{
		fclose(file);
	}
	else
	{
		MoveFile(L"AMConfig.ini", L"AMConfig.ini.orig");
	}

	// Create AMConfig
	FILE* file2 = fopen("AMConfig.ini", "wb");
	fwrite(AMConfig, 1, sizeof(AMConfig), file2);
	fclose(file2);


	// Create WritableConfig
	FILE* writecon = fopen("WritableConfig.ini", "wb");
	fwrite(WritableConfig, 1, sizeof(WritableConfig), writecon);
	fclose(writecon);

	// maybe useless, and wrong too lmao
	static uintptr_t imageBase;
	imageBase = (uintptr_t)GetModuleHandleA(0);
	injector::MakeNOP(imageBase + 0x3BB3, 6, true); // FF 15 37 A9 02 00 

	/*
	// Set IP hooks
	std::string gameURL = config["General"]["Game URL"];
	localhost = gameURL.c_str();

	// poweron
	char powerOnStr[100];
	strcat(powerOnStr, "https://");
	strcat(powerOnStr, localhost);
	strcat(powerOnStr, "/allnet/poweron");
	powerOn = powerOnStr;

	// downloadorder
	char dlOrderStr[100];
	strcat(dlOrderStr, "https://");
	strcat(dlOrderStr, localhost);
	strcat(dlOrderStr, "/allnet/downloadorder");
	dlOrder = dlOrderStr;
	*/

	return;
}

typedef HRESULT(__stdcall* DllRegisterServerFunc)();

static void dllreg()
{
	//iauthdll.dll
	HMODULE hModule = LoadLibrary(L"iauthdll.dll");
	DllRegisterServerFunc DllRegisterServer = (DllRegisterServerFunc)GetProcAddress(hModule, "DllRegisterServer");
	HRESULT hr = DllRegisterServer();
	if (SUCCEEDED(hr))
	{
#ifdef DEBUG
		īnfo(true, "iauthdll.dll registered successfully!");
#endif
	}
	else
	{
		int msgboxID = MessageBox(
			NULL,
			(LPCWSTR)L"There was an error registering a DLL, make sure you run TeknoParrotUI as admin",
			(LPCWSTR)L"iauthdll.dll Register Error",
			MB_ICONWARNING | MB_OK
		);
		// There was an error
	}
}

static InitFunction HookAmAuthD64([]()
{
	// Write config files for maximum tune
	prepareWMMT();

	// DLL Register
	dllreg();

	// Hook
	MH_Initialize();
	MH_CreateHookApi(L"kernel32.dll", "SetSystemTime", SetSystemTimeHook, (void**)&orig_SetSystemTime);
	MH_CreateHookApi(L"ws2_32.dll", "getaddrinfo", getaddrinfoHookAMAuth, (void**)&g_origgetaddrinfoo);
	MH_CreateHookApi(L"ws2_32.dll", "htons", htonsHook, (void**)&htons_orig);
	MH_CreateHookApi(L"iphlpapi.dll", "GetRTTAndHopCount", GetRTTAndHopCountStubAM, NULL);
	MH_EnableHook(MH_ALL_HOOKS);

}, GameID::AmAuthD64);
#pragma optimize("", on)
#endif