#include <StdInc.h>
#include "Utility/InitFunction.h"
#include "Utility/GameDetect.h"
#include "Functions/Global.h"
#include "Functions/FFB/FfbBridge.h"
#include "MinHook.h"
#include <Utility/Hooking.Patterns.h>

#ifdef _M_AMD64
#pragma optimize("", off)

static bool g_enabled;
static bool g_logging;
static bool g_suppressError;
static bool g_stubRunning;

static FILE* g_log;
static CRITICAL_SECTION g_logLock;

void FfbLog(const char* format, ...)
{
	if (!g_logging)
		return;

	char buffer[512];

	SYSTEMTIME now;
	GetLocalTime(&now);

	int length = _snprintf(buffer, sizeof(buffer), "[%02d:%02d:%02d.%03d] ",
		now.wHour, now.wMinute, now.wSecond, now.wMilliseconds);

	if (length < 0)
		length = 0;

	va_list args;
	va_start(args, format);
	_vsnprintf(buffer + length, sizeof(buffer) - length - 1, format, args);
	va_end(args);

	buffer[sizeof(buffer) - 1] = '\0';

	EnterCriticalSection(&g_logLock);

	if (g_log)
	{
		fprintf(g_log, "%s\n", buffer);
		fflush(g_log);
	}

	LeaveCriticalSection(&g_logLock);
}

// ---------------------------------------------------------------------------
// The board stub
// ---------------------------------------------------------------------------

static const char* const kPipeName = "\\\\.\\pipe\\op-strpcb";

// Wheel centre, the value the game's own FFB object initialises itself to.
static const uint16_t kWheelCentre = 0x01FF;

static volatile LONG g_reportPoweredOff;

const char* FfbStrPcbPipe()
{
	return g_stubRunning ? kPipeName : nullptr;
}

// C01 reports the motor up and C06 reports it down. State_PowerOn waits for the
// first, the power off wait for the second, and a boot check that never sees
// C06 sits there until it times out.
static DWORD WINAPI FfbStubThread(LPVOID)
{
	uint8_t buffer[256];

	// The game closes the port and opens it again, entering the test menu does
	for (;;)
	{
		HANDLE pipe = CreateNamedPipeA(kPipeName,
			PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_WAIT,
			PIPE_UNLIMITED_INSTANCES, 512, 512, 25, nullptr);

		if (pipe == INVALID_HANDLE_VALUE)
		{
			FfbLog("stub: CreateNamedPipe failed (%lu)", GetLastError());
			Sleep(1000);
			continue;
		}

		BOOL connected = ConnectNamedPipe(pipe, nullptr)
			? TRUE
			: (GetLastError() == ERROR_PIPE_CONNECTED);

		if (!connected)
		{
			FfbLog("stub: ConnectNamedPipe failed (%lu)", GetLastError());
			CloseHandle(pipe);
			Sleep(1000);
			continue;
		}

		FfbLog("stub: game connected");

		for (;;)
		{
			DWORD available = 0;

			// One thread and one handle: a blocking ReadFile would hold the file
			// object and stall every write.
			if (!PeekNamedPipe(pipe, nullptr, 0, nullptr, &available, nullptr))
				break;

			if (available > 0)
			{
				DWORD wanted = (available > sizeof(buffer)) ? (DWORD)sizeof(buffer) : available;
				DWORD read = 0;

				if (!ReadFile(pipe, buffer, wanted, &read, nullptr) || read == 0)
					break;

				FfbLog("stub: %lu bytes from the game", read);
			}

			uint8_t frames[6] =
			{
				0, 0, 0,
				'H', kWheelCentre >> 8, kWheelCentre & 0xFF
			};

			memcpy(frames, g_reportPoweredOff ? "C06" : "C01", 3);

			DWORD written = 0;

			if (!WriteFile(pipe, frames, sizeof(frames), &written, nullptr))
				break;

			Sleep(4);
		}

		FfbLog("stub: link closed (%lu), waiting for the game again", GetLastError());
		DisconnectNamedPipe(pipe);
		CloseHandle(pipe);
	}
}

// ---------------------------------------------------------------------------
// Hooks
// ---------------------------------------------------------------------------

static bool FfbInstall(const char* name, hook::pattern pattern, void* detour, void** original)
{
	if (pattern.size() != 1)
	{
		FfbLog("%s: pattern matched %zu times, not hooking", name, pattern.size());
		return false;
	}

	void* target = pattern.get(0).get<void>(0);

	if (MH_CreateHook(target, detour, original) != MH_OK || MH_EnableHook(target) != MH_OK)
	{
		FfbLog("%s: hook failed", name);
		return false;
	}

	FfbLog("%s hooked at rva 0x%llX", name,
		(unsigned long long)((uintptr_t)target - (uintptr_t)GetModuleHandleA(nullptr)));

	return true;
}

// State_PowerOn and State_PowerOff, which decide which status the board should
// be reporting.
static uintptr_t(__fastcall* g_origPowerOn)(void*, uintptr_t, uintptr_t, uintptr_t);
static uintptr_t(__fastcall* g_origPowerOff)(void*, uintptr_t, uintptr_t, uintptr_t);

static uintptr_t __fastcall FfbPowerOnHook(void* self, uintptr_t a2, uintptr_t a3, uintptr_t a4)
{
	if (InterlockedExchange(&g_reportPoweredOff, 0) != 0)
		FfbLog("board now reports C01");

	return g_origPowerOn(self, a2, a3, a4);
}

static uintptr_t __fastcall FfbPowerOffHook(void* self, uintptr_t a2, uintptr_t a3, uintptr_t a4)
{
	if (InterlockedExchange(&g_reportPoweredOff, 1) == 0)
		FfbLog("board now reports C06");

	return g_origPowerOff(self, a2, a3, a4);
}

// The FFB error state, a leaf that raises a global flag the boot check turns
// into E2212 on screen.
static uintptr_t(__fastcall* g_origErrorState)(void*, uintptr_t, uintptr_t, uintptr_t);
static uint8_t* g_errorFlag;

static uintptr_t __fastcall FfbErrorStateHook(void* self, uintptr_t a2, uintptr_t a3, uintptr_t a4)
{
	uintptr_t result = g_origErrorState(self, a2, a3, a4);

	if (g_suppressError && g_errorFlag)
		*g_errorFlag = 0;

	return result;
}

// The torque entry point. rdx is the ten bit torque, r8 the spring coefficient
// and r9 the friction coefficient, all destined for the board.
static uintptr_t(__fastcall* g_origTorque)(uintptr_t, uintptr_t, uintptr_t, uintptr_t);

static uintptr_t __fastcall FfbTorqueHook(uintptr_t a1, uintptr_t torque, uintptr_t spring, uintptr_t friction)
{
	FfbPublishForce((unsigned int)(torque & 0xFFFF),
		(unsigned int)(spring & 0xFF), (unsigned int)(friction & 0xFF));

	return g_origTorque(a1, torque, spring, friction);
}

// The effect trigger, which runs the generators feeding the collision channel and then calls the engine below.
static uintptr_t(__fastcall* g_origTrigger)(void*);
static volatile LONG g_rumbleFrames;

static uintptr_t __fastcall FfbTriggerHook(void* self)
{
	if (self)
		InterlockedExchange(&g_rumbleFrames, (LONG)*(uint32_t*)((uint8_t*)self + 0x1C));

	return g_origTrigger(self);
}

// The effect engine, which receives the physics the road feel is built from.
static uintptr_t(__fastcall* g_origEngine)(void*, float, float, float);

static uintptr_t __fastcall FfbEngineHook(void* self, float slip, float spring, float friction)
{
	// collisions arrives on the stack; the register arguments are all taken.
	float collisions = *(float*)((uint8_t*)_AddressOfReturnAddress() + 0x28);

	FfbPublishPhysics(slip, spring, friction, collisions, (unsigned int)g_rumbleFrames);

	return g_origEngine(self, slip, spring, friction);
}

// ---------------------------------------------------------------------------

static void FfbInstallHooks()
{
	g_enabled = !ToBool(config["FFB"]["Disable"]);
	g_suppressError = !ToBool(config["FFB"]["ReportErrors"]);

	g_logging = ToBool(config["FFB"]["Log"]) ||
		GetFileAttributesA("ffblog.on") != INVALID_FILE_ATTRIBUTES;

	if (g_logging)
	{
		InitializeCriticalSection(&g_logLock);
		g_log = fopen("OpenParrotFfb.log", "a");
		FfbLog("---- session start, game id %d ----", (int)GameDetect::currentGame);
	}

	if (!g_enabled)
		return;

	// COM1 is the FFB PCB on a drive cabinet and the touch panel on a terminal.
	// A terminal has no wheel, and taking the port there only breaks the touch
	// screen, which the boot check reports as E2405.
	if (ToBool(config["General"]["TerminalMode"]))
	{
		FfbLog("terminal mode - COM1 stays with the touch panel");
		return;
	}

	MH_Initialize();

	FfbInstall("State_PowerOn",
		hook::pattern(
			"48 89 5C 24 08 57 48 81 EC 80 00 00 00 33 FF 48 "
			"8B D9 48 8D 15 ? ? ? ? 48 8D 4C 24 30 44 8D 47 16"),
		FfbPowerOnHook, (void**)&g_origPowerOn);

	FfbInstall("State_PowerOff",
		hook::pattern(
			"48 89 5C 24 08 57 48 81 EC 80 00 00 00 33 FF 48 "
			"8B D9 48 8D 15 ? ? ? ? 48 8D 4C 24 30 44 8D 47 17"),
		FfbPowerOffHook, (void**)&g_origPowerOff);

	FfbInstall("torque entry",
		hook::pattern(
			"48 83 EC 38 48 8B 0D ? ? ? ? 48 85 C9 74 11 0F B6 "
			"44 24 60 48 8B 09 88 44 24 20 E8 ? ? ? ? 48 83 C4 38 C3"),
		FfbTorqueHook, (void**)&g_origTorque);

	FfbInstall("effect trigger",
		hook::pattern(
			"40 53 48 83 EC 30 80 79 5C 00 48 8B D9 74 11 48 "
			"8B 49 08 E8 ? ? ? ? 84 C0 74 04 C6 43 5C 00 8B 4B 1C"),
		FfbTriggerHook, (void**)&g_origTrigger);

	FfbInstall("effect engine",
		hook::pattern(
			"48 83 EC 38 F3 0F 10 44 24 60 48 8B 49 08 F3 0F "
			"11 44 24 20 E8 ? ? ? ? 48 83 C4 38 C3"),
		FfbEngineHook, (void**)&g_origEngine);

	auto errorState = hook::pattern("C6 05 ? ? ? ? 01 32 C0 C6 81 FC 00 00 00 00 C3");

	if (errorState.size() == 1)
	{
		// Resolve the flag from the instruction's own displacement so it stays correct across builds.
		const uint8_t* store = (const uint8_t*)errorState.get(0).get<void>(0);
		int32_t displacement = *(const int32_t*)(store + 2);
		g_errorFlag = (uint8_t*)(store + 7 + displacement);

		FfbInstall("error state", errorState, FfbErrorStateHook, (void**)&g_origErrorState);
	}

	g_stubRunning = true;
	CreateThread(nullptr, 0, FfbStubThread, nullptr, 0, nullptr);
}

static InitFunction ffbWmmt6([]() { FfbInstallHooks(); }, GameID::WMMT6);
static InitFunction ffbWmmt6R([]() { FfbInstallHooks(); }, GameID::WMMT6R);

#pragma optimize("", on)
#endif
