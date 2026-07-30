#include <StdInc.h>
#include "FfbBridge.h"

#ifdef _M_AMD64
#pragma optimize("", off)

extern void FfbLog(const char* format, ...);

static int32_t* g_state;

static bool FfbOpenSection()
{
	if (g_state)
		return true;

	HANDLE section = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr,
		PAGE_READWRITE, 0, 64, L"OpenParrot_FfbState");

	if (!section)
		return false;

	g_state = (int32_t*)MapViewOfFile(section, FILE_MAP_ALL_ACCESS, 0, 0, 64);

	if (!g_state)
		return false;

	g_state[0] = 'OPFB';
	FfbLog("publishing on OpenParrot_FfbState");
	return true;
}

void FfbPublishForce(unsigned int torque, unsigned int spring, unsigned int friction)
{
	if (!FfbOpenSection())
		return;

	g_state[2] = (int32_t)torque;
	g_state[3] = (int32_t)spring;
	g_state[4] = (int32_t)friction;

	// Written last, so a reader that sees a new sequence knows the rest is ready.
	g_state[1] = g_state[1] + 1;
}

void FfbPublishPhysics(float slip, float spring, float friction, float collisions,
	unsigned int rumbleFrames)
{
	if (!FfbOpenSection())
		return;

	memcpy(&g_state[5], &slip, sizeof(slip));
	memcpy(&g_state[6], &spring, sizeof(spring));
	memcpy(&g_state[7], &friction, sizeof(friction));
	memcpy(&g_state[8], &collisions, sizeof(collisions));

	g_state[9] = (int32_t)rumbleFrames;
}

#pragma optimize("", on)
#endif
