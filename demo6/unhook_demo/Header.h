#pragma once
#include <windows.h>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <vector>

typedef void  (WINAPI* typeSleep)(
	DWORD dwMilis
	);

typedef DWORD(NTAPI* typeNtFlushInstructionCache)(
	HANDLE ProcessHandle,
	PVOID BaseAddress,
	ULONG NumberOfBytesToFlush
	);

typedef std::unique_ptr<std::remove_pointer<HANDLE>::type, decltype(&::CloseHandle)> HandlePtr;

struct HookedSleep
{
	typeSleep origSleep;
	BYTE    sleepStub[16];
};

struct HookTrampolineBuffers
{
	// (Input) Buffer containing bytes that should be restored while unhooking.
	BYTE* originalBytes;
	DWORD originalBytesSize;

	// (Output) Buffer that will receive bytes present prior to trampoline installation/restoring.
	BYTE* previousBytes;
	DWORD previousBytesSize;
};


void WINAPI MySleep(DWORD _dwMilliseconds);