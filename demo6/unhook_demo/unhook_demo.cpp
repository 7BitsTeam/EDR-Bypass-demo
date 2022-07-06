// unhook_demo.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <intrin.h>
#include "Header.h"

using namespace std;

HookedSleep g_hookedSleep;

void WINAPI MySleep(DWORD dwMilliseconds)
{
	//
	// Locate this stack frame's return address.
	// 
	//MessageBoxA(0,"whoami",NULL, NULL);

	cout << "hooked sleep executed" << endl;
}


bool fastTrampoline(bool installHook, BYTE* addressToHook, LPVOID jumpAddress, HookTrampolineBuffers* buffers /*= NULL*/)
{
#ifdef _WIN64
	uint8_t trampoline[] = {
		0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r10, addr
		0x41, 0xFF, 0xE2                                            // jmp r10
	};

	uint64_t addr = (uint64_t)(jumpAddress);
	memcpy(&trampoline[2], &addr, sizeof(addr));
#else
	uint8_t trampoline[] = {
		0xB8, 0x00, 0x00, 0x00, 0x00,     // mov eax, addr
		0xFF, 0xE0                        // jmp eax
	};

	uint32_t addr = (uint32_t)(jumpAddress);
	memcpy(&trampoline[1], &addr, sizeof(addr));
#endif

	DWORD dwSize = sizeof(trampoline);
	DWORD oldProt = 0;
	bool output = false;

	if (installHook)
	{
		if (buffers != NULL)
		{
			if (buffers->previousBytes == nullptr || buffers->previousBytesSize == 0)
				return false;

			memcpy(buffers->previousBytes, addressToHook, buffers->previousBytesSize);
		}

		if (::VirtualProtect(
			addressToHook,
			dwSize,
			PAGE_EXECUTE_READWRITE,
			&oldProt
		))
		{
			memcpy(addressToHook, trampoline, dwSize);
			output = true;
		}
	}
	else
	{
		if (buffers == NULL)
			return false;

		if (buffers->originalBytes == nullptr || buffers->originalBytesSize == 0)
			return false;

		dwSize = buffers->originalBytesSize;

		if (::VirtualProtect(
			addressToHook,
			dwSize,
			PAGE_EXECUTE_READWRITE,
			&oldProt
		))
		{
			memcpy(addressToHook, buffers->originalBytes, dwSize);
			output = true;
		}
	}

	static typeNtFlushInstructionCache pNtFlushInstructionCache = NULL;
	if (!pNtFlushInstructionCache)
		pNtFlushInstructionCache = (typeNtFlushInstructionCache)
		GetProcAddress(GetModuleHandleA("ntdll"), "NtFlushInstructionCache");

	//
	// We're flushing instructions cache just in case our hook didn't kick in immediately.
	//
	if (pNtFlushInstructionCache)
		pNtFlushInstructionCache(GetCurrentProcess(), addressToHook, dwSize);

	::VirtualProtect(
		addressToHook,
		dwSize,
		oldProt,
		&oldProt
	);

	return output;
}

bool hookSleep()
{
	HookTrampolineBuffers buffers = { 0 };
	buffers.previousBytes = g_hookedSleep.sleepStub;
	buffers.previousBytesSize = sizeof(g_hookedSleep.sleepStub);

	g_hookedSleep.origSleep = reinterpret_cast<typeSleep>(Sleep);

	if (!fastTrampoline(true, (BYTE*)::Sleep, (void*)& MySleep, &buffers))
		return false;

	return true;
}

int main()
{
	hookSleep();
	Sleep(5000);
	#define FROM_DISK == 1
	HMODULE hwhand = LoadLibraryA("RefleXXion-DLL.dll");
	Sleep(5000);
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
