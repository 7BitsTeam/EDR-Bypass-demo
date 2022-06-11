# SharpInjector
Project now has a 2nd branch, DInvoke, that implements Reprobate for D/Invoke functionality - 1/15/2022

## Objectives
* Utilize encrypted shellcode
* Option to include the shellcode within the executable or download shellcode from URL
* Ability to quickly switch which Windows API call is used for execution
* Ability to spawn a specifed process (default: iexplore.exe) for shellcode to be injected into (for remote injection methods)
* Ability to spoof the parent process (default: explorer.exe) of target process that will be injected into (for remote injection methods)

## Overview 
This solution has two projects: ScEncryptor and SharpInjector. The ScEncryptor project will allow you to encrypt a `.bin` file containing your shellcode. The SharpInjector project will be compiled with the resulting encrypted shellcode and inject it into memory. The shellcode the project comes with simply opens calc.

## Usage
1. Set the encryption key in ScEncryptor\Program.cs (the key must be 16/24/32 bytes)
2. Build the ScEncryptor project
3. Use the resulting executable to encrypt your shellcode: `ScEncryptor.exe C:\Temp\shellcode.bin` (The encrypted shellcode will be automatically inserted in SharpInjector\Shellycode.cs)
4. Optional: set `EncSc = ""` within SharpInjector\Shellycode.cs and instead host the shellcode string on the web. Set the `ShellcodeUrl` variable in SharpInjector\Program.cs to the URL of the `EncSc` string
5. Set the decryption key in SharpInjector\Program.cs
6. Set the `exeMethod`, `ParentName`, and `ProgramPath` variables in SharpInjector\Program.cs to desired values
7. Build the SharpInjector project (set to x64 before building)

## Execution Methods
Current options for shellcode execution include the following Windows API calls:
* CreateFiber
* CreateRemoteThread
* CreateRemoteThreadEx
* CreateThread
* EtwpCreateEtwThread
* QueueUserAPC
* RtlCreateUserThread
