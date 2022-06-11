using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

namespace SharpInjector
{
    class WinAPI
    {
        public static readonly UInt32 MEM_COMMIT = 0x1000;
        public static readonly UInt32 MEM_RESERVE = 0x2000;
        public static readonly UInt32 PAGE_EXECUTE_READ = 0x20;
        public static readonly UInt32 PAGE_READWRITE = 0x04;
        public static readonly UInt32 PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000;
        public static readonly UInt32 SW_HIDE = 0x0000;

        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }

        public struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            [MarshalAs(UnmanagedType.Bool)]
            public bool bInheritHandle;
        }

        public struct STARTUPINFO
        {
            public uint cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        public struct STARTUPINFOEX
        {
            public STARTUPINFO StartupInfo;
            public IntPtr lpAttributeList;
        }

        public enum StartupInfoFlags : uint
        {
            STARTF_USESHOWWINDOW = 0x00000001,
            STARTF_USESTDHANDLES = 0x00000100
        }

        public enum ProcessCreationFlags : uint
        {
            CREATE_NO_WINDOW = 0x08000000,
            CREATE_SUSPENDED = 0x00000004,
            EXTENDED_STARTUPINFO_PRESENT = 0x00080000
        }

        public enum ProcessAccessFlags : uint
        {
            PROCESS_CREATE_PROCESS = 0x0080,
            PROCESS_DUP_HANDLE = 0x0040
        }

        public enum FreeType : uint
        {
            MEM_DECOMMIT = 0x4000,
            MEM_RELEASE = 0x8000,
        }

        public enum ThreadAccess : int
        {
            SET_CONTEXT = 0x0010
        }

        [DllImport("kernel32.dll")]
        public static extern bool CloseHandle(
            IntPtr hObject
        );

        [DllImport("kernel32.dll")]
        public static extern IntPtr ConvertThreadToFiber(
            IntPtr lpParameter);

        [DllImport("kernel32.dll")]
        public static extern IntPtr CreateFiber(
            uint dwStackSize,
            IntPtr lpStartAddress,
            IntPtr lpParameter);

        [DllImport("kernel32.dll")]
        public static extern bool CreateProcess(
            string lpApplicationName,
            string lpCommandLine,
            ref SECURITY_ATTRIBUTES lpProcessAttributes,
            ref SECURITY_ATTRIBUTES lpThreadAttributes,
            bool bInheritHandles,
            ProcessCreationFlags dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            ref STARTUPINFOEX lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll")]
        public static extern IntPtr CreateThread(
            IntPtr lpThreadSecurityAttributes,
            uint dwStackSize,
            IntPtr lpStartAddress,
            IntPtr param,
            UInt32 dwCreationFlags,
            ref UInt32 lpThreadId);

        [DllImport("kernel32.dll")]
        public static extern IntPtr CreateRemoteThread(
            IntPtr hProcess,
            IntPtr lpThreadAttributes,
            uint dwStackSize,
            IntPtr lpStartAddress,
            IntPtr lpParameter,
            uint dwCreationFlags,
            IntPtr lpThreadId);

        [DllImport("kernel32.dll")]
        public static extern IntPtr CreateRemoteThreadEx(
            IntPtr hProcess,
            IntPtr lpThreadAttributes,
            uint dwStackSize,
            IntPtr lpStartAddress,
            IntPtr lpParameter,
            uint dwCreationFlags,
            IntPtr lpAttributeList,
            IntPtr lpThreadId);

        [DllImport("ntdll.dll")]
        public static extern IntPtr EtwpCreateEtwThread(
            IntPtr lpStartAddress,
            IntPtr lpParameter);

        [DllImport("kernel32.dll")]
        public static extern bool InitializeProcThreadAttributeList(
            IntPtr lpAttributeList,
            int dwAttributeCount,
            int dwFlags,
            ref IntPtr lpSize);

        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(
            ProcessAccessFlags dwDesiredAccess,
            bool bInheritHandle,
            int dwProcessId);

        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenThread(
            ThreadAccess dwDesiredAccess,
            bool bInheritHandle,
            int dwThreadId);

        [DllImport("kernel32.dll")]
        public static extern IntPtr QueueUserAPC(
            IntPtr pfnAPC,
            IntPtr hThread,
            IntPtr dwData
            );

        [DllImport("kernel32.dll")]
        public static extern uint ResumeThread(
            IntPtr hThread);

        [DllImport("kernel32.dll", EntryPoint = "RtlMoveMemory")]
        public static extern void RtlCopyMemory(
            IntPtr Destination,
            IntPtr Source,
            Int32 length);

        [DllImport("ntdll.dll")]
        public static extern long RtlCreateUserThread(
            IntPtr hProcess,
            UInt32 SecurityDescriptor,
            bool CreateSuspended,
            ulong StackZeroBits,
            UInt32 StackReserved,
            UInt32 StackCommit,
            IntPtr StartAddress,
            UInt32 StartParameter,
            IntPtr Destination,
            out IntPtr hThread,
            out UInt32 ClientID);

        [DllImport("kernel32.dll")]
        public static extern void SwitchToFiber(
            IntPtr lpFiber);

        [DllImport("kernel32.dll")]
        public static extern bool TerminateProcess(
            IntPtr hProcess,
            uint uExitCode);

        [DllImport("kernel32.dll")]
        public static extern bool UpdateProcThreadAttribute(
            IntPtr lpAttributeList,
            uint dwFlags,
            IntPtr Attribute,
            IntPtr lpValue,
            IntPtr cbSize,
            IntPtr lpPreviousValue,
            IntPtr lpReturnSize);

        [DllImport("kernel32.dll")]
        public static extern IntPtr VirtualAlloc(
            IntPtr lpAddress,
            Int32 dwSize,
            UInt32 flAllocationType,
            UInt32 flProtect);

       [DllImport("kernel32.dll")]
        public static extern IntPtr VirtualAllocEx(
            IntPtr hProcess,
            IntPtr lpAddress,
            Int32 dwSize,
            UInt32 flAllocationType,
            UInt32 flProtect);

        [DllImport("kernel32.dll")]
        public static extern bool VirtualFree(
            IntPtr lpAddress,
            UInt32 dwSize,
            FreeType dwFreeType);

        [DllImport("kernel32.dll")]
        public static extern bool VirtualFreeEx(
            IntPtr hProcess,
            IntPtr lpAddress,
            int dwSize,
            FreeType dwFreeType);

        [DllImport("kernel32.dll")]
        public static extern bool VirtualProtect(
            IntPtr lpAddress,
            int dwSize,
            uint flNewProtect,
            out uint lpflOldProtect);

        [DllImport("kernel32.dll")]
        public static extern bool VirtualProtectEx(
            IntPtr handle,
            IntPtr lpAddress,
            int dwSize,
            uint flNewProtect,
            out uint lpflOldProtect);

        [DllImport("kernel32.dll")]
        public static extern UInt32 WaitForSingleObject(
            IntPtr hHandle,
            uint dwMilliseconds);

        [DllImport("kernel32.dll")]
        public static extern bool WriteProcessMemory(
        IntPtr hProcess,
        IntPtr lpBaseAddress,
        byte[] lpBuffer,
        int nSize,
        out IntPtr lpNumberofBytesWritten);

        public static void Clean(IntPtr hprocess, IntPtr address, int length)
        {
            VirtualFreeEx(hprocess, address, length, WinAPI.FreeType.MEM_RELEASE);
            TerminateProcess(hprocess, 0);
        }
    }
}
