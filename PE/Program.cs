using PeNet;
using System;
using System.IO;
using PeNet.Header.Pe;

namespace PE
{
    class Program
    {
        static int Main(string[] args)
        {        
            try
            {
                if (!File.Exists(args[0]))
                {
                    Console.WriteLine("File does not exist.");
                    return 1;
                }
            }
            catch(IndexOutOfRangeException i)
            {
                Console.WriteLine("usage: sc <filename.exe>"+i.HelpLink);
                return 1;

            }

            Console.WriteLine(Packer(args));

            return 0;

        }

        static string Packer(string[] args)
        {
            var bin = File.ReadAllBytes(args[0]);
            var pE = new PeFile(bin);

            if (!pE.IsExe) throw new
            PeException("Not a exe file.");

            if (pE.IsDotNet) throw new
             PeException(".NET file are not supported yet.");

            // Add Loader

            pE.AddSection(".araara", 1000,
            ScnCharacteristicsType.Align1024Bytes);

            var sections = pE.ImageSectionHeaders;
            sections[0].Characteristics =
            ScnCharacteristicsType.MemWrite |
            ScnCharacteristicsType.MemRead;

            byte[] Loader = File.ReadAllBytes(@"C:\Users\PC\source\repos\PE\PE\Loader\loader");

            if (Loader == null)
            {
                throw new PeException("Loader adding failed.");
            }


            ulong OEP = pE.ImageNtHeaders.OptionalHeader.AddressOfEntryPoint
            + pE.ImageNtHeaders.OptionalHeader.ImageBase;

            Loader[0] = (byte)OEP;

            ulong EncryptedSectionStart =
            sections[0].VirtualAddress
            + pE.ImageNtHeaders.OptionalHeader.ImageBase;

            Loader[4] = (byte)EncryptedSectionStart;
            Loader[8] = (byte)sections[0].SizeOfRawData;


            for (int i = 0; i < sections.Length; i++)
            {
                if (sections[i].Name == ".araara")
                {
                    pE.ImageNtHeaders.OptionalHeader.AddressOfEntryPoint =
                    sections[0].VirtualAddress + 0x200;
                }
            }


            for (ulong i = 0; i < sections[0].SizeOfRawData; i++)
            {
                sections[0].PointerToRawData ^= 0x55;
            }

            for (int i = 0; i < sections.Length; i++)
            {
                if (sections[i].Name == ".araara")
                {
                    pE.RawFile.WriteBytes(sections[i].PointerToRawData, Loader);

                }

            }

            Dump(args[0], pE);
            return "Successfully completed.";

        }

        static void Dump(string name,PeFile pE)
        {
            var file = pE.RawFile.ToArray();
            if (file == null) throw new
            PeException();
            File.WriteAllBytes("V"+name, file);
            

        }
    }
}
