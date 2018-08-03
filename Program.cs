using System;
using System.IO;

namespace BFTTFify
{
    class Program
    {
        private enum Platform
        {
            None,
            Nx,
            Cafe,
            Win,
        }

        static void Main(string[] args)
        {
            Console.WriteLine("BFTTFutil, a tool for encrypting\\decrypting BFTTF\\BFOTF from\\to TTF\\OTF\nCreated by CHEMI6DER Copyright 2018");
            //See if we have 3 arguments, otherwise print usage
            if (args.Length != 3)
            {
                Console.WriteLine("Usage: bfttfutil.exe <mode> <infile> <outfile>\nModes:\n    -enc_nx   Encrypts TTF\\OTF for use with NX\n    -enc_cafe Encrypts TTF\\OTF for use with CAFE\n    -enc_win  Encrypts TTF\\OTF for use with WINDOWS?\n    -dec      Decrypts BFTTF\\BFOTF to TTF\\OTF");
                return;
            }
            //Check if input file exists
            if (!File.Exists(args[1]))
            {
                Console.WriteLine("Err 0x0: Input file does not exist");
                return;
            }

            //Determine what to do based on mode input by user
            if (args[0] == "-dec")
            {
                Console.WriteLine("Decrypting " + args[1] + " ...");
                DecryptBFTTF(args[1], args[2]);
            }
            else if (args[0] == "-enc_nx")
            {
                Console.WriteLine("Encrypting " + args[1] + " for platform NX...");
                EncryptBFTTF(Platform.Nx, args[1], args[2]);
            }
            else if (args[0] == "-enc_cafe")
            {
                Console.WriteLine("Encrypting " + args[1] + " for platform CAFE...");
                EncryptBFTTF(Platform.Cafe, args[1], args[2]);
            }
            else if (args[0] == "-enc_win")
            {
                Console.WriteLine("Encrypting " + args[1] + " for platform WIN...");
                EncryptBFTTF(Platform.Win, args[1], args[2]);
            }
            else
            {
                Console.WriteLine("Err 0x1: Invalid operation mode");
                Console.WriteLine("Usage: bfttfify.exe <mode> <infile> <outfile>\nModes:\n    -enc_nx   Encrypts TTF\\OTF for use with NX\n    -enc_cafe Encrypts TTF\\OTF for use with CAFE\n    -enc_win  Encrypts TTF\\OTF for use with WINDOWS?\n    -dec      Decrypts BFTTF\\BFOTF to TTF\\OTF(NX only for now)");
                return;
            }

        }

        private static void EncryptBFTTF(Platform platform, string infile, string outfile)
        {
            UInt32 enc_key;
            switch (platform)
            {
                case Platform.Nx:
                    enc_key = 1231165446U;
                    break;
                case Platform.Cafe:
                    enc_key = 2364726489U;
                    break;
                case Platform.Win:
                    enc_key = 2785117442U;
                    break;
                default:
                    //Special case if you SOMEHOW manage to mess up the program!!!
                    Console.WriteLine("Err 0xFF: You've messed something up");
                    return;
            }

            //Read all bytes from the input file to an array
            byte[] inFile = File.ReadAllBytes(infile);

            UInt32[] outFile = new UInt32[2 + (inFile.Length + 3) / 4];
            outFile[0] = 2140799512U;
            outFile[1] = (UInt32)inFile.Length;

            //Encryption
            for (int i = 2; i < outFile.Length; ++i)
            {
                UInt32 value = 0;
                for (int j = 0; j < 4; ++j)
                {
                    int k = (i - 2) * 4 + j;
                    if (inFile.Length > k)
                        value |= (UInt32)inFile[k] << 8 * (3 - j);
                }
                outFile[i] = value;
            }
            for (int i = 0; i < outFile.Length; ++i)
            {
                UInt32 value = outFile[i] ^ enc_key;
                UInt32 value2 = (value & 4278255360U) >> 8 | (UInt32)((int)value << 8 & -16711936);
                outFile[i] = value2 >> 16 | value2 << 16;
            }

            //Writing encrypted data to file
            BinaryWriter br = new BinaryWriter(File.Create(outfile));
            foreach (UInt32 value in outFile) br.Write(value);
            br.Close();

            //Congradulate user on successful encryption
            Console.WriteLine("Successefully encrypted to " + outfile);
        }

        private static void DecryptBFTTF(string infile, string outfile)
        {
            //Get first four bytes of the file to determine the platform and the decryption key
            BinaryReader br = new BinaryReader(File.OpenRead(infile));
            UInt32 magic = br.ReadUInt32();
            br.Close();
            UInt32 dec_key = 0;
            switch (magic)
            {
                case 0x1A879BD9:
                    dec_key = 2785117442U;
                    break;
                case 0x1E1AF836:
                    dec_key = 1231165446U;
                    break;
                case 0xC1DE68F3:
                    dec_key = 2364726489U;
                    break;
                default:
                    Console.WriteLine("Err 0x2: Input file isn't a BFTTF\\BFOTF");
                    break;
            }

            //Read the input file into a byte array
            byte[] inFile = File.ReadAllBytes(infile);

            //Decryption
            if (inFile.Length <= 8) return;
            uint value = GetUInt32(inFile, 4) ^ dec_key;
            if (inFile.Length < value) return;
            byte[] outFile = new byte[inFile.Length - 8];
            int pos = 8;
            while (pos < inFile.Length)
            {
                SetToUInt32(GetUInt32(inFile, pos) ^ dec_key, outFile, pos - 8);
                pos += 4;
            }

            //Write decrypted file to disk
            BinaryWriter bw = new BinaryWriter(File.Create(outfile));
            bw.Write(outFile);
            bw.Close();

            //Congradulate user on successful decryption
            Console.WriteLine("Successefully decrypted to " + outfile);
        }

        private static UInt32 GetUInt32(byte[] data, int pos)
        {
            return (UInt32)(data[pos + 3] | data[pos + 2] << 8 | data[pos + 1] << 16 | data[pos] << 24);
        }

        private static void SetToUInt32(uint val, byte[] data, int pos)
        {
            data[pos + 3] = (byte)(val & (uint)byte.MaxValue);
            data[pos + 2] = (byte)(val >> 8 & (uint)byte.MaxValue);
            data[pos + 1] = (byte)(val >> 16 & (uint)byte.MaxValue);
            data[pos] = (byte)(val >> 24 & (uint)byte.MaxValue);
        }
    }
}
