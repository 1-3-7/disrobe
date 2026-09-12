using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace ReactorStringsCompat.Packer
{
    internal static class Program
    {
        private static readonly byte[] Key = new byte[]
        {
            0x21, 0x43, 0x65, 0x87, 0xA9, 0xCB, 0xED, 0x0F,
            0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE,
            0x55, 0xAA, 0x11, 0xEE, 0x22, 0xDD, 0x33, 0xCC,
            0x44, 0xBB, 0x66, 0x99, 0x77, 0x88, 0x5A, 0xA5
        };

        private static readonly byte[] Iv = new byte[]
        {
            0x90, 0x81, 0x72, 0x63, 0x54, 0x45, 0x36, 0x27,
            0x18, 0x09, 0xFA, 0xEB, 0xDC, 0xCD, 0xBE, 0xAF
        };

        private static readonly byte[] DecoyKey = new byte[]
        {
            0x7D, 0x3C, 0x91, 0xE2, 0x16, 0x58, 0xA4, 0xCF,
            0x20, 0x6B, 0xD7, 0x39, 0x85, 0xFA, 0x42, 0x1E,
            0xB0, 0x74, 0x2D, 0xC8, 0x53, 0x9F, 0x06, 0xE1,
            0x68, 0xAB, 0x35, 0xF4, 0x8A, 0x17, 0xCD, 0x52
        };

        private static readonly byte[] DecoyIv = new byte[]
        {
            0x13, 0x57, 0x9B, 0xDF, 0x02, 0x46, 0x8A, 0xCE,
            0xF1, 0xBD, 0x79, 0x35, 0xE0, 0xAC, 0x68, 0x24
        };

        private static int Main(string[] args)
        {
            if (args.Length != 5)
            {
                return 2;
            }
            string[] values = JsonSerializer.Deserialize<string[]>(File.ReadAllText(args[0]))
                ?? throw new InvalidDataException("expected strings missing");
            (byte[] plain, int[] offsets) = Encode(values);
            (byte[] decoyPlain, _) = Encode(new string[] { "disconnected-decoy-value" });
            byte[] iv = (byte[])Iv.Clone();
            Array.Reverse(iv);
            File.WriteAllBytes(args[1], Encrypt(plain, Key, iv));
            File.WriteAllBytes(args[2], Encrypt(decoyPlain, DecoyKey, DecoyIv));
            File.WriteAllText(args[3], RenderOffsets(offsets), new UTF8Encoding(false));
            File.WriteAllText(args[4], JsonSerializer.Serialize(values), new UTF8Encoding(false));
            return 0;
        }

        private static (byte[], int[]) Encode(IReadOnlyList<string> values)
        {
            using MemoryStream stream = new();
            using BinaryWriter writer = new(stream, Encoding.Unicode, true);
            int[] offsets = new int[values.Count];
            for (int index = 0; index < values.Count; index++)
            {
                offsets[index] = checked((int)stream.Position);
                byte[] bytes = Encoding.Unicode.GetBytes(values[index]);
                writer.Write(bytes.Length);
                writer.Write(bytes);
            }
            writer.Flush();
            return (stream.ToArray(), offsets);
        }

        private static byte[] Encrypt(byte[] plain, byte[] key, byte[] iv)
        {
            using Aes aes = Aes.Create();
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            aes.Key = key;
            aes.IV = iv;
            using ICryptoTransform encryptor = aes.CreateEncryptor();
            return encryptor.TransformFinalBlock(plain, 0, plain.Length);
        }

        private static string RenderOffsets(IReadOnlyList<int> offsets)
        {
            StringBuilder source = new();
            source.Append("namespace ReactorStringsCompat\n{\n    internal static class Offsets\n    {\n        internal static readonly int[] Values = new int[] { ");
            for (int index = 0; index < offsets.Count; index++)
            {
                if (index != 0)
                {
                    source.Append(", ");
                }
                source.Append(offsets[index]);
            }
            source.Append(" };\n    }\n}\n");
            return source.ToString();
        }
    }
}
