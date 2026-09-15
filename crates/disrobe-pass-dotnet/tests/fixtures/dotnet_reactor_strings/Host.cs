using System;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

[assembly: AssemblyMetadata("Protector", ".NET Reactor")]

namespace ReactorStringsCompat
{
    internal static class Program
    {
        private static byte[] DecryptDecoy()
        {
            byte[] key = new byte[]
            {
                0x7D, 0x3C, 0x91, 0xE2, 0x16, 0x58, 0xA4, 0xCF,
                0x20, 0x6B, 0xD7, 0x39, 0x85, 0xFA, 0x42, 0x1E,
                0xB0, 0x74, 0x2D, 0xC8, 0x53, 0x9F, 0x06, 0xE1,
                0x68, 0xAB, 0x35, 0xF4, 0x8A, 0x17, 0xCD, 0x52
            };
            byte[] iv = new byte[]
            {
                0x13, 0x57, 0x9B, 0xDF, 0x02, 0x46, 0x8A, 0xCE,
                0xF1, 0xBD, 0x79, 0x35, 0xE0, 0xAC, 0x68, 0x24
            };
            Stream resource = Assembly.GetExecutingAssembly()
                .GetManifestResourceStream("00-reactor-decoy")
                ?? throw new InvalidDataException("resource missing");
            Aes aes = Aes.Create();
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            aes.Key = key;
            aes.IV = iv;
            ICryptoTransform transform = aes.CreateDecryptor();
            CryptoStream crypto = new(resource, transform, CryptoStreamMode.Read);
            MemoryStream plain = new();
            crypto.CopyTo(plain);
            aes.Dispose();
            resource.Dispose();
            return plain.ToArray();
        }

        private static byte[] DecryptResource()
        {
#if CATCH_PATH
            try
            {
#endif
            byte[] key = new byte[]
            {
                0x21, 0x43, 0x65, 0x87, 0xA9, 0xCB, 0xED, 0x0F,
                0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE,
                0x55, 0xAA, 0x11, 0xEE, 0x22, 0xDD, 0x33, 0xCC,
                0x44, 0xBB, 0x66, 0x99, 0x77, 0x88, 0x5A, 0xA5
            };
            byte[] iv = new byte[]
            {
#if POST_SET_REVERSE
                0xAF, 0xBE, 0xCD, 0xDC, 0xEB, 0xFA, 0x09, 0x18,
                0x27, 0x36, 0x45, 0x54, 0x63, 0x72, 0x81, 0x90
#else
                0x90, 0x81, 0x72, 0x63, 0x54, 0x45, 0x36, 0x27,
                0x18, 0x09, 0xFA, 0xEB, 0xDC, 0xCD, 0xBE, 0xAF
#endif
            };
#if !POST_SET_REVERSE
            Array.Reverse(iv);
#endif
            Stream resource = Assembly.GetExecutingAssembly()
                .GetManifestResourceStream("reactor-static-strings")
                ?? throw new InvalidDataException("resource missing");
#if MIXED_INSTANCE
            Aes unrelatedAes = Aes.Create();
            unrelatedAes.Mode = CipherMode.CBC;
            unrelatedAes.Padding = PaddingMode.PKCS7;
            unrelatedAes.Key = key;
            unrelatedAes.IV = iv;
            ICryptoTransform unrelatedTransform = unrelatedAes.CreateDecryptor();
#endif
            Aes aes = Aes.Create();
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            aes.Key = key;
            aes.IV = iv;
#if POST_SET_REVERSE
            Array.Reverse(iv);
#endif
            ICryptoTransform transform = aes.CreateDecryptor();
            CryptoStream crypto = new(resource, transform, CryptoStreamMode.Read);
            MemoryStream plain = new();
            crypto.CopyTo(plain);
            aes.Dispose();
            resource.Dispose();
            return plain.ToArray();
#if CATCH_PATH
            }
            catch (CryptographicException)
            {
                return DecryptDecoy();
            }
#endif
        }

        internal static string Decode(int offset)
        {
#if DISCARDED_DECOY
            _ = DecryptDecoy();
#endif
            byte[] data = DecryptResource();
            int length = BitConverter.ToInt32(data, offset);
            return Encoding.Unicode.GetString(data, offset + 4, length);
        }

#if AMBIGUOUS
        internal static string DecodeDecoy(int offset)
        {
            byte[] data = DecryptDecoy();
            int length = BitConverter.ToInt32(data, offset);
            return Encoding.Unicode.GetString(data, offset + 4, length);
        }
#endif

        private static int Main()
        {
            string[] values = new string[Offsets.Values.Length];
            for (int index = 0; index < Offsets.Values.Length; index++)
            {
                values[index] = Decode(Offsets.Values[index]);
            }
            Console.Write(JsonSerializer.Serialize(values));
            return 0;
        }
    }
}
