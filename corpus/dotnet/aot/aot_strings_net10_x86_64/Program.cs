using System;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Text;

namespace Tidewater.Signals
{
    internal static class Lexicon
    {
        private const uint Golden = 0x9E3779B9;
        private const uint Salt = 0x5A17C0DE;

        private static readonly int[] Offsets = { 0, 10, 18, 29, 43, 55, 59, 67, 77 };

        private static readonly byte[] Blob =
        {
            0x63, 0x1B, 0x42, 0xB4, 0x47, 0x36, 0x59, 0x25, 0x4F, 0xB4, 0x77, 0x18, 0x87, 0x4F, 0x8F, 0xE6,
            0x57, 0xE9, 0xB8, 0x72, 0xC9, 0x1A, 0xF6, 0x5C, 0x87, 0x90, 0x63, 0xF4, 0xE5, 0x81, 0x9E, 0xDE,
            0x97, 0x29, 0xF8, 0x98, 0xC8, 0x76, 0xCD, 0xF8, 0x61, 0x1A, 0x55, 0x38, 0x1B, 0x7D, 0x87, 0x87,
            0x31, 0xA6, 0x98, 0xAB, 0xAE, 0x33, 0xF1, 0xD0, 0x27, 0x52, 0x0F, 0x3F, 0xC3, 0x63, 0xE8, 0xD7,
            0x5A, 0xAE, 0x2A, 0x6D, 0x22, 0x54, 0x23, 0xB0, 0xD3, 0x3C, 0xC4, 0xEE, 0x87,
        };

        [MethodImpl(MethodImplOptions.NoInlining)]
        internal static string Get(int index)
        {
            int start = Offsets[index];
            int end = Offsets[index + 1];
            int length = end - start;
            uint seed = unchecked((uint)(index + 1) * Golden) ^ (uint)start ^ ((uint)length << 12) ^ ((uint)length >> 1) ^ Salt;
            byte[] plain = new byte[length];
            for (int i = 0; i < length; i++)
            {
                seed ^= seed << 13;
                seed ^= seed >> 17;
                seed ^= seed << 5;
                byte b = Blob[start + i];
                byte rotated = (byte)((b << 5) | (b >> 3));
                plain[i] = (byte)(rotated ^ (byte)((seed >> 8) ^ seed));
            }
            return Encoding.UTF8.GetString(plain);
        }
    }

    internal static class Program
    {
        private static int Main(string[] args)
        {
            long total = args.Length;
            total += Lexicon.Get(0).Length;
            total += Lexicon.Get(3).Length;
            total += Lexicon.Get(7).Length;
            total += Lexicon.Get(5).Length;
            Console.WriteLine(Lexicon.Get(1));
            Console.WriteLine(Lexicon.Get(6));
            Console.WriteLine(total.ToString(CultureInfo.InvariantCulture));
            return total == 0 ? 1 : 0;
        }
    }
}
