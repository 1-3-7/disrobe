using System;

namespace CffSample
{
    public static class Crc
    {
        public static uint Crc32(byte[] data)
        {
            uint crc = 0xFFFFFFFFu;
            for (int i = 0; i < data.Length; i++)
            {
                crc ^= data[i];
                for (int bit = 0; bit < 8; bit++)
                {
                    if ((crc & 1u) != 0u)
                    {
                        crc = (crc >> 1) ^ 0xEDB88320u;
                    }
                    else
                    {
                        crc = crc >> 1;
                    }
                }
            }
            return crc ^ 0xFFFFFFFFu;
        }
    }

    public static class Tokenizer
    {
        public static int Classify(char c)
        {
            if (c >= '0' && c <= '9')
            {
                return 1;
            }
            if (c >= 'a' && c <= 'z')
            {
                return 2;
            }
            if (c >= 'A' && c <= 'Z')
            {
                return 2;
            }
            if (c == ' ' || c == '\t')
            {
                return 0;
            }
            return 3;
        }

        public static int CountWords(string text)
        {
            int words = 0;
            bool inWord = false;
            for (int i = 0; i < text.Length; i++)
            {
                int kind = Classify(text[i]);
                if (kind == 2)
                {
                    if (!inWord)
                    {
                        words = words + 1;
                        inWord = true;
                    }
                }
                else
                {
                    inWord = false;
                }
            }
            return words;
        }
    }

    public static class Numeric
    {
        public static int Gcd(int a, int b)
        {
            while (b != 0)
            {
                int t = b;
                b = a % b;
                a = t;
            }
            if (a < 0)
            {
                return -a;
            }
            return a;
        }

        public static int Collatz(int n)
        {
            int steps = 0;
            while (n > 1)
            {
                if ((n & 1) == 0)
                {
                    n = n / 2;
                }
                else
                {
                    n = 3 * n + 1;
                }
                steps = steps + 1;
            }
            return steps;
        }

        public static int Clamp(int value, int lo, int hi)
        {
            if (value < lo)
            {
                return lo;
            }
            if (value > hi)
            {
                return hi;
            }
            return value;
        }
    }

    public static class Program
    {
        public static void Main()
        {
            byte[] sample = new byte[] { 0x68, 0x65, 0x6C, 0x6C, 0x6F };
            Console.WriteLine(Crc.Crc32(sample));
            Console.WriteLine(Tokenizer.Classify('7'));
            Console.WriteLine(Tokenizer.Classify('q'));
            Console.WriteLine(Tokenizer.Classify('#'));
            Console.WriteLine(Tokenizer.CountWords("the quick brown fox"));
            Console.WriteLine(Numeric.Gcd(48, 36));
            Console.WriteLine(Numeric.Collatz(27));
            Console.WriteLine(Numeric.Clamp(150, 0, 100));
        }
    }
}
