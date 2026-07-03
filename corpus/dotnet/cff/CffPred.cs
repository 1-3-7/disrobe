using System;

namespace CffPred
{
    public static class Hashing
    {
        public static uint Fnv1a(byte[] data)
        {
            uint hash = 2166136261u;
            for (int i = 0; i < data.Length; i++)
            {
                hash ^= data[i];
                hash = hash * 16777619u;
            }
            return hash;
        }

        public static int Adler(byte[] data)
        {
            int a = 1;
            int b = 0;
            for (int i = 0; i < data.Length; i++)
            {
                a = (a + data[i]) % 65521;
                b = (b + a) % 65521;
            }
            return (b << 16) | a;
        }
    }

    public static class Numeric
    {
        public static int Gcd(int x, int y)
        {
            while (y != 0)
            {
                int t = y;
                y = x % y;
                x = t;
            }
            if (x < 0)
            {
                return -x;
            }
            return x;
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

    public static class Secrets
    {
        public static string Decode(int id)
        {
            char[] seed;
            if (id == 11)
            {
                seed = new char[] { 'O', 'L', 'E', 'L', 'H' };
            }
            else if (id == 22)
            {
                seed = new char[] { 'C', 'C', 'A', 'A', 'B', 'D', 'E', 'F' };
            }
            else
            {
                seed = new char[] { '_' };
            }
            int n = seed.Length;
            char[] outp = new char[n];
            for (int i = 0; i < n; i++)
            {
                outp[i] = (char)(seed[i] + 1);
            }
            return new string(outp);
        }
    }

    public static class Program
    {
        public static void Main()
        {
            byte[] sample = new byte[] { 0x64, 0x69, 0x73, 0x72, 0x6F, 0x62, 0x65 };
            Console.WriteLine(Hashing.Fnv1a(sample));
            Console.WriteLine(Hashing.Adler(sample));
            Console.WriteLine(Numeric.Gcd(1071, 462));
            Console.WriteLine(Numeric.Collatz(97));
            Console.WriteLine(Numeric.Clamp(420, 0, 255));
            Console.WriteLine(Tokenizer.CountWords("the quick brown fox jumps"));
            Console.WriteLine(Secrets.Decode(11));
            Console.WriteLine(Secrets.Decode(22));
        }
    }
}
