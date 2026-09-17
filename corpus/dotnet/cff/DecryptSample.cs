using System;

namespace DecryptSample
{
    public static class Strings
    {
        public static char[] Decrypt(int id)
        {
            char[] seed;
            if (id == 100)
            {
                seed = new char[] { 'G', 'E', 'N', 'U', 'I', 'N', 'E' };
            }
            else if (id == 200)
            {
                seed = new char[] { 'P', 'A', 'Y', 'L', 'O', 'A', 'D' };
            }
            else
            {
                seed = new char[] { '?' };
            }
            int n = seed.Length;
            char[] outp = new char[n];
            for (int i = 0; i < n; i++)
            {
                outp[i] = (char)(seed[i] ^ 0x20);
            }
            return outp;
        }
    }

    public static class Program
    {
        public static void Main()
        {
            Console.WriteLine(new string(Strings.Decrypt(100)));
            Console.WriteLine(new string(Strings.Decrypt(200)));
        }
    }
}
