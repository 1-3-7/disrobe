using System;

namespace Behaviour
{
    public static class InterpolatedStrings
    {
        public static void Run()
        {
            int b = 6;
            int d = 8;
            string s = $"{d}-{b}";
            Console.WriteLine(s + " " + s.Length);
            d = d * 13;
            s = $"{d}-{(b * d) % 97}";
            Console.WriteLine(s + " " + s.Length);
            s = $"[{b,4}|{d:D5}]";
            Console.WriteLine(s);
        }
    }
}
