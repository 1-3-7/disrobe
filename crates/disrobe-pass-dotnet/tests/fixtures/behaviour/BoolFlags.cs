using System;
using System.Collections.Generic;

namespace Behaviour
{
    public static class BoolFlags
    {
        private static int Show(int value)
        {
            return value * 10;
        }

        public static void Run()
        {
            List<int> t = new List<int>();
            t.Add(4);
            int a = 3;
            int b = 2;
            int c = 4;
            int d = 3;
            int e = 5;
            bool g1 = (a > b) && c > 2;
            if (g1 || d == 3)
            {
                a = a + 1;
            }
            Console.WriteLine(g1 ? 1 : 0);
            bool g2 = ((3 % 9) >= 14) && e > 3;
            if (g2 || b != (b % 9))
            {
                d = d - 18;
            }
            Console.WriteLine(g2 ? 1 : 0);
            bool g3 = t.Contains(a);
            Console.WriteLine(g3 ? 1 : 0);
            Console.WriteLine(Show(t.Contains(4) ? 0 : 1));
            Console.WriteLine(a + " " + d);
        }
    }
}
