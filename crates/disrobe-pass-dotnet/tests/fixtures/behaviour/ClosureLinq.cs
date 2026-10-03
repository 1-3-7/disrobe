using System;
using System.Collections.Generic;
using System.Linq;

namespace Behaviour
{
    public static class ClosureLinq
    {
        public static void Run()
        {
            List<int> t = new List<int>();
            int a = 0;
            int c = 6;
            for (int i = 0; i < 12; i++)
            {
                t.Add((i * 7) % 13);
            }
            a = t.Where(x => x > c).Select(x => x % 8).Sum() % 1000;
            c = c + 3;
            int filtered = t.Count(x => x > c);
            Console.WriteLine(a + " " + c + " " + filtered);
        }
    }
}
