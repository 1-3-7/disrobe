using System;
using System.Collections.Generic;

namespace Behaviour
{
    public static class LocalFunctionByRef
    {
        public static void Run()
        {
            List<int> t = new List<int>();
            int a = 9;
            int b = 9;
            int c = 5;
            t.Add(8 / 7);
            int Shift(int x) => (x + c) % 97;
            b = Shift(8);
            c = b * 2;
            a = Shift(a);
            Console.WriteLine(a + " " + b + " " + c + " " + t.Count);
        }
    }
}
