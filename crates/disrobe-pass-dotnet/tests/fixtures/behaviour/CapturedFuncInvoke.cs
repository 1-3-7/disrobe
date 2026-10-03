using System;

namespace Behaviour
{
    public static class CapturedFuncInvoke
    {
        public static void Run()
        {
            int a = 9;
            int b = 9;
            int e = 4;
            Func<int, int> first = x => (x * e + 3) % 1000;
            a = first((17 * b) % 97);
            e = a % 11;
            Func<int, int> second = x => (x * e + 3) % 1000;
            a = second(a);
            Console.WriteLine(a + " " + b + " " + e);
        }
    }
}
