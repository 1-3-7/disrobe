using System;

namespace Behaviour
{
    public static class SharedClosure
    {
        public static void Run()
        {
            int a = 3;
            int d = 4;
            int e = 6;
            int Step(int x) => (x + e) % 97;
            e = Step(18 + d);
            Func<int, int> scale = x => (x * e + 1) % 1000;
            a = scale(a);
            e = e + 1;
            a = Step(a) + scale(2);
            Console.WriteLine(a + " " + d + " " + e);
        }
    }
}
