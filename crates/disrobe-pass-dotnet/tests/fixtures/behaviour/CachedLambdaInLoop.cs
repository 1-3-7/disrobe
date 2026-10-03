using System;

namespace Behaviour
{
    public static class CachedLambdaInLoop
    {
        public static void Run()
        {
            int a = 3;
            int c = 4;
            for (int i = 0; i < 4; i++)
            {
                Func<int, int> f = x => (x * c + 5) % 1000;
                a = f(a);
                c = c + 1;
            }
            Console.WriteLine(a + " " + c);
        }
    }
}
