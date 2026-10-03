using System;

namespace Behaviour
{
    public static class FilterWithFlags
    {
        public static void Run()
        {
            for (int round = 0; round < 3; round++)
            {
                int a = round;
                int c = 4 + round;
                int e = round * 2;
                bool g = (0 <= c) && a > 0;
                try
                {
                    a = 12 / ((a + e) % 3);
                }
                catch (DivideByZeroException) when (e > 1)
                {
                    Console.WriteLine("filtered");
                }
                catch (DivideByZeroException)
                {
                    Console.WriteLine("zero");
                }
                if (g || !((c / 5) == (a % 6)))
                {
                    c = c + 1;
                }
                Console.WriteLine(g ? 1 : 0);
                Console.WriteLine(a + " " + c);
            }
        }
    }
}
