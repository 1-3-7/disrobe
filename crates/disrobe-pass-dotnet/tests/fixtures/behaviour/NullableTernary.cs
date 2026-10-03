using System;

namespace Behaviour
{
    public static class NullableTernary
    {
        public static void Run()
        {
            for (int round = 0; round < 3; round++)
            {
                int a = 3;
                int b = 6 + round;
                int c = 9;
                int e = 2 + round;
                b *= (round + 1);
                int? m = ((b <= (5 - 1)) && c > 3) ? (e % 2) : (int?)null;
                a = (m ?? c) % 1000;
                if (m.HasValue)
                {
                    Console.WriteLine("value " + m.Value);
                }
                Console.WriteLine(a + " " + b);
            }
        }
    }
}
