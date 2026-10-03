using System;

namespace Behaviour
{
    public static class CapturedTernaryAnd
    {
        public static void Run()
        {
            for (int round = 0; round < 4; round++)
            {
                int b = 6;
                int c = 8 - round;
                int d = round;
                int e = 10 + round;
                int Mix(int x) => (x + b) % 97;
                b = (((e % 10) == d) && c > 6) ? (d - e) : c;
                Console.WriteLine(Mix(3) + " " + b);
            }
        }
    }
}
