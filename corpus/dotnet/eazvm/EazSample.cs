using System;

namespace EazSample
{
    public static class Compute
    {
        public static int Add(int a, int b)
        {
            return a + b;
        }

        public static int Poly(int x)
        {
            return x * x + 3 * x - 1;
        }

        public static int SumTo(int n)
        {
            int total = 0;
            for (int i = 1; i <= n; i++)
            {
                total += i;
            }
            return total;
        }

        public static int Classify(int value)
        {
            if (value < 0)
            {
                return -1;
            }
            if (value == 0)
            {
                return 0;
            }
            return 1;
        }

        public static int Max3(int a, int b, int c)
        {
            int m = a;
            if (b > m)
            {
                m = b;
            }
            if (c > m)
            {
                m = c;
            }
            return m;
        }
    }

    public static class Program
    {
        public static void Main()
        {
            Console.WriteLine(Compute.Add(2, 3));
            Console.WriteLine(Compute.Poly(7));
            Console.WriteLine(Compute.SumTo(10));
            Console.WriteLine(Compute.Classify(-5));
            Console.WriteLine(Compute.Max3(3, 9, 4));
        }
    }
}
