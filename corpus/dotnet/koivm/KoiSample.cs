using System;
using System.Reflection;

[assembly: Obfuscation(Feature = "+koi", Exclude = false, ApplyToMembers = true)]

namespace KoiSample
{
    public static class Arithmetic
    {
        public static int Add(int a, int b)
        {
            return a + b;
        }

        public static int Square(int x)
        {
            return x * x;
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

        public static long Factorial(int n)
        {
            long result = 1;
            while (n > 1)
            {
                result *= n;
                n--;
            }
            return result;
        }
    }

    public sealed class Counter
    {
        private int count;

        public Counter(int start)
        {
            count = start;
        }

        public int Increment()
        {
            count = count + 1;
            return count;
        }

        public int Value()
        {
            return count;
        }
    }

    public static class Text
    {
        public static string Greeting()
        {
            return "koivm sample";
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
            Console.WriteLine(Arithmetic.Add(2, 3));
            Console.WriteLine(Arithmetic.Square(7));
            Console.WriteLine(Arithmetic.SumTo(10));
            Console.WriteLine(Arithmetic.Classify(-5));
            Console.WriteLine(Arithmetic.Factorial(5));
            Console.WriteLine(new Counter(40).Increment());
            Console.WriteLine(Text.Greeting());
            Console.WriteLine(Text.Max3(3, 9, 4));
        }
    }
}
