using System;

namespace GauntletBitMono
{
    public static class PriceCalculator
    {
        public static int Classify(int n)
        {
            if (n > 10)
            {
                return n * 2;
            }
            return n + 1;
        }

        public static int SumTo(int n)
        {
            int acc = 0;
            for (int i = 0; i < n; i++)
            {
                acc += i;
            }
            return acc;
        }

        public static string Pick(int k)
        {
            switch (k)
            {
                case 0: return "zero";
                case 1: return "one";
                case 2: return "two";
                default: return "many";
            }
        }
    }

    public static class Program
    {
        public static void Main()
        {
            Console.WriteLine(PriceCalculator.Classify(7) + "," + PriceCalculator.Classify(20));
            Console.WriteLine(PriceCalculator.SumTo(5));
            Console.WriteLine(PriceCalculator.Pick(1) + "," + PriceCalculator.Pick(9));
        }
    }
}
