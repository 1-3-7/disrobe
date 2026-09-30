using System;

namespace StackSpill
{
    public static partial class Probe
    {
        public static void Concat()
        {
            Console.WriteLine(Ledger.Classify(7) + "," + Ledger.Classify(20));
        }

        public static void ByRef(int seed)
        {
            int value = seed;
            Console.WriteLine(Ledger.Pair(Ledger.Twice(ref value), value = 9));
        }

        public static void Argument(int n)
        {
            Console.WriteLine(Ledger.Pair(n, n = Ledger.Classify(n)));
        }

        public static void AfterConditional(bool flag)
        {
            Console.WriteLine(Ledger.Classify(7) + "," + (flag ? Ledger.Classify(20) : Ledger.Classify(3)));
        }

        public static void InsideConditional(bool flag)
        {
            int value = Ledger.Classify(7);
            Console.WriteLine(Ledger.Pair(value, flag ? (value = 9) : 1));
        }

        public static void StaticField()
        {
            Console.WriteLine(Ledger.Pair(Total, Total = 9));
        }

        public static void Element(int[] slots)
        {
            Console.WriteLine(Ledger.Pair(slots[0], slots[0] = 9));
        }

        public static void Untouched(int n)
        {
            int doubled = n * 2;
            Console.WriteLine(Ledger.Pair(doubled, n + 1));
        }
    }
}
