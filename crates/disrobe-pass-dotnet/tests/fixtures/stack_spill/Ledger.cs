using System;

namespace StackSpill
{
    public static class Ledger
    {
        public static int Classify(int value)
        {
            return value < 10 ? value + 1 : value * 2;
        }

        public static int Twice(ref int value)
        {
            value *= 2;
            return value;
        }

        public static int Pair(int first, int second)
        {
            return first * 100 + second;
        }
    }

    public static partial class Probe
    {
        public static int Total;
    }

    public static class Program
    {
        public static void Main()
        {
            Probe.Concat();
            Probe.ByRef(4);
            Probe.Argument(6);
            Probe.AfterConditional(true);
            Probe.AfterConditional(false);
            Probe.InsideConditional(true);
            Probe.InsideConditional(false);
            Probe.Total = 5;
            Probe.StaticField();
            Probe.Element(new int[] { 3, 5 });
            Probe.Untouched(2);
        }
    }
}
