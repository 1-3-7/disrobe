using System;

namespace ConstProbe
{
    public static class Consts
    {
        public static double NegZeroDouble()
        {
            return -0.0;
        }

        public static double PositiveInfinityDouble()
        {
            return double.PositiveInfinity;
        }

        public static double NegativeInfinityDouble()
        {
            return double.NegativeInfinity;
        }

        public static double PlainDouble()
        {
            return 2.5;
        }

        public static float NegZeroFloat()
        {
            return -0.0f;
        }

        public static float PositiveInfinityFloat()
        {
            return float.PositiveInfinity;
        }

        public static float PlainFloat()
        {
            return 1.5f;
        }

        public static int ShortNegative()
        {
            return -5;
        }

        public static int ShortNegativeBoundary()
        {
            return -100;
        }

        public static int WideInt()
        {
            return 1000000;
        }

        public static long WideLong()
        {
            return 5000000000L;
        }
    }
}
