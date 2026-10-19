[assembly: System.Runtime.Versioning.TargetFramework(".NETCoreApp,Version=v9.0", FrameworkDisplayName = ".NET 9.0")]

namespace Layout
{
    public static class Calc
    {
        private static int seed;
        private static int other;

        static Calc()
        {
            seed = 3;
            other = 4;
        }

        public static int A(int x)
        {
            return B(x) + 1;
        }

        public static int B(int x)
        {
            return x * 2;
        }

        public static int C(int x)
        {
            return A(x) + B(x) + seed;
        }

        public static int D()
        {
            return seed + other;
        }

        public static string Name(Alpha alpha, Beta beta)
        {
            return alpha.Label + beta.Label;
        }
    }

    public class Alpha
    {
        public string Label = "alpha";

        public int Weight()
        {
            return Calc.D() + Label.Length;
        }
    }

    public class Beta
    {
        public string Label = "beta";

        public Alpha Make()
        {
            return new Alpha();
        }
    }
}
