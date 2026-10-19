[assembly: System.Runtime.Versioning.TargetFramework(".NETCoreApp,Version=v9.0", FrameworkDisplayName = ".NET 9.0")]

namespace Scoring
{
    public static class Rules
    {
        public static string Greet(string name)
        {
            return "Howdy " + name;
        }

        public static int Score(int a, int b)
        {
            return a * 3 + b;
        }

        public static int Unchanged(int x)
        {
            return x + 1;
        }

        public static int Guarded(string text)
        {
            try
            {
                return int.Parse(text);
            }
            catch (System.OverflowException)
            {
                return -1;
            }
        }

        public static long Sum(int[] values)
        {
            long total = 0;
            for (int i = 0; i < values.Length; i++)
            {
                total += values[i];
            }
            return total;
        }
    }
}
