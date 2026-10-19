[assembly: System.Runtime.Versioning.TargetFramework(".NETCoreApp,Version=v9.0", FrameworkDisplayName = ".NET 9.0")]

namespace Stable
{
    public class Counter
    {
        private int value;

        public int Value => value;

        public void Increment()
        {
            value++;
        }

        public override string ToString()
        {
            return "Counter(" + value + ")";
        }
    }

    public static class Program
    {
        public static int Run(int times)
        {
            Counter counter = new Counter();
            for (int i = 0; i < times; i++)
            {
                counter.Increment();
            }
            return counter.Value;
        }
    }
}
