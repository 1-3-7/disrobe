[assembly: System.Runtime.Versioning.TargetFramework(".NETCoreApp,Version=v9.0", FrameworkDisplayName = ".NET 9.0")]

namespace Units
{
    public class Converter
    {
        public int Id;

        public volatile int Flag;

        public long Size { get; }

        public string Label { get; init; }

        public virtual int Weigh(in int amount)
        {
            return amount * 2;
        }

        public long Convert(int value)
        {
            return value * 10L;
        }

        public void Log(string message, int level)
        {
            System.Console.WriteLine(message + level);
        }

        public void Put(int value)
        {
            Id = value;
        }

        public void Put(double value)
        {
            Id = (int)value;
        }

        public static int Measure(in int length)
        {
            return length + 1;
        }

        public static T First<T>(System.Collections.Generic.IList<T> items) where T : class
        {
            return items[0];
        }
    }
}
