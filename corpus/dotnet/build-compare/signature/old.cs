[assembly: System.Runtime.Versioning.TargetFramework(".NETCoreApp,Version=v9.0", FrameworkDisplayName = ".NET 9.0")]

namespace Units
{
    public class Converter
    {
        public long Id;

        public int Flag;

        public int Size { get; }

        public string Label { get; set; }

        public virtual int Weigh(ref int amount)
        {
            return amount * 2;
        }

        public int Convert(int value)
        {
            return value * 10;
        }

        public void Log(string message)
        {
            System.Console.WriteLine(message);
        }

        public void Put(int value)
        {
            Id = value;
        }

        public void Put(string value)
        {
            Id = value.Length;
        }

        public static void Measure(ref int length)
        {
            length = length + 1;
        }

        public static T First<T>(T[] items)
        {
            return items[0];
        }
    }
}
