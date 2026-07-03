using System;

namespace CilProbe
{
    public sealed class Probe
    {
        private int _accumulator;
        private static int _counter;

        public int Transform(int seed, byte[] data)
        {
            int total = seed;
            for (int i = 0; i < data.Length; i++)
            {
                byte b = data[i];
                total = total + (b ^ 0x5A);
                total = total - (b >> 1);
                total = total * 3;
                data[i] = (byte)(b & 0x7F);
            }
            _accumulator = total;
            _counter = _counter + 1;
            return total;
        }

        public string Describe(int value)
        {
            if (value > 100)
            {
                return Emit("large value seen");
            }
            return Emit("small value seen");
        }

        private string Emit(string message)
        {
            Console.WriteLine(message);
            return message;
        }

        public bool IsProbe(object candidate)
        {
            return candidate is Probe;
        }
    }
}
