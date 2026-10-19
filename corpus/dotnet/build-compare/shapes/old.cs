[assembly: System.Runtime.Versioning.TargetFramework(".NETCoreApp,Version=v9.0", FrameworkDisplayName = ".NET 9.0")]

namespace Shapes
{
    using System;
    using System.Collections.Generic;
    using System.Runtime.InteropServices;

    public interface IShape
    {
        double Area();
    }

    public sealed class Square : IShape, IComparable<Square>
    {
        public const int Sides = 4;
        public double Side;

        double IShape.Area()
        {
            return Side * Side;
        }

        public int CompareTo(Square other)
        {
            return Side.CompareTo(other.Side);
        }
    }

    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    public struct Packed
    {
        public byte Tag;
        public long Value;
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct Overlay
    {
        [FieldOffset(0)]
        public int Whole;

        [FieldOffset(0)]
        public short Low;
    }

    public unsafe struct Buffer
    {
        public fixed byte Data[16];
    }

    public static unsafe class Native
    {
        public static delegate*<int, int> Doubler;
        public static int[,] Grid = new int[2, 2];

        [DllImport("kernel32.dll")]
        public static extern int lstrlenW([MarshalAs(UnmanagedType.LPWStr)] string text);

        public static int Total(Dictionary<string, int>.Enumerator cursor)
        {
            return cursor.Current.Value;
        }

        public static int First(int[] values)
        {
            fixed (int* start = values)
            {
                return start[0];
            }
        }

        public static T Pick<T>(T first, T second) where T : IComparable<T>
        {
            return first.CompareTo(second) > 0 ? first : second;
        }

        public static int Scale(int value, int factor = 2)
        {
            return value * factor;
        }
    }

    public class Box<T> where T : struct
    {
        public T Item;

        public event EventHandler Changed;

        public int Count { get; }

        public void Touch()
        {
            Changed?.Invoke(this, EventArgs.Empty);
        }
    }
}
