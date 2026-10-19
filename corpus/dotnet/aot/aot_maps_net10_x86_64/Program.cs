using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.CompilerServices;

namespace Tidewater.Gauges
{
    public static class Readings
    {
        public static int Add(int left, int right) => left + right;

        public static T Echo<T>(T value) => value;

        public static TResult Relabel<TSource, TResult>(TSource value, TResult label) => value is null ? label : label;

        public static string Label(int gauge) => "gauge-" + gauge.ToString();
    }

    public readonly struct Sample<T>
    {
        public Sample(T value, int tick)
        {
            Value = value;
            Tick = tick;
        }

        public T Value { get; }

        public int Tick { get; }

        public Sample<T> Advance(int ticks) => new Sample<T>(Value, Tick + ticks);
    }

    public sealed class Station<T>
    {
        private T _last;

        public Station(T initial)
        {
            _last = initial;
        }

        public T Swap(T next)
        {
            T previous = _last;
            _last = next;
            return previous;
        }
    }

    public static class Harbor
    {
        public static class Pier
        {
            public static int Depth(int tide, int draft) => tide - draft;
        }
    }

    internal static class Smoothing
    {
        [MethodImpl(MethodImplOptions.NoInlining)]
        internal static int Average(int[] values)
        {
            int sum = 0;
            foreach (int value in values)
            {
                sum += value;
            }
            return values.Length == 0 ? 0 : sum / values.Length;
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        internal static T Pick<T>(T left, T right, bool first) => first ? left : right;

        [StackTraceHidden]
        [MethodImpl(MethodImplOptions.NoInlining)]
        internal static int Clamp(int value, int low, int high) => value < low ? low : value > high ? high : value;

        internal static class Window
        {
            [MethodImpl(MethodImplOptions.NoInlining)]
            internal static int Span(int first, int last) => last - first + 1;
        }
    }

    internal sealed class Ring<T>
    {
        private readonly T[] _items;
        private int _next;

        internal Ring(int capacity)
        {
            _items = new T[capacity];
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        internal void Push(T value)
        {
            _items[_next] = value;
            _next = (_next + 1) % _items.Length;
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        internal T Peek() => _items[(_next + _items.Length - 1) % _items.Length];
    }

    internal static class Program
    {
        private static int Main(string[] args)
        {
            int total = 0;
            foreach (MethodInfo method in typeof(Readings).GetMethods(BindingFlags.Public | BindingFlags.Static))
            {
                total += method.Name.Length;
            }
            foreach (MethodInfo method in typeof(Station<int>).GetMethods())
            {
                total += method.Name.Length;
            }
            foreach (MethodInfo method in typeof(Station<string>).GetMethods())
            {
                total += method.Name.Length;
            }
            foreach (MethodInfo method in typeof(Sample<long>).GetMethods())
            {
                total += method.Name.Length;
            }
            foreach (MethodInfo method in typeof(Sample<string>).GetMethods())
            {
                total += method.Name.Length;
            }
            MethodInfo echo = typeof(Readings).GetMethod(nameof(Readings.Echo))!;
            object? fromInt = echo.MakeGenericMethod(typeof(int)).Invoke(null, new object[] { 7 });
            object? fromLong = echo.MakeGenericMethod(typeof(long)).Invoke(null, new object[] { 7L });
            object? fromString = echo.MakeGenericMethod(typeof(string)).Invoke(null, new object[] { "seven" });
            MethodInfo relabel = typeof(Readings).GetMethod(nameof(Readings.Relabel))!;
            object? relabelled = relabel.MakeGenericMethod(typeof(int), typeof(string)).Invoke(null, new object[] { 3, "three" });
            object? relabelledBack = relabel.MakeGenericMethod(typeof(string), typeof(int)).Invoke(null, new object[] { "three", 3 });
            total += Readings.Echo(args.Length) + Readings.Echo((long)args.Length).GetHashCode() + Readings.Echo("tide").Length;
            total += Readings.Relabel(args.Length, "count").Length + Readings.Relabel("count", args.Length);
            Station<int> levels = new Station<int>(4);
            Station<string> names = new Station<string>("north");
            total += levels.Swap(args.Length) + names.Swap("south").Length;
            Sample<long> reading = new Sample<long>(12L, 1).Advance(args.Length);
            Sample<string> note = new Sample<string>("calm", 2).Advance(args.Length);
            total += reading.Tick + note.Tick + Harbor.Pier.Depth(args.Length, 2) + Readings.Add(total, 1);
            total += Smoothing.Average(new[] { total, args.Length, 3 }) + Smoothing.Window.Span(args.Length, 9);
            total += Smoothing.Pick(args.Length, 4, total > 2) + Smoothing.Pick("ebb", "flow", total > 5).Length;
            total += Smoothing.Clamp(total, 1, 4096);
            Ring<int> depths = new Ring<int>(3);
            depths.Push(total);
            Ring<string> labels = new Ring<string>(2);
            labels.Push("slack");
            total += depths.Peek() + labels.Peek().Length;
            Assembly assembly = typeof(Program).Assembly;
            foreach (string name in assembly.GetManifestResourceNames())
            {
                using Stream? stream = assembly.GetManifestResourceStream(name);
                total += stream is null ? 0 : (int)stream.Length;
            }
            Console.WriteLine(Readings.Label(total));
            Console.WriteLine($"{fromInt} {fromLong} {fromString} {relabelled} {relabelledBack}");
            return total == 0 ? 1 : 0;
        }
    }
}
