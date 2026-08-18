using System;
using System.Globalization;
using System.Reflection;
using System.Runtime.CompilerServices;

Console.WriteLine(ManagedFpAbiProbe.AddDouble(1.5, 2.25).ToString(CultureInfo.InvariantCulture));
Console.WriteLine(ManagedFpAbiProbe.ScaleFloat(1.5f, 2.5f).ToString(CultureInfo.InvariantCulture));
Console.WriteLine(ManagedFpAbiProbe.Promote(0.5f).ToString(CultureInfo.InvariantCulture));
Console.WriteLine(ManagedFpAbiProbe.Weight(3, 1.5f, 0.25f).ToString(CultureInfo.InvariantCulture));
Console.WriteLine(ManagedFpAbiProbe.Offset(1.5, 4).ToString(CultureInfo.InvariantCulture));
Console.WriteLine(ManagedFpAbiProbe.Mix(1.5, 2.5f, 3, 4.5).ToString(CultureInfo.InvariantCulture));
Console.WriteLine(ManagedFpAbiProbe.Split(0x1234_5678L).Low.ToString(CultureInfo.InvariantCulture));

ManagedFpAbiProbe probe = new ManagedFpAbiProbe(7);
probe.SetSlot(9);
probe.SetRatio(0.125);
Console.WriteLine(probe.Slot.ToString(CultureInfo.InvariantCulture));
Console.WriteLine(probe.Ratio.ToString(CultureInfo.InvariantCulture));
probe.Clear();
Console.WriteLine(probe.Slot.ToString(CultureInfo.InvariantCulture));

unsafe
{
    int cell = 0;
    ManagedFpAbiProbe.Store((IntPtr)(&cell), 11);
    Console.WriteLine(cell.ToString(CultureInfo.InvariantCulture));
}

foreach (ConstructorInfo constructor in typeof(ManagedFpAbiProbe).GetConstructors(
    BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly))
{
    Console.WriteLine(constructor.ToString());
}

foreach (MethodInfo method in typeof(ManagedFpAbiProbe).GetMethods(
    BindingFlags.Public | BindingFlags.Static | BindingFlags.Instance | BindingFlags.DeclaredOnly))
{
    Console.WriteLine(method.ToString());
}

public struct ManagedPair
{
    public long Low;
    public long High;

    public ManagedPair(long low, long high)
    {
        this.Low = low;
        this.High = high;
    }
}

public sealed class ManagedFpAbiProbe
{
    public int Slot;
    public double Ratio;

    [MethodImpl(MethodImplOptions.NoInlining)]
    public ManagedFpAbiProbe(int slot) => this.Slot = slot;

    [MethodImpl(MethodImplOptions.NoInlining)]
    public static double AddDouble(double left, double right) => left + right;

    [MethodImpl(MethodImplOptions.NoInlining)]
    public static float ScaleFloat(float value, float factor) => value * factor;

    [MethodImpl(MethodImplOptions.NoInlining)]
    public static double Promote(float value) => value;

    [MethodImpl(MethodImplOptions.NoInlining)]
    public static float Weight(int count, float left, float right) => left * count + right;

    [MethodImpl(MethodImplOptions.NoInlining)]
    public static double Offset(double value, int count) => value + count;

    [MethodImpl(MethodImplOptions.NoInlining)]
    public static double Mix(double first, float second, int third, double fourth) =>
        first + second + third + fourth;

    [MethodImpl(MethodImplOptions.NoInlining)]
    public void SetSlot(int value) => this.Slot = value;

    [MethodImpl(MethodImplOptions.NoInlining)]
    public void SetRatio(double ratio) => this.Ratio = ratio;

    [MethodImpl(MethodImplOptions.NoInlining)]
    public void Clear() => this.Slot = 0;

    [MethodImpl(MethodImplOptions.NoInlining)]
    public static unsafe void Store(IntPtr target, int value) => *(int*)target = value;

    [MethodImpl(MethodImplOptions.NoInlining)]
    public static ManagedPair Split(long value) => new ManagedPair(value & 0xffff, value >> 16);
}
