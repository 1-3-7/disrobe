using System;
using System.Globalization;
using System.Reflection;
using System.Runtime.CompilerServices;

Console.WriteLine(ManagedAbiProbe.Add(19, 23).ToString(CultureInfo.InvariantCulture));
Console.WriteLine(ManagedAbiProbe.Negate(5).ToString(CultureInfo.InvariantCulture));
Console.WriteLine(ManagedAbiProbe.Widen(7).ToString(CultureInfo.InvariantCulture));
Console.WriteLine(ManagedAbiProbe.IsPositive(3).ToString(CultureInfo.InvariantCulture));
Console.WriteLine(ManagedAbiProbe.Mask(0xF0F0F0F0u, 8).ToString(CultureInfo.InvariantCulture));
Console.WriteLine(ManagedAbiProbe.Blend(1, 2, 3, 4).ToString(CultureInfo.InvariantCulture));
Console.WriteLine(new ManagedAbiProbe(3).Scale(4).ToString(CultureInfo.InvariantCulture));

foreach (MethodInfo method in typeof(ManagedAbiProbe).GetMethods(
    BindingFlags.Public | BindingFlags.Static | BindingFlags.Instance | BindingFlags.DeclaredOnly))
{
    Console.WriteLine(method.ToString());
}

public sealed class ManagedAbiProbe
{
    private readonly int factor;

    public ManagedAbiProbe(int factor) => this.factor = factor;

    [MethodImpl(MethodImplOptions.NoInlining)]
    public static int Add(int left, int right) => left + right;

    [MethodImpl(MethodImplOptions.NoInlining)]
    public static int Negate(int value) => -value;

    [MethodImpl(MethodImplOptions.NoInlining)]
    public static long Widen(int value) => value;

    [MethodImpl(MethodImplOptions.NoInlining)]
    public static bool IsPositive(int value) => value > 0;

    [MethodImpl(MethodImplOptions.NoInlining)]
    public static uint Mask(uint value, byte shift) => value >> shift;

    [MethodImpl(MethodImplOptions.NoInlining)]
    public static int Blend(int first, int second, int third, int fourth) =>
        first + second * 2 + third * 3 + fourth * 4;

    [MethodImpl(MethodImplOptions.NoInlining)]
    public int Scale(int value) => value * this.factor;
}
