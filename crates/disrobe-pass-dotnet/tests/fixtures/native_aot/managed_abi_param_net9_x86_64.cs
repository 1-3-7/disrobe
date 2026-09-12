using System;
using System.Globalization;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

ManagedPair pair = new ManagedPair { Low = 3, High = 5 };
ManagedTriple triple = new ManagedTriple { First = 1, Second = 2, Third = 4 };
ManagedSmall small = new ManagedSmall { Only = 9 };
ManagedMixed blend = new ManagedMixed { First = 6, Second = 8, Third = 11 };
ManagedSequentialClass held = new ManagedSequentialClass { First = 13, Second = 17, Third = 19 };

Console.WriteLine(ManagedParamProbe.Sum(pair).ToString(CultureInfo.InvariantCulture));
Console.WriteLine(ManagedParamProbe.Scale(pair, 7L).ToString(CultureInfo.InvariantCulture));
Console.WriteLine(ManagedParamProbe.Wide(triple).ToString(CultureInfo.InvariantCulture));
Console.WriteLine(ManagedParamProbe.Echo(pair).High.ToString(CultureInfo.InvariantCulture));
Console.WriteLine(ManagedParamProbe.Narrow(small).ToString(CultureInfo.InvariantCulture));
Console.WriteLine(ManagedParamProbe.Blend(blend).ToString(CultureInfo.InvariantCulture));
Console.WriteLine(ManagedParamProbe.Head(held).ToString(CultureInfo.InvariantCulture));
Console.WriteLine(ManagedParamProbe.Tail(triple).ToString(CultureInfo.InvariantCulture));

ManagedParamProbe probe = new ManagedParamProbe(2L);
Console.WriteLine(probe.Weighted(pair).ToString(CultureInfo.InvariantCulture));

foreach (FieldInfo field in typeof(ManagedPair).GetFields(
    BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly))
{
    Console.WriteLine(field.ToString());
}

foreach (FieldInfo field in typeof(ManagedTriple).GetFields(
    BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly))
{
    Console.WriteLine(field.ToString());
}

foreach (FieldInfo field in typeof(ManagedSmall).GetFields(
    BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly))
{
    Console.WriteLine(field.ToString());
}

foreach (FieldInfo field in typeof(ManagedMixed).GetFields(
    BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly))
{
    Console.WriteLine(field.ToString());
}

foreach (FieldInfo field in typeof(ManagedSequentialClass).GetFields(
    BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly))
{
    Console.WriteLine(field.ToString());
}

foreach (ConstructorInfo constructor in typeof(ManagedParamProbe).GetConstructors(
    BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly))
{
    Console.WriteLine(constructor.ToString());
}

foreach (MethodInfo method in typeof(ManagedParamProbe).GetMethods(
    BindingFlags.Public | BindingFlags.Static | BindingFlags.Instance | BindingFlags.DeclaredOnly))
{
    Console.WriteLine(method.ToString());
}

public struct ManagedPair
{
    public long Low;
    public long High;
}

public struct ManagedTriple
{
    public long First;
    public long Second;
    public long Third;
}

public struct ManagedSmall
{
    public int Only;
}

public struct ManagedMixed
{
    public int First;
    public int Second;
    public long Third;
}

[StructLayout(LayoutKind.Sequential)]
public sealed class ManagedSequentialClass
{
    public long First;
    public long Second;
    public long Third;
}

public sealed class ManagedParamProbe
{
    public long Weight;

    [MethodImpl(MethodImplOptions.NoInlining)]
    public ManagedParamProbe(long weight) => this.Weight = weight;

    [MethodImpl(MethodImplOptions.NoInlining)]
    public static long Sum(ManagedPair pair) => pair.Low + pair.High;

    [MethodImpl(MethodImplOptions.NoInlining)]
    public static long Scale(ManagedPair pair, long factor) => pair.Low * factor + pair.High;

    [MethodImpl(MethodImplOptions.NoInlining)]
    public static long Wide(ManagedTriple triple) => triple.First + triple.Second + triple.Third;

    [MethodImpl(MethodImplOptions.NoInlining)]
    public static ManagedPair Echo(ManagedPair pair)
    {
        ManagedPair copy;
        copy.Low = pair.High;
        copy.High = pair.Low;
        return copy;
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    public static int Narrow(ManagedSmall small) => small.Only + 1;

    [MethodImpl(MethodImplOptions.NoInlining)]
    public static long Blend(ManagedMixed mixed) => mixed.First + mixed.Second + mixed.Third;

    [MethodImpl(MethodImplOptions.NoInlining)]
    public static long Head(ManagedSequentialClass held) => held.First + held.Second;

    [MethodImpl(MethodImplOptions.NoInlining)]
    public static long Tail(ManagedTriple triple) => triple.Second + triple.Third;

    [MethodImpl(MethodImplOptions.NoInlining)]
    public long Weighted(ManagedPair pair) => pair.Low * this.Weight + pair.High;
}
