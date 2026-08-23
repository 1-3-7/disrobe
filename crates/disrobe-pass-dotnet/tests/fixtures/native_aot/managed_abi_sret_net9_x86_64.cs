using System;
using System.Globalization;
using System.Reflection;
using System.Runtime.CompilerServices;

Console.WriteLine(ManagedSretProbe.Split(0x1234_5678L).Low.ToString(CultureInfo.InvariantCulture));
Console.WriteLine(ManagedSretProbe.Spread(9L).Third.ToString(CultureInfo.InvariantCulture));
Console.WriteLine(ManagedSretProbe.Quarter(7).Fourth.ToString(CultureInfo.InvariantCulture));
Console.WriteLine(ManagedSretProbe.Narrow(11).Only.ToString(CultureInfo.InvariantCulture));
Console.WriteLine(ManagedSretProbe.Widen(3).Second.ToString(CultureInfo.InvariantCulture));
Console.WriteLine(ManagedSretProbe.Label(5L).Count.ToString(CultureInfo.InvariantCulture));

ManagedSretProbe probe = new ManagedSretProbe(4L);
Console.WriteLine(probe.Doubled().High.ToString(CultureInfo.InvariantCulture));

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

foreach (FieldInfo field in typeof(ManagedQuad).GetFields(
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

foreach (FieldInfo field in typeof(ManagedLabelled).GetFields(
    BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly))
{
    Console.WriteLine(field.ToString());
}

foreach (ConstructorInfo constructor in typeof(ManagedSretProbe).GetConstructors(
    BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly))
{
    Console.WriteLine(constructor.ToString());
}

foreach (MethodInfo method in typeof(ManagedSretProbe).GetMethods(
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

public struct ManagedQuad
{
    public int First;
    public int Second;
    public int Third;
    public int Fourth;
}

public struct ManagedSmall
{
    public int Only;
}

public struct ManagedMixed
{
    public int First;
    public double Second;
}

public struct ManagedLabelled
{
    public string Text;
    public long Count;
}

public sealed class ManagedSretProbe
{
    public long Slot;

    [MethodImpl(MethodImplOptions.NoInlining)]
    public ManagedSretProbe(long slot) => this.Slot = slot;

    [MethodImpl(MethodImplOptions.NoInlining)]
    public static ManagedPair Split(long value)
    {
        ManagedPair pair;
        pair.Low = value & 0xffff;
        pair.High = value >> 16;
        return pair;
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    public static ManagedTriple Spread(long value)
    {
        ManagedTriple triple;
        triple.First = value;
        triple.Second = value + 1;
        triple.Third = value + 2;
        return triple;
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    public static ManagedQuad Quarter(int value)
    {
        ManagedQuad quad;
        quad.First = value;
        quad.Second = value + 1;
        quad.Third = value + 2;
        quad.Fourth = value + 3;
        return quad;
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    public static ManagedSmall Narrow(int value)
    {
        ManagedSmall small;
        small.Only = value + 1;
        return small;
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    public static ManagedMixed Widen(int value)
    {
        ManagedMixed mixed;
        mixed.First = value;
        mixed.Second = value;
        return mixed;
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    public static ManagedLabelled Label(long count)
    {
        ManagedLabelled labelled;
        labelled.Text = null;
        labelled.Count = count;
        return labelled;
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    public ManagedPair Doubled()
    {
        ManagedPair pair;
        pair.Low = this.Slot;
        pair.High = this.Slot;
        return pair;
    }
}
