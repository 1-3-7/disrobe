namespace Sample;

public static class UnsignedOverflow
{
    public static bool InRange(int index, int length)
    {
        return (uint)index < (uint)length;
    }

    public static int GuardIndex(int index, int length)
    {
        if ((uint)index >= (uint)length)
        {
            return -1;
        }
        return index;
    }

    public static int DivideUnsigned(int dividend, int divisor)
    {
        return (int)((uint)dividend / (uint)divisor);
    }

    public static int RemainderUnsigned(int dividend, int divisor)
    {
        return (int)((uint)dividend % (uint)divisor);
    }

    public static long DivideUnsignedWide(long dividend, long divisor)
    {
        return (long)((ulong)dividend / (ulong)divisor);
    }

    public static uint DivideDeclaredUnsigned(uint dividend, uint divisor)
    {
        return dividend / divisor;
    }

    public static int AddChecked(int left, int right)
    {
        return checked(left + right);
    }

    public static long MultiplyChecked(long left, long right)
    {
        return checked(left * right);
    }

    public static uint SubtractCheckedUnsigned(uint left, uint right)
    {
        return checked(left - right);
    }

    public static ulong ZeroExtend(int value)
    {
        return (ulong)(uint)value;
    }

    public static long SignExtendUnsigned(uint value)
    {
        return (long)(int)value;
    }

    public static bool LessOrUnordered(double left, double right)
    {
        return !(left >= right);
    }

    public static string Bucket(uint value)
    {
        return value switch
        {
            < 10 => "low",
            < 100 => "mid",
            < 1000 => "high",
            _ => "extreme",
        };
    }
}

public enum Flags : uint
{
    None = 0,
    High = 0x80000000,
}

public static class UnsignedOverflowRefusal
{
    public static bool FlagsBelow(Flags left, Flags right)
    {
        return left < right;
    }
}
