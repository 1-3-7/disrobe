using System;

public static class BrowserNumbers
{
    public static long AboveSafe() => 9007199254740993L;

    public static long Minimum() => long.MinValue;

    public static double NegativeZeroBits() =>
        BitConverter.Int64BitsToDouble(unchecked((long)0x8000000000000000UL));

    public static double LiteralDouble() => 1.25d;

    public static double NegativeZeroLiteral() => -0.0d;
}
