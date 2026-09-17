using System;

namespace Sample;

public class Patterns
{
    public string Quadrant(int x, int y)
    {
        return (x, y) switch
        {
            ( > 0, > 0) => "I",
            ( < 0, > 0) => "II",
            ( < 0, < 0) => "III",
            ( > 0, < 0) => "IV",
            _ => "axis",
        };
    }

    public int Step(int a, int b)
    {
        return (a, b) switch
        {
            ( > 0, > 0) => 3,
            ( > 0, < 0) => 2,
            ( < 0, > 0) => 1,
            ( < 0, < 0) => 0,
            _ => -1,
        };
    }

    public string Diagonal(int u, int v)
    {
        return (u, v) switch
        {
            ( >= 5, >= 5) => "high",
            ( < 5, < 5) => "low",
            _ => "mixed",
        };
    }
}
