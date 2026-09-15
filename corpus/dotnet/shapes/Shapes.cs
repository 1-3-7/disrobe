using System;

namespace Sample;

public class Shapes
{
    public string Grade(int score)
    {
        return score switch
        {
            >= 90 => "A",
            >= 80 => "B",
            >= 70 => "C",
            _ => "F",
        };
    }

    public string Size(int n)
    {
        return n switch
        {
            >= 1000 => "huge",
            >= 100 => "big",
            >= 10 => "medium",
            _ => "small",
        };
    }

    public int Negate(int x)
    {
        return -x;
    }

    public int Mul(int a, int b)
    {
        return a * b;
    }
}
