using System;

namespace Sample;

public class Ranges
{
    public string Band(int n)
    {
        return n switch
        {
            >= 0 and < 10 => "low",
            >= 10 and < 100 => "mid",
            >= 100 and < 1000 => "high",
            _ => "extreme",
        };
    }

    public int Level(int value)
    {
        return value switch
        {
            >= 0 and < 5 => 1,
            >= 5 and < 25 => 2,
            >= 25 and < 125 => 3,
            _ => 0,
        };
    }

    public string Window(int t)
    {
        return t switch
        {
            >= -10 and < 0 => "before",
            >= 0 and < 10 => "during",
            _ => "after",
        };
    }
}
