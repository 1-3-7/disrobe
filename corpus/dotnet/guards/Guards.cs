using System;

namespace Sample;

public class Guards
{
    public string Tier(int score)
    {
        return score switch
        {
            var x when x > 100 => "platinum",
            var x when x > 50 => "gold",
            var x when x > 0 => "silver",
            _ => "none",
        };
    }

    public string Sign(int n)
    {
        return n switch
        {
            var x when x > 0 => "positive",
            var x when x < 0 => "negative",
            _ => "zero",
        };
    }

    public int Bucket(int value)
    {
        return value switch
        {
            var v when v >= 1000 => 3,
            var v when v >= 100 => 2,
            var v when v >= 1 => 1,
            _ => 0,
        };
    }

    public string Reach(int distance)
    {
        return distance switch
        {
            var d when d <= 0 => "here",
            var d when d <= 10 => "near",
            var d when d <= 100 => "far",
            _ => "remote",
        };
    }
}
