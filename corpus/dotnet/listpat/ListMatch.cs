using System;

namespace Sample;

public class ListMatch
{
    public string Shape(int[] a)
    {
        return a switch
        {
            [] => "empty",
            [_] => "one",
            [1, .., 3] => "one-to-three",
            [.., var last] => "tail",
            _ => "other",
        };
    }

    public string Head(int[] a)
    {
        return a switch
        {
            [var first, ..] => "front",
            _ => "none",
        };
    }

    public string Pair(int[] a)
    {
        return a switch
        {
            [1, 2] => "one-two",
            [_, _] => "two",
            _ => "other",
        };
    }

    public string Bounds(int[] a)
    {
        return a switch
        {
            [] => "z",
            [_, ..] => "some",
            _ => "other",
        };
    }
}
