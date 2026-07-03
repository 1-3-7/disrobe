using System;

namespace Sample;

public record Point(int X, int Y);

public class PosMatch
{
    public string Locate(Point p)
    {
        return p switch
        {
            Point(0, 0) => "origin",
            Point(0, _) => "y-axis",
            Point(_, 0) => "x-axis",
            _ => "plane",
        };
    }

    public string Corner(Point p)
    {
        return p switch
        {
            Point(1, 1) => "one-one",
            Point(2, 3) => "two-three",
            _ => "other",
        };
    }
}
