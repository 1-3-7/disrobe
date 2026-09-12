using System;

namespace Sample;

public record Vec(int X, int Y);

public class Records
{
    public Vec ResetY(Vec v) => v with { Y = 0 };
    public Vec SetBoth(Vec v) => v with { X = 1, Y = 2 };
    public Vec Replace(Vec v, int x) => v with { X = x };
}
