using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Sample;

public record Point(int X, int Y);

public static class Constructs
{
    public static IEnumerable<int> Evens(int n)
    {
        for (int i = 0; i < n; i++)
        {
            if ((i & 1) == 0)
                yield return i;
        }
    }

    public static async Task<int> SumAsync(int n)
    {
        int total = 0;
        for (int i = 1; i <= n; i++)
        {
            await Task.Yield();
            total += i;
        }
        return total;
    }

    public static Func<int, int> MakeAdder(int delta)
    {
        return x => x + delta;
    }

    public static string Classify(string kind)
    {
        return kind switch
        {
            "alpha" => "first",
            "beta" => "second",
            "gamma" => "third",
            _ => "unknown",
        };
    }

    public static (int sum, int product) Combine(int a, int b)
    {
        return (a + b, a * b);
    }

    public static int Sumsq(IEnumerable<int> xs) => xs.Select(x => x * x).Sum();
}
