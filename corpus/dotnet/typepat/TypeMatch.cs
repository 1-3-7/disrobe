using System;

namespace Sample;

public class TypeMatch
{
    public string Describe(object value)
    {
        return value switch
        {
            int => "int",
            string => "text",
            _ => "other",
        };
    }

    public string Rank(object value)
    {
        return value switch
        {
            byte => "byte",
            short => "short",
            long => "long",
            double => "double",
            _ => "unknown",
        };
    }

    public int Kind(object value)
    {
        return value switch
        {
            bool => 1,
            char => 2,
            string => 3,
            _ => 0,
        };
    }
}
