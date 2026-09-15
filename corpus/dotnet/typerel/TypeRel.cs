using System;
using System.Text;

namespace Sample;

public class TypeRel
{
    public string Classify(object o)
    {
        return o switch
        {
            string { Length: > 3 } => "long-str",
            int[] { Length: > 0 } => "nonempty-arr",
            StringBuilder { Length: >= 2 } => "sb2",
            _ => "other",
        };
    }

    public string Range(object o)
    {
        return o switch
        {
            string { Length: >= 1 and < 5 } => "short",
            int[] { Length: >= 5 } => "big-arr",
            _ => "other",
        };
    }

    public string Bounds(object o)
    {
        return o switch
        {
            string { Length: >= 2 } => "s2",
            int[] { Length: < 3 } => "small-arr",
            _ => "other",
        };
    }
}
