using System;
using System.Collections.Generic;
using System.Text;

namespace Sample;

public class PropMatch
{
    public string Release(Version v)
    {
        return v switch
        {
            { Major: 0, Minor: 0 } => "zero",
            { Major: 0 } => "premajor",
            { Minor: 0 } => "preminor",
            _ => "released",
        };
    }

    public string Kind(object o)
    {
        return o switch
        {
            string { Length: 0 } => "empty-str",
            int[] { Length: 0 } => "empty-arr",
            StringBuilder { Length: 0 } => "empty-sb",
            _ => "other",
        };
    }

    public string Segment(Version v)
    {
        return v switch
        {
            { Major: 2 } => "maj",
            { Minor: 3 } => "min",
            { Build: 4 } => "bld",
            _ => "other",
        };
    }

    public string Sized(object o)
    {
        return o switch
        {
            string { Length: 3 } => "s3",
            StringBuilder { Length: 5 } => "sb5",
            _ => "other",
        };
    }

    public string Major(Version v)
    {
        return v switch
        {
            { Major: 1 } => "one",
            { Major: 3 } => "three",
            { Major: 5 } => "five",
            _ => "other",
        };
    }

    public string Series(Version v)
    {
        return v switch
        {
            { Major: 1 } => "a",
            { Major: 2 } => "b",
            { Major: 3 } => "c",
            _ => "other",
        };
    }

    public string Gate(Version v)
    {
        return v switch
        {
            { Major: > 0 } => "pos",
            { Minor: > 0 } => "minpos",
            _ => "zero",
        };
    }

    public string Span(Version v)
    {
        return v switch
        {
            { Major: >= 1 and < 5 } => "early",
            { Major: >= 5 and < 10 } => "mid",
            _ => "late",
        };
    }

    public string Bound(Version v)
    {
        return v switch
        {
            { Major: >= 2 } => "ge2",
            { Minor: < 3 } => "lt3",
            _ => "none",
        };
    }
}
