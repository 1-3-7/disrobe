#if NETSTANDARD2_0
namespace System.Runtime.CompilerServices
{
    public static class IsExternalInit { }

    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Struct | AttributeTargets.Field | AttributeTargets.Property, AllowMultiple = false, Inherited = false)]
    public sealed class RequiredMemberAttribute : Attribute { }

    [AttributeUsage(AttributeTargets.All, AllowMultiple = true, Inherited = false)]
    public sealed class CompilerFeatureRequiredAttribute : Attribute
    {
        public CompilerFeatureRequiredAttribute(string featureName)
        {
            FeatureName = featureName;
        }

        public string FeatureName { get; }
        public bool IsOptional { get; set; }
        public const string RefStructs = nameof(RefStructs);
        public const string RequiredMembers = nameof(RequiredMembers);
    }

    public sealed class CallerArgumentExpressionAttribute : Attribute
    {
        public CallerArgumentExpressionAttribute(string parameterName)
        {
            ParameterName = parameterName;
        }

        public string ParameterName { get; }
    }

    [AttributeUsage(AttributeTargets.Method | AttributeTargets.Constructor | AttributeTargets.Property, AllowMultiple = true, Inherited = false)]
    public sealed class SkipLocalsInitAttribute : Attribute { }
}

namespace System
{
    public readonly struct Index : IEquatable<Index>
    {
        private readonly int value;

        public Index(int value, bool fromEnd = false)
        {
            if (value < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(value));
            }
            this.value = fromEnd ? ~value : value;
        }

        public static Index Start => new(0);
        public static Index End => new(~0, fromEnd: false);

        public int Value => value < 0 ? ~value : value;
        public bool IsFromEnd => value < 0;

        public int GetOffset(int length) => IsFromEnd ? length - Value : Value;

        public static Index FromStart(int value) => new(value, fromEnd: false);
        public static Index FromEnd(int value) => new(value, fromEnd: true);
        public static implicit operator Index(int value) => new(value, fromEnd: false);

        public bool Equals(Index other) => value == other.value;
        public override bool Equals(object? obj) => obj is Index i && Equals(i);
        public override int GetHashCode() => value.GetHashCode();
    }

    public readonly struct Range : IEquatable<Range>
    {
        public Range(Index start, Index end)
        {
            Start = start;
            End = end;
        }

        public Index Start { get; }
        public Index End { get; }

        public static Range All => new(Index.Start, Index.End);
        public static Range StartAt(Index start) => new(start, Index.End);
        public static Range EndAt(Index end) => new(Index.Start, end);

        public (int Offset, int Length) GetOffsetAndLength(int length)
        {
            int s = Start.GetOffset(length);
            int e = End.GetOffset(length);
            if ((uint)e > (uint)length || (uint)s > (uint)e)
            {
                throw new ArgumentOutOfRangeException(nameof(length));
            }
            return (s, e - s);
        }

        public bool Equals(Range other) => Start.Equals(other.Start) && End.Equals(other.End);
        public override bool Equals(object? obj) => obj is Range r && Equals(r);
        public override int GetHashCode() => Start.GetHashCode() ^ (End.GetHashCode() << 1);
    }
}

namespace System.Diagnostics.CodeAnalysis
{
    [AttributeUsage(AttributeTargets.Constructor, AllowMultiple = false, Inherited = false)]
    public sealed class SetsRequiredMembersAttribute : Attribute { }

    [AttributeUsage(AttributeTargets.Parameter | AttributeTargets.Property | AttributeTargets.Field, Inherited = false)]
    public sealed class AllowNullAttribute : Attribute { }

    [AttributeUsage(AttributeTargets.Parameter | AttributeTargets.Property | AttributeTargets.Field, Inherited = false)]
    public sealed class DisallowNullAttribute : Attribute { }

    [AttributeUsage(AttributeTargets.Field | AttributeTargets.Parameter | AttributeTargets.Property | AttributeTargets.ReturnValue, Inherited = false)]
    public sealed class MaybeNullAttribute : Attribute { }

    [AttributeUsage(AttributeTargets.Field | AttributeTargets.Parameter | AttributeTargets.Property | AttributeTargets.ReturnValue, Inherited = false)]
    public sealed class NotNullAttribute : Attribute { }

    [AttributeUsage(AttributeTargets.Parameter, Inherited = false)]
    public sealed class MaybeNullWhenAttribute : Attribute
    {
        public MaybeNullWhenAttribute(bool returnValue) { ReturnValue = returnValue; }
        public bool ReturnValue { get; }
    }

    [AttributeUsage(AttributeTargets.Method | AttributeTargets.Property, Inherited = false, AllowMultiple = true)]
    public sealed class MemberNotNullAttribute : Attribute
    {
        public MemberNotNullAttribute(string member) { Members = new[] { member }; }
        public MemberNotNullAttribute(params string[] members) { Members = members; }
        public string[] Members { get; }
    }

    [AttributeUsage(AttributeTargets.Parameter, Inherited = false)]
    public sealed class NotNullWhenAttribute : Attribute
    {
        public NotNullWhenAttribute(bool returnValue) { ReturnValue = returnValue; }
        public bool ReturnValue { get; }
    }
}
#endif
