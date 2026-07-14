namespace ChaOracle;

public abstract class BaseGreeter
{
    public abstract string Greet();
}

public sealed class SealedGreeter : BaseGreeter
{
    public override string Greet()
    {
        return "base";
    }
}

public interface IOnly
{
    string Invoke();
}

public sealed class OnlyImplementation : IOnly
{
    public string Invoke()
    {
        return "only";
    }
}

public interface IPoly
{
    string Invoke();
}

public sealed class FirstImplementation : IPoly
{
    public string Invoke()
    {
        return "first";
    }
}

public sealed class SecondImplementation : IPoly
{
    public string Invoke()
    {
        return "second";
    }
}

public interface IInherited
{
    string Invoke();
}

public class InheritedBase : IInherited
{
    public virtual string Invoke()
    {
        return "base-inherited";
    }
}

public sealed class InheritedDerived : InheritedBase
{
    public override string Invoke()
    {
        return "derived-inherited";
    }
}

public class SlotBase
{
    public virtual string Invoke()
    {
        return "slot-base";
    }
}

public class SlotHider : SlotBase
{
    public new virtual string Invoke()
    {
        return "slot-hider";
    }
}

public sealed class SlotDerived : SlotHider
{
    public override string Invoke()
    {
        return "slot-derived";
    }
}

public class SlotGap : SlotHider
{
}

public sealed class SlotGapDerived : SlotGap
{
    public override string Invoke()
    {
        return "slot-gap-derived";
    }
}

public sealed class ExactGreeter
    : IExactGreeter
{
    public string Greet()
    {
        return "exact";
    }
}

public interface IExactGreeter
{
    string Greet();
}

public sealed class OtherExactGreeter : IExactGreeter
{
    public string Greet()
    {
        return "other-exact";
    }
}

public static class Calls
{
    private static readonly ExactGreeter StaticGreeter = new ExactGreeter();
    private static ExactGreeter MutableGreeter = new ExactGreeter();

    public static string CallBaseViaNewObject()
    {
        BaseGreeter value = new SealedGreeter();
        return value.Greet();
    }

    public static string CallUniqueInterface(IOnly value)
    {
        return value.Invoke();
    }

    public static string CallUniqueInterfaceViaNewObject()
    {
        IOnly value = new OnlyImplementation();
        return value.Invoke();
    }

    public static string CallConstrainedGeneric<T>(T value)
        where T : IOnly
    {
        return value.Invoke();
    }

    public static string CallPolymorphicInterface(IPoly value)
    {
        return value.Invoke();
    }

    public static string CallInheritedInterface()
    {
        IInherited value = new InheritedDerived();
        return value.Invoke();
    }

    public static string CallShadowedVirtualSlot()
    {
        SlotBase value = new SlotDerived();
        return value.Invoke();
    }

    public static string CallNonImmediateVirtualOverride()
    {
        SlotHider value = new SlotGapDerived();
        return value.Invoke();
    }

    public static string CallExactNewObject()
    {
        IExactGreeter value = new ExactGreeter();
        return value.Greet();
    }

    public static string CallNullableSealed(ExactGreeter value)
    {
        return value.Greet();
    }

    public static string CallAcrossBranch(bool condition)
    {
        IExactGreeter value = new ExactGreeter();
        if (condition)
        {
            return value.Greet();
        }

        return value.Greet();
    }

    public static string CallSealedStaticField()
    {
        IExactGreeter value = StaticGreeter;
        return value.Greet();
    }

    public static string CallMutableStaticField()
    {
        IExactGreeter value = MutableGreeter;
        return value.Greet();
    }
}
