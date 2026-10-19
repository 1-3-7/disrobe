[assembly: System.Runtime.Versioning.TargetFramework(".NETCoreApp,Version=v9.0", FrameworkDisplayName = ".NET 9.0")]
[assembly: System.Reflection.AssemblyDescription("second release")]
[assembly: System.CLSCompliant(true)]

namespace Tagged
{
    [System.Obsolete("use V3", true)]
    public class Legacy
    {
    }

    public class Data
    {
        public int Cache;

        [System.ComponentModel.Description("stored value")]
        public int Value;
    }

    [System.Diagnostics.DebuggerDisplay("{Name}")]
    [System.ComponentModel.Description("a person")]
    public class Person
    {
        public string Name;

        public void Rename([System.Runtime.CompilerServices.CallerFilePath] string caller = "")
        {
            Name = caller;
        }

        [System.Diagnostics.Conditional("TRACE")]
        public void Trace(string message)
        {
            Name = message;
        }
    }
}
