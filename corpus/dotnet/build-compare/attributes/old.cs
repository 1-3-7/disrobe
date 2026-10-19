[assembly: System.Runtime.Versioning.TargetFramework(".NETCoreApp,Version=v9.0", FrameworkDisplayName = ".NET 9.0")]
[assembly: System.Reflection.AssemblyDescription("first release")]

namespace Tagged
{
    [System.Obsolete("use V2")]
    public class Legacy
    {
    }

    [System.Serializable]
    public class Data
    {
        [System.NonSerialized]
        public int Cache;

        public int Value;
    }

    [System.Diagnostics.DebuggerDisplay("{Name}")]
    public class Person
    {
        public string Name;

        public void Rename([System.Runtime.CompilerServices.CallerMemberName] string caller = "")
        {
            Name = caller;
        }

        public void Trace(string message)
        {
            Name = message;
        }
    }
}
