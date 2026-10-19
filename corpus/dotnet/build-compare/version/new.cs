[assembly: System.Runtime.Versioning.TargetFramework(".NETCoreApp,Version=v9.0", FrameworkDisplayName = ".NET 9.0")]
[assembly: System.Reflection.AssemblyVersion("2.1.0.0")]
[assembly: System.Reflection.AssemblyFileVersion("2.1.3.0")]
[assembly: System.Reflection.AssemblyInformationalVersion("2.1.3")]

namespace Release
{
    public static class Info
    {
        public static string Describe(int build)
        {
            return "build " + build;
        }
    }
}
