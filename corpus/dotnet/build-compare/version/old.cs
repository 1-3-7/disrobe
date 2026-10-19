[assembly: System.Runtime.Versioning.TargetFramework(".NETCoreApp,Version=v8.0", FrameworkDisplayName = ".NET 8.0")]
[assembly: System.Reflection.AssemblyVersion("1.0.0.0")]
[assembly: System.Reflection.AssemblyFileVersion("1.0.0.0")]
[assembly: System.Reflection.AssemblyInformationalVersion("1.0.0")]

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
