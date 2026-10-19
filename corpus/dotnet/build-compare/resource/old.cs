[assembly: System.Runtime.Versioning.TargetFramework(".NETCoreApp,Version=v9.0", FrameworkDisplayName = ".NET 9.0")]

namespace Assets
{
    public static class Catalog
    {
        public static System.IO.Stream Open(string name)
        {
            return typeof(Catalog).Assembly.GetManifestResourceStream(name);
        }
    }
}
