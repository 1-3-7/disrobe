using System.Reflection;
using System.Runtime.Loader;

if (args.Length != 1)
{
    return 2;
}

string assemblyPath = Path.GetFullPath(args[0]);
Assembly assembly = AssemblyLoadContext.Default.LoadFromAssemblyPath(assemblyPath);
BindingFlags flags = BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly;
IEnumerable<MethodInfo> methods = assembly.GetTypes()
    .SelectMany(type => type.GetMethods(flags))
    .Where(method => method.ReturnType == typeof(string) && method.GetParameters().Length == 0)
    .OrderBy(method => method.MetadataToken);

foreach (MethodInfo method in methods)
{
    string value = (string?)method.Invoke(null, null) ?? string.Empty;
    string bytes = Convert.ToHexString(System.Text.Encoding.UTF8.GetBytes(value));
    Console.WriteLine($"0x{method.MetadataToken:X8}\t{bytes}");
}

return 0;
