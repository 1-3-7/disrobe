using System.Reflection;

int result = ManifestProbe.Add(19, 23);
Console.WriteLine(result);
Console.WriteLine(typeof(ManifestProbe).GetMethod(nameof(ManifestProbe.Add), BindingFlags.Public | BindingFlags.Static));

public static class ManifestProbe
{
    public static int Add(int left, int right) => left + right;
}
