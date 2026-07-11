using System;
using System.IO;
using System.IO.Compression;
using System.Reflection;

[assembly: SmartAssembly.Attributes.PoweredByAttribute]

namespace SmartAssembly.Attributes
{
    [AttributeUsage(AttributeTargets.Assembly)]
    public sealed class PoweredByAttribute : Attribute
    {
    }
}

namespace SmartAssemblyCompat
{
    internal static class Program
    {
        private static int Main()
        {
            using Stream resource = Assembly.GetExecutingAssembly()
                .GetManifestResourceStream("[z]payload")
                ?? throw new InvalidDataException("resource missing");
            using BinaryReader reader = new(resource);
            if (reader.ReadInt32() != 0x017D7A7B)
            {
                throw new InvalidDataException("header");
            }
            int total = reader.ReadInt32();
            using MemoryStream restored = new(total);
            while (restored.Length < total)
            {
                int compressedLength = reader.ReadInt32();
                int inflatedLength = reader.ReadInt32();
                byte[] compressed = reader.ReadBytes(compressedLength);
                using MemoryStream part = new(compressed, false);
                using DeflateStream deflate = new(part, CompressionMode.Decompress);
                byte[] inflated = new byte[inflatedLength];
                deflate.ReadExactly(inflated);
                restored.Write(inflated);
            }
            if (restored.Length != total || resource.Position != resource.Length)
            {
                throw new InvalidDataException("length");
            }
            Assembly payload = Assembly.Load(restored.ToArray());
            Type probe = payload.GetType("SmartAssemblyCompat.Payload.Probe", true)
                ?? throw new TypeLoadException();
            MethodInfo message = probe.GetMethod("Message", BindingFlags.Public | BindingFlags.Static)
                ?? throw new MissingMethodException();
            Console.WriteLine((string)(message.Invoke(null, null) ?? string.Empty));
            return 0;
        }
    }
}
