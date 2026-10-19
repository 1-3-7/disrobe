using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Text.Json;

if (args.Length != 1)
{
    Console.Error.WriteLine("usage: PreserveSigMetadata <assembly>");
    return 2;
}

using FileStream stream = File.OpenRead(args[0]);
using PEReader pe = new(stream);
MetadataReader reader = pe.GetMetadataReader();
List<PInvokeReference> pinvokes = [];

foreach (TypeDefinitionHandle typeHandle in reader.TypeDefinitions)
{
    TypeDefinition type = reader.GetTypeDefinition(typeHandle);
    string typeName = reader.GetString(type.Namespace) + "." + reader.GetString(type.Name);
    foreach (MethodDefinitionHandle methodHandle in type.GetMethods())
    {
        MethodDefinition method = reader.GetMethodDefinition(methodHandle);
        MethodImport import = method.GetImport();
        if (import.Module.IsNil)
        {
            continue;
        }

        pinvokes.Add(new PInvokeReference(
            typeName + "::" + reader.GetString(method.Name),
            reader.GetString(reader.GetModuleReference(import.Module).Name),
            reader.GetString(import.Name),
            (method.ImplAttributes & MethodImplAttributes.PreserveSig) != 0));
    }
}

Console.Out.Write(JsonSerializer.Serialize(
    new
    {
        pinvokes = pinvokes.Select(pinvoke => new
        {
            method = pinvoke.Method,
            module = pinvoke.Module,
            entry_point = pinvoke.EntryPoint,
            preserve_sig = pinvoke.PreserveSig,
        }),
    },
    new JsonSerializerOptions { WriteIndented = true }));
return 0;

internal sealed record PInvokeReference(
    string Method,
    string Module,
    string EntryPoint,
    bool PreserveSig);
