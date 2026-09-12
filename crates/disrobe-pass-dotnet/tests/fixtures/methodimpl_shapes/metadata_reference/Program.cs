using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;

if (args.Length < 1)
{
    Console.Error.WriteLine("usage: mdprobe <assembly>");
    return 2;
}

using FileStream stream = File.OpenRead(args[0]);
using PEReader pe = new PEReader(stream);
MetadataReader md = pe.GetMetadataReader();

static string Describe(MetadataReader md, EntityHandle handle)
{
    if (handle.IsNil)
    {
        return "nil";
    }
    int rid = MetadataTokens.GetRowNumber(handle);
    return $"{handle.Kind}[{rid}]";
}

Console.WriteLine("== HeapSizes ==");
Console.WriteLine($"StringHeapSizeIsLarge={md.GetHeapSize(HeapIndex.String) > 0xFFFF}");
Console.WriteLine($"StringHeap={md.GetHeapSize(HeapIndex.String)} BlobHeap={md.GetHeapSize(HeapIndex.Blob)} GuidHeap={md.GetHeapSize(HeapIndex.Guid)} UserStringHeap={md.GetHeapSize(HeapIndex.UserString)}");

Console.WriteLine("== TypeDef ==");
foreach (TypeDefinitionHandle handle in md.TypeDefinitions)
{
    TypeDefinition def = md.GetTypeDefinition(handle);
    Console.WriteLine($"rid={MetadataTokens.GetRowNumber(handle)} ns={md.GetString(def.Namespace)} name={md.GetString(def.Name)} attrs=0x{(int)def.Attributes:X8} base={Describe(md, def.BaseType)}");
}

Console.WriteLine("== TypeRef ==");
for (int i = 1; i <= md.GetTableRowCount(TableIndex.TypeRef); i++)
{
    TypeReferenceHandle handle = MetadataTokens.TypeReferenceHandle(i);
    TypeReference reference = md.GetTypeReference(handle);
    Console.WriteLine($"rid={i} ns={md.GetString(reference.Namespace)} name={md.GetString(reference.Name)} scope={Describe(md, reference.ResolutionScope)}");
}

Console.WriteLine("== MethodDef ==");
foreach (MethodDefinitionHandle handle in md.MethodDefinitions)
{
    MethodDefinition def = md.GetMethodDefinition(handle);
    TypeDefinitionHandle owner = def.GetDeclaringType();
    Console.WriteLine($"rid={MetadataTokens.GetRowNumber(handle)} name={md.GetString(def.Name)} attrs=0x{(int)def.Attributes:X4} rva={def.RelativeVirtualAddress} owner={MetadataTokens.GetRowNumber(owner)}");
}

Console.WriteLine("== MemberRef ==");
for (int i = 1; i <= md.GetTableRowCount(TableIndex.MemberRef); i++)
{
    MemberReferenceHandle handle = MetadataTokens.MemberReferenceHandle(i);
    MemberReference reference = md.GetMemberReference(handle);
    Console.WriteLine($"rid={i} name={md.GetString(reference.Name)} parent={Describe(md, reference.Parent)}");
}

Console.WriteLine("== MethodImpl ==");
for (int i = 1; i <= md.GetTableRowCount(TableIndex.MethodImpl); i++)
{
    MethodImplementationHandle handle = MetadataTokens.MethodImplementationHandle(i);
    MethodImplementation implementation = md.GetMethodImplementation(handle);
    Console.WriteLine($"rid={i} class={Describe(md, implementation.Type)} body={Describe(md, implementation.MethodBody)} decl={Describe(md, implementation.MethodDeclaration)}");
}

Console.WriteLine("== ModuleRef ==");
for (int i = 1; i <= md.GetTableRowCount(TableIndex.ModuleRef); i++)
{
    ModuleReferenceHandle handle = MetadataTokens.ModuleReferenceHandle(i);
    ModuleReference reference = md.GetModuleReference(handle);
    Console.WriteLine($"rid={i} name={md.GetString(reference.Name)}");
}

Console.WriteLine("== AssemblyRef ==");
foreach (AssemblyReferenceHandle handle in md.AssemblyReferences)
{
    AssemblyReference reference = md.GetAssemblyReference(handle);
    Console.WriteLine($"rid={MetadataTokens.GetRowNumber(handle)} name={md.GetString(reference.Name)} version={reference.Version}");
}

return 0;
