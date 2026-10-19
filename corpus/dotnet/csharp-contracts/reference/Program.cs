using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;

using FileStream input = File.OpenRead(args[0]);
using PEReader pe = new(input);
MetadataReader reader = pe.GetMetadataReader();
foreach (TypeDefinitionHandle handle in reader.TypeDefinitions)
{
    TypeDefinition type = reader.GetTypeDefinition(handle);
    string owner = reader.GetString(type.Namespace) + "." + reader.GetString(type.Name);
    foreach (MethodDefinitionHandle methodHandle in type.GetMethods())
    {
        MethodDefinition method = reader.GetMethodDefinition(methodHandle);
        Console.WriteLine($"def {MetadataTokens.GetToken(methodHandle):X8} {owner}::{reader.GetString(method.Name)} sig={Convert.ToHexString(reader.GetBlobBytes(method.Signature))}");
        if (method.RelativeVirtualAddress != 0)
            Console.WriteLine("il " + Convert.ToHexString(pe.GetMethodBody(method.RelativeVirtualAddress).GetILBytes()!));
    }
}
foreach (MemberReferenceHandle handle in reader.MemberReferences)
{
    MemberReference member = reader.GetMemberReference(handle);
    string owner = member.Parent.Kind.ToString();
    if (member.Parent.Kind == HandleKind.TypeReference)
    {
        TypeReference type = reader.GetTypeReference((TypeReferenceHandle)member.Parent);
        owner = reader.GetString(type.Namespace) + "." + reader.GetString(type.Name);
    }
    Console.WriteLine($"ref {MetadataTokens.GetToken(handle):X8} {owner}::{reader.GetString(member.Name)} sig={Convert.ToHexString(reader.GetBlobBytes(member.Signature))}");
}
for (int index = 1; index <= reader.GetTableRowCount(TableIndex.MethodSpec); index++)
{
    MethodSpecificationHandle handle = MetadataTokens.MethodSpecificationHandle(index);
    MethodSpecification spec = reader.GetMethodSpecification(handle);
    Console.WriteLine($"spec {MetadataTokens.GetToken(handle):X8} method={MetadataTokens.GetToken(spec.Method):X8} args={Convert.ToHexString(reader.GetBlobBytes(spec.Signature))}");
}
foreach (FieldDefinitionHandle handle in reader.FieldDefinitions)
{
    FieldDefinition field = reader.GetFieldDefinition(handle);
    Console.WriteLine($"field {MetadataTokens.GetToken(handle):X8} {reader.GetString(field.Name)} rva={field.GetRelativeVirtualAddress():X8}");
}
