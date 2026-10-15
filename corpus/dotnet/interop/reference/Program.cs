using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using System.Text.Json;

namespace InteropDump
{
    internal sealed class NameProvider : ICustomAttributeTypeProvider<string>
    {
        private readonly MetadataReader reader;

        public NameProvider(MetadataReader reader) => this.reader = reader;

        public string GetPrimitiveType(PrimitiveTypeCode typeCode) => typeCode.ToString();
        public string GetSystemType() => "System.Type";
        public string GetSZArrayType(string elementType) => elementType + "[]";
        public string GetTypeFromDefinition(MetadataReader r, TypeDefinitionHandle handle, byte rawTypeKind) => Program.TypeName(r, handle);
        public string GetTypeFromReference(MetadataReader r, TypeReferenceHandle handle, byte rawTypeKind)
        {
            TypeReference reference = r.GetTypeReference(handle);
            string ns = r.GetString(reference.Namespace);
            string name = r.GetString(reference.Name);
            return ns.Length == 0 ? name : ns + "." + name;
        }
        public string GetTypeFromSerializedName(string name) => name;
        public PrimitiveTypeCode GetUnderlyingEnumType(string type) => PrimitiveTypeCode.Int32;
        public bool IsSystemType(string type) => type == "System.Type";
    }

    internal static class Program
    {
        public static string TypeName(MetadataReader reader, TypeDefinitionHandle handle)
        {
            TypeDefinition type = reader.GetTypeDefinition(handle);
            string name = reader.GetString(type.Name);
            TypeDefinitionHandle outer = type.GetDeclaringType();
            if (!outer.IsNil)
            {
                return TypeName(reader, outer) + "/" + name;
            }
            string ns = reader.GetString(type.Namespace);
            return ns.Length == 0 ? name : ns + "." + name;
        }

        private static string AttributeName(MetadataReader reader, CustomAttribute attribute)
        {
            EntityHandle owner = attribute.Constructor.Kind switch
            {
                HandleKind.MemberReference => reader.GetMemberReference((MemberReferenceHandle)attribute.Constructor).Parent,
                HandleKind.MethodDefinition => reader.GetMethodDefinition((MethodDefinitionHandle)attribute.Constructor).GetDeclaringType(),
                _ => default,
            };
            if (owner.Kind == HandleKind.TypeReference)
            {
                TypeReference reference = reader.GetTypeReference((TypeReferenceHandle)owner);
                return reader.GetString(reference.Namespace) + "." + reader.GetString(reference.Name);
            }
            if (owner.Kind == HandleKind.TypeDefinition)
            {
                return TypeName(reader, (TypeDefinitionHandle)owner);
            }
            return "";
        }

        private static object Plain(object value)
        {
            if (value is ImmutableArray<CustomAttributeTypedArgument<string>> items)
            {
                return items.Select(item => Plain(item.Value)).ToList();
            }
            return value;
        }

        private static Dictionary<string, object> Named(CustomAttributeValue<string> value)
        {
            Dictionary<string, object> named = new Dictionary<string, object>();
            foreach (CustomAttributeNamedArgument<string> argument in value.NamedArguments)
            {
                named[argument.Name] = Plain(argument.Value);
            }
            return named;
        }

        private static int Main(string[] args)
        {
            using FileStream stream = File.OpenRead(args[0]);
            using PEReader pe = new PEReader(stream);
            MetadataReader reader = pe.GetMetadataReader();
            NameProvider provider = new NameProvider(reader);

            List<object> pinvokes = new List<object>();
            List<object> libraryImports = new List<object>();
            List<object> nativeCallable = new List<object>();
            List<object> comImports = new List<object>();

            foreach (TypeDefinitionHandle typeHandle in reader.TypeDefinitions)
            {
                TypeDefinition type = reader.GetTypeDefinition(typeHandle);
                string typeName = TypeName(reader, typeHandle);
                if ((type.Attributes & TypeAttributes.Import) != 0)
                {
                    string guid = null;
                    foreach (CustomAttributeHandle handle in type.GetCustomAttributes())
                    {
                        CustomAttribute attribute = reader.GetCustomAttribute(handle);
                        if (AttributeName(reader, attribute) == "System.Runtime.InteropServices.GuidAttribute")
                        {
                            guid = (string)attribute.DecodeValue(provider).FixedArguments[0].Value;
                        }
                    }
                    comImports.Add(new
                    {
                        type = typeName,
                        token = MetadataTokens.GetToken(typeHandle),
                        guid,
                        is_interface = (type.Attributes & TypeAttributes.Interface) != 0,
                    });
                }
                foreach (MethodDefinitionHandle methodHandle in type.GetMethods())
                {
                    MethodDefinition method = reader.GetMethodDefinition(methodHandle);
                    string methodName = typeName + "::" + reader.GetString(method.Name);
                    int token = MetadataTokens.GetToken(methodHandle);
                    MethodImport import = method.GetImport();
                    if (!import.Module.IsNil)
                    {
                        MethodImportAttributes flags = import.Attributes;
                        pinvokes.Add(new
                        {
                            method = methodName,
                            token,
                            module = reader.GetString(reader.GetModuleReference(import.Module).Name),
                            entry_point = reader.GetString(import.Name),
                            flags = (int)flags,
                            char_set = (flags & MethodImportAttributes.CharSetMask).ToString(),
                            calling_convention = (flags & MethodImportAttributes.CallingConventionMask).ToString(),
                            set_last_error = (flags & MethodImportAttributes.SetLastError) != 0,
                            exact_spelling = (flags & MethodImportAttributes.ExactSpelling) != 0,
                            best_fit = (flags & MethodImportAttributes.BestFitMappingMask).ToString(),
                            throw_on_unmappable = (flags & MethodImportAttributes.ThrowOnUnmappableCharMask).ToString(),
                            preserve_sig = (method.ImplAttributes & MethodImplAttributes.PreserveSig) != 0,
                        });
                    }
                    foreach (CustomAttributeHandle handle in method.GetCustomAttributes())
                    {
                        CustomAttribute attribute = reader.GetCustomAttribute(handle);
                        string name = AttributeName(reader, attribute);
                        if (name == "System.Runtime.InteropServices.LibraryImportAttribute")
                        {
                            CustomAttributeValue<string> value = attribute.DecodeValue(provider);
                            libraryImports.Add(new
                            {
                                method = methodName,
                                token,
                                library = (string)value.FixedArguments[0].Value,
                                named = Named(value),
                            });
                        }
                        else if (name == "System.Runtime.InteropServices.UnmanagedCallersOnlyAttribute")
                        {
                            CustomAttributeValue<string> value = attribute.DecodeValue(provider);
                            nativeCallable.Add(new
                            {
                                method = methodName,
                                token,
                                named = Named(value),
                            });
                        }
                    }
                }
            }

            Console.Out.Write(JsonSerializer.Serialize(new
            {
                pinvokes,
                library_imports = libraryImports,
                native_callable = nativeCallable,
                com_imports = comImports,
            }, new JsonSerializerOptions { WriteIndented = true }));
            return 0;
        }
    }
}
