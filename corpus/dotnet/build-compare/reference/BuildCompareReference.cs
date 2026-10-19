using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Reflection.Emit;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using System.Text;

namespace BuildCompareReference
{
    internal sealed class Utf8Ordinal : IComparer<string>
    {
        public static readonly Utf8Ordinal Instance = new Utf8Ordinal();

        public int Compare(string left, string right)
        {
            byte[] a = Encoding.UTF8.GetBytes(left);
            byte[] b = Encoding.UTF8.GetBytes(right);
            int shared = Math.Min(a.Length, b.Length);
            for (int i = 0; i < shared; i++)
            {
                if (a[i] != b[i])
                {
                    return a[i].CompareTo(b[i]);
                }
            }
            return a.Length.CompareTo(b.Length);
        }
    }

    internal sealed class Located
    {
        public Located(string value, string location)
        {
            Value = value;
            Location = location;
        }

        public string Value { get; }

        public string Location { get; }
    }

    internal sealed class Entry
    {
        public string Key = "";
        public string Group = "";
        public string Signature = "";
        public string Location = "";
        public List<KeyValuePair<string, string>> Aspects = new List<KeyValuePair<string, string>>();
        public Body Body;
    }

    internal sealed class Body
    {
        public byte[] Raw;
        public List<string> Normalized;
        public int CodeSize;
        public bool Present;
    }

    internal sealed class AttributeEntry
    {
        public string Group = "";
        public string Value = "";
        public string Location = "";
    }

    internal sealed class Names : ISignatureTypeProvider<string, object>
    {
        private readonly MetadataReader reader;

        public Names(MetadataReader reader)
        {
            this.reader = reader;
        }

        public static string Qualify(string ns, string name)
        {
            return ns.Length == 0 ? name : ns + "." + name;
        }

        public string TypeDef(TypeDefinitionHandle handle)
        {
            TypeDefinition type = reader.GetTypeDefinition(handle);
            string own = Qualify(reader.GetString(type.Namespace), reader.GetString(type.Name));
            TypeDefinitionHandle outer = type.GetDeclaringType();
            return outer.IsNil ? own : TypeDef(outer) + "/" + own;
        }

        public string TypeRef(TypeReferenceHandle handle)
        {
            TypeReference type = reader.GetTypeReference(handle);
            string own = Qualify(reader.GetString(type.Namespace), reader.GetString(type.Name));
            EntityHandle scope = type.ResolutionScope;
            if (scope.IsNil)
            {
                return "[*]" + own;
            }
            switch (scope.Kind)
            {
                case HandleKind.ModuleDefinition:
                    return "[.module]" + own;
                case HandleKind.ModuleReference:
                    return "[.module " + reader.GetString(reader.GetModuleReference((ModuleReferenceHandle)scope).Name) + "]" + own;
                case HandleKind.AssemblyReference:
                    return "[" + reader.GetString(reader.GetAssemblyReference((AssemblyReferenceHandle)scope).Name) + "]" + own;
                case HandleKind.TypeReference:
                    return TypeRef((TypeReferenceHandle)scope) + "/" + own;
                default:
                    throw new BadImageFormatException("resolution scope " + scope.Kind);
            }
        }

        public string TypeSpec(TypeSpecificationHandle handle)
        {
            return reader.GetTypeSpecification(handle).DecodeSignature(this, null);
        }

        public string Type(EntityHandle handle)
        {
            if (handle.IsNil)
            {
                return "none";
            }
            switch (handle.Kind)
            {
                case HandleKind.TypeDefinition:
                    return TypeDef((TypeDefinitionHandle)handle);
                case HandleKind.TypeReference:
                    return TypeRef((TypeReferenceHandle)handle);
                case HandleKind.TypeSpecification:
                    return TypeSpec((TypeSpecificationHandle)handle);
                default:
                    throw new BadImageFormatException("type handle " + handle.Kind);
            }
        }

        public static string Prefix(SignatureHeader header)
        {
            StringBuilder text = new StringBuilder();
            if (header.IsInstance)
            {
                text.Append("instance ");
            }
            if (header.HasExplicitThis)
            {
                text.Append("explicit ");
            }
            int kind = header.RawValue & 0x0F;
            switch (kind)
            {
                case 0:
                case 8:
                    break;
                case 1:
                    text.Append("unmanaged cdecl ");
                    break;
                case 2:
                    text.Append("unmanaged stdcall ");
                    break;
                case 3:
                    text.Append("unmanaged thiscall ");
                    break;
                case 4:
                    text.Append("unmanaged fastcall ");
                    break;
                case 5:
                    text.Append("vararg ");
                    break;
                case 9:
                    text.Append("unmanaged ");
                    break;
                default:
                    text.Append("callconv(" + kind + ") ");
                    break;
            }
            return text.ToString();
        }

        public static string Parameters(MethodSignature<string> signature)
        {
            List<string> parts = new List<string>();
            for (int i = 0; i < signature.ParameterTypes.Length; i++)
            {
                if (i == signature.RequiredParameterCount)
                {
                    parts.Add("...");
                }
                parts.Add(signature.ParameterTypes[i]);
            }
            return "(" + string.Join(", ", parts) + ")";
        }

        public static string Arity(MethodSignature<string> signature)
        {
            return signature.GenericParameterCount == 0 ? "" : "``" + signature.GenericParameterCount;
        }

        public static string Standalone(MethodSignature<string> signature)
        {
            return Prefix(signature.Header) + signature.ReturnType + Arity(signature) + Parameters(signature);
        }

        public static string Member(MethodSignature<string> signature, string owner, string name)
        {
            return Prefix(signature.Header) + signature.ReturnType + " " + owner + "::" + name + Arity(signature) + Parameters(signature);
        }

        public string MethodKey(MethodDefinitionHandle handle)
        {
            MethodDefinition method = reader.GetMethodDefinition(handle);
            MethodSignature<string> signature = method.DecodeSignature(this, null);
            return Member(signature, TypeDef(method.GetDeclaringType()), reader.GetString(method.Name));
        }

        public string FieldKey(FieldDefinitionHandle handle)
        {
            FieldDefinition field = reader.GetFieldDefinition(handle);
            return TypeDef(field.GetDeclaringType()) + "::" + reader.GetString(field.Name);
        }

        public string FieldMember(FieldDefinitionHandle handle)
        {
            FieldDefinition field = reader.GetFieldDefinition(handle);
            return field.DecodeSignature(this, null) + " " + FieldKey(handle);
        }

        public string MemberRefParent(EntityHandle parent)
        {
            switch (parent.Kind)
            {
                case HandleKind.TypeDefinition:
                case HandleKind.TypeReference:
                case HandleKind.TypeSpecification:
                    return Type(parent);
                case HandleKind.ModuleReference:
                    return "[.module " + reader.GetString(reader.GetModuleReference((ModuleReferenceHandle)parent).Name) + "]";
                case HandleKind.MethodDefinition:
                    return MethodKey((MethodDefinitionHandle)parent);
                default:
                    throw new BadImageFormatException("member reference parent " + parent.Kind);
            }
        }

        public string MemberRef(MemberReferenceHandle handle, out bool isField)
        {
            MemberReference member = reader.GetMemberReference(handle);
            string parent = MemberRefParent(member.Parent);
            string name = reader.GetString(member.Name);
            if (member.GetKind() == MemberReferenceKind.Field)
            {
                isField = true;
                return member.DecodeFieldSignature(this, null) + " " + parent + "::" + name;
            }
            isField = false;
            return Member(member.DecodeMethodSignature(this, null), parent, name);
        }

        public string Method(EntityHandle handle)
        {
            switch (handle.Kind)
            {
                case HandleKind.MethodDefinition:
                    return MethodKey((MethodDefinitionHandle)handle);
                case HandleKind.MemberReference:
                    return MemberRef((MemberReferenceHandle)handle, out bool _);
                default:
                    throw new BadImageFormatException("method handle " + handle.Kind);
            }
        }

        public string MethodSpec(MethodSpecificationHandle handle)
        {
            MethodSpecification spec = reader.GetMethodSpecification(handle);
            ImmutableArray<string> arguments = spec.DecodeSignature(this, null);
            return Method(spec.Method) + "<" + string.Join(", ", arguments) + ">";
        }

        public string StandaloneSig(StandaloneSignatureHandle handle)
        {
            StandaloneSignature signature = reader.GetStandaloneSignature(handle);
            if (signature.GetKind() == StandaloneSignatureKind.LocalVariables)
            {
                return "[" + string.Join(", ", signature.DecodeLocalSignature(this, null)) + "]";
            }
            return Standalone(signature.DecodeMethodSignature(this, null));
        }

        public string Operand(int token)
        {
            if ((token >> 24) == 0x70)
            {
                string value = reader.GetUserString(MetadataTokens.UserStringHandle(token & 0x00FFFFFF));
                StringBuilder hex = new StringBuilder("string ");
                foreach (char unit in value)
                {
                    hex.Append(((int)unit & 0xFF).ToString("X2"));
                    hex.Append(((int)unit >> 8).ToString("X2"));
                }
                return hex.ToString();
            }
            EntityHandle handle = MetadataTokens.EntityHandle(token);
            switch (handle.Kind)
            {
                case HandleKind.TypeDefinition:
                case HandleKind.TypeReference:
                case HandleKind.TypeSpecification:
                    return "type " + Type(handle);
                case HandleKind.MethodDefinition:
                    return "method " + MethodKey((MethodDefinitionHandle)handle);
                case HandleKind.FieldDefinition:
                    return "field " + FieldMember((FieldDefinitionHandle)handle);
                case HandleKind.MemberReference:
                {
                    string text = MemberRef((MemberReferenceHandle)handle, out bool isField);
                    return (isField ? "field " : "method ") + text;
                }
                case HandleKind.MethodSpecification:
                    return "methodspec " + MethodSpec((MethodSpecificationHandle)handle);
                case HandleKind.StandaloneSignature:
                    return "sig " + StandaloneSig((StandaloneSignatureHandle)handle);
                default:
                    return "token 0x" + token.ToString("X8");
            }
        }

        public string GetArrayType(string elementType, ArrayShape shape)
        {
            List<string> dimensions = new List<string>();
            for (int i = 0; i < shape.Rank; i++)
            {
                string lower = i < shape.LowerBounds.Length ? shape.LowerBounds[i].ToString() : "";
                string size = i < shape.Sizes.Length ? shape.Sizes[i].ToString() : "";
                dimensions.Add(lower + ":" + size);
            }
            return elementType + "[" + string.Join(",", dimensions) + "]";
        }

        public string GetByReferenceType(string elementType)
        {
            return elementType + "&";
        }

        public string GetFunctionPointerType(MethodSignature<string> signature)
        {
            return "method " + Standalone(signature);
        }

        public string GetGenericInstantiation(string genericType, ImmutableArray<string> typeArguments)
        {
            return genericType + "<" + string.Join(", ", typeArguments) + ">";
        }

        public string GetGenericMethodParameter(object genericContext, int index)
        {
            return "!!" + index;
        }

        public string GetGenericTypeParameter(object genericContext, int index)
        {
            return "!" + index;
        }

        public string GetModifiedType(string modifier, string unmodifiedType, bool isRequired)
        {
            return unmodifiedType + (isRequired ? " modreq(" : " modopt(") + modifier + ")";
        }

        public string GetPinnedType(string elementType)
        {
            return elementType + " pinned";
        }

        public string GetPointerType(string elementType)
        {
            return elementType + "*";
        }

        public string GetPrimitiveType(PrimitiveTypeCode typeCode)
        {
            switch (typeCode)
            {
                case PrimitiveTypeCode.Boolean: return "bool";
                case PrimitiveTypeCode.Byte: return "uint8";
                case PrimitiveTypeCode.Char: return "char";
                case PrimitiveTypeCode.Double: return "float64";
                case PrimitiveTypeCode.Int16: return "int16";
                case PrimitiveTypeCode.Int32: return "int32";
                case PrimitiveTypeCode.Int64: return "int64";
                case PrimitiveTypeCode.IntPtr: return "native int";
                case PrimitiveTypeCode.Object: return "object";
                case PrimitiveTypeCode.SByte: return "int8";
                case PrimitiveTypeCode.Single: return "float32";
                case PrimitiveTypeCode.String: return "string";
                case PrimitiveTypeCode.TypedReference: return "typedref";
                case PrimitiveTypeCode.UInt16: return "uint16";
                case PrimitiveTypeCode.UInt32: return "uint32";
                case PrimitiveTypeCode.UInt64: return "uint64";
                case PrimitiveTypeCode.UIntPtr: return "native uint";
                case PrimitiveTypeCode.Void: return "void";
                default: throw new BadImageFormatException("primitive " + typeCode);
            }
        }

        public string GetSZArrayType(string elementType)
        {
            return elementType + "[]";
        }

        public string GetTypeFromDefinition(MetadataReader r, TypeDefinitionHandle handle, byte rawTypeKind)
        {
            return TypeDef(handle);
        }

        public string GetTypeFromReference(MetadataReader r, TypeReferenceHandle handle, byte rawTypeKind)
        {
            return TypeRef(handle);
        }

        public string GetTypeFromSpecification(MetadataReader r, object genericContext, TypeSpecificationHandle handle, byte rawTypeKind)
        {
            return TypeSpec(handle);
        }
    }

    internal sealed class Assembly
    {
        private static readonly Dictionary<short, OpCode> OneByte = new Dictionary<short, OpCode>();
        private static readonly Dictionary<short, OpCode> TwoByte = new Dictionary<short, OpCode>();

        static Assembly()
        {
            foreach (FieldInfo field in typeof(OpCodes).GetFields(BindingFlags.Public | BindingFlags.Static))
            {
                OpCode code = (OpCode)field.GetValue(null);
                if (code.Size == 1)
                {
                    OneByte[code.Value] = code;
                }
                else
                {
                    TwoByte[(short)(code.Value & 0xFF)] = code;
                }
            }
        }

        private readonly PEReader pe;
        private readonly MetadataReader reader;
        private readonly Names names;
        private readonly Dictionary<int, string> paramOwners = new Dictionary<int, string>();
        private readonly Dictionary<int, string> interfaceOwners = new Dictionary<int, string>();
        private readonly Dictionary<int, string> propertyKeys = new Dictionary<int, string>();
        private readonly Dictionary<int, string> eventKeys = new Dictionary<int, string>();

        public Assembly(PEReader pe)
        {
            this.pe = pe;
            reader = pe.GetMetadataReader();
            names = new Names(reader);
            Identity = new SortedDictionary<string, Located>(Utf8Ordinal.Instance);
            Entities = new Dictionary<string, List<Entry>>();
            foreach (string kind in new[] { "assembly-ref", "type", "field", "method", "property", "event", "pinvoke", "resource" })
            {
                Entities[kind] = new List<Entry>();
            }
            Attributes = new List<AttributeEntry>();
            foreach (TypeDefinitionHandle typeHandle in reader.TypeDefinitions)
            {
                TypeDefinition type = reader.GetTypeDefinition(typeHandle);
                string typeName = names.TypeDef(typeHandle);
                foreach (MethodDefinitionHandle methodHandle in type.GetMethods())
                {
                    string key = names.MethodKey(methodHandle);
                    foreach (ParameterHandle parameter in reader.GetMethodDefinition(methodHandle).GetParameters())
                    {
                        paramOwners[MetadataTokens.GetRowNumber(parameter)] = key;
                    }
                }
                foreach (InterfaceImplementationHandle implementation in type.GetInterfaceImplementations())
                {
                    interfaceOwners[MetadataTokens.GetRowNumber(implementation)] = names.Type(reader.GetInterfaceImplementation(implementation).Interface) + " of " + typeName;
                }
                foreach (PropertyDefinitionHandle propertyHandle in type.GetProperties())
                {
                    PropertyDefinition property = reader.GetPropertyDefinition(propertyHandle);
                    propertyKeys[MetadataTokens.GetRowNumber(propertyHandle)] = Names.Member(property.DecodeSignature(names, null), typeName, reader.GetString(property.Name));
                }
                foreach (EventDefinitionHandle eventHandle in type.GetEvents())
                {
                    eventKeys[MetadataTokens.GetRowNumber(eventHandle)] = typeName + "::" + reader.GetString(reader.GetEventDefinition(eventHandle).Name);
                }
            }
            ReadIdentity();
            ReadAssemblyRefs();
            ReadTypes();
            ReadPinvokes();
            ReadResources();
            ReadAttributes();
        }

        public SortedDictionary<string, Located> Identity { get; }

        public Dictionary<string, List<Entry>> Entities { get; }

        public List<AttributeEntry> Attributes { get; }

        private static string Row(TableIndex table, int row)
        {
            return table + "#" + row;
        }

        private static string Row(EntityHandle handle)
        {
            TableIndex table;
            MetadataTokens.TryGetTableIndex(handle.Kind, out table);
            return Row(table, MetadataTokens.GetRowNumber(handle));
        }

        private static string Hex(byte[] bytes)
        {
            return Convert.ToHexString(bytes);
        }

        private string Blob(BlobHandle handle)
        {
            return handle.IsNil ? "" : Hex(reader.GetBlobBytes(handle));
        }

        private string Constant(ConstantHandle handle)
        {
            if (handle.IsNil)
            {
                return "none";
            }
            Constant constant = reader.GetConstant(handle);
            return ((byte)constant.TypeCode).ToString("X2") + ":" + Blob(constant.Value);
        }

        private string Marshal(BlobHandle handle)
        {
            return handle.IsNil ? "none" : Blob(handle);
        }

        private string Security(DeclarativeSecurityAttributeHandleCollection handles)
        {
            List<string> items = new List<string>();
            foreach (DeclarativeSecurityAttributeHandle handle in handles)
            {
                DeclarativeSecurityAttribute attribute = reader.GetDeclarativeSecurityAttribute(handle);
                items.Add("0x" + ((ushort)attribute.Action).ToString("X4") + ":" + Blob(attribute.PermissionSet));
            }
            items.Sort(Utf8Ordinal.Instance);
            return "[" + string.Join(", ", items) + "]";
        }

        private string GenericParameters(GenericParameterHandleCollection handles)
        {
            List<string> items = new List<string>();
            foreach (GenericParameterHandle handle in handles)
            {
                GenericParameter parameter = reader.GetGenericParameter(handle);
                List<string> constraints = new List<string>();
                foreach (GenericParameterConstraintHandle constraint in parameter.GetConstraints())
                {
                    constraints.Add(names.Type(reader.GetGenericParameterConstraint(constraint).Type));
                }
                constraints.Sort(Utf8Ordinal.Instance);
                items.Add(reader.GetString(parameter.Name) + "/0x" + ((ushort)parameter.Attributes).ToString("X4") + "/[" + string.Join(", ", constraints) + "]");
            }
            return "[" + string.Join(", ", items) + "]";
        }

        private void ReadIdentity()
        {
            if (reader.IsAssembly)
            {
                AssemblyDefinition assembly = reader.GetAssemblyDefinition();
                string row = Row(TableIndex.Assembly, 1);
                Identity["name"] = new Located(reader.GetString(assembly.Name), row);
                Identity["version"] = new Located(assembly.Version.ToString(4), row);
                string culture = reader.GetString(assembly.Culture);
                Identity["culture"] = new Located(culture.Length == 0 ? "neutral" : culture, row);
                Identity["flags"] = new Located("0x" + ((uint)assembly.Flags).ToString("X8"), row);
                Identity["hash-algorithm"] = new Located("0x" + ((uint)assembly.HashAlgorithm).ToString("X8"), row);
                byte[] token = assembly.GetAssemblyName().GetPublicKeyToken() ?? Array.Empty<byte>();
                Identity["public-key-token"] = new Located(token.Length == 0 ? "null" : Convert.ToHexString(token).ToLowerInvariant(), row);
                Identity["security"] = new Located(Security(assembly.GetDeclarativeSecurityAttributes()), row);
                string framework = "none";
                string frameworkRow = "-";
                foreach (CustomAttributeHandle handle in assembly.GetCustomAttributes())
                {
                    CustomAttribute attribute = reader.GetCustomAttribute(handle);
                    if (AttributeTypeIs(attribute, "System.Runtime.Versioning", "TargetFrameworkAttribute"))
                    {
                        BlobReader value = reader.GetBlobReader(attribute.Value);
                        if (value.ReadUInt16() != 1)
                        {
                            throw new BadImageFormatException("attribute prolog");
                        }
                        framework = value.ReadSerializedString() ?? "null";
                        frameworkRow = Row(handle);
                        break;
                    }
                }
                Identity["target-framework"] = new Located(framework, frameworkRow);
            }
            ModuleDefinition module = reader.GetModuleDefinition();
            Identity["module"] = new Located(reader.GetString(module.Name), Row(TableIndex.Module, 1));
            Identity["mvid"] = new Located(module.Mvid.IsNil ? "none" : reader.GetGuid(module.Mvid).ToString("D"), Row(TableIndex.Module, 1));
            Identity["metadata-version"] = new Located(reader.MetadataVersion, "metadata-root");
            Identity["pe-timestamp"] = new Located("0x" + ((uint)pe.PEHeaders.CoffHeader.TimeDateStamp).ToString("X8"), "coff-header");
            Identity["machine"] = new Located("0x" + ((ushort)pe.PEHeaders.CoffHeader.Machine).ToString("X4"), "coff-header");
            Identity["clr-flags"] = new Located("0x" + ((uint)pe.PEHeaders.CorHeader.Flags).ToString("X8"), "cli-header");
            bool reproducible = pe.ReadDebugDirectory().Any(entry => entry.Type == DebugDirectoryEntryType.Reproducible);
            Identity["reproducible"] = new Located(reproducible ? "yes" : "no", "debug-directory");
        }

        private bool AttributeTypeIs(CustomAttribute attribute, string ns, string name)
        {
            EntityHandle owner;
            if (attribute.Constructor.Kind == HandleKind.MethodDefinition)
            {
                owner = reader.GetMethodDefinition((MethodDefinitionHandle)attribute.Constructor).GetDeclaringType();
            }
            else
            {
                owner = reader.GetMemberReference((MemberReferenceHandle)attribute.Constructor).Parent;
            }
            if (owner.Kind == HandleKind.TypeReference)
            {
                TypeReference type = reader.GetTypeReference((TypeReferenceHandle)owner);
                return reader.GetString(type.Namespace) == ns && reader.GetString(type.Name) == name;
            }
            if (owner.Kind == HandleKind.TypeDefinition)
            {
                TypeDefinition type = reader.GetTypeDefinition((TypeDefinitionHandle)owner);
                return reader.GetString(type.Namespace) == ns && reader.GetString(type.Name) == name;
            }
            return false;
        }

        private void ReadAssemblyRefs()
        {
            foreach (AssemblyReferenceHandle handle in reader.AssemblyReferences)
            {
                AssemblyReference reference = reader.GetAssemblyReference(handle);
                string culture = reader.GetString(reference.Culture);
                string key = reader.GetBlobBytes(reference.PublicKeyOrToken).Length == 0 ? "null" : Blob(reference.PublicKeyOrToken);
                Entry entry = new Entry
                {
                    Key = reader.GetString(reference.Name),
                    Location = Row(handle),
                };
                entry.Aspects.Add(new KeyValuePair<string, string>("version", reference.Version.ToString(4)));
                entry.Aspects.Add(new KeyValuePair<string, string>("culture", culture.Length == 0 ? "neutral" : culture));
                entry.Aspects.Add(new KeyValuePair<string, string>("flags", "0x" + ((uint)reference.Flags).ToString("X8")));
                entry.Aspects.Add(new KeyValuePair<string, string>("public-key", key));
                Entities["assembly-ref"].Add(entry);
            }
        }

        private void ReadTypes()
        {
            foreach (TypeDefinitionHandle typeHandle in reader.TypeDefinitions)
            {
                TypeDefinition type = reader.GetTypeDefinition(typeHandle);
                string typeName = names.TypeDef(typeHandle);
                List<string> interfaces = new List<string>();
                foreach (InterfaceImplementationHandle implementation in type.GetInterfaceImplementations())
                {
                    interfaces.Add(names.Type(reader.GetInterfaceImplementation(implementation).Interface));
                }
                interfaces.Sort(Utf8Ordinal.Instance);
                List<string> impls = new List<string>();
                foreach (MethodImplementationHandle implementation in type.GetMethodImplementations())
                {
                    MethodImplementation methodImpl = reader.GetMethodImplementation(implementation);
                    impls.Add(names.Method(methodImpl.MethodBody) + " => " + names.Method(methodImpl.MethodDeclaration));
                }
                impls.Sort(Utf8Ordinal.Instance);
                TypeLayout layout = type.GetLayout();
                Entry entry = new Entry { Key = typeName, Location = Row(typeHandle) };
                entry.Aspects.Add(new KeyValuePair<string, string>("flags", "0x" + ((uint)type.Attributes).ToString("X8")));
                entry.Aspects.Add(new KeyValuePair<string, string>("extends", names.Type(type.BaseType)));
                entry.Aspects.Add(new KeyValuePair<string, string>("interfaces", "[" + string.Join(", ", interfaces) + "]"));
                entry.Aspects.Add(new KeyValuePair<string, string>("generic-parameters", GenericParameters(type.GetGenericParameters())));
                entry.Aspects.Add(new KeyValuePair<string, string>("layout", "pack " + layout.PackingSize + " size " + layout.Size));
                entry.Aspects.Add(new KeyValuePair<string, string>("method-impls", "[" + string.Join(", ", impls) + "]"));
                entry.Aspects.Add(new KeyValuePair<string, string>("security", Security(type.GetDeclarativeSecurityAttributes())));
                Entities["type"].Add(entry);
                foreach (FieldDefinitionHandle fieldHandle in type.GetFields())
                {
                    FieldDefinition field = reader.GetFieldDefinition(fieldHandle);
                    int offset = field.GetOffset();
                    Entry fieldEntry = new Entry { Key = names.FieldKey(fieldHandle), Location = Row(fieldHandle) };
                    fieldEntry.Aspects.Add(new KeyValuePair<string, string>("flags", "0x" + ((ushort)field.Attributes).ToString("X4")));
                    fieldEntry.Aspects.Add(new KeyValuePair<string, string>("type", field.DecodeSignature(names, null)));
                    fieldEntry.Aspects.Add(new KeyValuePair<string, string>("constant", Constant(field.GetDefaultValue())));
                    fieldEntry.Aspects.Add(new KeyValuePair<string, string>("offset", offset < 0 ? "none" : offset.ToString()));
                    fieldEntry.Aspects.Add(new KeyValuePair<string, string>("marshal", Marshal(field.GetMarshallingDescriptor())));
                    Entities["field"].Add(fieldEntry);
                }
                foreach (MethodDefinitionHandle methodHandle in type.GetMethods())
                {
                    Entities["method"].Add(ReadMethod(methodHandle, typeName));
                }
                foreach (PropertyDefinitionHandle propertyHandle in type.GetProperties())
                {
                    PropertyDefinition property = reader.GetPropertyDefinition(propertyHandle);
                    MethodSignature<string> signature = property.DecodeSignature(names, null);
                    string name = reader.GetString(property.Name);
                    PropertyAccessors accessors = property.GetAccessors();
                    List<string> roles = new List<string>();
                    if (!accessors.Getter.IsNil)
                    {
                        roles.Add("get " + reader.GetString(reader.GetMethodDefinition(accessors.Getter).Name));
                    }
                    if (!accessors.Setter.IsNil)
                    {
                        roles.Add("set " + reader.GetString(reader.GetMethodDefinition(accessors.Setter).Name));
                    }
                    foreach (MethodDefinitionHandle other in accessors.Others)
                    {
                        roles.Add("other " + reader.GetString(reader.GetMethodDefinition(other).Name));
                    }
                    Entry propertyEntry = new Entry
                    {
                        Key = Names.Member(signature, typeName, name),
                        Group = typeName + "::" + name,
                        Signature = Names.Standalone(signature),
                        Location = Row(propertyHandle),
                    };
                    propertyEntry.Aspects.Add(new KeyValuePair<string, string>("flags", "0x" + ((ushort)property.Attributes).ToString("X4")));
                    propertyEntry.Aspects.Add(new KeyValuePair<string, string>("accessors", "[" + string.Join(", ", roles) + "]"));
                    propertyEntry.Aspects.Add(new KeyValuePair<string, string>("constant", Constant(property.GetDefaultValue())));
                    Entities["property"].Add(propertyEntry);
                }
                foreach (EventDefinitionHandle eventHandle in type.GetEvents())
                {
                    EventDefinition definition = reader.GetEventDefinition(eventHandle);
                    EventAccessors accessors = definition.GetAccessors();
                    List<string> roles = new List<string>();
                    if (!accessors.Adder.IsNil)
                    {
                        roles.Add("add " + reader.GetString(reader.GetMethodDefinition(accessors.Adder).Name));
                    }
                    if (!accessors.Remover.IsNil)
                    {
                        roles.Add("remove " + reader.GetString(reader.GetMethodDefinition(accessors.Remover).Name));
                    }
                    if (!accessors.Raiser.IsNil)
                    {
                        roles.Add("raise " + reader.GetString(reader.GetMethodDefinition(accessors.Raiser).Name));
                    }
                    foreach (MethodDefinitionHandle other in accessors.Others)
                    {
                        roles.Add("other " + reader.GetString(reader.GetMethodDefinition(other).Name));
                    }
                    Entry eventEntry = new Entry
                    {
                        Key = typeName + "::" + reader.GetString(definition.Name),
                        Location = Row(eventHandle),
                    };
                    eventEntry.Aspects.Add(new KeyValuePair<string, string>("flags", "0x" + ((ushort)definition.Attributes).ToString("X4")));
                    eventEntry.Aspects.Add(new KeyValuePair<string, string>("type", names.Type(definition.Type)));
                    eventEntry.Aspects.Add(new KeyValuePair<string, string>("accessors", "[" + string.Join(", ", roles) + "]"));
                    Entities["event"].Add(eventEntry);
                }
            }
        }

        private Entry ReadMethod(MethodDefinitionHandle handle, string typeName)
        {
            MethodDefinition method = reader.GetMethodDefinition(handle);
            MethodSignature<string> signature = method.DecodeSignature(names, null);
            string name = reader.GetString(method.Name);
            List<string> parameters = new List<string>();
            foreach (ParameterHandle parameterHandle in method.GetParameters())
            {
                Parameter parameter = reader.GetParameter(parameterHandle);
                string item = parameter.SequenceNumber + " " + reader.GetString(parameter.Name) + " 0x" + ((ushort)parameter.Attributes).ToString("X4");
                string constant = Constant(parameter.GetDefaultValue());
                if (constant != "none")
                {
                    item += " = " + constant;
                }
                string marshal = Marshal(parameter.GetMarshallingDescriptor());
                if (marshal != "none")
                {
                    item += " marshal " + marshal;
                }
                parameters.Add(item);
            }
            Entry entry = new Entry
            {
                Key = Names.Member(signature, typeName, name),
                Group = typeName + "::" + name,
                Signature = Names.Standalone(signature),
                Location = Row(handle),
            };
            entry.Aspects.Add(new KeyValuePair<string, string>("flags", "0x" + ((ushort)method.Attributes).ToString("X4")));
            entry.Aspects.Add(new KeyValuePair<string, string>("impl-flags", "0x" + ((ushort)method.ImplAttributes).ToString("X4")));
            entry.Aspects.Add(new KeyValuePair<string, string>("parameters", "[" + string.Join(", ", parameters) + "]"));
            entry.Aspects.Add(new KeyValuePair<string, string>("generic-parameters", GenericParameters(method.GetGenericParameters())));
            entry.Aspects.Add(new KeyValuePair<string, string>("security", Security(method.GetDeclarativeSecurityAttributes())));
            entry.Body = ReadBody(method);
            return entry;
        }

        private Body ReadBody(MethodDefinition method)
        {
            if (method.RelativeVirtualAddress == 0 || (method.ImplAttributes & MethodImplAttributes.CodeTypeMask) != MethodImplAttributes.IL)
            {
                return new Body { Present = false };
            }
            MethodBodyBlock block = pe.GetMethodBody(method.RelativeVirtualAddress);
            byte[] raw = pe.GetSectionData(method.RelativeVirtualAddress).GetContent(0, block.Size).ToArray();
            List<string> normalized = new List<string>
            {
                "maxstack " + block.MaxStack,
                "initlocals " + block.LocalVariablesInitialized,
                "locals " + (block.LocalSignature.IsNil ? "none" : names.StandaloneSig(block.LocalSignature)),
            };
            byte[] il = block.GetILBytes();
            BlobReader code = block.GetILReader();
            while (code.RemainingBytes > 0)
            {
                byte first = code.ReadByte();
                OpCode opcode;
                if (first == 0xFE)
                {
                    byte second = code.ReadByte();
                    if (!TwoByte.TryGetValue(second, out opcode))
                    {
                        throw new BadImageFormatException("opcode FE " + second.ToString("X2"));
                    }
                }
                else if (!OneByte.TryGetValue(first, out opcode))
                {
                    throw new BadImageFormatException("opcode " + first.ToString("X2"));
                }
                string operand;
                switch (opcode.OperandType)
                {
                    case OperandType.InlineNone:
                        operand = "";
                        break;
                    case OperandType.ShortInlineBrTarget:
                    case OperandType.ShortInlineI:
                    case OperandType.ShortInlineVar:
                        operand = code.ReadByte().ToString();
                        break;
                    case OperandType.InlineVar:
                        operand = code.ReadUInt16().ToString();
                        break;
                    case OperandType.InlineBrTarget:
                    case OperandType.InlineI:
                    case OperandType.ShortInlineR:
                        operand = code.ReadInt32().ToString();
                        break;
                    case OperandType.InlineI8:
                    case OperandType.InlineR:
                        operand = code.ReadInt64().ToString();
                        break;
                    case OperandType.InlineSwitch:
                    {
                        int count = code.ReadInt32();
                        List<string> targets = new List<string>();
                        for (int i = 0; i < count; i++)
                        {
                            targets.Add(code.ReadInt32().ToString());
                        }
                        operand = string.Join(",", targets);
                        break;
                    }
                    case OperandType.InlineField:
                    case OperandType.InlineMethod:
                    case OperandType.InlineSig:
                    case OperandType.InlineString:
                    case OperandType.InlineTok:
                    case OperandType.InlineType:
                        operand = names.Operand(code.ReadInt32());
                        break;
                    default:
                        throw new BadImageFormatException("operand type " + opcode.OperandType);
                }
                normalized.Add(opcode.Value.ToString("X4") + " " + operand);
            }
            foreach (ExceptionRegion region in block.ExceptionRegions)
            {
                string handler = region.Kind == ExceptionRegionKind.Catch ? names.Type(region.CatchType) : region.Kind == ExceptionRegionKind.Filter ? region.FilterOffset.ToString() : "";
                normalized.Add("eh " + region.Kind + " " + region.TryOffset + " " + region.TryLength + " " + region.HandlerOffset + " " + region.HandlerLength + " " + handler);
            }
            return new Body { Present = true, Raw = raw, Normalized = normalized, CodeSize = il.Length };
        }

        private void ReadPinvokes()
        {
            int rows = reader.GetTableRowCount(TableIndex.ImplMap);
            if (rows == 0)
            {
                return;
            }
            ImmutableArray<byte> metadata = pe.GetMetadata().GetContent();
            int start = reader.GetTableMetadataOffset(TableIndex.ImplMap);
            int rowSize = reader.GetTableRowSize(TableIndex.ImplMap);
            int stringSize = reader.GetTableRowSize(TableIndex.ModuleRef);
            int moduleSize = reader.GetTableRowCount(TableIndex.ModuleRef) < 0x10000 ? 2 : 4;
            int memberSize = rowSize - 2 - stringSize - moduleSize;
            for (int row = 1; row <= rows; row++)
            {
                int at = start + (row - 1) * rowSize;
                ushort flags = (ushort)(metadata[at] | (metadata[at + 1] << 8));
                int member = ReadIndex(metadata, at + 2, memberSize);
                int importName = ReadIndex(metadata, at + 2 + memberSize, stringSize);
                int scope = ReadIndex(metadata, at + 2 + memberSize + stringSize, moduleSize);
                string key;
                int memberRow = member >> 1;
                if ((member & 1) == 1)
                {
                    MethodDefinitionHandle method = MetadataTokens.MethodDefinitionHandle(memberRow);
                    key = names.MethodKey(method);
                    MethodImport import = reader.GetMethodDefinition(method).GetImport();
                    if (import.Module.IsNil || reader.GetString(import.Name) != reader.GetString(MetadataTokens.StringHandle(importName)) || (ushort)import.Attributes != flags || MetadataTokens.GetRowNumber(import.Module) != scope)
                    {
                        throw new InvalidOperationException("ImplMap#" + row + " disagrees with MethodDefinition.GetImport");
                    }
                }
                else
                {
                    key = names.FieldKey(MetadataTokens.FieldDefinitionHandle(memberRow));
                }
                string module = scope == 0 ? "none" : reader.GetString(reader.GetModuleReference(MetadataTokens.ModuleReferenceHandle(scope)).Name);
                Entry entry = new Entry { Key = key, Location = Row(TableIndex.ImplMap, row) };
                entry.Aspects.Add(new KeyValuePair<string, string>("module", module));
                entry.Aspects.Add(new KeyValuePair<string, string>("entry-point", reader.GetString(MetadataTokens.StringHandle(importName))));
                entry.Aspects.Add(new KeyValuePair<string, string>("flags", "0x" + flags.ToString("X4")));
                Entities["pinvoke"].Add(entry);
            }
        }

        private static int ReadIndex(ImmutableArray<byte> bytes, int at, int size)
        {
            int value = bytes[at] | (bytes[at + 1] << 8);
            if (size == 4)
            {
                value |= (bytes[at + 2] << 16) | (bytes[at + 3] << 24);
            }
            return value;
        }

        private void ReadResources()
        {
            foreach (ManifestResourceHandle handle in reader.ManifestResources)
            {
                ManifestResource resource = reader.GetManifestResource(handle);
                string implementation;
                string size = "none";
                string digest = "none";
                if (resource.Implementation.IsNil)
                {
                    implementation = "embedded";
                    int rva = pe.PEHeaders.CorHeader.ResourcesDirectory.RelativeVirtualAddress + (int)resource.Offset;
                    BlobReader data = pe.GetSectionData(rva).GetReader();
                    int length = data.ReadInt32();
                    byte[] bytes = data.ReadBytes(length);
                    size = length.ToString();
                    digest = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
                }
                else if (resource.Implementation.Kind == HandleKind.AssemblyFile)
                {
                    implementation = "file " + reader.GetString(reader.GetAssemblyFile((AssemblyFileHandle)resource.Implementation).Name);
                }
                else if (resource.Implementation.Kind == HandleKind.AssemblyReference)
                {
                    implementation = "assembly " + reader.GetString(reader.GetAssemblyReference((AssemblyReferenceHandle)resource.Implementation).Name);
                }
                else
                {
                    throw new BadImageFormatException("resource implementation " + resource.Implementation.Kind);
                }
                Entry entry = new Entry { Key = reader.GetString(resource.Name), Location = Row(handle) };
                entry.Aspects.Add(new KeyValuePair<string, string>("flags", "0x" + ((uint)resource.Attributes).ToString("X8")));
                entry.Aspects.Add(new KeyValuePair<string, string>("implementation", implementation));
                entry.Aspects.Add(new KeyValuePair<string, string>("size", size));
                entry.Aspects.Add(new KeyValuePair<string, string>("sha256", digest));
                Entities["resource"].Add(entry);
            }
        }

        private string GenericParameterOwner(GenericParameterHandle handle)
        {
            GenericParameter parameter = reader.GetGenericParameter(handle);
            string owner = parameter.Parent.Kind == HandleKind.TypeDefinition
                ? "type " + names.TypeDef((TypeDefinitionHandle)parameter.Parent)
                : "method " + names.MethodKey((MethodDefinitionHandle)parameter.Parent);
            return "generic-parameter " + parameter.Index + " of " + owner;
        }

        private string Owner(EntityHandle parent)
        {
            int row = MetadataTokens.GetRowNumber(parent);
            switch (parent.Kind)
            {
                case HandleKind.AssemblyDefinition:
                    return "assembly";
                case HandleKind.ModuleDefinition:
                    return "module";
                case HandleKind.TypeDefinition:
                    return "type " + names.TypeDef((TypeDefinitionHandle)parent);
                case HandleKind.FieldDefinition:
                    return "field " + names.FieldKey((FieldDefinitionHandle)parent);
                case HandleKind.MethodDefinition:
                    return "method " + names.MethodKey((MethodDefinitionHandle)parent);
                case HandleKind.Parameter:
                    return "parameter " + reader.GetParameter((ParameterHandle)parent).SequenceNumber + " of " + paramOwners[row];
                case HandleKind.PropertyDefinition:
                    return "property " + propertyKeys[row];
                case HandleKind.EventDefinition:
                    return "event " + eventKeys[row];
                case HandleKind.InterfaceImplementation:
                    return "interface " + interfaceOwners[row];
                case HandleKind.GenericParameter:
                    return GenericParameterOwner((GenericParameterHandle)parent);
                case HandleKind.GenericParameterConstraint:
                {
                    GenericParameterConstraint constraint = reader.GetGenericParameterConstraint((GenericParameterConstraintHandle)parent);
                    return "constraint " + names.Type(constraint.Type) + " of " + GenericParameterOwner(constraint.Parameter);
                }
                case HandleKind.TypeReference:
                    return "type-ref " + names.Type(parent);
                case HandleKind.TypeSpecification:
                    return "type-spec " + names.Type(parent);
                case HandleKind.MemberReference:
                    return "member-ref " + names.MemberRef((MemberReferenceHandle)parent, out bool _);
                case HandleKind.MethodSpecification:
                    return "method-spec " + names.MethodSpec((MethodSpecificationHandle)parent);
                case HandleKind.StandaloneSignature:
                    return "signature " + names.StandaloneSig((StandaloneSignatureHandle)parent);
                case HandleKind.ModuleReference:
                    return "module-ref " + reader.GetString(reader.GetModuleReference((ModuleReferenceHandle)parent).Name);
                case HandleKind.AssemblyReference:
                    return "assembly-ref " + reader.GetString(reader.GetAssemblyReference((AssemblyReferenceHandle)parent).Name);
                case HandleKind.AssemblyFile:
                    return "file " + reader.GetString(reader.GetAssemblyFile((AssemblyFileHandle)parent).Name);
                case HandleKind.ExportedType:
                {
                    ExportedType exported = reader.GetExportedType((ExportedTypeHandle)parent);
                    return "exported-type " + Names.Qualify(reader.GetString(exported.Namespace), reader.GetString(exported.Name));
                }
                case HandleKind.ManifestResource:
                    return "resource " + reader.GetString(reader.GetManifestResource((ManifestResourceHandle)parent).Name);
                default:
                    throw new BadImageFormatException("attribute parent " + parent.Kind);
            }
        }

        private void ReadAttributes()
        {
            foreach (CustomAttributeHandle handle in reader.CustomAttributes)
            {
                CustomAttribute attribute = reader.GetCustomAttribute(handle);
                string type;
                MethodSignature<string> constructor;
                if (attribute.Constructor.Kind == HandleKind.MethodDefinition)
                {
                    MethodDefinition method = reader.GetMethodDefinition((MethodDefinitionHandle)attribute.Constructor);
                    type = names.TypeDef(method.GetDeclaringType());
                    constructor = method.DecodeSignature(names, null);
                }
                else
                {
                    MemberReference member = reader.GetMemberReference((MemberReferenceHandle)attribute.Constructor);
                    type = names.MemberRefParent(member.Parent);
                    constructor = member.DecodeMethodSignature(names, null);
                }
                Attributes.Add(new AttributeEntry
                {
                    Group = Owner(attribute.Parent) + " @ " + type,
                    Value = Names.Parameters(constructor) + " 0x" + Blob(attribute.Value),
                    Location = Row(handle),
                });
            }
        }
    }

    internal static class Program
    {
        private static readonly string[] EntityOrder = { "assembly-ref", "type", "field", "method", "property", "event", "pinvoke", "resource" };

        private static string Line(string change, string entity, string key, string aspect, string old, string current, string oldRow, string newRow)
        {
            switch (change)
            {
                case "added":
                    return "added " + entity + " " + key + (current == null ? "" : " = " + current) + " [" + newRow + "]";
                case "removed":
                    return "removed " + entity + " " + key + (old == null ? "" : " = " + old) + " [" + oldRow + "]";
                default:
                    return "changed " + entity + " " + key + (aspect == null ? "" : " " + aspect) + ": " + old + " -> " + current + " [" + oldRow + " -> " + newRow + "]";
            }
        }

        private static void CompareEntries(string entity, Entry old, Entry current, string key, List<string> lines)
        {
            if (old.Signature != current.Signature)
            {
                lines.Add(Line("changed", entity, key, "signature", old.Signature, current.Signature, old.Location, current.Location));
            }
            for (int i = 0; i < old.Aspects.Count; i++)
            {
                if (old.Aspects[i].Value != current.Aspects[i].Value)
                {
                    lines.Add(Line("changed", entity, key, old.Aspects[i].Key, old.Aspects[i].Value, current.Aspects[i].Value, old.Location, current.Location));
                }
            }
            if (old.Body == null)
            {
                return;
            }
            Body a = old.Body;
            Body b = current.Body;
            if (!a.Present && !b.Present)
            {
                return;
            }
            string before = a.Present ? a.CodeSize + " bytes" : "none";
            string after = b.Present ? b.CodeSize + " bytes" : "none";
            if (!a.Present || !b.Present)
            {
                lines.Add(Line("changed", entity, key, "body il-changed", before, after, old.Location, current.Location));
                return;
            }
            bool rawEqual = a.Raw.AsSpan().SequenceEqual(b.Raw);
            bool normalizedEqual = a.Normalized.SequenceEqual(b.Normalized);
            if (rawEqual && normalizedEqual)
            {
                return;
            }
            string kind = normalizedEqual ? "body token-renumbered" : "body il-changed";
            lines.Add(Line("changed", entity, key, kind, before, after, old.Location, current.Location));
        }

        private static void Diff(string entity, List<Entry> olds, List<Entry> news, bool paired, List<string> lines)
        {
            Dictionary<string, List<Entry>> byKey = new Dictionary<string, List<Entry>>();
            foreach (Entry entry in news)
            {
                if (!byKey.TryGetValue(entry.Key, out List<Entry> list))
                {
                    byKey[entry.Key] = list = new List<Entry>();
                }
                list.Add(entry);
            }
            List<Entry> removed = new List<Entry>();
            foreach (Entry entry in olds)
            {
                if (byKey.TryGetValue(entry.Key, out List<Entry> list) && list.Count > 0)
                {
                    Entry match = list[0];
                    list.RemoveAt(0);
                    CompareEntries(entity, entry, match, entry.Key, lines);
                }
                else
                {
                    removed.Add(entry);
                }
            }
            List<Entry> added = news.Where(entry => byKey[entry.Key].Contains(entry)).ToList();
            if (paired)
            {
                foreach (Entry entry in removed.ToList())
                {
                    List<Entry> oldGroup = removed.Where(other => other.Group == entry.Group).ToList();
                    List<Entry> newGroup = added.Where(other => other.Group == entry.Group).ToList();
                    if (oldGroup.Count == 1 && newGroup.Count == 1)
                    {
                        CompareEntries(entity, entry, newGroup[0], entry.Key, lines);
                        removed.Remove(entry);
                        added.Remove(newGroup[0]);
                    }
                }
            }
            foreach (Entry entry in removed)
            {
                lines.Add(Line("removed", entity, entry.Key, null, null, null, entry.Location, null));
            }
            foreach (Entry entry in added)
            {
                lines.Add(Line("added", entity, entry.Key, null, null, null, null, entry.Location));
            }
        }

        private static void DiffAttributes(List<AttributeEntry> olds, List<AttributeEntry> news, List<string> lines)
        {
            List<AttributeEntry> remaining = new List<AttributeEntry>(news);
            List<AttributeEntry> removed = new List<AttributeEntry>();
            foreach (AttributeEntry entry in olds)
            {
                AttributeEntry match = remaining.FirstOrDefault(other => other.Group == entry.Group && other.Value == entry.Value);
                if (match != null)
                {
                    remaining.Remove(match);
                }
                else
                {
                    removed.Add(entry);
                }
            }
            foreach (AttributeEntry entry in removed.ToList())
            {
                List<AttributeEntry> oldGroup = removed.Where(other => other.Group == entry.Group).ToList();
                List<AttributeEntry> newGroup = remaining.Where(other => other.Group == entry.Group).ToList();
                if (oldGroup.Count == 1 && newGroup.Count == 1)
                {
                    lines.Add(Line("changed", "attribute", entry.Group, "value", entry.Value, newGroup[0].Value, entry.Location, newGroup[0].Location));
                    removed.Remove(entry);
                    remaining.Remove(newGroup[0]);
                }
            }
            foreach (AttributeEntry entry in removed)
            {
                lines.Add(Line("removed", "attribute", entry.Group, null, entry.Value, null, entry.Location, null));
            }
            foreach (AttributeEntry entry in remaining)
            {
                lines.Add(Line("added", "attribute", entry.Group, null, null, entry.Value, null, entry.Location));
            }
        }

        private static Assembly Load(string path)
        {
            byte[] bytes = File.ReadAllBytes(path);
            return new Assembly(new PEReader(ImmutableArray.Create(bytes)));
        }

        private static int Main(string[] args)
        {
            if (args.Length != 2)
            {
                Console.Error.WriteLine("usage: BuildCompareReference <old.dll> <new.dll>");
                return 2;
            }
            Assembly old = Load(args[0]);
            Assembly current = Load(args[1]);
            List<string> lines = new List<string>();
            foreach (string field in old.Identity.Keys.Union(current.Identity.Keys))
            {
                Located a = old.Identity.TryGetValue(field, out Located x) ? x : new Located("none", "-");
                Located b = current.Identity.TryGetValue(field, out Located y) ? y : new Located("none", "-");
                if (a.Value != b.Value)
                {
                    lines.Add(Line("changed", "identity", field, null, a.Value, b.Value, a.Location, b.Location));
                }
            }
            foreach (string entity in EntityOrder)
            {
                Diff(entity, old.Entities[entity], current.Entities[entity], entity == "method" || entity == "property", lines);
            }
            DiffAttributes(old.Attributes, current.Attributes, lines);
            lines.Sort(Utf8Ordinal.Instance);
            StringBuilder output = new StringBuilder();
            foreach (string line in lines)
            {
                output.Append(line).Append('\n');
            }
            Stream stdout = Console.OpenStandardOutput();
            byte[] encoded = new UTF8Encoding(false).GetBytes(output.ToString());
            stdout.Write(encoded, 0, encoded.Length);
            stdout.Flush();
            return 0;
        }
    }
}
