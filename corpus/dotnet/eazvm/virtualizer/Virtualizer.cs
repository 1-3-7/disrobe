using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using System.Text;

namespace EazVmBuilder
{
    internal enum EazOperand
    {
        None,
        InlineI,
        InlineVarArg,
        InlineVarLoc,
        ShortBr,
        InlineMethod,
        InlineString,
    }

    internal sealed class CilOp
    {
        public string Name = "";
        public EazOperand Operand;
        public int OperandI;
        public int VarIndex;
        public int BranchTargetIlOffset;
        public int IlOffset;
        public int IlSize;
        public string MemberName = "";
        public string LiteralString = "";
    }

    internal sealed class SrcMethod
    {
        public string Name = "";
        public int ParamCount;
        public int LocalCount;
        public bool ReturnsVoid;
        public List<CilOp> Body = new();
    }

    internal static class Program
    {
        private static readonly uint[] PseudoRandomInts = { 52200625u, 614125u, 7225u, 85u, 1u };

        private static int Main(string[] args)
        {
            string cleanPath = args.Length > 0 ? args[0] : "EazSample.clean.dll";
            string outPath = args.Length > 1 ? args[1] : "EazSample.eazvm.dll";
            string mapPath = args.Length > 2 ? args[2] : "EazSample.opcodemap.txt";
            int seed = args.Length > 3 ? int.Parse(args[3]) : 0x5EA2;

            byte[] cleanBytes = File.ReadAllBytes(cleanPath);
            List<SrcMethod> methods = ReadComputeMethods(cleanBytes);

            var rng = new NetRandom(seed);
            Dictionary<string, int> opcodeMap = BuildOpcodeMap(rng);

            int resourceKey = rng.Next() | 1;
            int positionKey = rng.Next() | 1;

            var bodies = new List<(SrcMethod m, byte[] body)>();
            foreach (SrcMethod m in methods)
                bodies.Add((m, SerializeMethodBody(m, opcodeMap)));

            byte[] plainResource;
            var positions = new Dictionary<string, long>();
            using (var ms = new MemoryStream())
            {
                foreach ((SrcMethod m, byte[] body) in bodies)
                {
                    positions[m.Name] = ms.Position;
                    ms.Write(body, 0, body.Length);
                }
                plainResource = ms.ToArray();
            }

            byte[] encResource = CryptResource(plainResource, resourceKey);

            var positionStrings = new Dictionary<string, string>();
            foreach ((SrcMethod m, byte[] _) in bodies)
                positionStrings[m.Name] = EncodePositionString(positions[m.Name], positionKey);

            EmitAssembly(outPath, methods, opcodeMap, encResource, positionStrings, resourceKey, positionKey);

            WriteMap(mapPath, opcodeMap, resourceKey, positionKey, positions, positionStrings, methods);

            Console.WriteLine($"virtualized {methods.Count} methods -> {outPath} ({encResource.Length}-byte resource)");
            return 0;
        }

        private static List<SrcMethod> ReadComputeMethods(byte[] image)
        {
            var result = new List<SrcMethod>();
            using var peReader = new PEReader(ImmutableArray.Create(image));
            MetadataReader md = peReader.GetMetadataReader();

            foreach (TypeDefinitionHandle tdh in md.TypeDefinitions)
            {
                TypeDefinition td = md.GetTypeDefinition(tdh);
                string typeName = md.GetString(td.Name);
                if (typeName != "Compute")
                    continue;

                foreach (MethodDefinitionHandle mdh in td.GetMethods())
                {
                    MethodDefinition method = md.GetMethodDefinition(mdh);
                    string methodName = md.GetString(method.Name);
                    if (methodName == ".ctor")
                        continue;

                    MethodSignature<string> sig = method.DecodeSignature(new SimpleSigProvider(), null);
                    int paramCount = sig.ParameterTypes.Length;
                    bool returnsVoid = sig.ReturnType == "void";

                    int rva = method.RelativeVirtualAddress;
                    MethodBodyBlock bodyBlock = peReader.GetMethodBody(rva);
                    int localCount = CountLocals(md, bodyBlock.LocalSignature);

                    List<CilOp> ops = DecodeCil(bodyBlock.GetILBytes(), md);
                    result.Add(new SrcMethod
                    {
                        Name = methodName,
                        ParamCount = paramCount,
                        LocalCount = localCount,
                        ReturnsVoid = returnsVoid,
                        Body = ops,
                    });
                }
            }

            result.Sort((a, b) => string.CompareOrdinal(a.Name, b.Name));
            return result;
        }

        private static int CountLocals(MetadataReader md, StandaloneSignatureHandle handle)
        {
            if (handle.IsNil)
                return 0;
            StandaloneSignature sig = md.GetStandaloneSignature(handle);
            ImmutableArray<string> locals = sig.DecodeLocalSignature(new SimpleSigProvider(), null);
            return locals.Length;
        }

        private static List<CilOp> DecodeCil(byte[] il, MetadataReader md)
        {
            var ops = new List<CilOp>();
            int pos = 0;
            while (pos < il.Length)
            {
                int start = pos;
                byte b = il[pos++];
                var op = new CilOp { IlOffset = start };
                switch (b)
                {
                    case 0x00: op.Name = "nop"; break;
                    case 0x02: op.Name = "ldarg.0"; break;
                    case 0x03: op.Name = "ldarg.1"; break;
                    case 0x04: op.Name = "ldarg.2"; break;
                    case 0x05: op.Name = "ldarg.3"; break;
                    case 0x06: op.Name = "ldloc.0"; break;
                    case 0x07: op.Name = "ldloc.1"; break;
                    case 0x08: op.Name = "ldloc.2"; break;
                    case 0x09: op.Name = "ldloc.3"; break;
                    case 0x0A: op.Name = "stloc.0"; break;
                    case 0x0B: op.Name = "stloc.1"; break;
                    case 0x0C: op.Name = "stloc.2"; break;
                    case 0x0D: op.Name = "stloc.3"; break;
                    case 0x0E: op.Name = "ldarg.s"; op.Operand = EazOperand.InlineVarArg; op.VarIndex = il[pos++]; break;
                    case 0x10: op.Name = "starg.s"; op.Operand = EazOperand.InlineVarArg; op.VarIndex = il[pos++]; break;
                    case 0x11: op.Name = "ldloc.s"; op.Operand = EazOperand.InlineVarLoc; op.VarIndex = il[pos++]; break;
                    case 0x13: op.Name = "stloc.s"; op.Operand = EazOperand.InlineVarLoc; op.VarIndex = il[pos++]; break;
                    case 0x14: op.Name = "ldnull"; break;
                    case 0x15: op.Name = "ldc.i4.m1"; break;
                    case 0x16: op.Name = "ldc.i4.0"; break;
                    case 0x17: op.Name = "ldc.i4.1"; break;
                    case 0x18: op.Name = "ldc.i4.2"; break;
                    case 0x19: op.Name = "ldc.i4.3"; break;
                    case 0x1A: op.Name = "ldc.i4.4"; break;
                    case 0x1B: op.Name = "ldc.i4.5"; break;
                    case 0x1C: op.Name = "ldc.i4.6"; break;
                    case 0x1D: op.Name = "ldc.i4.7"; break;
                    case 0x1E: op.Name = "ldc.i4.8"; break;
                    case 0x1F: op.Name = "ldc.i4.s"; op.Operand = EazOperand.InlineI; op.OperandI = (sbyte)il[pos++]; break;
                    case 0x20: op.Name = "ldc.i4"; op.Operand = EazOperand.InlineI; op.OperandI = BitConverter.ToInt32(il, pos); pos += 4; break;
                    case 0x25: op.Name = "dup"; break;
                    case 0x26: op.Name = "pop"; break;
                    case 0x28: op.Name = "call"; op.Operand = EazOperand.InlineMethod; op.MemberName = ResolveMemberName(md, BitConverter.ToInt32(il, pos)); pos += 4; break;
                    case 0x2A: op.Name = "ret"; break;
                    case 0x2B: op.Name = "br.s"; op.Operand = EazOperand.ShortBr; op.BranchTargetIlOffset = pos + 1 + (sbyte)il[pos]; pos++; break;
                    case 0x2C: op.Name = "brfalse.s"; op.Operand = EazOperand.ShortBr; op.BranchTargetIlOffset = pos + 1 + (sbyte)il[pos]; pos++; break;
                    case 0x2D: op.Name = "brtrue.s"; op.Operand = EazOperand.ShortBr; op.BranchTargetIlOffset = pos + 1 + (sbyte)il[pos]; pos++; break;
                    case 0x2E: op.Name = "beq.s"; op.Operand = EazOperand.ShortBr; op.BranchTargetIlOffset = pos + 1 + (sbyte)il[pos]; pos++; break;
                    case 0x2F: op.Name = "bge.s"; op.Operand = EazOperand.ShortBr; op.BranchTargetIlOffset = pos + 1 + (sbyte)il[pos]; pos++; break;
                    case 0x30: op.Name = "bgt.s"; op.Operand = EazOperand.ShortBr; op.BranchTargetIlOffset = pos + 1 + (sbyte)il[pos]; pos++; break;
                    case 0x31: op.Name = "ble.s"; op.Operand = EazOperand.ShortBr; op.BranchTargetIlOffset = pos + 1 + (sbyte)il[pos]; pos++; break;
                    case 0x32: op.Name = "blt.s"; op.Operand = EazOperand.ShortBr; op.BranchTargetIlOffset = pos + 1 + (sbyte)il[pos]; pos++; break;
                    case 0x58: op.Name = "add"; break;
                    case 0x59: op.Name = "sub"; break;
                    case 0x5A: op.Name = "mul"; break;
                    case 0x5B: op.Name = "div"; break;
                    case 0x5D: op.Name = "rem"; break;
                    case 0x72: op.Name = "ldstr"; op.Operand = EazOperand.InlineString; op.LiteralString = ResolveUserString(md, BitConverter.ToInt32(il, pos)); pos += 4; break;
                    default: throw new NotSupportedException($"unhandled CIL byte 0x{b:X2} at {start}");
                }
                op.IlSize = pos - start;
                ops.Add(op);
            }
            return ops;
        }

        private static string ResolveMemberName(MetadataReader md, int token)
        {
            var handle = MetadataTokens.EntityHandle(token);
            switch (handle.Kind)
            {
                case HandleKind.MethodDefinition:
                {
                    MethodDefinition m = md.GetMethodDefinition((MethodDefinitionHandle)handle);
                    return md.GetString(m.Name);
                }
                case HandleKind.MemberReference:
                {
                    MemberReference mr = md.GetMemberReference((MemberReferenceHandle)handle);
                    return md.GetString(mr.Name);
                }
                default:
                    return $"token:{token:X8}";
            }
        }

        private static string ResolveUserString(MetadataReader md, int token)
        {
            var handle = MetadataTokens.UserStringHandle(token);
            return md.GetUserString(handle);
        }

        private static Dictionary<string, int> BuildOpcodeMap(NetRandom rng)
        {
            string[] handled =
            {
                "nop", "ldarg.0", "ldarg.1", "ldarg.2", "ldarg.3", "ldarg.s", "starg.s",
                "ldloc.0", "ldloc.1", "ldloc.2", "ldloc.3", "stloc.0", "stloc.1", "stloc.2", "stloc.3",
                "ldloc.s", "stloc.s", "ldnull",
                "ldc.i4.m1", "ldc.i4.0", "ldc.i4.1", "ldc.i4.2", "ldc.i4.3", "ldc.i4.4",
                "ldc.i4.5", "ldc.i4.6", "ldc.i4.7", "ldc.i4.8", "ldc.i4.s", "ldc.i4",
                "dup", "pop", "call", "ret",
                "br.s", "brfalse.s", "brtrue.s", "beq.s", "bge.s", "bgt.s", "ble.s", "blt.s",
                "add", "sub", "mul", "div", "rem", "ldstr",
            };
            var used = new HashSet<int>();
            var map = new Dictionary<string, int>();
            foreach (string name in handled)
            {
                int code;
                do
                {
                    code = rng.Next();
                } while (code == 0 || !used.Add(code));
                map[name] = code;
            }
            return map;
        }

        private static byte[] SerializeMethodBody(SrcMethod m, Dictionary<string, int> opcodeMap)
        {
            using var ms = new MemoryStream();
            var w = new BinaryWriter(ms);

            w.Write((byte)0);

            w.Write((short)m.LocalCount);
            for (int i = 0; i < m.LocalCount; i++)
                w.Write((int)0x100);

            w.Write((int)(m.ReturnsVoid ? 0 : 0x101));
            w.Write(false);
            w.Write((int)0);

            w.Write((short)m.ParamCount);
            for (int i = 0; i < m.ParamCount; i++)
            {
                w.Write((int)0x101);
                w.Write(true);
            }

            w.Write(m.Name);

            w.Write((short)0);

            var virtualOffsets = new Dictionary<int, int>();
            int vpos = 0;
            foreach (CilOp op in m.Body)
            {
                virtualOffsets[op.IlOffset] = vpos;
                vpos += VirtualSize(op);
            }

            using var code = new MemoryStream();
            var cw = new BinaryWriter(code);
            foreach (CilOp op in m.Body)
                EncodeInstruction(cw, op, opcodeMap, virtualOffsets);
            byte[] codeBytes = code.ToArray();

            w.Write((int)codeBytes.Length);
            w.Write(codeBytes);

            return ms.ToArray();
        }

        private static int VirtualSize(CilOp op)
        {
            int n = 4;
            switch (op.Operand)
            {
                case EazOperand.None: break;
                case EazOperand.InlineI:
                    n += op.Name == "ldc.i4.s" ? 1 : 4;
                    break;
                case EazOperand.InlineVarArg:
                case EazOperand.InlineVarLoc:
                    n += op.Name.EndsWith(".s") ? 1 : 2;
                    break;
                case EazOperand.ShortBr:
                    n += 4;
                    break;
                case EazOperand.InlineMethod:
                case EazOperand.InlineString:
                    n += 4;
                    break;
            }
            return n;
        }

        private static void EncodeInstruction(BinaryWriter w, CilOp op, Dictionary<string, int> map, Dictionary<int, int> virtualOffsets)
        {
            WriteInt32Special(w, map[op.Name]);
            switch (op.Operand)
            {
                case EazOperand.None:
                    break;
                case EazOperand.InlineI:
                    if (op.Name == "ldc.i4.s")
                        w.Write((sbyte)op.OperandI);
                    else
                        w.Write((int)op.OperandI);
                    break;
                case EazOperand.InlineVarArg:
                case EazOperand.InlineVarLoc:
                    if (op.Name.EndsWith(".s"))
                        w.Write((byte)op.VarIndex);
                    else
                        w.Write((ushort)op.VarIndex);
                    break;
                case EazOperand.ShortBr:
                {
                    int target = virtualOffsets[op.BranchTargetIlOffset];
                    w.Write((int)target);
                    break;
                }
                case EazOperand.InlineMethod:
                    WriteInt32Special(w, StableMemberId(op.MemberName));
                    break;
                case EazOperand.InlineString:
                    WriteInt32Special(w, StableStringId(op.LiteralString));
                    break;
            }
        }

        private static int StableMemberId(string name)
        {
            return unchecked((int)(Fnv(name) | 0x40000000u));
        }

        private static int StableStringId(string s)
        {
            return unchecked((int)(Fnv(s) | 0x20000000u));
        }

        private static uint Fnv(string s)
        {
            uint h = 2166136261u;
            foreach (char c in s)
            {
                h ^= c;
                h *= 16777619u;
            }
            return h & 0x0FFFFFFFu;
        }

        private static void WriteInt32Special(BinaryWriter w, int value)
        {
            uint v = unchecked((uint)value);
            var b = new byte[4];
            b[0] = (byte)(v >> 16);
            b[1] = (byte)(v >> 8);
            b[2] = (byte)v;
            b[3] = (byte)(v >> 24);
            w.Write(b);
        }

        private static byte[] CryptResource(byte[] plain, int key)
        {
            var outBytes = new byte[plain.Length];
            for (int i = 0; i < plain.Length; i++)
                outBytes[i] = (byte)(((uint)key | (uint)(long)i) ^ plain[i]);
            return outBytes;
        }

        private static string EncodePositionString(long position, int cryptoKey)
        {
            var raw = new byte[8];
            BinaryPrimitivesWriteInt64BigEndian(raw, position);
            var enc = new byte[8];
            for (int i = 0; i < 8; i++)
                enc[i] = (byte)(((uint)cryptoKey | (uint)(long)i) ^ raw[i]);
            return Base85Encode(enc);
        }

        private static void BinaryPrimitivesWriteInt64BigEndian(byte[] buf, long value)
        {
            for (int i = 0; i < 8; i++)
                buf[i] = (byte)(value >> (8 * (7 - i)));
        }

        private static string Base85Encode(byte[] data)
        {
            var sb = new StringBuilder();
            int full = data.Length / 4;
            for (int g = 0; g < full; g++)
            {
                uint num = 0;
                for (int j = 0; j < 4; j++)
                    num = (num << 8) | data[g * 4 + j];
                EmitGroup(sb, num, 5);
            }
            int rem = data.Length % 4;
            if (rem > 0)
            {
                uint num = 0;
                for (int j = 0; j < 4; j++)
                {
                    num <<= 8;
                    if (j < rem)
                        num |= data[full * 4 + j];
                }
                EmitGroup(sb, num, rem + 1);
            }
            return sb.ToString();
        }

        private static void EmitGroup(StringBuilder sb, uint num, int count)
        {
            var chars = new char[5];
            for (int i = 4; i >= 0; i--)
            {
                chars[i] = (char)('!' + (int)(num % 85));
                num /= 85;
            }
            for (int i = 0; i < count; i++)
                sb.Append(chars[i]);
        }

        private static void WriteMap(string path, Dictionary<string, int> map, int resourceKey, int positionKey,
            Dictionary<string, long> positions, Dictionary<string, string> positionStrings, List<SrcMethod> methods)
        {
            var sb = new StringBuilder();
            sb.AppendLine($"resource_key={resourceKey}");
            sb.AppendLine($"position_key={positionKey}");
            foreach (KeyValuePair<string, int> kv in map.OrderBy(k => k.Key, StringComparer.Ordinal))
                sb.AppendLine($"op {kv.Key} {unchecked((uint)kv.Value)}");
            foreach (SrcMethod m in methods)
                sb.AppendLine($"method {m.Name} pos={positions[m.Name]} pstr={positionStrings[m.Name]} params={m.ParamCount} locals={m.LocalCount} ret={(m.ReturnsVoid ? "void" : "i4")}");
            File.WriteAllText(path, sb.ToString());
        }

        // -------- assembly emission --------

        private static void EmitAssembly(string outPath, List<SrcMethod> methods, Dictionary<string, int> opcodeMap,
            byte[] encResource, Dictionary<string, string> positionStrings, int resourceKey, int positionKey)
        {
            var md = new MetadataBuilder();
            var ilBuilder = new BlobBuilder();

            md.AddModule(0, md.GetOrAddString("EazSample.eazvm.dll"),
                md.GetOrAddGuid(Guid.NewGuid()), default, default);

            AssemblyReferenceHandle corlib = md.AddAssemblyReference(
                md.GetOrAddString("System.Runtime"),
                new Version(9, 0, 0, 0), default,
                md.GetOrAddBlob(new byte[] { 0xB0, 0x3F, 0x5F, 0x7F, 0x11, 0xD5, 0x0A, 0x3A }),
                default, default);
            AssemblyReferenceHandle consoleAsm = md.AddAssemblyReference(
                md.GetOrAddString("System.Console"),
                new Version(9, 0, 0, 0), default,
                md.GetOrAddBlob(new byte[] { 0xB0, 0x3F, 0x5F, 0x7F, 0x11, 0xD5, 0x0A, 0x3A }),
                default, default);

            TypeReferenceHandle objectTypeRef = md.AddTypeReference(corlib, md.GetOrAddString("System"), md.GetOrAddString("Object"));
            TypeReferenceHandle consoleTypeRef = md.AddTypeReference(consoleAsm, md.GetOrAddString("System"), md.GetOrAddString("Console"));

            var writeLineIntSig = new BlobBuilder();
            new BlobEncoder(writeLineIntSig).MethodSignature().Parameters(1,
                r => r.Void(), p => p.AddParameter().Type().Int32());
            MemberReferenceHandle writeLineInt = md.AddMemberReference(consoleTypeRef,
                md.GetOrAddString("WriteLine"), md.GetOrAddBlob(writeLineIntSig));

            var objectCtorSig = new BlobBuilder();
            new BlobEncoder(objectCtorSig).MethodSignature(isInstanceMethod: true)
                .Parameters(0, r => r.Void(), p => { });
            MemberReferenceHandle objectCtor = md.AddMemberReference(objectTypeRef,
                md.GetOrAddString(".ctor"), md.GetOrAddBlob(objectCtorSig));

            var methodHandles = new Dictionary<string, MethodDefinitionHandle>();
            MethodDefinitionHandle firstMethod = default;
            bool firstSet = false;

            var methodBodyStream = new MethodBodyStreamEncoder(ilBuilder);
            var fieldList = new List<(string name, int code)>();

            foreach (SrcMethod m in methods)
            {
                var sig = new BlobBuilder();
                BlobEncoder be = new BlobEncoder(sig);
                MethodSignatureEncoder mse = be.MethodSignature();
                mse.Parameters(m.ParamCount,
                    ret => { if (m.ReturnsVoid) ret.Void(); else ret.Type().Int32(); },
                    par => { for (int i = 0; i < m.ParamCount; i++) par.AddParameter().Type().Int32(); });

                var il = new InstructionEncoder(new BlobBuilder());
                string pstr = positionStrings[m.Name];
                il.LoadString(md.GetOrAddUserString(pstr));
                il.LoadConstantI4(resourceKey);
                il.LoadConstantI4(positionKey);
                il.OpCode(ILOpCode.Pop);
                il.OpCode(ILOpCode.Pop);
                il.OpCode(ILOpCode.Pop);
                if (m.ReturnsVoid)
                {
                    il.OpCode(ILOpCode.Ret);
                }
                else
                {
                    il.LoadConstantI4(0);
                    il.OpCode(ILOpCode.Ret);
                }
                int bodyOffset = methodBodyStream.AddMethodBody(il);

                MethodDefinitionHandle handle = md.AddMethodDefinition(
                    MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.HideBySig,
                    MethodImplAttributes.IL,
                    md.GetOrAddString(m.Name),
                    md.GetOrAddBlob(sig),
                    bodyOffset,
                    parameterList: default);
                methodHandles[m.Name] = handle;
                if (!firstSet) { firstMethod = handle; firstSet = true; }
            }

            var handlerHandles = new List<MethodDefinitionHandle>();
            foreach (KeyValuePair<string, int> kv in opcodeMap.OrderBy(k => k.Key, StringComparer.Ordinal))
            {
                MethodDefinitionHandle h = EmitHandler(md, methodBodyStream, kv.Key, kv.Value);
                handlerHandles.Add(h);
                if (!firstSet) { firstMethod = h; firstSet = true; }
            }

            MethodDefinitionHandle dictMethod = EmitDictionaryMethod(md, methodBodyStream, opcodeMap, handlerHandles);

            MethodDefinitionHandle mainMethod = EmitMain(md, methodBodyStream, methods, methodHandles, writeLineInt);

            md.AddTypeDefinition(default, default,
                md.GetOrAddString("<Module>"),
                default(EntityHandle),
                MetadataTokens.FieldDefinitionHandle(1),
                firstMethod);

            FieldDefinitionHandle firstField = MetadataTokens.FieldDefinitionHandle(md.GetRowCount(TableIndex.Field) + 1);

            md.AddTypeDefinition(
                TypeAttributes.Public | TypeAttributes.Abstract | TypeAttributes.Sealed | TypeAttributes.BeforeFieldInit,
                md.GetOrAddString("EazSample"),
                md.GetOrAddString("Compute"),
                objectTypeRef,
                firstField,
                firstMethod);

            md.AddTypeDefinition(
                TypeAttributes.Public | TypeAttributes.Abstract | TypeAttributes.Sealed | TypeAttributes.BeforeFieldInit,
                md.GetOrAddString("EazSample"),
                md.GetOrAddString("Program"),
                objectTypeRef,
                firstField,
                mainMethod);

            ManifestResourceHandle _ = md.AddManifestResource(
                ManifestResourceAttributes.Private,
                md.GetOrAddString("EazVirtualizedStream"),
                default,
                0);

            md.AddAssembly(
                md.GetOrAddString("EazSample"),
                new Version(1, 0, 0, 0), default, default,
                default, AssemblyHashAlgorithm.Sha1);

            var rootBuilder = new MetadataRootBuilder(md);
            var managedResources = new BlobBuilder();
            managedResources.WriteInt32(encResource.Length);
            managedResources.WriteBytes(encResource);

            var peHeaderBuilder = new PEHeaderBuilder(
                imageCharacteristics: Characteristics.ExecutableImage | Characteristics.Dll);

            var peBuilder = new ManagedPEBuilder(
                peHeaderBuilder,
                rootBuilder,
                ilBuilder,
                managedResources: managedResources,
                entryPoint: mainMethod,
                flags: CorFlags.ILOnly);

            var peBlob = new BlobBuilder();
            peBuilder.Serialize(peBlob);
            using var fs = new FileStream(outPath, FileMode.Create, FileAccess.Write);
            peBlob.WriteContentTo(fs);
        }

        private static MethodDefinitionHandle EmitHandler(MetadataBuilder md, MethodBodyStreamEncoder bodies, string opName, int code)
        {
            var sig = new BlobBuilder();
            new BlobEncoder(sig).MethodSignature().Parameters(0, r => r.Void(), p => { });
            var il = new InstructionEncoder(new BlobBuilder());
            int fp = HandlerFingerprint(opName);
            il.LoadConstantI4(fp);
            il.OpCode(ILOpCode.Pop);
            il.LoadConstantI4(code);
            il.OpCode(ILOpCode.Pop);
            il.OpCode(ILOpCode.Ret);
            int bodyOffset = bodies.AddMethodBody(il);
            return md.AddMethodDefinition(
                MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.HideBySig,
                MethodImplAttributes.IL,
                md.GetOrAddString("h_" + opName.Replace('.', '_')),
                md.GetOrAddBlob(sig),
                bodyOffset,
                default);
        }

        private static MethodDefinitionHandle EmitDictionaryMethod(MetadataBuilder md, MethodBodyStreamEncoder bodies,
            Dictionary<string, int> opcodeMap, List<MethodDefinitionHandle> handlerHandles)
        {
            var sig = new BlobBuilder();
            new BlobEncoder(sig).MethodSignature().Parameters(0, r => r.Void(), p => { });
            var il = new InstructionEncoder(new BlobBuilder());
            int idx = 0;
            foreach (KeyValuePair<string, int> kv in opcodeMap.OrderBy(k => k.Key, StringComparer.Ordinal))
            {
                il.LoadConstantI4(kv.Value);
                il.OpCode(ILOpCode.Pop);
                il.OpCode(ILOpCode.Ldftn);
                il.Token(handlerHandles[idx]);
                il.OpCode(ILOpCode.Pop);
                idx++;
            }
            il.OpCode(ILOpCode.Ret);
            int bodyOffset = bodies.AddMethodBody(il);
            return md.AddMethodDefinition(
                MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.HideBySig,
                MethodImplAttributes.IL,
                md.GetOrAddString("BuildDispatchTable"),
                md.GetOrAddBlob(sig),
                bodyOffset,
                default);
        }

        private static MethodDefinitionHandle EmitMain(MetadataBuilder md, MethodBodyStreamEncoder bodies,
            List<SrcMethod> methods, Dictionary<string, MethodDefinitionHandle> methodHandles, MemberReferenceHandle writeLineInt)
        {
            var sig = new BlobBuilder();
            new BlobEncoder(sig).MethodSignature().Parameters(0, r => r.Void(), p => { });
            var il = new InstructionEncoder(new BlobBuilder());
            il.OpCode(ILOpCode.Ret);
            int bodyOffset = bodies.AddMethodBody(il);
            return md.AddMethodDefinition(
                MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.HideBySig,
                MethodImplAttributes.IL,
                md.GetOrAddString("Main"),
                md.GetOrAddBlob(sig),
                bodyOffset,
                default);
        }

        private static int HandlerFingerprint(string opName)
        {
            return unchecked((int)(Fnv("HANDLER:" + opName) | 0x10000000u));
        }
    }

    internal sealed class SimpleSigProvider : ISignatureTypeProvider<string, object?>, ISimpleTypeProvider<string>
    {
        public string GetPrimitiveType(PrimitiveTypeCode typeCode) => typeCode switch
        {
            PrimitiveTypeCode.Void => "void",
            PrimitiveTypeCode.Int32 => "int32",
            PrimitiveTypeCode.Int64 => "int64",
            PrimitiveTypeCode.String => "string",
            PrimitiveTypeCode.Boolean => "bool",
            _ => typeCode.ToString(),
        };

        public string GetTypeFromDefinition(MetadataReader reader, TypeDefinitionHandle handle, byte rawTypeKind)
            => reader.GetString(reader.GetTypeDefinition(handle).Name);

        public string GetTypeFromReference(MetadataReader reader, TypeReferenceHandle handle, byte rawTypeKind)
            => reader.GetString(reader.GetTypeReference(handle).Name);

        public string GetSZArrayType(string elementType) => elementType + "[]";
        public string GetArrayType(string elementType, ArrayShape shape) => elementType + "[]";
        public string GetByReferenceType(string elementType) => elementType + "&";
        public string GetPointerType(string elementType) => elementType + "*";
        public string GetGenericInstantiation(string genericType, ImmutableArray<string> typeArguments) => genericType;
        public string GetGenericMethodParameter(object? genericContext, int index) => "!!" + index;
        public string GetGenericTypeParameter(object? genericContext, int index) => "!" + index;
        public string GetModifiedType(string modifier, string unmodifiedType, bool isRequired) => unmodifiedType;
        public string GetPinnedType(string elementType) => elementType;
        public string GetFunctionPointerType(MethodSignature<string> signature) => "fnptr";
        public string GetTypeFromSpecification(MetadataReader reader, object? genericContext, TypeSpecificationHandle handle, byte rawTypeKind) => "typespec";
    }
}
