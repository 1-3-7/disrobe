using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;

namespace EazReinject
{
    internal sealed class RecoveredMethod
    {
        public string Name = "";
        public int ParamCount;
        public int LocalCount;
        public bool ReturnsVoid;
        public List<string[]> Lines = new();
    }

    internal static class Program
    {
        private static int Main(string[] args)
        {
            string cilPath = args.Length > 0 ? args[0] : "EazSample.recovered.cil";
            string outPath = args.Length > 1 ? args[1] : "EazSample.devirt.dll";
            List<RecoveredMethod> methods = ParseRecovered(File.ReadAllText(cilPath));
            EmitAndWrite(outPath, methods);
            Console.WriteLine($"reinjected {methods.Count} methods -> {outPath}");
            return 0;
        }

        private static List<RecoveredMethod> ParseRecovered(string text)
        {
            var methods = new List<RecoveredMethod>();
            RecoveredMethod? cur = null;
            foreach (string rawLine in text.Split('\n'))
            {
                string line = rawLine.Trim();
                if (line.Length == 0)
                    continue;
                if (line.StartsWith("method "))
                {
                    cur = new RecoveredMethod();
                    string[] parts = line.Split(' ');
                    cur.Name = parts[1];
                    foreach (string p in parts)
                    {
                        if (p.StartsWith("params="))
                            cur.ParamCount = int.Parse(p.Substring("params=".Length));
                        else if (p.StartsWith("locals="))
                            cur.LocalCount = int.Parse(p.Substring("locals=".Length));
                        else if (p.StartsWith("ret="))
                            cur.ReturnsVoid = p.Substring("ret=".Length) == "void";
                    }
                    methods.Add(cur);
                }
                else if (line == "end")
                {
                    cur = null;
                }
                else if (cur != null)
                {
                    cur.Lines.Add(line.Split(' '));
                }
            }
            return methods;
        }

        private static void EmitAndWrite(string outPath, List<RecoveredMethod> methods)
        {
            var md = new MetadataBuilder();
            var ilBuilder = new BlobBuilder();

            md.AddModule(0, md.GetOrAddString("EazSample.devirt.dll"),
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

            var writeLineSig = new BlobBuilder();
            new BlobEncoder(writeLineSig).MethodSignature().Parameters(1,
                r => r.Void(), p => p.AddParameter().Type().Int32());
            MemberReferenceHandle writeLineInt = md.AddMemberReference(consoleTypeRef,
                md.GetOrAddString("WriteLine"), md.GetOrAddBlob(writeLineSig));

            var bodies = new MethodBodyStreamEncoder(ilBuilder);
            var handles = new Dictionary<string, MethodDefinitionHandle>();
            MethodDefinitionHandle first = default;
            bool firstSet = false;

            foreach (RecoveredMethod m in methods)
            {
                MethodDefinitionHandle h = EmitMethod(md, bodies, m);
                handles[m.Name] = h;
                if (!firstSet) { first = h; firstSet = true; }
            }

            MethodDefinitionHandle main = EmitMain(md, bodies, handles, writeLineInt);

            md.AddTypeDefinition(default, default,
                md.GetOrAddString("<Module>"), default(EntityHandle),
                MetadataTokens.FieldDefinitionHandle(1), first);

            md.AddTypeDefinition(
                TypeAttributes.Public | TypeAttributes.Abstract | TypeAttributes.Sealed | TypeAttributes.BeforeFieldInit,
                md.GetOrAddString("EazSample"), md.GetOrAddString("Compute"),
                objectTypeRef, MetadataTokens.FieldDefinitionHandle(1), first);

            md.AddTypeDefinition(
                TypeAttributes.Public | TypeAttributes.Abstract | TypeAttributes.Sealed | TypeAttributes.BeforeFieldInit,
                md.GetOrAddString("EazSample"), md.GetOrAddString("Program"),
                objectTypeRef, MetadataTokens.FieldDefinitionHandle(1), main);

            md.AddAssembly(md.GetOrAddString("EazSample"),
                new Version(1, 0, 0, 0), default, default, default, AssemblyHashAlgorithm.Sha1);

            var root = new MetadataRootBuilder(md);
            var peHeader = new PEHeaderBuilder(imageCharacteristics: Characteristics.ExecutableImage | Characteristics.Dll);
            var pe = new ManagedPEBuilder(peHeader, root, ilBuilder, entryPoint: main, flags: CorFlags.ILOnly);
            var blob = new BlobBuilder();
            pe.Serialize(blob);
            using var fs = new FileStream(outPath, FileMode.Create, FileAccess.Write);
            blob.WriteContentTo(fs);
        }

        private static MethodDefinitionHandle EmitMethod(MetadataBuilder md, MethodBodyStreamEncoder bodies, RecoveredMethod m)
        {
            var sig = new BlobBuilder();
            new BlobEncoder(sig).MethodSignature().Parameters(m.ParamCount,
                ret => { if (m.ReturnsVoid) ret.Void(); else ret.Type().Int32(); },
                par => { for (int i = 0; i < m.ParamCount; i++) par.AddParameter().Type().Int32(); });

            var cf = new ControlFlowBuilder();
            var il = new InstructionEncoder(new BlobBuilder(), cf);

            var labels = new Dictionary<int, LabelHandle>();
            for (int i = 0; i < m.Lines.Count; i++)
                labels[i] = il.DefineLabel();

            for (int i = 0; i < m.Lines.Count; i++)
            {
                il.MarkLabel(labels[i]);
                string[] line = m.Lines[i];
                string op = line[1];
                EmitOp(il, op, line, labels);
            }

            StandaloneSignatureHandle localSig = default;
            if (m.LocalCount > 0)
            {
                var locals = new BlobBuilder();
                LocalVariablesEncoder lenc = new BlobEncoder(locals).LocalVariableSignature(m.LocalCount);
                for (int i = 0; i < m.LocalCount; i++)
                    lenc.AddVariable().Type().Int32();
                localSig = md.AddStandaloneSignature(md.GetOrAddBlob(locals));
            }

            int bodyOffset = bodies.AddMethodBody(il, maxStack: 8, localVariablesSignature: localSig);

            return md.AddMethodDefinition(
                MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.HideBySig,
                MethodImplAttributes.IL,
                md.GetOrAddString(m.Name),
                md.GetOrAddBlob(sig),
                bodyOffset, default);
        }

        private static void EmitOp(InstructionEncoder il, string op, string[] line, Dictionary<int, LabelHandle> labels)
        {
            switch (op)
            {
                case "nop": il.OpCode(ILOpCode.Nop); break;
                case "ldarg.0": il.LoadArgument(0); break;
                case "ldarg.1": il.LoadArgument(1); break;
                case "ldarg.2": il.LoadArgument(2); break;
                case "ldarg.3": il.LoadArgument(3); break;
                case "ldloc.0": il.LoadLocal(0); break;
                case "ldloc.1": il.LoadLocal(1); break;
                case "ldloc.2": il.LoadLocal(2); break;
                case "ldloc.3": il.LoadLocal(3); break;
                case "stloc.0": il.StoreLocal(0); break;
                case "stloc.1": il.StoreLocal(1); break;
                case "stloc.2": il.StoreLocal(2); break;
                case "stloc.3": il.StoreLocal(3); break;
                case "ldc.i4.m1": il.LoadConstantI4(-1); break;
                case "ldc.i4.0": il.LoadConstantI4(0); break;
                case "ldc.i4.1": il.LoadConstantI4(1); break;
                case "ldc.i4.2": il.LoadConstantI4(2); break;
                case "ldc.i4.3": il.LoadConstantI4(3); break;
                case "ldc.i4.4": il.LoadConstantI4(4); break;
                case "ldc.i4.5": il.LoadConstantI4(5); break;
                case "ldc.i4.6": il.LoadConstantI4(6); break;
                case "ldc.i4.7": il.LoadConstantI4(7); break;
                case "ldc.i4.8": il.LoadConstantI4(8); break;
                case "ldc.i4.s":
                case "ldc.i4": il.LoadConstantI4(int.Parse(line[2])); break;
                case "add": il.OpCode(ILOpCode.Add); break;
                case "sub": il.OpCode(ILOpCode.Sub); break;
                case "mul": il.OpCode(ILOpCode.Mul); break;
                case "div": il.OpCode(ILOpCode.Div); break;
                case "rem": il.OpCode(ILOpCode.Rem); break;
                case "and": il.OpCode(ILOpCode.And); break;
                case "xor": il.OpCode(ILOpCode.Xor); break;
                case "dup": il.OpCode(ILOpCode.Dup); break;
                case "pop": il.OpCode(ILOpCode.Pop); break;
                case "ret": il.OpCode(ILOpCode.Ret); break;
                case "br.s": il.Branch(ILOpCode.Br, labels[TargetIndex(line[2])]); break;
                case "brtrue.s": il.Branch(ILOpCode.Brtrue, labels[TargetIndex(line[2])]); break;
                case "brfalse.s": il.Branch(ILOpCode.Brfalse, labels[TargetIndex(line[2])]); break;
                case "beq.s": il.Branch(ILOpCode.Beq, labels[TargetIndex(line[2])]); break;
                case "bge.s": il.Branch(ILOpCode.Bge, labels[TargetIndex(line[2])]); break;
                case "bgt.s": il.Branch(ILOpCode.Bgt, labels[TargetIndex(line[2])]); break;
                case "ble.s": il.Branch(ILOpCode.Ble, labels[TargetIndex(line[2])]); break;
                case "blt.s": il.Branch(ILOpCode.Blt, labels[TargetIndex(line[2])]); break;
                default: throw new NotSupportedException($"reinject op {op}");
            }
        }

        private static int TargetIndex(string label)
        {
            return int.Parse(label.Substring("IL_".Length));
        }

        private static MethodDefinitionHandle EmitMain(MetadataBuilder md, MethodBodyStreamEncoder bodies,
            Dictionary<string, MethodDefinitionHandle> handles, MemberReferenceHandle writeLineInt)
        {
            var sig = new BlobBuilder();
            new BlobEncoder(sig).MethodSignature().Parameters(0, r => r.Void(), p => { });
            var il = new InstructionEncoder(new BlobBuilder());

            EmitCall(il, handles, "Add", new[] { 2, 3 }, writeLineInt);
            EmitCall(il, handles, "Poly", new[] { 7 }, writeLineInt);
            EmitCall(il, handles, "Mixed", new[] { int.MinValue, -1 }, writeLineInt);
            EmitCall(il, handles, "SumTo", new[] { 10 }, writeLineInt);
            EmitCall(il, handles, "Classify", new[] { -5 }, writeLineInt);
            EmitCall(il, handles, "Max3", new[] { 3, 9, 4 }, writeLineInt);

            il.OpCode(ILOpCode.Ret);
            int bodyOffset = bodies.AddMethodBody(il, maxStack: 8);
            return md.AddMethodDefinition(
                MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.HideBySig,
                MethodImplAttributes.IL,
                md.GetOrAddString("Main"),
                md.GetOrAddBlob(sig),
                bodyOffset, default);
        }

        private static void EmitCall(InstructionEncoder il, Dictionary<string, MethodDefinitionHandle> handles,
            string name, int[] argv, MemberReferenceHandle writeLineInt)
        {
            if (!handles.TryGetValue(name, out MethodDefinitionHandle h))
                return;
            foreach (int a in argv)
                il.LoadConstantI4(a);
            il.Call(h);
            il.Call(writeLineInt);
        }
    }
}
