using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Reflection.Emit;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;

if (args.Length != 1)
{
    throw new ArgumentException("expected output path");
}

string outputPath = Path.GetFullPath(args[0]);
string? outputDirectory = Path.GetDirectoryName(outputPath);
if (outputDirectory is null)
{
    throw new ArgumentException("output path has no parent directory");
}

Directory.CreateDirectory(outputDirectory);

var assembly = new PersistedAssemblyBuilder(
    new AssemblyName("ChaDuplicateDispatch"),
    typeof(object).Assembly);
ModuleBuilder module = assembly.DefineDynamicModule("ChaDuplicateDispatch");
TypeBuilder iface = module.DefineType(
    "ChaDuplicateDispatch.I",
    TypeAttributes.Public | TypeAttributes.Interface | TypeAttributes.Abstract);
MethodBuilder interfaceMethod = iface.DefineMethod(
    "Invoke",
    MethodAttributes.Public
        | MethodAttributes.Abstract
        | MethodAttributes.Virtual
        | MethodAttributes.NewSlot
        | MethodAttributes.HideBySig,
    typeof(int),
    Type.EmptyTypes);
TypeBuilder implementation = module.DefineType(
    "ChaDuplicateDispatch.C",
    TypeAttributes.Public | TypeAttributes.Class);
implementation.AddInterfaceImplementation(iface);
ConstructorBuilder constructor = implementation.DefineConstructor(
    MethodAttributes.Public,
    CallingConventions.Standard,
    Type.EmptyTypes);
ILGenerator constructorIl = constructor.GetILGenerator();
constructorIl.Emit(OpCodes.Ldarg_0);
constructorIl.Emit(OpCodes.Call, typeof(object).GetConstructor(Type.EmptyTypes)!);
constructorIl.Emit(OpCodes.Ret);
MethodAttributes implementationAttributes = MethodAttributes.Public
    | MethodAttributes.Virtual
    | MethodAttributes.Final
    | MethodAttributes.NewSlot
    | MethodAttributes.HideBySig;
MethodBuilder first = implementation.DefineMethod(
    "Invoke",
    implementationAttributes,
    typeof(int),
    Type.EmptyTypes);
ILGenerator firstIl = first.GetILGenerator();
firstIl.Emit(OpCodes.Ldc_I4_1);
firstIl.Emit(OpCodes.Ret);
MethodBuilder second = implementation.DefineMethod(
    "Invoke",
    implementationAttributes,
    typeof(int),
    Type.EmptyTypes);
ILGenerator secondIl = second.GetILGenerator();
secondIl.Emit(OpCodes.Ldc_I4_2);
secondIl.Emit(OpCodes.Ret);
TypeBuilder explicitImplementation = module.DefineType(
    "ChaDuplicateDispatch.ExplicitC",
    TypeAttributes.Public | TypeAttributes.Class);
explicitImplementation.AddInterfaceImplementation(iface);
ConstructorBuilder explicitConstructor = explicitImplementation.DefineConstructor(
    MethodAttributes.Public,
    CallingConventions.Standard,
    Type.EmptyTypes);
ILGenerator explicitConstructorIl = explicitConstructor.GetILGenerator();
explicitConstructorIl.Emit(OpCodes.Ldarg_0);
explicitConstructorIl.Emit(OpCodes.Call, typeof(object).GetConstructor(Type.EmptyTypes)!);
explicitConstructorIl.Emit(OpCodes.Ret);
MethodBuilder explicitMethod = explicitImplementation.DefineMethod(
    "ChaDuplicateDispatch.I.Invoke",
    MethodAttributes.Private
        | MethodAttributes.Virtual
        | MethodAttributes.Final
        | MethodAttributes.NewSlot
        | MethodAttributes.HideBySig,
    typeof(int),
    Type.EmptyTypes);
ILGenerator explicitIl = explicitMethod.GetILGenerator();
explicitIl.Emit(OpCodes.Ldc_I4_3);
explicitIl.Emit(OpCodes.Ret);
explicitImplementation.DefineMethodOverride(explicitMethod, interfaceMethod);
TypeBuilder calls = module.DefineType(
    "ChaDuplicateDispatch.Calls",
    TypeAttributes.Public | TypeAttributes.Abstract | TypeAttributes.Sealed);
MethodBuilder call = calls.DefineMethod(
    "Call",
    MethodAttributes.Public | MethodAttributes.Static,
    typeof(int),
    Type.EmptyTypes);
ILGenerator callIl = call.GetILGenerator();
callIl.Emit(OpCodes.Newobj, constructor);
callIl.Emit(OpCodes.Callvirt, interfaceMethod);
callIl.Emit(OpCodes.Ret);
MethodBuilder explicitCall = calls.DefineMethod(
    "CallExplicit",
    MethodAttributes.Public | MethodAttributes.Static,
    typeof(int),
    Type.EmptyTypes);
ILGenerator explicitCallIl = explicitCall.GetILGenerator();
explicitCallIl.Emit(OpCodes.Newobj, explicitConstructor);
explicitCallIl.Emit(OpCodes.Callvirt, interfaceMethod);
explicitCallIl.Emit(OpCodes.Ret);
iface.CreateType();
implementation.CreateType();
explicitImplementation.CreateType();
calls.CreateType();
assembly.Save(outputPath);

using (FileStream stream = File.OpenRead(outputPath))
using (var pe = new PEReader(stream))
{
    MetadataReader reader = pe.GetMetadataReader();
    TypeDefinition type = reader.TypeDefinitions
        .Select(reader.GetTypeDefinition)
        .Single(definition => reader.GetString(definition.Name) == "C");
    TypeDefinition explicitType = reader.TypeDefinitions
        .Select(reader.GetTypeDefinition)
        .Single(definition => reader.GetString(definition.Name) == "ExplicitC");
    MethodDefinitionHandle[] methods = type.GetMethods()
        .Where(handle => reader.GetString(reader.GetMethodDefinition(handle).Name) == "Invoke")
        .ToArray();
    if (methods.Length != 2)
    {
        throw new InvalidOperationException("duplicate method count");
    }

    byte[] firstSignature = reader.GetBlobBytes(reader.GetMethodDefinition(methods[0]).Signature);
    byte[] secondSignature = reader.GetBlobBytes(reader.GetMethodDefinition(methods[1]).Signature);
    if (!firstSignature.AsSpan().SequenceEqual(secondSignature)
        || type.GetMethodImplementations().Any()
        || explicitType.GetMethodImplementations().Count() != 1)
    {
        throw new InvalidOperationException("duplicate metadata shape");
    }

    Assembly loaded = Assembly.LoadFile(outputPath);
    Type loadedInterface = loaded.GetType("ChaDuplicateDispatch.I", throwOnError: true)!;
    Type loadedImplementation = loaded.GetType("ChaDuplicateDispatch.C", throwOnError: true)!;
    Type loadedExplicitImplementation = loaded.GetType("ChaDuplicateDispatch.ExplicitC", throwOnError: true)!;
    Type loadedCalls = loaded.GetType("ChaDuplicateDispatch.Calls", throwOnError: true)!;
    InterfaceMapping mapping = loadedImplementation.GetInterfaceMap(loadedInterface);
    int firstToken = MetadataTokens.GetToken(methods[0]);
    if (mapping.TargetMethods.Length != 1 || mapping.TargetMethods[0].MetadataToken != firstToken)
    {
        throw new InvalidOperationException("interface map target");
    }

    object? result = loadedCalls.GetMethod("Call")!.Invoke(null, null);
    object? explicitResult = loadedCalls.GetMethod("CallExplicit")!.Invoke(null, null);
    if (!Equals(result, 1) || !Equals(explicitResult, 3))
    {
        throw new InvalidOperationException("interface dispatch result");
    }

    InterfaceMapping explicitMapping = loadedExplicitImplementation.GetInterfaceMap(loadedInterface);
    if (explicitMapping.TargetMethods.Length != 1)
    {
        throw new InvalidOperationException("explicit interface map target");
    }

    Console.WriteLine(
        "duplicate-methods=2; duplicate-methodimpls=0; duplicate-interface-result=1; explicit-methodimpls=1; explicit-interface-result=3");
}
