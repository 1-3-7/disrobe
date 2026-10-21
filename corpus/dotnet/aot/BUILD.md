# NativeAOT reflection and stack-trace maps

`aot_maps_net10_x86_64/` holds a C# program written for this repository, the .NET 10 NativeAOT executable published from it, two embedded resources, and an excerpt of the linker map from the same build. `crates/disrobe-pass-dotnet/tests/native_aot_maps_net10.rs` grades three readers against them. The executable is never run.

The program is shaped to exercise each map:

- `Readings.Echo<T>` and `Readings.Relabel<TSource, TResult>` are instantiated over value types and over reference types and made reflection-visible through `MakeGenericMethod`. The invoke map then carries several entries for one method record that differ only in their generic arguments (`Echo<Int32>`, `Echo<Int64>`, `Echo<__Canon>`).
- `Smoothing`, `Smoothing.Window` and `Ring<T>` are never reflected over, so their compiled bodies are named only by the stack-trace map. `Smoothing.Clamp` carries `[StackTraceHidden]`.
- `resources/tide_table.json` and `resources/gauge_curve.bin` are embedded as `Tidewater.Gauges.tide_table.json` and `Tidewater.Gauges.gauge_curve.bin`. Neither file contains a line ending, and the binary file contains NUL bytes, so a checkout that converts line endings cannot change their bytes.

## Runtime behaviour the tests rely on

These points come from the dotnet/runtime sources at tag `v10.0.0` (MIT licence); each file's sha256 is listed below.

- The invoke map writer (`ReflectionInvokeMapNode.cs`) emits, per entry, the flags, the method's metadata offset, the declaring type's external-reference index, the entrypoint index, the invoke-stub index unless `NeedsParameterInterpretation` is set, and for generic methods a count-prefixed sequence of generic-argument type indices (`VertexSequence.Save` writes the count first). The reader (`ExecutionEnvironmentImplementation.MappingTables.cs`, `GetTypeSequence`) reads the count first as well. One metadata offset therefore appears once per compiled instantiation, and entries for the same method are told apart by their argument sequence.
- `NativeWriter` unifies equal vertices and `Section.Place` returns the existing placed vertex for an equal one, so two hash-table entries may legally point at one vertex. A repeated entry with the same entrypoint is a duplicate, not a conflict.
- The stack-trace map (`StackTraceMethodMappingNode.cs`, read by `StackTraceMetadata.cs`) is a 32-bit entry count followed by command-coded entries: a command byte (`0x01` owning type, `0x02` name, `0x04` signature, `0x08` signature plus method instantiation, `0x10` hidden), the updated fields, and a 32-bit relative pointer to the method body. Owning types are full metadata tokens; names, signatures and instantiations are offsets into the embedded metadata blob.
- `MetadataManager.cs` leaves a method out of the stack-trace map when it is in the invoke map, or when its body is folded into another; the runtime names those through reflection metadata instead. For methods on generic types the owning type is the generic definition instantiated over its formal parameters, and a generic method's instantiation is recorded as its formal parameter names.
- The resource index (`ResourceIndexNode.cs`) is a native hash table of (assembly name, resource name, offset, length) tuples into the resource data blob.
- The AMD64 `RhpAssignRef` helper (`runtime/amd64/WriteBarriers.asm`) stores the reference from `rdx` through the destination in `rcx`, then updates the write-watch and generational card tables. The fixture's 97-byte helper body at RVA `0xb04e0` has SHA-256 `31e6a1f513121c857e2a2fd214e9aec33c1194d16d4978b389b8fb1804116e85`; the managed linker map independently bounds `Station<string>.Swap`, whose call at RVA `0x94519` targets that body.
- The AMD64 `RhpNewFast` helper (`runtime/amd64/AllocFast.asm`) allocates a non-array object from the current thread's allocation context and falls back to `RhpNewObject`. The fixture's 64-byte helper body at RVA `0xb0280` has SHA-256 `17c584aed4a975d8939ddf0c9c840daa74dfa337bc3c77bb504a68219fbf28a8`; the managed linker map independently bounds `Program.Main`, including its call at RVA `0x833b7` to that body.

| Runtime source (`src/coreclr/...` at `v10.0.0`) | sha256 |
| --- | --- |
| `tools/aot/ILCompiler.Compiler/Compiler/DependencyAnalysis/ReflectionInvokeMapNode.cs` | `47affda8f5aee559b81072d103efebd899cf285d8c53e987a9c35a7a8a3783a1` |
| `tools/Common/Internal/NativeFormat/NativeFormatWriter.cs` | `c84bbbe013e83af3aeac3bb47d36849fd432368c1d01c9c9007e2958328a1b1b` |
| `nativeaot/System.Private.Reflection.Execution/src/Internal/Reflection/Execution/ExecutionEnvironmentImplementation.MappingTables.cs` | `9e58a25b7da667f8801d1fe84a293502ae0da1d0e2fe1f4e1fcf06d6f4c422e8` |
| `tools/aot/ILCompiler.Compiler/Compiler/DependencyAnalysis/StackTraceMethodMappingNode.cs` | `16674c7156aab537ab0d0f566e6a370621122c8cc399ee4729ed58ec3fbcfbc0` |
| `nativeaot/System.Private.StackTraceMetadata/src/Internal/StackTraceMetadata/StackTraceMetadata.cs` | `8246a4fa809652e2e0d4b8c938f4a56e148ef7eea5673c8579d10292a5392f4f` |
| `tools/Common/Internal/Runtime/StackTraceData.cs` | `1b435cf6602b4e580efbe3e2d3961fe2f4046238a1331a2625a6b498a7fdf164` |
| `tools/aot/ILCompiler.Compiler/Compiler/MetadataManager.cs` | `590b70031122bc6d84f813bff623f6a1ab508462904de5f9f6f1fc3af47afcf5` |
| `tools/aot/ILCompiler.Compiler/Compiler/DependencyAnalysis/ResourceIndexNode.cs` | `316a3cece22aab485b731285bfb8513d8f3afffbd3661abc046cb3dc42ca3aab` |
| `tools/Common/Internal/Runtime/MetadataBlob.cs` | `684172213616a8e0581277e131b7b8076e6a184dd6f41b86655b35934dd1be08` |
| `runtime/amd64/WriteBarriers.asm` | `4452bd7f582853996230e568e7beba39d990154181bf94134ac110e4d4c1c4` |
| `runtime/amd64/AllocFast.asm` | `e6f71e46f05118691209a46b6f7447cd894f51c7f3ae0dab938adba55a9cd7d6` |

## Toolchain

- .NET SDK 10.0.100 for win-x64, `https://builds.dotnet.microsoft.com/dotnet/Sdk/10.0.100/dotnet-sdk-10.0.100-win-x64.zip` (301,667,702 bytes; sha512 `24b033418a3969effd49b4651ef7ebbffeb284773b99545d78dce61a82e57f38db7facdb013c609ba15573c072f0e093363ae470824a6847f3c6111078c1fb64`, the value in the release metadata at `https://builds.dotnet.microsoft.com/dotnet/release-metadata/10.0/releases.json`; sha256 `ce09b60637c525a5ccd3368962dc936df10141d397e305f5406318f61da66709`), unpacked without an installer. Runtime Microsoft.NETCore.App 10.0.0.
- NuGet packages restored by the publish: `Microsoft.DotNet.ILCompiler` 10.0.0 (package sha512 `XXkdkHkgVPvAmXDeP3HIpDlNTswlsK9fuIkPHVDYcmxRuFnEEc/1yEg+MikjA7+fw6TSy1AqkNdcyrjJjag48w==`) and `runtime.win-x64.Microsoft.DotNet.ILCompiler` 10.0.0 (package sha512 `XHtJ+LmFsV0RRD1H8zpRp3+yzOstV/TaRwAg38b+8PvgXn+VEIVVHzlqWu/eB8AMPoVbC7b+OnOTTlBPf3R7+g==`).
- MSVC linker from Visual Studio 2022 Build Tools, toolset 14.44.35207. The ILCompiler targets locate it through `vswhere.exe`, which has to be on `PATH`.

## Build

Copy `Program.cs`, `resources/` and the project file into an empty directory, rename `aot_maps_net10_x86_64.csproj.txt` to `aot_maps_net10_x86_64.csproj`, and run:

```sh
dotnet publish aot_maps_net10_x86_64.csproj -c Release -r win-x64 --self-contained true -o publish --disable-build-servers -p:UseSharedCompilation=false -nodeReuse:false
```

The project passes `/MAP` and `/PDBALTPATH:%_PDB%` to the linker and maps the project directory to `C:\src\aot_maps_net10_x86_64`, so neither the executable nor the map names the build directory. `publish/aot_maps_net10_x86_64.exe` is the committed executable.

The linker map is `obj/Release/net10.0/win-x64/native/aot_maps_net10_x86_64.link.map`. The committed reference keeps its load-address line and every public symbol of section `0001` that the linker took from the managed object, unchanged, and is compressed with `gzip -9 -n`:

```sh
awk '/Preferred load address/ || ($1 ~ /^0001:/ && $NF=="aot_maps_net10_x86_64.obj")' aot_maps_net10_x86_64.link.map > aot_maps_net10_x86_64.link-map-managed.txt
gzip -9 -n aot_maps_net10_x86_64.link-map-managed.txt
```

The excerpt has 4,482 lines. The full map is 3,207,969 bytes with sha256 `3da7655846b754ded4daede5e5033d1a7df3e277fde720100fbff60b58daf283`; the ILCompiler map (`IlcGenerateMapFile`) from the same build, not committed, has sha256 `5955bb84b6c0aa6dab3d6803edfdeb49aca2f30c49c833836deeda1f3fe243ec`.

| File | Bytes | sha256 |
| --- | --- | --- |
| `Program.cs` | 6,120 | `7de1a08d33fddfa54456b4b21d1c458a841b2912e6314d507f93dd8e0ee3a4a0` |
| `aot_maps_net10_x86_64.csproj.txt` | 999 | `21ea0c9e25f76dd2d540c69e0d8242511ddc5d0287e8192ac96de80081532681` |
| `resources/tide_table.json` | 141 | `0478e99c9f92a9ecb3c78c9a756b8c3994941ba874d6d70175cf8518eacd9353` |
| `resources/gauge_curve.bin` | 512 | `08ac48e649b513d133de8324a7c75f166f3347490afcbe447e8df6debf09208b` |
| `aot_maps_net10_x86_64.exe` | 1,848,832 | `b9afd2376ec05994d15a3e2c08cf2fd0609c7afaf78fb1b3cb43b0a3cb93e3a8` |
| `aot_maps_net10_x86_64.link-map-managed.txt` (decompressed) | | `d36a47cb96cada894384f123549bc7567788f8d483915fe0f24e67775b246569` |
| `aot_maps_net10_x86_64.link-map-managed.txt.gz` | 67,002 | `0c1ec71b7342320d18234f04215be3b5ca7a56cdbed787498bbaede7d723c610` |

`gauge_curve.bin` holds bytes `(37 * i + 11) mod 256` for `i` from 0 to 511.

# NativeAOT constructor initializers

`aot_ctor_net10_x86_64/` holds a second C# program written for this repository, the .NET 10 NativeAOT executable published from it and the managed excerpt of its linker map. `crates/disrobe-pass-dotnet/tests/native_aot_constructor_fixture.rs` grades constructor initializer recovery against the constants the source assigns. The executable is never run.

The program is shaped so that the compiler produces every store form a constant-assigning constructor can take:

- `Berth` declares 49 instance fields of every primitive width (bool, byte, sbyte, short, ushort, char, int, uint, long, ulong, float, double, an int enum and a string) and its parameterless constructor assigns each one a literal. The runtime lays the fields out by size, not declaration order, so the object spans 0xd0 bytes and the 1- and 2-byte fields sit past offset 0x80, which forces 32-bit displacements.
- `Buoy` declares three fields inside the 8-bit displacement range.
- `Main` names both types in `typeof(T).GetFields` with `BindingFlags.NonPublic | BindingFlags.Instance` and reads each field through `GetValue`, so ILCompiler keeps the field metadata and emits a FieldAccessMap entry for every field, and reflection-invokes the `Berth` constructor (`GetConstructors` plus `ConstructorInfo.Invoke`), so that `.ctor` keeps an invoke-map entry with an entrypoint. The `Buoy` constructor is never reflected over, so it is absent from the invoke map and the stack-trace map names its body instead. Together the two constructors exercise both ways an image binds a constructor body to its type; a constructor that is merely enumerated without `Invoke` gets an invoke-map entry with no entrypoint and is left out of the stack-trace map, so nothing binds it.
- Both constructors carry `MethodImplOptions.NoInlining`, so each keeps a body the linker map bounds.

## Compiler output the tests rely on

Observed with llvm-objdump 19.1.7 on the committed image (`Berth..ctor` at RVA 0x81cc0, `Buoy..ctor` at RVA 0x82010):

- Immediate stores through `rcx`: `c6 41|81 disp imm8`, `66 c7 41|81 disp imm16`, `c7 41|81 disp imm32` and `48 c7 41|81 disp imm32` (sign-extended to 64 bits), with an 8-bit displacement below 0x80 and a 32-bit one above.
- Constants that do not fit a sign-extended 32-bit immediate (`0x1122334455667788`, `0x100000000`, the double 51.4779) are loaded with `48 b8 imm64` into `rax` and stored by the next instruction `48 89 41|81 disp`.
- Adjacent fields are coalesced: `_lit = true; _lane = 200` becomes one `mov word ptr [rcx+0xd6], 0xc801`, `_light0`/`_light1` one word store, and each pair of consecutive `int` fields one `movabs rax, imm64; mov qword ptr [rcx+disp], rax`. The reader splits such a store across the FieldAccessMap offsets it covers.
- The float 182.5 is stored as the dword immediate `0x43368000`; the string `"north pier"` is a `lea rax, [rip+disp]` of a frozen string object followed by a pointer store. The reader records that pair as a reference store and resolves the object as a frozen string.

## Frozen string layout the reader relies on

These points come from the dotnet/runtime sources at tag `v10.0.0` (MIT licence); each file's sha256 is listed below.

- `FrozenStringNode.cs` emits a frozen string as a pointer relocation to the constructed `System.String` MethodTable, a 4-byte UTF-16 code-unit count, the code units, and a two-byte null terminator; nothing precedes the MethodTable pointer at the symbol.
- `ModuleHeaders.cs` numbers the NativeAOT ReadyToRun section that holds frozen objects `FrozenObjectRegion = 206`; the reader accepts an object only inside that section's bounds.
- `MethodTable.h` and `MethodTable.Constants.cs` define the flags word at the start of a MethodTable: `HasComponentSizeFlag = 0x80000000` with the component size in the low 16 bits (`sizeof(char)` for `String`), the element type in bits 26 to 30 (`Class = 0x14`) and the kind in bits 16 and 17 (`CanonicalEEType = 0`). The reader requires all three on the MethodTable the object points at, and refuses the whole set when validated objects point at more than one MethodTable.

| Runtime source (`src/coreclr/...` at `v10.0.0`) | sha256 |
| --- | --- |
| `tools/aot/ILCompiler.Compiler/Compiler/DependencyAnalysis/FrozenStringNode.cs` | `40d622f9194a8e908ac759961ac1125253ccf5e0d217ba20efb65f7859e0fb3d` |
| `tools/Common/Internal/Runtime/ModuleHeaders.cs` | `1ddcb09ab04210002627171fe01072181fdb38428a3b3c9335e1ce00d036da21` |
| `nativeaot/Runtime/inc/MethodTable.h` | `b2ee1699166ef67b25fb4f992adbd5d80794a8a9043158064cb73372b7a6e851` |
| `tools/Common/Internal/Runtime/MethodTable.Constants.cs` | `7cda109c57a7b98b6ccb78d19b92ed08256e7ad7ca2cc9b16355cd29078e75aa` |

## Toolchain and build

Same SDK, ILCompiler packages and MSVC linker as `aot_maps_net10_x86_64` above (.NET SDK 10.0.100, `Microsoft.DotNet.ILCompiler` and `runtime.win-x64.Microsoft.DotNet.ILCompiler` 10.0.0 with the package sha512 values listed there, MSVC 14.44.35207). Copy `Program.cs` and the project file into an empty directory, rename `aot_ctor_net10_x86_64.csproj.txt` to `aot_ctor_net10_x86_64.csproj`, and run:

```sh
dotnet publish aot_ctor_net10_x86_64.csproj -c Release -r win-x64 --self-contained true -o publish --disable-build-servers -p:UseSharedCompilation=false -nodeReuse:false
```

`publish/aot_ctor_net10_x86_64.exe` is the committed executable; the image carries zero occurrences of `C:\` in ASCII and in UTF-16LE. The managed excerpt of `obj/Release/net10.0/win-x64/native/aot_ctor_net10_x86_64.link.map` is produced with the same `awk` and `gzip -9 -n` commands as above (object name `aot_ctor_net10_x86_64.obj`) and has 4,401 lines. The full map is 3,181,129 bytes with sha256 `fd28551f2bbb24aa716cc7146a22ac42176f760d2d04b7383b28982e62679a21`; the ILCompiler map (`aot_ctor_net10_x86_64.map.xml`, not committed) has sha256 `730fdaa2f3607848f74b9083e1c2469fb494581e014b74965b38800f9f541341`.

| File | Bytes | sha256 |
| --- | --- | --- |
| `Program.cs` | 6,550 | `3dc92f481cd3d8b9f119c0feb51bb03ef3fff63f787ebdb7a1261b7b9f2b4351` |
| `aot_ctor_net10_x86_64.csproj.txt` | 785 | `38e0db2e9d9218aadbb6751d68be1e0c3a4e76a92363c7bf90ea8ab885fc6e82` |
| `aot_ctor_net10_x86_64.exe` | 1,832,960 | `f9648c15a3adad32b5f4bb6570156a5717e128cc68c204e47f7e32e1b4564aaf` |
| `aot_ctor_net10_x86_64.link-map-managed.txt` (decompressed) | | `eeb4d519827c7dddea52617dc0aabd5558a76dfa7d2449637dee8569ec20edcb` |
| `aot_ctor_net10_x86_64.link-map-managed.txt.gz` | 65,816 | `87b05c7e4d40a6f16487d595f554569886a2cfb2c7f0ef65e3209e5a30a2d9fd` |
