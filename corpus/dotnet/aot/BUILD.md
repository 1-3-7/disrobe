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
