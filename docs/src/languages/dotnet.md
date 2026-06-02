# .NET / CIL

**disrobe** parses the full .NET PE + CLR metadata surface, decompiles CIL to C#, F#, and VB pseudo-source, reverses 20+ obfuscators, and handles ReadyToRun and Native AOT images.

## Decompiling

```sh
disrobe dotnet decompile App.dll --backend ilspy --out src/
disrobe dotnet decompile App.exe --backend dnspyex --out src/
disrobe dotnet decompile App.dll --backend de4dot --out src/
```

Routes a .NET PE (`.dll` / `.exe`) through ILSpy, dnSpy, dnSpyEx, or de4dot. **disrobe** owns the in-house CIL disassembler (full opcode table) and the CIL-to-C#/F#/VB lowering, so the structural recovery is its own even when a rendering backend is used.

## Static analysis

```sh
disrobe dotnet analyze App.dll
disrobe dotnet backends                  # report available .NET backends on PATH
```

`analyze` reports the PE header, CLR metadata, protector detection, and probes for ReadyToRun (R2R) and Native AOT images, with symbol recovery on AOT builds.

## Obfuscator reversal

**disrobe** reverses the .NET obfuscator field - ConfuserEx and ConfuserEx2 (string decryption, control-flow flattening, constants, anti-tamper, resources), .NET Reactor, Eazfuscator.NET, SmartAssembly, Dotfuscator, Babel, CryptoObfuscator, Agile.NET, ArmDot, Goliath, Skater, Spices.Net, Obfuscar, and more. Grey-zone commercial protectors are gated behind `--i-have-authorization`.

## Chaining

```sh
disrobe auto App.exe --out recovered/    # ConfuserEx2 PE -> de4dot -> ILSpy -> C#
```
