# .NET / CIL

**disrobe** parses the full .NET PE + CLR metadata surface, decompiles CIL to C#, F#, and VB pseudo-source, detects 19 obfuscators and reverses 16 (3 detect-only), and handles ReadyToRun and Native AOT images.

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

**disrobe** detects and routes the .NET obfuscator field, with recovery depth varying by protector and what is statically reversible:

- **ConfuserEx / ConfuserEx2** - in-house recovery is the *constants* protection (the documented FOSS "Ki.Constants" block-XOR / LZMA-validated algorithm) plus byte-exact encrypted-resource extraction. Full deobfuscation (control-flow flattening, runtime-VM string decryption, anti-tamper) is **delegated to de4dot** via `disrobe auto` / `--backend de4dot`; disrobe does not reimplement it in-house.
- **Eazfuscator.NET, SmartAssembly, .NET Reactor, Babel, CryptoObfuscator, Agile.NET** - detected and routed report-only (encrypted-resource location + watermark scan); no in-house decryption.
- **Dotfuscator, DeepSea, Goliath, Skater, Spices.Net** - detected and routed to attribute-strip + report.
- **ArmDot, Themida/.NET, ILProtector, MaxtoCode** - native/VM protectors: detect-only by policy.
- **Obfuscar** - dedicated in-house peeler (rename-only metadata; no byte rewrite).

Grey-zone commercial protectors are gated behind `--i-have-authorization`.

## Chaining

```sh
disrobe auto App.exe --out recovered/    # ConfuserEx2 PE -> de4dot -> ILSpy -> C#
```
