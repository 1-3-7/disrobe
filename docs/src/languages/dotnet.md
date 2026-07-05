# .NET / CIL

**disrobe** parses the full .NET PE + CLR metadata surface, decompiles CIL to C#, F#, and VB pseudo-source, detects <!-- m:dotnet_protectors -->23<!-- /m --> protectors, and handles ReadyToRun and Native AOT images. In-house static recovery reverses ConfuserEx2 constant decryption on a real committed sample (its encrypted-resource layer is carved byte-exact but walled on the runtime key, and full ConfuserEx2 cleanup delegates to `--backend de4dot`); the Eazfuscator VM-tier is devirtualized at 57 of 57 instructions against an in-repo EazVM virtualizer of our own (the committed assembly is encoded by that virtualizer, not the shipping Eazfuscator.NET product); the KoiVM VM-tier is devirtualized on a committed sample produced by the real KoiVM tool (all six virtualized bodies lifted back to CIL and graded against the independently compiled clean baseline); and ILProtector and MaxToCode are detected and structurally enumerated with their method bodies walled on the native-runtime key (derived in the loader, absent from the assembly), never fabricated. The rest are detected with watermark-strip and encrypted-resource classification.

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

**disrobe** detects <!-- m:dotnet_protectors -->23<!-- /m --> protector families. Recovery depth varies by protector and by what is statically present in the artifact. The model for in-house recovery is the same one used by the JVM and Lua passes: locate the decryptor method or key inside the assembly and emulate it over the encrypted data through the in-house CIL stack-machine, never a re-derived or hard-coded key.

Reversed on a real committed sample (plaintext recovered from the artifact, plaintext-absent oracle):

- **ConfuserEx2**: in-house recovery reverses the *constants* protection (the documented FOSS "Ki.Constants" block-XOR / LZMA-validated algorithm) on a real committed `SampleConstants.confuserex2.dll`, with a test whose fixture holds only ciphertext plus the real decryptor and asserts plaintext not present anywhere in it. The encrypted-resource layer is carved byte-exact but walled on the runtime key. Full deobfuscation (control-flow flattening, runtime-VM string decryption, anti-tamper) is **delegated to de4dot** via `disrobe auto` / `--backend de4dot`; `disrobe` does not reimplement that tier in-house.

In-assembly-decryptor recovery, graded by round-trip against the pre-encryption original:

- **Eazfuscator.NET**: locates the static `char[]`/`byte[]` string-decryptor method and emulates its CIL over the encrypted `#US` literal table to recover the pre-VM plaintext strings. The VM-tier is devirtualized against an in-repo EazVM virtualizer of our own: the committed assembly is encoded by that virtualizer, not the shipping Eazfuscator.NET product. `disrobe` reads the embedded resource, recovers the per-build opcode map from the in-assembly dispatch table by fingerprinting each handler, decrypts the position-keyed instruction stream, and lifts every virtualized method body back to CIL, then grades that CIL against the clean DLL. The grade is an ordered instruction comparison (opcode and operand, with branch targets resolved to instruction index, not raw token): 57 of 57 instructions match in sequence across the five bodies (100%). A second gate rebuilds a runnable assembly from the recovered CIL and asserts its stdout is byte-identical to the clean baseline (run wherever a .NET runtime is on `PATH`). Per-build randomization is fully recovered; only a runtime-only homomorphic key, not present statically, would bound a given build.
- **ILProtector / MaxToCode**: classified by Invoke-stub and zero-RVA method enumeration, runtime-resource and `.mtc`/`.text1` section location, and container-framing parse. Real builds derive the per-method key inside the native loader (`Protect32/64.dll`) at run time, not in the managed assembly, so the encrypted bodies are walled and reported absent, never fabricated.
- **KoiVM (ConfuserEx VM)**: located by `#Koi` stream and `VMDispatcher` markers, then devirtualized on a committed sample produced by the **real KoiVM tool** (the TheProxyRE KoiVM fork driven through its public Virtualizer API over a benign self-authored exe, not a self-made encoder). `disrobe` reads the `#Koi` stream, fingerprints the VM-dispatch handler table, decodes the per-method instruction stream, and lifts all six virtualized bodies back to CIL through the same in-house CIL stack-machine used for Eazfuscator. The recovered bodies are graded against the independently compiled `KoiSample.clean.exe`: Add and Square recover fully and aggregate structural recovery stays at or above 75% against hand-derived ground-truth ops (a non-circular oracle), and the unobfuscated baseline correctly yields no KoiVM summary.

Doable now with an in-assembly key (detected + classified today; a per-protector decryptor emulation can be added on the same model when a real sample is available to fix the exact algorithm against):

- **SmartAssembly, .NET Reactor, Babel, Dotfuscator (Pro), Skater, Goliath, DeepSea**: the string key (per-string XOR lane, AES/Rijndael resource key, RC4(SHA1(resource)), or single-byte XOR) is embedded in the assembly, so the data is present and not a wall. These are currently detected with watermark-strip, identifier, and encrypted-resource classification, and the generic static-decoder opportunistically recovers in-lined integer/string constants where the decoder is a pure transform. Confirming a per-build algorithm needs a real protected sample (flagged for consent; nothing is downloaded).
- **CryptoObfuscator, Agile.NET (CV tier)**: 3DES/Rijndael string keys are in-assembly; same status as above.

Needs a real sample to build against (flagged for consent, never downloaded): **Spices.Net** (Cyrillic-homoglyph + ROT-N per-method scramble), and the commercial protectors above whose exact per-build transform is not documented.

Genuine walls (the key or the original code is not in the static artifact):

- **Themida / .NET wrapper**: managed methods are lifted into the Oreans native VM; per project policy `disrobe` does not ship a native-VM devirtualizer.
- **ArmDot**: custom per-method VM with LCG-encrypted opcodes; static devirtualization is not performed.
- **ILProtector / MaxToCode native-keyed configurations**: when the per-method key is computed inside the native stub, the original CIL is not statically present.

Other:

- **Obfuscar**: dedicated in-house peeler (NameMaker odometer classification; rename-only metadata, so there is no byte rewrite and no embedded name map to recover).

Commercial protector findings are reported with the recovery wall when the static artifact lacks the needed key or handler stream.

## Chaining

```sh
disrobe auto App.exe --out recovered/    # ConfuserEx2 PE -> de4dot -> ILSpy -> C#
```
