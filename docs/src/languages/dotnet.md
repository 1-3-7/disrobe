# .NET / CIL

`disrobe` parses the full .NET PE + CLR metadata surface, decompiles CIL to C#, F#, and VB pseudo-source, detects <!-- m:dotnet_protectors -->23<!-- /m --> protectors, and handles ReadyToRun and Native AOT images.

## At a glance

| Surface | Support |
|---|---|
| Decompile | In-house CIL disassembler (full opcode table) and CIL-to-C#/F#/VB lowering, so the structural recovery is disrobe's own even when a rendering backend is used |
| Rendering backends | ILSpy, dnSpy, dnSpyEx, de4dot via `--backend` |
| Images | ReadyToRun (R2R) and Native AOT probed, with symbol recovery on AOT builds; single-file bundles extracted member by member |
| ConfuserEx2 | Constant decryption and control-flow deflattening recovered in-house on real committed output; the encrypted-resource layer is carved byte-exact but walled on the runtime key; runtime-string and anti-tamper cleanup delegates to `--backend de4dot` |
| Eazfuscator.NET | String decryptor emulated over the `#US` table, graded on a fixture built to the published algorithm; VM tier devirtualized at all 57 instructions against an in-repo EazVM virtualizer of our own, not the shipping product |
| KoiVM | Devirtualized on a committed sample produced by the real KoiVM tool, all six virtualized bodies lifted back to CIL |
| SmartAssembly, .NET Reactor | Embedded-assembly resource decompressed and encrypted-string table decrypted, graded against Roslyn-built fixtures we build to the published algorithm; no assembly produced by either product is committed |
| Obfuscar | Dedicated in-house peeler: NameMaker odometer classification plus HideStrings recovery |
| ILProtector, MaxToCode | Detected and structurally enumerated; method bodies walled on the native-runtime key the assembly never carries |
| Themida .NET, ArmDot | Detected; no native-VM devirtualizer ships |

None of the walled bodies is fabricated. The rest of the detected set is reported with watermark-strip and encrypted-resource classification.

## Commands

```sh
disrobe dotnet decompile App.dll --backend ilspy --out src/
disrobe dotnet decompile App.exe --backend dnspyex --out src/
disrobe dotnet decompile App.dll --backend de4dot --out src/
disrobe dotnet analyze App.dll
disrobe dotnet backends                  # report available .NET backends on PATH
disrobe auto App.exe --out recovered/     # ConfuserEx2 PE -> de4dot -> ILSpy -> C#
```

`decompile` routes a .NET PE (`.dll` / `.exe`) through ILSpy, dnSpy, dnSpyEx, or de4dot. `analyze` reports the PE header, CLR metadata, protector detection, and probes for ReadyToRun (R2R) and Native AOT images, with symbol recovery on AOT builds.

## Coverage and fidelity

### Single-file bundles

A .NET single-file deployment packs the managed assemblies and their native runtime into one host executable. The `disrobe-binfmt` bundle reader (`disrobe_binfmt::containers::dotnet_bundle`) locates the bundle marker inside an MZ, ELF, or Mach-O host, parses the manifest, and extracts each embedded member (managed assemblies, native libraries, `deps.json`, `runtimeconfig.json`, and symbol files) to its recorded relative path, raw-inflating the deflate-compressed members that version 6 and later carry. Manifest major versions 1, 2, and 6 through 64 are read; the intermediate 3 to 5 range, which no shipping SDK emits, is rejected. Extraction is exercised by a round-trip that reconstructs every member byte-for-byte, and a declared member size that runs past the buffer is rejected rather than read out of bounds.

### Obfuscator reversal

`disrobe` detects <!-- m:dotnet_protectors -->23<!-- /m --> protector families. Recovery depth varies by protector and by what is statically present in the artifact. The model for in-house recovery is the same one used by the JVM and Lua passes: locate the decryptor method or key inside the assembly and emulate it over the encrypted data through the in-house CIL stack-machine, never a re-derived or hard-coded key.

Detection and string decryption are separate claims, and the evidence behind the second one differs by family. [String decryption evidence](#string-decryption-evidence) below states which families are graded on an assembly the protector itself produced and which are graded on a fixture we build to the published algorithm.

Reversed on a real committed sample (plaintext recovered from the artifact, plaintext-absent oracle):

- **ConfuserEx2**: in-house recovery reverses the *constants* protection (the documented FOSS "Ki.Constants" block-XOR / LZMA-validated algorithm) on a real committed `SampleConstants.confuserex2.dll`, with a test whose fixture holds only ciphertext plus the real decryptor and asserts plaintext not present anywhere in it. The encrypted-resource layer is carved byte-exact but walled on the runtime key. Control-flow flattening is deflattened in-house: `disrobe` rebuilds the original control-flow graph from the `while(true)/switch` dispatcher and recovers the switch-key encoding across ConfuserEx's NormalPredicate, x86Predicate (the native decoder stub emulated through the in-house x86 interpreter), and ExpressionPredicate (the inverse expression folded symbolically) modes, graded on real ConfuserEx `ctrl flow` output against the known clean baseline with every benign method's control-flow graph recovered to match. The remaining runtime-VM string decryption and anti-tamper cleanup are **delegated to de4dot** via `disrobe auto` / `--backend de4dot`.

In-assembly-decryptor recovery, graded by round-trip against the pre-encryption original:

- **Eazfuscator.NET**: locates the static `char[]`/`byte[]` string-decryptor method and emulates its CIL over the encrypted `#US` literal table to recover the pre-VM plaintext strings. The VM-tier is devirtualized against an in-repo EazVM virtualizer of our own: the committed assembly is encoded by that virtualizer, not the shipping Eazfuscator.NET product. `disrobe` reads the embedded resource, recovers the per-build opcode map from the in-assembly dispatch table by fingerprinting each handler, decrypts the position-keyed instruction stream, and lifts every virtualized method body back to CIL, then grades that CIL against the clean DLL. The grade is an ordered instruction comparison (opcode and operand, with branch targets resolved to instruction index, not raw token): 57 of 57 instructions match in sequence across the five bodies (100%). A second gate rebuilds a runnable assembly from the recovered CIL and asserts its stdout is byte-identical to the clean baseline (run wherever a .NET runtime is on `PATH`). Per-build randomization is fully recovered; only a runtime-only homomorphic key, not present statically, would bound a given build.
- **KoiVM (ConfuserEx VM)**: located by `#Koi` stream and `VMDispatcher` markers, then devirtualized on a committed sample produced by the **real KoiVM tool** (the TheProxyRE KoiVM fork driven through its public Virtualizer API over a benign self-authored exe, not a self-made encoder). `disrobe` reads the `#Koi` stream, fingerprints the VM-dispatch handler table, decodes the per-method instruction stream, and lifts all six virtualized bodies back to CIL through the same in-house CIL stack-machine used for Eazfuscator. The recovered bodies are graded against the independently compiled `KoiSample.clean.exe`: Add and Square recover fully and aggregate structural recovery stays at or above 75% against hand-derived ground-truth ops (a non-circular oracle), and the unobfuscated baseline correctly yields no KoiVM summary.
- **SmartAssembly (embedded assemblies)**: the mode-1 chunked raw-DEFLATE resource that carries a merged or embedded dependent assembly is decompressed back to the original assembly bytes, graded byte-for-byte against a committed Roslyn-built fixture (0 to 1 on the sample). The payload inside it is a real assembly; the mode-1 framing around it is built to the published algorithm, not taken from a SmartAssembly build. Non-mode-1 carriers are marked Unknown and malformed mode-1 is Rejected, never fabricated. String encryption is a separate axis (below).
- **.NET Reactor (encrypted-resource strings)**: the AES key and IV are read from the reachable encrypted-string resource and the string table is decrypted back to the original literals, graded against the runtime-validated originals of committed Roslyn-built fixtures carrying the .NET Reactor v4 static-string resource shape (astral-plane, embedded-nul, empty, and CJK strings all round-trip). No assembly produced by .NET Reactor is committed. An ambiguous or disconnected decoy key/IV tuple is Rejected as report-only, never guessed.
- **ILProtector / MaxToCode**: classified by Invoke-stub and zero-RVA method enumeration, runtime-resource and `.mtc`/`.text1` section location, and container-framing parse. Real builds derive the per-method key inside the native loader (`Protect32/64.dll`) at run time, not in the managed assembly, so the encrypted bodies are walled and reported absent, never fabricated.
- **Obfuscar**: dedicated in-house peeler (NameMaker odometer classification plus HideStrings recovery: the hidden `ldstr` literals are read back to their original bytes from the in-assembly FieldRVA carrier through the generated accessor, 15/15 on the gauntlet sample).

Detected and classified, with no dedicated string decryptor: **Dotfuscator (Pro), Goliath, DeepSea, Agile.NET (CV tier)**. The string key (per-string XOR lane, AES/Rijndael resource key, RC4(SHA1(resource)), or 3DES) is embedded in the assembly, so the data is present and not a wall. These carry watermark-strip, identifier, and encrypted-resource classification, and the generic static decoder opportunistically recovers in-lined integer and string constants where the decoder is a pure transform.

### String decryption evidence

Which families `disrobe` decrypts strings for, and what each claim is graded against:

| Evidence | Families |
|---|---|
| Graded on an assembly the protector's own tool produced | <!-- dotnet-string-evidence:real-sample -->ConfuserEx2, Obfuscar, BitMono<!-- /dotnet-string-evidence --> |
| Decoder implements the published algorithm, graded against a fixture built to it; no assembly from the product is committed | <!-- dotnet-string-evidence:modelled-algorithm -->SmartAssembly, Babel, Spices.Net, Skater, .NET Reactor, Eazfuscator.NET, CryptoObfuscator<!-- /dotnet-string-evidence --> |
| Key is native-loader-resident, so recovery stops at detection | <!-- dotnet-string-evidence:runtime-keyed -->Themida (.NET wrapper), ILProtector, MaxToCode<!-- /dotnet-string-evidence --> |

The second row is the one to read before pointing `disrobe` at a real protected assembly from those seven products. Each decoder there is written from the protector's published algorithm and is graded by encrypting a known plaintext with that algorithm and asserting the decoder returns it. That is evidence the decoder implements the algorithm we believe the protector uses. It is not evidence that the shipping product uses it, and it does not cover per-build variation those products may carry. All seven are commercial, and none of them has an artifact that is both benign and licensed for redistribution here, so no sample is committed to close the gap.

`crates/disrobe-pass-dotnet/src/protectors.rs` carries this split as `Protector::string_evidence`, and the tables above are regenerated from it. `cargo run -p xtask -- regen --check` fails if a family claims a committed sample the tree does not carry, or claims one whose `MANIFEST.toml` does not record the tool that produced it, or sits in the modelled row without being published there.

## Limits

Genuine walls (the key or the original code is not in the static artifact):

- **Themida / .NET wrapper**: managed methods are lifted into the Oreans native VM; per project policy `disrobe` does not ship a native-VM devirtualizer.
- **ArmDot**: custom per-method VM with LCG-encrypted opcodes; static devirtualization is not performed.
- **ILProtector / MaxToCode native-keyed configurations**: when the per-method key is computed inside the native stub, the original CIL is not statically present.
- **Obfuscar renames**: the rename itself embeds no in-PE name map, so original identifier names stay walled behind the out-of-band Mapping.txt.

Commercial protector findings are reported with the recovery wall when the static artifact lacks the needed key or handler stream.
