# .NET / CIL

`disrobe` parses .NET PE and CLR metadata, decompiles CIL to C#, F#, and VB pseudo-source, registers detection and routing for <!-- m:dotnet_protectors -->23<!-- /m --> protector families, and probes ReadyToRun and Native AOT images.

## At a glance

| Surface | Support |
|---|---|
| Decompile | In-house CIL disassembler and CIL-to-C#/F#/VB lowering, so the structural recovery is disrobe's own even when a rendering backend is used |
| Rendering backends | ILSpy, dnSpy, dnSpyEx, de4dot via `--backend` |
| Images | ReadyToRun (R2R) and Native AOT detection; `dotnet native-aot` exposes the library's name, type, method-boundary, and managed-signature recovery, graded on real Native AOT builds for PE and on hand-assembled ELF and Mach-O images that carry only a header and two metadata names; single-file bundles extracted member by member |
| ConfuserEx2 | Constant decryption recovered in-house on real ConfuserEx2 1.6.0 output; control-flow deflattening matched to the clean control-flow graph on ConfuserEx 1.x output and checked more narrowly on ConfuserEx2 1.6.0 output; the encrypted-resource layer is carved byte-exact but walled on the runtime key; runtime-string and anti-tamper cleanup delegates to `--backend de4dot` |
| Eazfuscator.NET | A generic XOR string decryptor emulated over the `#US` table, graded on a synthetic fixture rather than Eazfuscator.NET output; VM tier devirtualized at all 67 instructions against an in-repo EazVM virtualizer of our own, not the shipping product |
| KoiVM | Devirtualized on a committed sample produced by the real KoiVM tool, all six virtualized bodies lifted back to CIL |
| SmartAssembly, .NET Reactor | Embedded-assembly resource decompressed and encrypted-string table decrypted, graded against Roslyn-built fixtures we build to the published algorithm; no assembly produced by either product is committed |
| Obfuscar | Dedicated in-house peeler: NameMaker odometer classification plus HideStrings recovery |
| ILProtector, MaxToCode | Invoke-stub and zero-RVA structures enumerated on in-repo fixtures; native-keyed configurations remain report-only |
| Themida .NET, ArmDot | Detected; no native-VM devirtualizer ships |

Other registered families produce reports identifying the protector and the static recovery available for that input. Bodies that require an unavailable runtime key remain encrypted.

## Commands

```sh
disrobe dotnet decompile App.dll --backend ilspy --out src/
disrobe dotnet decompile App.exe --backend dnspy-ex --out src/
disrobe dotnet decompile App.single-file.exe --out recovered/
disrobe dotnet decompile App.dll --backend de4dot --out src/
disrobe dotnet analyze App.dll
disrobe dotnet native-aot App.native.exe --out aot.json
disrobe dotnet backends                  # report available .NET backends on PATH
disrobe auto App.exe --out recovered/     # static protector peel + in-house CIL-to-C#
```

`decompile` always runs the in-house CIL renderer. `--backend ilspy|dnspy|dnspy-ex|de4dot` also runs that external decompiler; a named backend that is not installed fails with an error. `disrobe auto` stays on the registered in-house pass and does not launch those backends. `analyze` reports the PE and CLR summary, protector detection, and whether ReadyToRun (R2R) or Native AOT is detected. Use `dotnet native-aot` for the detailed AOT report and recovered method bodies.

## Coverage and fidelity

### Single-file bundles

A .NET single-file deployment packs application files into a host executable. A self-contained
deployment can also carry native runtime components. The bundle reader
(`disrobe_binfmt::containers::dotnet_bundle`) finds the bundle marker inside a PE, ELF or Mach-O
host, reads the manifest, and returns each embedded member under its sanitized relative path. It
inflates a deflate-compressed member and returns a stored member as it lies. Members are managed
assemblies, native libraries, `deps.json`, `runtimeconfig.json` and symbol files. The reader also
parses `deps.json` into a typed manifest rather than only carving it, so the runtime assembly list
and the library table are readable as data.

`disrobe extract` writes the members to disk, and `disrobe auto` routes them onward with no
dedicated flag: an embedded managed assembly reaches the CIL pass on its own. `disrobe dotnet
decompile` accepts the same bundle as a direct input. It stages all recovered output beside the
destination and publishes the directory only after extraction and every managed assembly
decompilation succeed. `members/` holds every embedded file. `assemblies/<relative-path>/` holds
the normal manifest and pseudo-source for each managed assembly. `bundle.manifest.json` records the
bundle version, bundle ID, quota accounting, and managed assembly list. The command refuses a
non-empty destination and refuses more than 512 managed assemblies before invoking any rendering
backend.

The format defines exactly three manifest major versions, and the reader accepts those three and
refuses any other by number. Major 1 is what .NET Core 3.x wrote, major 2 is .NET 5, and major 6 is
.NET 6 and later. Major 1 has no deps or runtimeconfig block and records every entry as type
`Unknown`. Compression exists only from major 6.

Coverage is graded against bundles the real .NET tooling produced, in
`corpus/binfmt/dotnet-single-file`. Each extracted assembly is compared byte for byte with the
assembly the compiler emitted before bundling. The committed set spans all three major versions,
PE, ELF and Mach-O hosts, every one of the six entry types, and a bundle that mixes compressed and
stored entries. A declared member size that runs past the buffer, a path that escapes the output
directory, a duplicate path and a decompression bomb are each refused.

A universal (fat) Mach-O host is not supported. Its header-offset field is relative to the slice
rather than to the file, so the reader sees an implausible version and refuses the file instead of
reading the wrong offset.

### Native AOT images

The AOT report recovers metadata names, type and method attribution, method boundaries, and
pseudo-C bodies. That coverage is measured on x86_64 PE executables published by the .NET Native
AOT toolchain. The ELF and Mach-O fixtures are hand-assembled: each is a small assembly source
linked by `ld.lld` or `ld64.lld` into an image that holds a ReadyToRun header and two metadata
names. On those two formats the tests grade header location, layout-profile selection, and name
recovery only; no ELF or Mach-O image built by the .NET toolchain is committed, and type, method,
and body recovery on them is unmeasured. The parser reads layout metadata from the image; recovery
on aarch64, arm, and x86 remains outside the measured population.

### Obfuscator reversal

`disrobe` registers detection rules for <!-- m:dotnet_protectors -->23<!-- /m --> protector families. Recovery depth varies by protector and by what is statically present in the artifact. The per-family evidence below states what artifact is graded, what data is recovered, and where static recovery stops.

Detection and string decryption are separate claims, and the evidence behind the second one differs by family. [String decryption evidence](#string-decryption-evidence) below states which families are graded on an assembly the protector itself produced and which are graded on a fixture we build to the published algorithm.

Reversed on a real committed sample (plaintext recovered from the artifact, plaintext-absent oracle):

- **ConfuserEx2**: in-house recovery reverses the *constants* protection (the documented FOSS "Ki.Constants" block-XOR / LZMA-validated algorithm) on a real committed `SampleConstants.confuserex2.dll`, with a test whose fixture holds only ciphertext plus the real decryptor and asserts plaintext not present anywhere in it. The encrypted-resource layer is carved byte-exact but walled on the runtime key. Control-flow flattening is deflattened in-house: `disrobe` rebuilds the original control-flow graph from the `while(true)/switch` dispatcher and recovers the switch-key encoding. The deflattening evidence comes from two protector lines and differs in strength:
  - ConfuserEx 1.x (`yck1509/ConfuserEx`, `ctrl flow` protection): on the NormalPredicate sample all 6 flattened methods recover the clean build's control-flow graph with every opcode and operand in place; on the x86Predicate sample (the native decoder stub emulated through the in-house x86 interpreter) and the ExpressionPredicate sample (the inverse expression folded symbolically) all 8 methods each recover the clean control-flow graph.
  - ConfuserEx2 1.6.0: in the gauntlet sample the flattened `Process` method deflattens with no unresolved block, 11 of its 12 block signatures match the clean build, and every call-result `pop` survives. In `HelloAppLegacy.confuserex2.dll` every flattened method (the static constructor and the injected constant decoder) deflattens with no unresolved block and no edge to a missing block; that check has no clean baseline to compare against.

  For de4dot's runtime-VM string and anti-tamper handling, confirm de4dot is available with `disrobe dotnet backends`, then use `disrobe dotnet decompile App.exe --backend de4dot`. `disrobe auto` does not invoke that external backend.

In-assembly-decryptor recovery, graded by round-trip against the pre-encryption original. This list is grouped by how recovery works, not by who produced the sample, so a family in it also appears in [String decryption evidence](#string-decryption-evidence) below: the round-trip proves the decoder inverts the encryption, and the table below states whether the encrypted input came from the protector's own tool or from a fixture built to its published algorithm.

- **Eazfuscator.NET**: locates a static `char[]`/`byte[]` string-decryptor method and emulates its CIL over the encrypted `#US` literal table to recover the plaintext strings. The graded decryptor is a generic single-key XOR loop inside a synthetic PE that the test assembles itself; neither Eazfuscator.NET's own string algorithm nor its output is part of that grade, which is why the family also sits in the modelled row below. The VM tier is devirtualized against an in-repo EazVM virtualizer of our own: the committed assembly is encoded by that virtualizer, not the shipping Eazfuscator.NET product. `disrobe` reads the embedded resource, recovers the per-build opcode map from the in-assembly dispatch table by fingerprinting each handler, decrypts the position-keyed instruction stream, and lifts every virtualized method body back to CIL. It then applies width-checked MBA simplification to supported straight-line `int32` expressions before grading the result against the clean DLL. The ordered instruction comparison resolves branch targets to instruction indexes, and 67 of 67 instructions match in sequence across six bodies (100%). A second gate evaluates the recovered bodies in the product's bounded CIL emulator with the arguments `Main` passes and requires the six values the clean assembly prints. It also checks both sides of every recovered branch against the C# source, and a mutation of each branch must change a result. No assembly runs. For the committed seeded build, the randomized opcode map is recovered from the assembly rather than read from its sidecar.
- **KoiVM (ConfuserEx VM)**: detects the `#Koi` stream and `VMDispatcher` markers, identifies dispatch handlers, decodes each method's instruction stream, and lifts all six virtualized bodies to CIL. The committed fixture was produced by the TheProxyRE KoiVM fork through its public Virtualizer API over a benign test program. Recovery is compared with the separately compiled `KoiSample.clean.exe` and manually derived operations: Add and Square recover fully, and aggregate structural recovery has a 75% CI floor. The unobfuscated control produces no KoiVM summary.
- **SmartAssembly (embedded assemblies)**: the mode-1 chunked raw-DEFLATE resource that carries a merged or embedded dependent assembly is decompressed back to the original assembly bytes, graded byte-for-byte against a committed Roslyn-built fixture. The sample recovers <!-- m:dotnet_smartassembly_resources -->1 / 1<!-- /m --> embedded resource. The payload inside it is a real assembly; the mode-1 framing around it is built to the published algorithm, not taken from a SmartAssembly build. Non-mode-1 carriers are marked Unknown and malformed mode-1 is Rejected; neither produces a decoded value. String encryption is a separate axis (below).
- **.NET Reactor (encrypted-resource strings)**: the AES key and IV are read from the reachable encrypted-string resource and the string table is decrypted back to the original literals, graded against the runtime-validated originals of committed Roslyn-built fixtures carrying the .NET Reactor v4 static-string resource shape (astral-plane, embedded-nul, empty, and CJK strings all round-trip). No assembly produced by .NET Reactor is committed. An ambiguous or disconnected decoy key/IV tuple is Rejected as report-only, never guessed.
- **ILProtector / MaxToCode**: classified on in-repo structural fixtures by Invoke-stub and zero-RVA method enumeration, runtime-resource and `.mtc`/`.text1` section location, and container-framing parse. For native-keyed configurations, the managed assembly does not carry the per-method key used by the runtime loader, so the encrypted bodies remain report-only.
- **Obfuscar**: dedicated in-house peeler (NameMaker odometer classification plus HideStrings recovery: the hidden `ldstr` literals are read back to their original bytes from the in-assembly FieldRVA carrier through the generated accessor, <!-- m:dotnet_obfuscar_hidden_strings -->15 / 15<!-- /m --> on the gauntlet sample).

**Babel, Dotfuscator (Pro), Goliath, DeepSea, and Agile.NET** have detection and classification
support. Babel reports the string-recovery prerequisite: a matching protected/plain sample or a
verified decoder chain. The other paths report watermarks, identifier characteristics, and
encrypted-resource details. They can also use the generic static decoder for supported pure transforms.

### String decryption evidence

Which families `disrobe` decrypts strings for, and what each claim is graded against:

| Evidence | Families |
|---|---|
| Graded on an assembly the protector's own tool produced | <!-- dotnet-string-evidence:real-sample -->ConfuserEx2, Obfuscar, BitMono<!-- /dotnet-string-evidence --> |
| Decoder implements the published algorithm, graded against a fixture built to it; no assembly from the product is committed | <!-- dotnet-string-evidence:modelled-algorithm -->SmartAssembly, Spices.Net, Skater, .NET Reactor, Eazfuscator.NET, CryptoObfuscator<!-- /dotnet-string-evidence --> |
| Key is native-loader-resident, so recovery stops at detection | <!-- dotnet-string-evidence:runtime-keyed -->Themida (.NET wrapper), ILProtector, MaxToCode<!-- /dotnet-string-evidence --> |

The second row tests algorithm implementations against known plaintexts encrypted by repository
fixtures. Product versions and per-build variants are outside that comparison; the corpus contains
no redistributable product-produced sample for those families. The Eazfuscator.NET entry is weaker
than the others in that row: its graded decoder is a generic XOR decryptor on a synthetic fixture,
not an implementation of the product's string algorithm.

`crates/disrobe-pass-dotnet/src/protectors.rs` carries this split as `Protector::string_evidence`, and the tables above are regenerated from it. `cargo run -p xtask -- regen --check` fails if a family claims a committed sample the tree does not carry, or claims one whose `MANIFEST.toml` does not record the tool that produced it, or sits in the modelled row without being published there.

## Limits

Recovery stops at these boundaries:

- **Themida / .NET wrapper**: native VM bodies are outside the current recovery scope; `disrobe` does not ship a native-VM devirtualizer.
- **ArmDot**: detected and reported, but no static devirtualizer ships.
- **ILProtector / MaxToCode native-keyed configurations**: when the per-method key is computed inside the native stub, the original CIL is not statically present.
- **Obfuscar renames**: original identifiers require the separate `Mapping.txt`; the PE contains no name map.

Protector reports identify the missing key or handler stream when those bytes are unavailable in the artifact.
