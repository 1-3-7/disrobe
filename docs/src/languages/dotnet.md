# .NET / CIL

`disrobe` parses .NET PE and CLR metadata, decompiles CIL to C#, F#, and VB pseudo-source, registers detection and routing for <!-- m:dotnet_protectors -->23<!-- /m --> protector families, and probes ReadyToRun and Native AOT images.

## At a glance

| Surface | Support |
|---|---|
| Decompile | In-house CIL disassembler and CIL-to-C#/F#/VB lowering, so the structural recovery is disrobe's own even when a rendering backend is used |
| Rendering backends | ILSpy, dnSpy, dnSpyEx, de4dot via `--backend` |
| Images | ReadyToRun (R2R) and Native AOT detection; the library AOT report recovers names and metadata attribution on committed fixtures, while CLI analysis currently reports detection only; single-file bundles extracted member by member |
| ConfuserEx2 | Constant decryption and control-flow deflattening recovered in-house on real committed output; the encrypted-resource layer is carved byte-exact but walled on the runtime key; runtime-string and anti-tamper cleanup delegates to `--backend de4dot` |
| Eazfuscator.NET | String decryptor emulated over the `#US` table, graded on a fixture built to the published algorithm; VM tier devirtualized at all 67 instructions against an in-repo EazVM virtualizer of our own, not the shipping product |
| KoiVM | Devirtualized on a committed sample produced by the real KoiVM tool, all six virtualized bodies lifted back to CIL |
| SmartAssembly, .NET Reactor | Embedded-assembly resource decompressed and encrypted-string table decrypted, graded against Roslyn-built fixtures we build to the published algorithm; no assembly produced by either product is committed |
| Obfuscar | Dedicated in-house peeler: NameMaker odometer classification plus HideStrings recovery |
| ILProtector, MaxToCode | Invoke-stub and zero-RVA structures enumerated on in-repo fixtures; native-keyed configurations remain report-only |
| Themida .NET, ArmDot | Detected; no native-VM devirtualizer ships |

None of the walled bodies is fabricated. Other registered families have protector-specific reports and only the static recovery their corresponding peel paths can substantiate.

## Commands

```sh
disrobe dotnet decompile App.dll --backend ilspy --out src/
disrobe dotnet decompile App.exe --backend dnspy-ex --out src/
disrobe dotnet decompile App.single-file.exe --out recovered/
disrobe dotnet decompile App.dll --backend de4dot --out src/
disrobe dotnet analyze App.dll
disrobe dotnet backends                  # report available .NET backends on PATH
disrobe auto App.exe --out recovered/     # static protector peel + in-house CIL-to-C#
```

`decompile` always runs the in-house CIL renderer. Its default `--backend auto` policy may also invoke the first installed external backend in this order: ILSpy, dnSpyEx, dnSpy, then de4dot. `--backend ilspy|dnspy|dnspy-ex|de4dot` requests one explicitly, but the current selector falls back to the same first-installed order if the requested tool is absent. `disrobe auto` stays on the registered in-house pass and does not launch those backends. `analyze` reports the PE and CLR summary, protector detection, and whether ReadyToRun (R2R) or Native AOT is detected. Detailed AOT names and metadata attribution are exposed by the library AOT report, not the current CLI summary.

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

The AOT report recovers metadata names, type and method attribution, method boundaries and
pseudo-C bodies. Every Native AOT image it is graded against, in both the crate fixtures and the
corpus, is x86_64. No aarch64, arm or x86 Native AOT image is committed in any container, so no
grade covers those architectures and none is claimed for them. The PE, ELF and Mach-O host
containers are each graded, but only at x86_64.

The parser reads the layout from the image rather than from the architecture, so it is expected to
carry to other architectures. Expected is not graded, and until an image exists to grade against,
that expectation is the only basis for it.

### Obfuscator reversal

`disrobe` registers detection rules for <!-- m:dotnet_protectors -->23<!-- /m --> protector families. Recovery depth varies by protector and by what is statically present in the artifact. The per-family evidence below states what artifact is graded, what data is recovered, and where static recovery stops.

Detection and string decryption are separate claims, and the evidence behind the second one differs by family. [String decryption evidence](#string-decryption-evidence) below states which families are graded on an assembly the protector itself produced and which are graded on a fixture we build to the published algorithm.

Reversed on a real committed sample (plaintext recovered from the artifact, plaintext-absent oracle):

- **ConfuserEx2**: in-house recovery reverses the *constants* protection (the documented FOSS "Ki.Constants" block-XOR / LZMA-validated algorithm) on a real committed `SampleConstants.confuserex2.dll`, with a test whose fixture holds only ciphertext plus the real decryptor and asserts plaintext not present anywhere in it. The encrypted-resource layer is carved byte-exact but walled on the runtime key. Control-flow flattening is deflattened in-house: `disrobe` rebuilds the original control-flow graph from the `while(true)/switch` dispatcher and recovers the switch-key encoding across ConfuserEx's NormalPredicate, x86Predicate (the native decoder stub emulated through the in-house x86 interpreter), and ExpressionPredicate (the inverse expression folded symbolically) modes, graded on real ConfuserEx `ctrl flow` output against the known clean baseline with every benign method's control-flow graph recovered to match. For de4dot's runtime-VM string and anti-tamper handling, confirm de4dot is available with `disrobe dotnet backends`, then use `disrobe dotnet decompile App.exe --backend de4dot`. `disrobe auto` does not invoke that external backend.

In-assembly-decryptor recovery, graded by round-trip against the pre-encryption original. This list is grouped by how recovery works, not by who produced the sample, so a family in it also appears in [String decryption evidence](#string-decryption-evidence) below: the round-trip proves the decoder inverts the encryption, and the table below states whether the encrypted input came from the protector's own tool or from a fixture built to its published algorithm.

- **Eazfuscator.NET**: locates the static `char[]`/`byte[]` string-decryptor method and emulates its CIL over the encrypted `#US` literal table to recover the pre-VM plaintext strings, graded on a fixture built to the published algorithm rather than on Eazfuscator.NET output, which is why the family also sits in the modelled row below. The VM tier is devirtualized against an in-repo EazVM virtualizer of our own: the committed assembly is encoded by that virtualizer, not the shipping Eazfuscator.NET product. `disrobe` reads the embedded resource, recovers the per-build opcode map from the in-assembly dispatch table by fingerprinting each handler, decrypts the position-keyed instruction stream, and lifts every virtualized method body back to CIL. It then applies width-checked MBA simplification to supported straight-line `int32` expressions before grading the result against the clean DLL. The ordered instruction comparison resolves branch targets to instruction indexes, and 67 of 67 instructions match in sequence across six bodies (100%). A second gate rebuilds a runnable assembly from the recovered CIL and asserts its stdout is byte-identical to the clean baseline; CI provisions .NET, while local runs require `dotnet` on `PATH`. For the committed seeded build, the randomized opcode map is recovered from the assembly rather than read from its sidecar.
- **KoiVM (ConfuserEx VM)**: located by `#Koi` stream and `VMDispatcher` markers, then devirtualized on a committed sample produced by the **real KoiVM tool** (the TheProxyRE KoiVM fork driven through its public Virtualizer API over a benign self-authored exe, not a self-made encoder). `disrobe` reads the `#Koi` stream, fingerprints the VM-dispatch handler table, decodes the per-method instruction stream, and lifts all six virtualized bodies back to CIL through the same in-house CIL stack-machine used for Eazfuscator. The recovered bodies are graded against the independently compiled `KoiSample.clean.exe`: Add and Square recover fully and aggregate structural recovery stays at or above a 75% CI floor against hand-derived ground-truth ops (a non-circular oracle), and the unobfuscated baseline correctly yields no KoiVM summary.
- **SmartAssembly (embedded assemblies)**: the mode-1 chunked raw-DEFLATE resource that carries a merged or embedded dependent assembly is decompressed back to the original assembly bytes, graded byte-for-byte against a committed Roslyn-built fixture. The sample recovers <!-- m:dotnet_smartassembly_resources -->1 / 1<!-- /m --> embedded resource. The payload inside it is a real assembly; the mode-1 framing around it is built to the published algorithm, not taken from a SmartAssembly build. Non-mode-1 carriers are marked Unknown and malformed mode-1 is Rejected, never fabricated. String encryption is a separate axis (below).
- **.NET Reactor (encrypted-resource strings)**: the AES key and IV are read from the reachable encrypted-string resource and the string table is decrypted back to the original literals, graded against the runtime-validated originals of committed Roslyn-built fixtures carrying the .NET Reactor v4 static-string resource shape (astral-plane, embedded-nul, empty, and CJK strings all round-trip). No assembly produced by .NET Reactor is committed. An ambiguous or disconnected decoy key/IV tuple is Rejected as report-only, never guessed.
- **ILProtector / MaxToCode**: classified on in-repo structural fixtures by Invoke-stub and zero-RVA method enumeration, runtime-resource and `.mtc`/`.text1` section location, and container-framing parse. For native-keyed configurations, the managed assembly does not carry the per-method key used by the runtime loader, so the encrypted bodies remain report-only.
- **Obfuscar**: dedicated in-house peeler (NameMaker odometer classification plus HideStrings recovery: the hidden `ldstr` literals are read back to their original bytes from the in-assembly FieldRVA carrier through the generated accessor, <!-- m:dotnet_obfuscar_hidden_strings -->15 / 15<!-- /m --> on the gauntlet sample).

Detected and classified without a family-specific string fidelity claim: **Babel, Dotfuscator (Pro), Goliath, DeepSea, Agile.NET**. Babel reports detection and an explicit string-recovery wall because no authentic protected/plain sample or authenticated decoder chain is committed. The other peel paths report matched watermarks, identifier characteristics, and relevant encrypted-resource details, and may run the generic static decoder when it can prove a pure transform.

### String decryption evidence

Which families `disrobe` decrypts strings for, and what each claim is graded against:

| Evidence | Families |
|---|---|
| Graded on an assembly the protector's own tool produced | <!-- dotnet-string-evidence:real-sample -->ConfuserEx2, Obfuscar, BitMono<!-- /dotnet-string-evidence --> |
| Decoder implements the published algorithm, graded against a fixture built to it; no assembly from the product is committed | <!-- dotnet-string-evidence:modelled-algorithm -->SmartAssembly, Spices.Net, Skater, .NET Reactor, Eazfuscator.NET, CryptoObfuscator<!-- /dotnet-string-evidence --> |
| Key is native-loader-resident, so recovery stops at detection | <!-- dotnet-string-evidence:runtime-keyed -->Themida (.NET wrapper), ILProtector, MaxToCode<!-- /dotnet-string-evidence --> |

The second row is the one to read before pointing `disrobe` at a real protected assembly from the products listed there. Each decoder there is written from the protector's published algorithm and is graded by encrypting a known plaintext with that algorithm and asserting the decoder returns it. That is evidence the decoder implements the algorithm we believe the protector uses. It is not evidence that the shipping product uses it, and it does not cover per-build variation those products may carry. They are all commercial, and none has an artifact that is both benign and licensed for redistribution here, so no sample is committed to close the gap.

`crates/disrobe-pass-dotnet/src/protectors.rs` carries this split as `Protector::string_evidence`, and the tables above are regenerated from it. `cargo run -p xtask -- regen --check` fails if a family claims a committed sample the tree does not carry, or claims one whose `MANIFEST.toml` does not record the tool that produced it, or sits in the modelled row without being published there.

## Limits

Genuine walls (the key or the original code is not in the static artifact):

- **Themida / .NET wrapper**: native VM bodies are outside the current recovery scope; `disrobe` does not ship a native-VM devirtualizer.
- **ArmDot**: detected and reported, but no static devirtualizer ships.
- **ILProtector / MaxToCode native-keyed configurations**: when the per-method key is computed inside the native stub, the original CIL is not statically present.
- **Obfuscar renames**: the rename itself embeds no in-PE name map, so original identifier names stay walled behind the out-of-band Mapping.txt.

Commercial protector findings are reported with the recovery wall when the static artifact lacks the needed key or handler stream.
