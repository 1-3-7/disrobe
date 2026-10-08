# Anti-analysis defeat

`disrobe` analyzes samples statically by default. It recognizes obfuscation and anti-analysis patterns, recovers the available code and data, and reports missing runtime keys or unsupported transformations.

## Signature defeat

Identification never trusts a single magic byte. A zeroed or flipped magic, renamed `UPX0`/`UPX1` sections, or a corrupt `UPX!` marker is re-identified from internal self-consistency:

- **PE** through `e_lfanew` to the COFF and optional headers.
- **ELF / Mach-O** by header offsets that close against the file length.
- **ZIP** by its end-of-central-directory anchor.
- **DEX** by section-offset consistency.
- **Classfile** by a constant-pool walk.
- **wasm** by the LEB section stream.

A real UPX executable with a flipped `MZ` and renamed sections still unpacks byte-identically, because the structural `PackHeader` (method id, self-consistent compressed and uncompressed lengths, plausible version) is the signal a scrambler cannot remove without breaking the stub's own ability to self-extract.

## Code-signing verification

Malware often ships with a broken, expired, self-signed, or mismatched Authenticode signature to look trustworthy at a glance. For a signed PE, `disrobe native identify` verifies the signature end to end rather than trusting its presence: it recomputes the Authenticode hash and compares it to the claimed digest, walks the PKCS#7/CMS certificate chain to an embedded bundle of trusted code-signing roots, requires the code-signing extended key usage on the leaf, and cryptographically verifies any RFC 3161 timestamp before letting it extend validity. The result is a single verdict (Valid, HashMismatch, Expired, SelfSigned, UntrustedChain, WrongKeyUsage, and the rest), so a tampered `.text`, a forged timestamp, or a chain that does not reach a trusted root is surfaced instead of silently accepted. The [native guide](./languages/native.md) lists the signed-fixture and `osslsigncode` cross-checks behind it.

## String and data encryption

| Scheme | What `disrobe` does |
|---|---|
| Single-byte XOR stack strings | Recovers them with English-likeness key detection, on native via the in-house x86 emulator driving each decoder-shaped function. |
| Per-family keyed strings | Mirai, Dridex, and Trickbot keyed-string schemes decoded from their known transforms. |
| JVM string encryption | Emulates the in-class `decrypt(String)` / `decrypt(int, String)` method over the encrypted constants, running `<clinit>` for a static key or constructing the receiver for an instance key. |
| .NET constant decryption | ConfuserEx2 constants reversed on a real committed sample by emulating the in-assembly decryptor. |
| JS string-array rotation | The rotated string array is rebuilt and call sites inlined. |
| Python `exec`/`eval`/`compile` payloads | Unwrapped through base64/85/16/32 and zlib/lzma decode chains. |

Recovery stops when a required key exists only in a system property, environment variable, clock value, random source, or runtime table.

## Control-flow obfuscation

- **BlackObfuscator DEX flattening** is recognized: the `String.hashCode()`-keyed dispatcher and its `const-string` block names are used to annotate the recovered block order. The flattened method body remains in the emitted source.
- **OLLVM-style control-flow flattening** is deflattened on native, and the result is reported as a cover rather than as an equivalence. `disrobe` enumerates every state the dispatcher can select out of the sample's own compare tree or jump table, resolves the state transition out of each case region by value-set analysis over the state variable, and reports which states the recovered program reaches. A state it cannot reach stays in the denominator and carries a named reason. The `deobf.json` sidecar publishes the whole cover: the state list, the recovered state-to-state edge set, the case regions with their block spans, and one reason per uncovered state. Its `fully_recovered` flag is true only when all three of these hold: every dispatcher state is reached, no reached state has an unresolved transition, and the recovered edge set passes its consistency check. It is not a claim that the recovered program and the flattened one agree on every input. **Bogus control flow and instruction substitution** are reversed on the same path.
- **Proven-dead conditional arms** are folded on the AArch64 `native decompile` path by a symbolic devirtualizer that runs before structuring (on by default, disabled with `--no-devirt`). The fold is transactional: on any proof miss or budget exhaustion it reverts to the original function, so it replaces a construct only with a proven-equivalent one and adds no edges.
- **Obfuscator-planted out-of-range exception entries** that poison the JVM control-flow graph are dropped before structuring.
- **Flattened JS dispatchers** are collapsed back to structured control flow.

## Anti-disassembly and MBA

The JVM, Dalvik, and CIL decoders tolerate broken `StackMapTable`, fake exception ranges, and illegal-but-verifiable bytecode. On native, jump-into-the-middle desync, overlapping instructions, and opaque predicates are resolved in-tree. A mixed-boolean-arithmetic simplifier, wired through the JS and WebAssembly decoders as well, collapses MBA expressions back to their algebraic form through a layered stack: linear signature solving, nonlinear reduction modulo the null-polynomial ideal, e-graph equality saturation over proven ring identities, bounded enumerative synthesis for opaque leaves, and permutation-polynomial inversion. Each layer is sound or abstains, and a rewrite is emitted only after equivalence is proven over the full bitvector domain, so an expression the stack cannot prove is left untouched rather than approximated.

Indirect dispatch is resolved before the SMT tier is ever consulted. A strided-interval value-set analysis reads the masked, compare-guarded, or position-independent index bound off the path constraints and enumerates the jump table to a concrete target set that over-approximates, and usually equals, the reachable targets. It abstains when the table is writable or the index is unbounded, and defers to the solver only for a disequality residual, rather than narrowing past what it can justify. The over-approximation property is unit-tested and graded against a real gcc-compiled switch; it is not proved for every input. The value-set tier carries no solver dependency and compiles without one.

Every SMT verdict the simplifier and the devirtualizer depend on is independently checked before it is trusted. A SAT verdict is re-evaluated against the model the solver returned; an UNSAT verdict is reconfirmed by BDD bit-blasting, or, for the multiply-heavy opaque predicates the bit-blaster cannot settle, by a finite-difference polynomial certificate. A verdict that fails its own check, or a solver that panics or exhausts its budget, degrades to abstain, so a solver bug the independent check catches costs a recovery rather than producing a wrong answer. The external differential runs against pinned Z3 4.16.0 in CI and includes a seeded wrong rewrite as its control. The same harness supports Bitwuzla for local runs, but CI does not provision it. A defect shared by both the solver and its checker is outside what the differential can rule out.

## Bytecode virtualization

| Target | Status |
|---|---|
| **Lua (IronBrew2 2.7.0)** | Devirtualized in standard and MAX mode, graded by a real-`lua` execution differential. |
| **Native generic VM** | `disrobe native devirt` locates the interpreter, fingerprints each handler's micro-op behaviorally through the in-tree x86 emulator, and lifts to a re-executable IR plus pseudo-code, validated end-to-end on a self-authored Tigress-shape VM (the recovered IR re-executes byte-identically from machine code alone). |
| **VMProtect / Themida / Enigma front-ends** | Detection and structural analysis based on published format research. Recovery of a machine-keyed handler stream requires its key. |

## Overlay inflation

The PE overlay carve computes the true end of the executable image and isolates any trailing archive (gzip, xz, zstd, bzip2, tar, 7z, cab, rar) into its own segment, so padding cannot mask an appended payload.

## Symbol stripping

ProGuard/R8 mappings are replayed into `name-restoration.json` with overload matching; the emitted Java names are unchanged. Go type and stdlib names are recovered from surviving `pclntab`/`moduledata` on stripped binaries, Rust/C++/Swift/Itanium symbols are demangled, and structure is recovered from DWARF. garble's hashed user names remain unresolved without the required naming information; the report retains the structure and metadata that can be recovered.

## What grades each capability

The table links each capability to its compiler, runtime, verifier, or repository test. Partial and Detect-only rows identify the remaining recovery limits.

| Capability | What it does | Grading oracle |
|---|---|---|
| Opaque-predicate fold | Folds OLLVM bogus-control-flow always-taken / always-dead branches to their constant outcome | `crates/disrobe-pass-native/tests/lifting/ollvm_passes.rs` (`OpaqueResult::AlwaysTaken`, real `classify_fla.bin` and self-authored predicate) |
| Control-flow-flattening deflatten | Enumerates every state an OLLVM-flattened dispatcher can select, resolves the transition out of each case region, and places the reachable ones as a direct-edge program. Each state it does not reach is reported with a named reason instead of being dropped | `crates/disrobe-pass-native/tests/lifting/cff_dispatcher_cover.rs`. Cover is <!-- m:native_cff_cover_states -->9<!-- /m --> of the <!-- m:native_cff_dispatcher_states -->9<!-- /m --> dispatcher states across the two committed OLLVM `*_fla.bin` functions, with each denominator read back out of that sample's own compare tree rather than typed into the test. Separately a bounded `stub_emu` differential runs the flattened bytes and the re-emitted recovered bytes on 15 arguments per function and compares the return value against `corpus/native/ollvm/probe_src.c`, which is 60 executions under a 200000-step and 16 KiB-stack budget. A seeded missing state and a seeded wrong edge each turn one of those gates red |
| Verified MBA simplify | Collapses mixed-boolean-arithmetic back to algebraic form through the layered simplifier described above, then proves equivalence over the full bitvector domain before emitting | The acceptance gate records a proof at the expression's actual width through exhaustive enumeration where the domain is runnable, exact linear-column identity, BDD bit-blasting, or a finite-difference polynomial identity. A candidate is emitted only with one of those proven verdicts; otherwise the input is left untouched |
| OLLVM substitution undo | Lifts substituted arithmetic sequences (including shift-encoded carries and `movzx`/`xchg`-loaded narrow operands) back to the original operation, proven minimal | `ollvm_passes.rs` (`undo_ollvm_substitution`, asserts `changed && proven`, `simplified_nodes < original_nodes`) |
| Jump-table + PIC switch recovery | Resolves register-indirect dispatch and position-independent switch tables to concrete case-to-target lists | `disrobe-pass-native` deobf, graded by stub-emulator dispatch equivalence with clobbered-base and out-of-image counter-tests |
| Stack-string reconstruction | Drives each decoder-shaped function through the in-house x86 emulator to recover plaintext that only exists after the decoder runs | `crates/disrobe-pass-native/tests/oracles/stack_string_oracle.rs` (gcc-compiled object, `stub_emu` CPU memory state) |
| ABI / calling-convention inference | Infers calling convention, argument count, and return value from liveness on stripped code | `crates/disrobe-pass-native/tests/oracles/abi_inference_oracle.rs` (real clang-compiled prototypes, graded vs the source prototype) |
| Static type recovery | Recovers per-slot integer width and signedness from instruction semantics, splits a reused stack slot into distinct objects through region-typed memory-SSA and live-range analysis, and reconstructs struct, array, and union shape from access paths. Types resolved from a known library or OS prototype propagate backward into the caller's locals with `library!function` provenance; a slot with no sign signal, or an unresolved or conflicting call target, is reported unknown rather than guessed. `native decompile` emits the result as a `types.json` sidecar | `crates/disrobe-typerec` graded against an unstripped sibling's DWARF on an O0 corpus: width and struct field offset/width recall 1.0, live-range splitting lifts signedness recall from 0.25 to 1.0 on slot-reuse cases, with mutation checks that reject seeded-wrong widths, signs, offsets, and merged or invented fields |
| Solver-free indirect-dispatch resolution | A strided-interval value-set analysis resolves masked, compare-guarded, and position-independent indirect jumps to a concrete target set that over-approximates the reachable targets, usually exactly. It abstains, or defers to the SMT tier on a disequality residual, rather than narrowing past what it can justify | `disrobe-mba` jump-table VSA, unit-tested for the over-approximation property and graded against a real gcc-compiled switch (`crates/disrobe-mba/tests/jumptable_compiler_oracle.rs`, `crates/disrobe-mba/src/jumptable/vsa.rs`) |
| Copy-prop + branch-fold cleanup | Register copy-propagation and dead-store elimination over junk-shuffle blocks | `crates/disrobe-pass-native/tests/oracles/copyprop_oracle.rs` (concrete re-execution, live register equal before and after across seeds) |
| Path-sensitive dead-code removal | Drops blocks unreachable under the resolved predicate constraints | `disrobe-pass-native` `deobf/pathsense.rs`, applied only on a proven path constraint |
| Anti-disasm tolerance | Resolves jump-into-the-middle desync, overlapping instructions, and junk bytes; the JVM/Dalvik/CIL decoders tolerate broken `StackMapTable` and fake exception ranges | Native desync is graded on authored byte sequences (`crates/disrobe-pass-native/src/desync.rs` unit tests, `tests/lifting/desync_*.rs`); no real obfuscator output exercises it yet. The bytecode decoders are graded on malformed-bytecode fixtures |
| Runtime-check neutralisation | Plans same-length patches for debugger, PEB, timing, trap, and hypervisor checks, applied only with consent | Execution of self-authored gcc-compiled programs: armed builds print `debugged`, neutralised copies print `clean`, the control plans nothing, and a tampered plan is refused (`tests/oracles/anti_runtime_oracle.rs`) |
| Emulated anti-analysis answers | Serves pinned `rdtsc`, `cpuid`, timer, debugger-API, and PEB answers, dispatches vectored handlers, and runs TLS callbacks inside the stub emulator | A guarded authored stub unpacks to its original bytes and names every check it passed; inverted guards keep it from the entry point (`tests/packers/anti_guarded_stub.rs`) |
| Real OLLVM fold | Recovers pseudo-C for each function of the real ollvm 17 `bcf`, `sub`, and `split` ELFs in `corpus/native/ollvm/real/`, or refuses it with a named reason | The recovered C is compiled with gcc and swept over 25 inputs against the authored source, and a fully recovered file must print what the original program prints. Four of the nine functions recover: `sub` (`classify`, `sum_to` from `probe_src.c`; `classify` from the obfush sample) and `split` (`classify` from `probe_src.c`). Every `bcf` function and the two remaining `split` functions are refused by name. The recovered set is pinned, and a reference that returns one more than the source must fail the sweep (`tests/lifting/ollvm_real_fold.rs`). No flattened (`fla`) ELF from the real tool is committed yet |
| noreturn propagation | Propagates non-returning calls so the disassembler stops decoding junk past a terminal call | `disrobe-pass-native` flow analysis on the disassembled call graph |
| Generic VM devirt | Locates the interpreter, behaviorally fingerprints each handler through the x86 emulator, and lifts to re-executable IR plus pseudo-code | `crates/disrobe-pass-native/tests/oracles/vm_devirt_oracle.rs` (clang-compiled synthetic VM, recovered IR re-executes byte-identically from machine code alone); Lua IronBrew2 2.7.0 graded by a real-`lua` execution differential |
| Source-to-sink taint tracking | Tracks values from configured source calls to sink calls through register, stack, and inter-procedural propagation over the normalized IR | On NIST SARD Juliet v1.3, the native path detects 93 of 190 labeled CWE-78 flows (48.9%) with gcc 16.2.0 `-O2`, and 12 of 190 (6.3%) with `-O0`. Both runs produce zero false positives. Detection across more than one call remains 0 of 15 at either optimization level. The grader uses Juliet's `manifest.xml` and `Flow Variant` headers. Wasm, JVM, Dalvik and CIL inputs reach the same engine; these figures cover native input only |

## Runtime anti-debug and anti-VM checks

`disrobe behavior` and `disrobe capabilities` surface anti-debug, anti-VM, anti-sandbox, and timing checks, mapped to MITRE ATT&CK and MBC, with a confidence grade per technique. The core scan also names the instruction-level checks it can anchor to an address: a `PEB.BeingDebugged` or `PEB.NtGlobalFlag` read through `fs:[0x30]`/`gs:[0x60]`, an `int 2d` trap, and the anti-dump family (a `PEB.Ldr` `SizeOfImage` overwrite, a write to the mapped PE header, and `VirtualProtect`, `NtProtectVirtualMemory` or `ZwUnmapViewOfSection` aimed at the image header). A packer marker is reported as overcome only when an unpack pass ran in the same chain and produced a PE, ELF, or Mach-O layer; otherwise the finding names the missing pass.

### Inside the stub emulator

The x86 stub emulator that runs packer stubs answers each runtime check with a pinned "not debugged" value, so a guarded stub proceeds deterministically instead of halting. Every answer is recorded as a named, neutralised check anchored to the instruction or call site that asked, so nothing is served silently:

| Check | What the emulator answers |
|---|---|
| `rdtsc`, `rdtscp` | A monotonic counter that starts at `0x1_0000_0000` and advances `0x40` per read |
| `cpuid` | A GenuineIntel vendor, leaf 1 with the hypervisor bit (ECX bit 31) clear, and zeros for the `0x4000_0000` hypervisor leaves |
| `IsDebuggerPresent`, `CheckRemoteDebuggerPresent` | FALSE |
| `NtQueryInformationProcess` | `ProcessDebugPort` 0, `ProcessDebugObjectHandle` `STATUS_PORT_NOT_SET`, `ProcessDebugFlags` 1 |
| `NtSetInformationThread(ThreadHideFromDebugger)` | Success, with no effect |
| `OutputDebugStringA/W` | Swallowed |
| `GetTickCount`, `GetTickCount64`, `timeGetTime`, `QueryPerformanceCounter` | Pinned counters that advance a fixed step per call |
| PEB `BeingDebugged`, `NtGlobalFlag`, process heap `Flags` and `ForceFlags` | The values of an undebugged process; each read is reported at its instruction |
| `AddVectoredExceptionHandler` | Registers the handler; a fault or `int 2d`/`int3`/`icebp` trap dispatches vectored handlers before the SEH chain |
| TLS callbacks (PE32 and PE32+) | Run before the entry point with `DLL_PROCESS_ATTACH` |

The bounds stay in force: at most 16 vectored handlers and a vectored nesting depth of 16, at most 16 TLS callbacks sharing one eighth of the step budget, at most 8 watched PEB and heap fields, and at most 256 recorded checks per run, with the overflow counted rather than stored. A `cpuid` or `rdtsc` loop ends at the step cap. A self-authored packer-style stub whose decrypt loop is guarded by IsDebuggerPresent, the PEB and heap flags, an `rdtsc` delta, the `cpuid` hypervisor bit, `NtQueryInformationProcess`, a `GetTickCount` delta, a vectored handler around `int 2d`, and a TLS callback unpacks to its original bytes under the emulator, and inverting any guard keeps it from reaching the entry point (`crates/disrobe-pass-native/tests/packers/anti_guarded_stub.rs`).

### Opt-in neutralisation patches

`disrobe native decompile --neutralize ask|apply|skip` turns the runtime checks it finds in a PE into a patch plan the defender can accept or decline. Each patch names its technique, the instruction address and pattern it anchors to, the file offset and length, the original and replacement bytes, a risk note naming what could break, and a stable id. `ask` shows each patch and reads `y`, `n`, `a` (all remaining) or `q` (none) from stdin; it is the default when stdin is a terminal. `skip` writes the plan and report and applies nothing. Without the flag, a run whose stdin is not a terminal skips: it applies nothing and writes no plan, so scripted runs never patch. `apply` accepts every patch. The input file is never modified: accepted patches go to `<stem>.neutralized.<ext>` in the output directory, beside `neutralization.json`, which lists the plan and every applied, declined, and skipped patch. Before writing a patch, `disrobe` checks that the original bytes at its offset still match and refuses the whole plan if any differ. A declined patch leaves its technique reported as detected.

The plan covers `IsDebuggerPresent` and `CheckRemoteDebuggerPresent` call results, PEB `BeingDebugged` and `NtGlobalFlag` reads, `NtQueryInformationProcess` debug-class queries, `rdtsc`, `GetTickCount` and `QueryPerformanceCounter` delta compares, `int 2d` and `icebp` traps, and `cpuid` hypervisor-bit tests. Each replacement has exactly the length of the instruction it replaces. A vectored-handler control flow or a TLS callback is reported as a named refusal and never patched, because removing it changes what the program does rather than what it observes.

The plan is graded by execution on self-authored C programs in `corpus/native/anti-analysis/runtime/`, one per check, compiled with gcc at test time. Where a program can trip its own check without a debugger (an `-DARMED` build writes the PEB flag, zeroes the timing threshold, or sleeps between reads), the armed build prints `debugged`, and its neutralised copy prints `clean`. The benign control, which uses timers and `GetModuleFileNameA` without a decision, gets an empty plan. A plan whose original bytes were altered is refused before any write, and a plan made for one build is refused on another (`crates/disrobe-pass-native/tests/oracles/anti_runtime_oracle.rs`). `disrobe` never executes the input on its default path; the programs executed by these tests are the authored fixtures and their patched copies.

## Runtime-keyed protection

With a matching `pyarmor_runtime`, the static path supports the variants listed in the Python guide. The 72-of-72 structural result covers the manifest's v8/v9 default-trial wrappers: each decodes to a complete header-anchored root `CodeObject`. That measurement does not grade source recovery, original `.pyc` identity, or semantic equivalence. Some v6/v7 variants require the opt-in, sandboxed dynamic-capture path. For ionCube, SourceGuardian, Zend Guard, ILProtector, and MaxToCode, a required key may reside in a native loader or live process outside the artifact. Disrobe reports the missing key and leaves that content unrecovered.

See the [forensics and malware-safety posture](./forensics-safety.md) for how the default static path stays safe on untrusted input.
