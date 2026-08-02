# Anti-analysis defeat

`disrobe` is a static, deterministic analyzer that never runs the sample on the default path. It recognizes the standard anti-static-analysis arsenal and recovers what is statically recoverable, stating a wall where the data is genuinely absent rather than fabricating past it.

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

Runtime-keyed schemes (a key from a system property, the environment, the clock, a secure random, or a live cross-class table) are flagged as walls, not guessed.

## Control-flow obfuscation

- **BlackObfuscator DEX flattening** is deflattened: the `String.hashCode()`-keyed dispatcher is recognized, each block's `const-string` name is matched to its switch case, and the original linear block order is recovered and annotated in the output.
- **OLLVM-style control-flow flattening, bogus control flow, and instruction substitution** are reversed on native.
- **Proven-dead conditional arms** are folded on the AArch64 `native decompile` path by a symbolic devirtualizer that runs before structuring (on by default, disabled with `--no-devirt`). The fold is transactional: on any proof miss or budget exhaustion it reverts to the original function, so it only ever replaces a construct with a proven-equivalent one and never invents an edge.
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
| **VMProtect / Themida / Enigma front-ends** | Extended from published RE write-ups, not a running commercial sample. A per-machine-keyed handler stream is the residual wall. |

## Overlay inflation

The PE overlay carve computes the true end of the executable image and isolates any trailing archive (gzip, xz, zstd, bzip2, tar, 7z, cab, rar) into its own segment, so padding cannot mask an appended payload.

## Symbol stripping

ProGuard/R8 names are restored from `mapping.txt` (overload-correct), Go type and stdlib names are recovered from `pclntab`/`moduledata` on stripped binaries, Rust/C++/Swift/Itanium symbols are demangled, and structure is recovered from DWARF. garble name-hashing (HMAC-SHA256 over an absent build seed) is a wall, but structure, types, and control flow recover regardless.

## What grades each capability

An oracle that can reject a wrong answer (a compiler, a runtime, a verifier, exhaustive enumeration, or concrete re-execution) grades most rows below. The anti-disasm, noreturn, and path-sensitive rows state an in-tree gate instead. Partial and Detect-only rows state their residual.

| Capability | What it does | Grading oracle |
|---|---|---|
| Opaque-predicate fold | Folds OLLVM bogus-control-flow always-taken / always-dead branches to their constant outcome | `crates/disrobe-pass-native/tests/ollvm_passes.rs` (`OpaqueResult::AlwaysTaken`, real `classify_fla.bin` and self-authored predicate) |
| Control-flow-flattening deflatten | Recovers the dispatcher and original linear block order from an OLLVM-flattened function | `ollvm_passes.rs` (`CffUnflattenReport`, recovered-block count vs the self-authored and real `*_fla.bin` corpus) |
| Verified MBA simplify | Collapses mixed-boolean-arithmetic back to algebraic form through the layered simplifier described above, then proves equivalence over the full bitvector domain before emitting | The acceptance gate records a proof at the expression's actual width through exhaustive enumeration where the domain is runnable, exact linear-column identity, BDD bit-blasting, or a finite-difference polynomial identity. A candidate is emitted only with one of those proven verdicts; otherwise the input is left untouched |
| OLLVM substitution undo | Lifts substituted arithmetic sequences (including shift-encoded carries and `movzx`/`xchg`-loaded narrow operands) back to the original operation, proven minimal | `ollvm_passes.rs` (`undo_ollvm_substitution`, asserts `changed && proven`, `simplified_nodes < original_nodes`) |
| Jump-table + PIC switch recovery | Resolves register-indirect dispatch and position-independent switch tables to concrete case-to-target lists | `disrobe-pass-native` deobf, graded by stub-emulator dispatch equivalence with clobbered-base and out-of-image counter-tests |
| Stack-string reconstruction | Drives each decoder-shaped function through the in-house x86 emulator to recover plaintext that only exists after the decoder runs | `crates/disrobe-pass-native/tests/stack_string_oracle.rs` (gcc-compiled object, `stub_emu` CPU memory state) |
| ABI / calling-convention inference | Infers calling convention, argument count, and return value from liveness on stripped code | `crates/disrobe-pass-native/tests/abi_inference_oracle.rs` (real clang-compiled prototypes, graded vs the source prototype) |
| Static type recovery | Recovers per-slot integer width and signedness from instruction semantics, splits a reused stack slot into distinct objects through region-typed memory-SSA and live-range analysis, and reconstructs struct, array, and union shape from access paths. Types resolved from a known library or OS prototype propagate backward into the caller's locals with `library!function` provenance; a slot with no sign signal, or an unresolved or conflicting call target, is reported unknown rather than guessed. `native decompile` emits the result as a `types.json` sidecar | `crates/disrobe-typerec` graded against an unstripped sibling's DWARF on an O0 corpus: width and struct field offset/width recall 1.0, live-range splitting lifts signedness recall from 0.25 to 1.0 on slot-reuse cases, with mutation checks that reject seeded-wrong widths, signs, offsets, and merged or invented fields |
| Solver-free indirect-dispatch resolution | A strided-interval value-set analysis resolves masked, compare-guarded, and position-independent indirect jumps to a concrete target set that over-approximates the reachable targets, usually exactly. It abstains, or defers to the SMT tier on a disequality residual, rather than narrowing past what it can justify | `disrobe-mba` jump-table VSA, unit-tested for the over-approximation property and graded against a real gcc-compiled switch (`crates/disrobe-mba/tests/jumptable_compiler_oracle.rs`, `crates/disrobe-mba/src/jumptable/vsa.rs`) |
| Copy-prop + branch-fold cleanup | Register copy-propagation and dead-store elimination over junk-shuffle blocks | `crates/disrobe-pass-native/tests/copyprop_oracle.rs` (concrete re-execution, live register equal before and after across seeds) |
| Path-sensitive dead-code removal | Drops blocks unreachable under the resolved predicate constraints | `disrobe-pass-native` `deobf/pathsense.rs`, applied only on a proven path constraint |
| Anti-disasm tolerance | Resolves jump-into-the-middle desync, overlapping instructions, and junk bytes; the JVM/Dalvik/CIL decoders tolerate broken `StackMapTable` and fake exception ranges | in-tree, exercised on real obfuscator output and malformed-bytecode fixtures |
| noreturn propagation | Propagates non-returning calls so the disassembler stops decoding junk past a terminal call | `disrobe-pass-native` flow analysis on the disassembled call graph |
| Generic VM devirt | Locates the interpreter, behaviorally fingerprints each handler through the x86 emulator, and lifts to re-executable IR plus pseudo-code | `crates/disrobe-pass-native/tests/vm_devirt_oracle.rs` (clang-compiled synthetic VM, recovered IR re-executes byte-identically from machine code alone); Lua IronBrew2 2.7.0 graded by a real-`lua` execution differential |

## Warning the analyst before anything runs

`disrobe` also flags the evasion a sample attempts. `disrobe behavior` and `disrobe capabilities` surface al-khaser / Pafish-class anti-debug, anti-VM, anti-sandbox, and timing checks, mapped to MITRE ATT&CK and MBC, with a confidence grade per technique. This is detection only: `disrobe` never executes the sample on its default path and never implements any of these techniques itself.

## Runtime-keyed protection

With a matching `pyarmor_runtime`, the static path is used where supported. Its published 72-of-72 structural result is limited to manifest-named v8/v9 default-trial wrappers that decode to complete header-anchored root `CodeObject` values. It does not establish source recovery, original `.pyc` identity, execution, or semantic equivalence. v6/v7 may need the opt-in, sandboxed dynamic-capture path rather than emitting fabricated plaintext. ionCube, SourceGuardian, Zend Guard, ILProtector, and MaxToCode derive their key in a native loader or live process absent from the artifact, so they are walled and reported absent.

See the [forensics and malware-safety posture](./forensics-safety.md) for how the default static path stays safe on untrusted input.
