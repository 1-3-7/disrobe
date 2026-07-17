# Anti-analysis defeat

**disrobe** is a static, deterministic analyzer that never runs the sample on the default path. It recognizes the standard anti-static-analysis arsenal and recovers what is statically recoverable, stating a wall where the data is genuinely absent rather than fabricating past it.

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

| Scheme | What **disrobe** does |
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

Indirect dispatch is resolved before the SMT tier is ever consulted. A strided-interval value-set analysis reads the masked, compare-guarded, or position-independent index bound off the path constraints and enumerates the jump table to a concrete target set that is a sound superset of, and usually exactly, the reachable targets. It never drops a live target, abstains when the table is writable or the index is unbounded, and defers to the solver only for a disequality residual; the value-set tier carries no solver dependency and compiles without one.

Every SMT verdict the simplifier and the devirtualizer depend on is independently checked before it is trusted. A SAT verdict is re-evaluated against the model the solver returned; an UNSAT verdict is reconfirmed by BDD bit-blasting, or, for the multiply-heavy opaque predicates the bit-blaster cannot settle, by a finite-difference polynomial certificate. A verdict that fails its own check, or a solver that panics or exhausts its budget, degrades to abstain, so a solver bug can cost a recovery but never turn one into a wrong answer.

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

## Runtime-keyed protection

PyArmor v6-v9 static decryption succeeds when the `pyarmor_runtime` is supplied. With no runtime, the verdict routes to the dynamic-capture path (opt-in, sandboxed) rather than emitting fabricated plaintext. ionCube, SourceGuardian, Zend Guard, ILProtector, and MaxToCode derive their key in a native loader or live process absent from the artifact, so they are walled and reported absent.

See the [forensics and malware-safety posture](./forensics-safety.md) for how the default static path stays safe on untrusted input.
