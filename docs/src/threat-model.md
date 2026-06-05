# Threat model

This page is the explicit trust-boundary analysis for **disrobe**. It states what the tool treats as untrusted, where the boundaries are drawn, what each boundary defends against, and what is deliberately out of scope. It complements the operational [Security policy](./security.md) and the [Forensics and malware-safety posture](./forensics-safety.md): the security policy says *how to report* a problem and *what is in scope for a report*; this page says *what the design assumes an attacker can do and where the walls are*.

The single load-bearing assumption is this: **the input is hostile.** disrobe exists to parse protector output, packed executables, obfuscated bytecode, and exotic encoders. Every byte of every sample is treated as attacker-controlled. The analyst running disrobe is trusted; the artifact they point it at is not.

## Trust boundaries at a glance

```text
   ┌─────────────────────────── trusted ───────────────────────────┐
   │  analyst, host filesystem, disrobe binary, configuration       │
   └───────────────▲───────────────────────────────▲───────────────┘
                   │ B1                             │ B2
   ┌───────────────┴───────────────┐   ┌────────────┴───────────────┐
   │  untrusted sample bytes       │   │  untrusted .dr envelope     │
   │  (file / bytes_b64 / stdin)   │   │  (cache hit, peer-supplied) │
   └───────────────────────────────┘   └────────────────────────────┘
                   │ B3                             │ B4
   ┌───────────────┴───────────────┐   ┌────────────┴───────────────┐
   │  network surface              │   │  subprocess backends +      │
   │  (serve: HTTP / gRPC / LSP)   │   │  optional sample execution  │
   └───────────────────────────────┘   └────────────────────────────┘
```

There are four boundaries. Boundary 1 (sample bytes) and Boundary 2 (envelope bytes) are always present. Boundary 3 (network) is present only when `disrobe serve` is running. Boundary 4 (subprocess and dynamic execution) is present only when an explicit opt-in flag is passed.

## Boundary 1 - untrusted sample bytes

**Trusted side:** the disrobe process, the host, the analyst's intent.
**Untrusted side:** the sample. It arrives as a filesystem path, a `bytes_b64` blob over the daemon, or stdin. The parser must assume every length field, offset, opcode, and nested container is chosen by an adversary to break it.

**What this boundary defends against, and how:**

| Threat | Defense | Where |
|---|---|---|
| Memory-corruption via the parser | Pure-Rust, `#![forbid(unsafe_code)]` workspace-wide; the only opt-out is the two pyo3 C-interop crates, gated behind explicit features and never on the default path. | workspace lint config |
| Panic / abort on adversarial input | Any non-`Result::Err` failure on hostile bytes is a bug. Decoders return errors, they do not unwrap. | every `disrobe-pass-*` decoder |
| Decompression and zip bombs | Per-entry cap, aggregate cap, and an observed-ratio ceiling in the shared quota machinery. | `crates/disrobe-binfmt/src/quota.rs` |
| Path traversal (zip-slip and kin) | Every container extraction path routes through `sanitize_entry_path` and siblings before any write. | `crates/disrobe-binfmt/src/quota.rs` |
| Container-recursion bombs | Recursion-depth cap plus content-hash cycle detection in the chain runner (default depth 8). | chain runner |
| Malformed-length-field bombs | Length fields are validated against remaining buffer length before allocation; no length field is trusted to size an allocation. | binfmt + envelope decoder |

The envelope decoder and the container layer are the two most-exposed parsing surfaces and are fuzzed.

## Boundary 2 - untrusted `.dr` envelopes

The `.dr` envelope is content-addressed (BLAKE3-rooted, rkyv hot payload + postcard cold sidecar). A cache hit, a peer-supplied envelope, or a downstream stage all cross this boundary. An envelope is **not** trusted merely because it claims a hash.

**What this boundary defends against:**

- **Read-past-end.** The zero-copy rkyv access path is bounds-checked at decode; an envelope whose declared lengths exceed its actual bytes is rejected, not read past.
- **Integer overflow in length math.** Offset and length arithmetic is checked; an envelope cannot induce a wrapping add that yields an in-bounds-looking slice.
- **BLAKE3-mismatch acceptance.** The root hash is recomputed over the payload and compared; an envelope whose content does not match its claimed root is rejected. This is the property that makes `--no-cache` an *optimization* toggle and not a *correctness* toggle - a cache hit is provably the same bytes.

The decoder lives in `crates/disrobe-ir/src/envelope.rs` and is fuzzed against exactly these three attacks.

## Boundary 3 - the network surface (`disrobe serve`)

When the daemon runs, HTTP, gRPC, and LSP-over-stdio each cross a trust boundary. The governing rule is that **the server never opens a file based on a client-controlled string.**

- HTTP, gRPC, and the LSP `disrobe/analyze` method accept `bytes_b64` **only** - never a path. There is no client-reachable code path that turns a request field into a filesystem read.
- All request bodies reject unknown fields via `#[serde(deny_unknown_fields)]`, closing field-smuggling and forward-compat-confusion attacks.
- A non-loopback HTTP bind emits a `tracing::warn!` banner at startup, so an operator who exposes the daemon beyond localhost is told so explicitly.

The daemon is intended for localhost / trusted-network use; it is not an authenticated multi-tenant service, and exposing it publicly is an operator decision the warning banner flags.

## Boundary 4 - subprocess backends and optional sample execution

This is the boundary an analyst can choose to *not* cross at all. Two distinct sub-cases:

**Subprocess backends over the artifact (not the sample's logic).** Optional external tools - Ghidra, CFR, Vineflower, jadx, ILSpy, dnSpy, de4dot, Rizin - run as subprocesses over the *derived artifact*. They never execute the sample's own entry point. The exposure here is command-line construction: command lines are built from configuration and sometimes from user input, so command injection and argument smuggling are the in-scope threats, mitigated by constructing argument vectors directly rather than shelling out through a string.

**Dynamic execution of the sample.** A small number of paths *can* run adversarial code, and **none is on by default.** Each sits behind a named flag:

| Path | Gate | What runs |
|---|---|---|
| PyArmor v6/v7 dynamic-hook | `--allow-dynamic` | The obfuscated wrapper, in a watched subprocess, to capture marshal streams. Watchdog via `--dynamic-timeout` (default 60s). |
| PyArmor BCC native-body lift | `--allow-bcc` | Ghidra-headless over the native body - the analysis tool runs, not the sample's logic in-process. |

The default static paths (pickle symbolic VM, the v8 and v9-pro PyArmor peels) need no such gate: they parse and walk, they do not detonate. When dynamic execution is unavoidable, **run it inside a disposable, network-isolated sandbox** - disrobe gives you a watchdog and a captured-marshal manifest, but a dynamic hook is, by definition, executing attacker code.

## Non-execution stance (restated as an invariant)

The default-static stance is a *design invariant*, not a configuration default that can drift:

- disrobe does not unpickle. `disrobe pickle trace` walks the opcode stream **symbolically**, building the object graph without instantiating a single real object or resolving a single real global; `disrobe pickle safety` grades danger statically.
- disrobe does not call `__reduce__`, does not run a packed binary, does not invoke a sample's entry point on any default path.
- Any way to make a *default* path execute a sample is a vulnerability, in scope for the [Security policy](./security.md).

## Plugin and WASM isolation

Where disrobe loads analysis logic as data rather than as native code, that logic runs sandboxed: WASM-hosted analysis executes inside a `wasmparser`-validated, memory-bounded interpreter with no ambient filesystem or network capability, so a malicious or malformed module can consume bounded compute and nothing more. This keeps the extensibility surface from becoming a fresh native-code execution boundary.

## Supply chain

The integrity of the *binary the analyst runs* is its own boundary:

- **No untrusted bytecode in the public corpus.** The repository does not ship third-party copyrighted obfuscated bytecode; fixtures are either self-generated by `corpus/generate.{sh,ps1}` or referenced by BLAKE3 hash only. Every shipped fixture is pinned by hash in `corpus/native/packers/MANIFEST.toml` and sibling registries, and tests verify byte-identity before the parser ever sees the bytes.
- **Signed releases.** Release artifacts are signed with cosign keyless OIDC and minisign; every cosign signature is recorded in the Rekor public transparency log. Verification commands are in the [Security policy](./security.md).
- **Dependency hygiene.** `cargo deny` (advisories / bans / licenses / sources) runs on every push and weekly; `cargo audit` runs weekly. The clippy gate (`-D warnings`) is required for every commit on `main`.
- **History hygiene.** Branch protection on `main` requires approval, green CI, linear history, and no force-push or deletion; commit authorship uses the GitHub noreply form so personal email never enters history.

## Explicitly out of scope

The threat model deliberately does **not** defend against:

- **Decompilation-output correctness on adversarial bytecode.** disrobe will sometimes emit wrong source for hostile input; the round-trip metric exists to flag this honestly. A non-byte-perfect decompile is correctness work, not a security boundary.
- **Compute exhaustion via *legitimate* input.** Decompiling a 66 MiB Hermes bundle is genuinely expensive; a slow-but-bounded decompile of real input is not a vulnerability. (Adversarial *amplification* - a tiny input that forces unbounded work - *is* in scope, under Boundary 1.)
- **Vulnerabilities inside wrapped third-party tools.** Ghidra, jadx, CFR, and friends have their own security channels; we forward where we can identify the upstream.
- **Trusting the analyst.** disrobe assumes the operator is authorized and acting in good faith; it gates grey-zone protector behavior behind `--i-have-authorization` but does not, and cannot, adjudicate that authorization.

## Reporting

If you find a way to cross a boundary that this model claims is sealed - make a default path execute a sample, escape a container, accept a hash-mismatched envelope, or make the daemon read a file from a client string - that is a security issue. Report it privately, never as a public issue. See the [Security policy](./security.md).
