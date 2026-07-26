# Security policy

`disrobe` is a deobfuscator and decompiler suite. It parses adversarial binary input (protector output, packed PE, obfuscated bytecode, exotic encoders) and emits derived artifacts. Hardening the parsing surface is a primary concern.

## Supported versions

Security fixes ship on the `main` branch. Tagged releases (`v0.x.y`) snapshot known-good states. There is no LTS branch and no back-porting policy.

| Version  | Status        | Security fixes |
| -------- | ------------- | -------------- |
| `main`   | active        | yes (rolling)  |
| `0.10.x` | current minor | yes            |
| `< 0.10` | pre-release   | no             |

## Reporting a vulnerability

**Do not open a public issue for security reports.** Use GitHub's private security advisory channel:

<https://github.com/1-3-7/disrobe/security/advisories/new>

Include in the report:

- A description of the issue and its impact.
- A minimal reproducer (input bytes, command line, expected vs observed behavior).
- The `disrobe --version` output and the OS / arch.
- Whether you have a candidate fix.

We acknowledge reports within **72 hours**. The target for shipping a high-severity fix is **30 days**. Critical issues affecting parsing of untrusted input get same-week turnaround. We publish a GitHub Security Advisory and a CVE (where applicable) when the fix lands.

If you want to disclose publicly after the fix ships, we credit you in the advisory and in the release notes. Anonymous reports are welcome.

## In scope

The reporting channel covers any issue in the `disrobe` source tree that affects an instance running locally or in a CI:

- **Memory safety in the parsing surface.** `disrobe` is pure-Rust: `#![forbid(unsafe_code)]` is set on the parsing-surface crates, and the `unsafe` that exists is confined to interop boundaries. `crates/disrobe-pyarmor-cextract/` carries C-level pyo3 / libc interop behind explicit features, `crates/disrobe-wasm/` carries the WebAssembly C-ABI export shims, `crates/disrobe-ir/` has one audited memory-map, and the CLI install path has a single OS env-var call. Any panic / abort on adversarial input that is not a clean `Result::Err` is in scope. Any heap corruption is high severity.
- **Resource exhaustion on adversarial input.** Zip-bombs, decompression bombs, container-recursion bombs, malformed-length-field bombs. `disrobe`'s binfmt layer (`crates/disrobe-binfmt/src/quota.rs`) enforces per-entry and aggregate quotas; bypasses are in scope.
- **Path traversal.** zip-slip and equivalents on every container kind (zip, tar.{gz,bz2,xz,zst}, 7z, asar, cab, ar, deb, rpm, NSIS, InstallShield, Inno Setup, AppImage, Docker, OCI, Flatpak, Snap, squashfs, cramfs, ext4). Path-sanitisation lives in `crates/disrobe-binfmt/src/quota.rs::sanitize_entry_path` and sibling functions.
- **HTTP / gRPC server input handling.** `disrobe serve` (HTTP) and the gRPC surface accept `bytes_b64` only, never a filesystem path. Endpoints reject unknown JSON fields via `#[serde(deny_unknown_fields)]`. Any way to make the server read a file via a client-controlled string is high severity.
- **LSP-stdio input handling.** The `disrobe/analyze` LSP method also takes `bytes_b64` only with `deny_unknown_fields`. Same posture as HTTP.
- **Subprocess invocation.** `disrobe install`, `disrobe doctor --auto-install`, and backends that wrap external tools (CFR, Vineflower, jadx, ILSpy, dnSpy, de4dot, Ghidra, Rizin, ...) construct command lines from configuration and sometimes from user input. Command injection or argument smuggling is in scope.
- **`.dr` envelope handling.** `crates/disrobe-ir/src/envelope.rs` decodes a content-addressed binary format. Adversarial envelopes that cause read-past-end, integer overflow, or BLAKE3-mismatch acceptance are in scope.
- **Supply chain.** Tampering with our published binaries (when those land via `release.yml`) including signature-bypass, replay, cosign-bundle manipulation, or a forged build-provenance attestation.

## Out of scope

- **Decompilation output correctness on adversarial input.** `disrobe` sometimes produces wrong output on hostile bytecode; the round-trip metric exists to flag this. A decompile result that is not byte-perfect is not a security bug; it is correctness work. Open a normal issue or PR for these.
- **Compute exhaustion via legitimate input.** Decompiling a 66 MiB Hermes bundle is genuinely expensive. We optimise where reasonable, but a slow decompile is not a vulnerability.
- **Issues in third-party tools we wrap.** CFR, Vineflower, jadx, ILSpy, dnSpy, de4dot, Ghidra, Rizin, and friends each have their own security channels. We forward concerns where we can identify the upstream affected.
- **Repository operations outside the `disrobe` source tree.** GitHub platform issues, runner-image issues, and GitHub Actions issues go to GitHub.

## Hardening posture

- `#![forbid(unsafe_code)]` is set crate-by-crate across the parsing surface; the `unsafe` that exists sits at interop boundaries: `disrobe-pyarmor-cextract` (C-level pyo3 / libc interop), `disrobe-wasm` (WASM C-ABI export shims), an audited memory-map in `disrobe-ir`, and one OS env-var call in the CLI install path.
- Workspace clippy gate (`-D warnings -W unreachable_pub -W missing_debug_implementations -W unused`) is required for every commit on `main`.
- `cargo deny check` (advisories / bans / licenses / sources) runs on every push and weekly on a cron via `EmbarkStudios/cargo-deny-action@v2`.
- A dedicated `audit` job runs `cargo-deny check advisories` against the RustSec advisory database on the same triggers (every push to `main` and the weekly Monday 06:00 UTC cron).
- All container extractors share the quota machinery in `crates/disrobe-binfmt/src/quota.rs`: per-entry size cap, aggregate size cap, recursion-depth cap, zip-slip path sanitisation.
- `corpus/native/packers/MANIFEST.toml` and sibling registries pin every fixture by BLAKE3; tests verify byte-identity before exercising the parser.
- The HTTP / gRPC / LSP servers never read files from disk based on client input. Only `bytes_b64` is accepted; `#[serde(deny_unknown_fields)]` is enforced; non-loopback HTTP binds emit a `tracing::warn!` banner at startup.
- Every subprocess invocation in the attack surface table below routes its wait and capture through one shared primitive, `disrobe-core::subprocess`. If a caller-set timeout expires, the primitive kills and reaps the child. A caller-set byte cap truncates captured stdout/stderr instead of buffering unbounded output from a hostile or malfunctioning external tool. A pipe read error is treated the same as clean EOF, so the process's real exit code and the output already captured survive instead of being discarded as an indistinguishable timeout. Argv goes through `Command`'s own non-shell argument list, never a shell string, so a path or argument containing shell metacharacters reaches the child literally. The one exception is `mklink_junction`, which shells through `cmd.exe` on Windows and is tracked separately in that table.

## Fuzzing and panic-safety coverage

Test coverage against adversarial input has three distinct layers. They are not interchangeable. Naming them separately keeps a claim of "fuzzed" off a surface that has only the lighter layers.

1. **Continuous coverage-guided fuzzing** via `cargo-fuzz` / libFuzzer, defined in `fuzz/Cargo.toml`: `chain_driver.rs` and `chain_spec_parser.rs`. Both drive the chain-orchestration subsystem in `disrobe-core` (the `chain` feature), not the format parsers.
2. **Property-based tests** via `proptest`, six files: `crates/disrobe-bytes/tests/properties.rs`, `crates/disrobe-emit/tests/c_cc_oracle.rs`, `crates/disrobe-emit/tests/rust_roundtrip.rs`, `crates/disrobe-ir/tests/proptest_envelope.rs`, `crates/disrobe-llm-metadata/tests/selection_builder.rs`, `crates/disrobe-mba/tests/semantic_preservation.rs`. These cover byte-buffer primitives, the C/Rust emitters' round-trip properties, the `.dr` envelope decoder, LLM-metadata selection, and MBA semantic preservation. The inputs are generated structured values, not raw fuzzed bytes.
3. **Ad-hoc panic-safety unit tests.** A name-pattern grep (functions named `*_never_panics`, `no_panic`, `panic_safety`, `fuzz_decode_*`, plus files named `*resilience*`, `*adversarial*`, `fuzz_*`, `*malformed*`) turns up on the order of 55 files across the workspace; the exact count depends on where the pattern's boundary is drawn. Each feeds hand-picked or lightly randomized truncated/mutated/malformed bytes into a parser and asserts a clean `Err` rather than a panic. This is not property-based fuzzing (no shrinking, no corpus, no coverage feedback), but it is the widest-covering layer by file count and reaches most `disrobe-pass-*` crates, `disrobe-binfmt`, and `disrobe-core`.

**Known gap, stated plainly.** `disrobe-pass-py-deob`, `disrobe-pass-pyarmor`, `disrobe-pyarmor-cextract`, `disrobe-pyarmor-pytrace`, `disrobe-nir`, and `disrobe-nir-lift` have none of the three layers: no fuzz target, no proptest file, and no dedicated resilience/never-panics test file. `disrobe-pass-py-deob` and `disrobe-pass-pyarmor` each carry several scattered "rejects garbage/malformed bytes" assertions across their existing detector and unpack tests. Those assertions are not a one-off, but they are ad hoc coverage embedded in functional tests. They are not the dedicated-file treatment the rest of the pass crates get. These are major parsing surfaces: dozens of Python-obfuscator and PyArmor peelers, the native PyArmor C-extraction interop, and the cross-format IR lifters for JVM/Dalvik/CIL/AVM2/BEAM/Lua/Python/wasm. No broader "the parsing surface is fuzzed" claim elsewhere in the docs papers over this gap.

## Plugin trust model

Two crates implement `disrobe`'s WASM plugin substrate. Neither matches a "plugins run with full host privileges, unsandboxed" model. Analysis logic loaded as WASM is sandboxed by construction.

- **`disrobe-plugin-host`** (`crates/disrobe-plugin-host/src/lib.rs`) runs a raw core WASM module through `wasmtime` under three caps: a fuel budget (default 50,000,000, capped at 1,000,000,000), a wall-clock deadline (default 1s, capped at 30s, enforced by an epoch-interrupt watchdog thread), and a memory cap (default 16 MiB, capped at 256 MiB) enforced by a `ResourceLimiter`. If a module imports anything at all, `PluginHost::run` rejects it before instantiation: `first_import` denies the module and `Linker::define_unknown_imports_as_traps` backstops it. A module run through this path has no ambient filesystem, network, or host-function access. It can only transform the input bytes it is given and return output bytes, bounded by the caps above.
- **`disrobe-plugin-loader`** (`crates/disrobe-plugin-loader/src/lib.rs`, `manifest.rs`) verifies a WASM component against a `minisign` signature from a trusted key before it is even parsed as a component. It then walks the component's declared imports and rejects any import that a TOML manifest (`Manifest::grants`) does not explicitly grant. This is a capability allowlist, not a blanket trust grant. An unsigned, mis-signed, or over-capability-requesting component is rejected before it runs.

**What is not yet true, stated honestly.** The two crates are not wired to each other or to the CLI. Nothing in the workspace loads a signed, manifest-verified component from `disrobe-plugin-loader` and executes it through `disrobe-plugin-host`. The two operate on different WASM object kinds, core `Module` versus component-model `Component`, and no glue code between them exists yet. The WIT schema at `schemas/v0/wit/disrobe-plugin@0.1.0.wit` defines a `pass-descriptor` record carrying `id` and `version` fields intended for exactly this kind of provenance. No code path calls a plugin's `descriptor()` export, and no code path records a plugin's name and version into any `disrobe` output. There is no `wit-bindgen` / `bindgen!` usage anywhere in the workspace that would wire the WIT interface to real execution. Attaching a name/version field to either crate in isolation today would be cosmetic, since there is no execution path for it to travel through yet. This stays a disclosed gap rather than something bolted onto an unconnected crate.

**Editor integrations are a separate case.** The IDA / Ghidra / Binary Ninja / VS Code integrations under `editors/` (generated by `xtask plugins`) are not WASM plugins. They shell out to the real `disrobe` CLI binary as a subprocess from inside the host tool's own process, with the same privileges the analyst already has running that tool. They carry no additional trust boundary beyond "the analyst chose to install and run `disrobe`."

**Residual trust, stated plainly.** Resource sandboxing bounds compute, memory, and wall-clock time, and it denies ambient capability. It does not validate the correctness of a plugin's analysis output. A plugin that stays within its resource caps can still return incorrect or misleading bytes. Nothing downstream distinguishes in-house pass output from plugin output in provenance. Load plugins only from sources you trust for correctness, even though the sandbox bounds what a plugin can do to your machine.

## Attack surface inventory

The three tables below enumerate the surface by subsystem rather than one row per crate. Their contents come from reading the workspace, not from memory. CI cross-checks all three against the real crate tree, real `Command::new` call sites, and real `Cargo.toml` dependencies (`xtask attack-surface`, wired into `xtask regen --check`). A new pass crate, a new non-test subprocess call site, or a new crate linking `reqwest` / `axum` / `hyper` / `tonic` fails the build until the table is updated.

**Untrusted-input parsers (format / container / bytecode):**

| Family | Crates |
|---|---|
| Native executables and containers | `disrobe-binfmt` (PE/ELF/Mach-O; zip/tar/7z/cab/msi/nsis/deb/rpm/AppImage/... containers; quota + path-sanitisation), `disrobe-pass-native` (packers, protectors, disassembly), `disrobe-pass-nativelang` (Nim/Zig/Crystal/D), `disrobe-pass-webview` (Electron ASAR / Tauri / Wails frontend-asset carver from packed desktop binaries), `disrobe-sleigh` (Sleigh instruction decoder / p-code lifter for AArch64, ARM32/Thumb, MIPS32, RISC-V, and PowerPC over raw machine-code bytes), `disrobe-lift-x86` (x86-64 instruction decoder / p-code lifter over raw machine-code bytes via iced-x86), `disrobe-typerec` (integer width and signedness recovery over raw machine-code bytes via iced-x86, with DWARF ground-truth reading in its grading path) |
| .NET / CIL | `disrobe-pass-dotnet` |
| JVM / Android | `disrobe-pass-jvm`, `disrobe-nir-lift` (JVM/Dalvik/CIL/AVM2 bytecode lifters) |
| Python ecosystem | `disrobe-pass-py-decompile`, `disrobe-pass-py-disasm`, `disrobe-pass-py-deob`, `disrobe-pass-pyarmor`, `disrobe-pyarmor-cextract`, `disrobe-pyarmor-pytrace`, `disrobe-pass-pyinstaller`, `disrobe-pass-pyfreeze`, `disrobe-pass-nuitka`, `disrobe-pass-pickle`, `disrobe-py-marshal`, `disrobe-pass-sourcedefender` |
| JavaScript / wasm | `disrobe-pass-js-deob`, `disrobe-pass-wasm-deob` |
| Scripting / VM bytecode / mobile | `disrobe-pass-lua`, `disrobe-pass-ruby`, `disrobe-pass-php`, `disrobe-pass-shell`, `disrobe-pass-scriptlang`, `disrobe-pass-beam`, `disrobe-pass-go`, `disrobe-pass-as3`, `disrobe-pass-swift-objc`, `disrobe-pass-mobile`, `disrobe-dart` (Flutter/Dart AOT snapshot recovery) |
| Internal envelope / IR | `disrobe-ir` (`.dr` envelope decoder), `disrobe-nir` |

**Subprocess-capable code** (real `std::process::Command` call sites found by grep, non-test):

| Path | What it invokes |
|---|---|
| `crates/disrobe-binfmt/src/external_wrap.rs`, `crates/disrobe-core/src/format/process.rs` | Shared wrappers backing the optional-external-tool call sites: timeout-bounded spawn plus output capture. `process.rs` is `disrobe-core`'s native-only analog of `external_wrap.rs`. |
| `crates/disrobe-core/src/subprocess.rs` (`run_captured`) | The one shared spawn/wait-with-timeout/capped-capture primitive: kill-on-timeout, a caller-supplied byte cap on captured stdout/stderr. `disrobe-pass-dotnet`'s decompiler backend and `disrobe-pass-py-decompile`'s recompile-equivalence oracle (surfaced through the roundtrip metric) route their subprocess invocation through this call and no longer call `Command::new` directly; every other row in this table delegates the wait/capture half to it too while keeping its own spawn and error-type mapping local. |
| `crates/disrobe-cli/src/cli/native.rs`, `crates/disrobe-cli/src/cli/nuitka.rs`, `crates/disrobe-pass-native/src/decompile.rs`, `crates/disrobe-pass-jvm/src/backends.rs` | Optional decompiler/analysis backends (Ghidra, CFR, Vineflower, jadx, ILSpy, dnSpy, de4dot, Rizin) selected with `--backend` |
| `crates/disrobe-cli/src/cli/path_ops.rs` | Path-resolution / install helper invocations, including `mklink_junction` on Windows, which shells through `cmd.exe /c mklink /J` rather than calling the Windows junction API directly. This is a structurally different risk from every other row here: `cmd.exe` performs its own metacharacter reinterpretation of the command line it is handed, distinct from `Command`'s own argv-level (non-shell) passthrough that every other subprocess site in this table relies on. The stage path is resolved via `std::fs::canonicalize` before being passed in; the final path is existence-checked and has its parent directory created if missing. Neither is attacker-controlled free text in practice: both are built from an internal, ordinal-plus-pass-id path segment during chain-plan stage mirroring, not raw user input concatenated unsanitized. This site is excluded from the shared `disrobe-core::subprocess` primitive and from the Wave-1/2/3 containment work above on purpose, since a `cmd.exe`-level metacharacter audit is a distinct piece of work from the `Command`-level timeout/capture hardening the rest of this table documents. |
| `crates/disrobe-cli/src/cli/install/mod.rs` | `disrobe install`'s package-manager / installer action execution, `sudo`-wrapped when the action is admin-required |
| `crates/disrobe-cli/src/cli/doctor/mod.rs`, `crates/disrobe-cli/src/cli/bug_report.rs` | `disrobe doctor` / `disrobe bug-report` probing an installed tool's version banner |
| `crates/disrobe-pass-nuitka/src/frozen.rs` (`verify_recompile`) | Spawns a Python interpreter at a caller-supplied path to check a recovered module recompiles |
| `crates/disrobe-pass-pyarmor/src/dynamic_hook.rs` | `--allow-dynamic` PyArmor key extraction: spawns the located Python interpreter against the obfuscated wrapper under a generated helper script |

`crates/disrobe-core/src/recon/git_history.rs`, `crates/disrobe-pass-native/src/pseudo_c.rs`, `crates/disrobe-pass-wasm-deob/src/structured.rs`, and `crates/disrobe-cli/src/cli/config_merge.rs` also call `std::process::Command`. Every call site found there sits inside a `#[cfg(test)]` module (test-only recompile-equivalence grading against a host `rustc`/`git`) and does not ship in the release binary. `crates/disrobe-pass-py-decompile/examples/decomp_one.rs` calls `Command` too. It is an `examples/` binary and is not part of any shipped target.

**Network-capable code** (excluding dev/test-only dependencies):

| Direction | Crate | Path |
|---|---|---|
| Inbound (server) | `disrobe-cli` | `disrobe serve`: HTTP via `axum` / `hyper`, gRPC via `tonic`. `bytes_b64`-only bodies, `deny_unknown_fields`, non-loopback bind warns at startup (Boundary 3 in the threat model). Gated behind the `serve` subcommand, not running by default. |
| Outbound (client) | `disrobe-cli` | `crates/disrobe-cli/src/cli/install_deps.rs`: `reqwest` calls to fetch release metadata and download optional backend tools (e.g. Ghidra) during `disrobe install` / `disrobe doctor --auto-install`. Opt-in subcommands, not run implicitly. |
| Outbound (client) | `disrobe-prowl` | OSINT / IOC harvester; queries public web archives and threat-intel feeds via `reqwest`. A dedicated, explicitly-invoked tool, not part of the default parsing path. |

None of the parser crates in the first table above link `reqwest`, `axum`, `hyper`, or `tonic`. Network capability is confined to the CLI's `serve` / `install` / `doctor` paths and the separate `disrobe-prowl` tool.

## Cryptography

- Identity hash: BLAKE3 (the `blake3` crate, `0.x`).
- Stream / file hashing: BLAKE3 incremental.
- Symmetric: AES-CBC / AES-GCM via RustCrypto's `aes` / `aes-gcm` (used only inside specific parsers such as Confidential's swift-decrypt and AES-zip, never on our own envelope format, which is content-addressed not encrypted).
- Asymmetric: none in the disrobe runtime path. The release pipeline signs binaries via [cosign](https://github.com/sigstore/cosign) keyless OIDC and [minisign](https://github.com/jedisct1/minisign).

## Sigstore transparency log

Release artifacts published via the `release.yml` workflow are signed with cosign keyless. Every signature is recorded in the [Rekor public transparency log](https://search.sigstore.dev/). The bundle already carries both the certificate and the signature, so `--bundle` alone is enough to verify a downloaded binary. There is no separate `.sig` file. Verify with:

```sh
cosign verify-blob \
  --bundle disrobe-v0.10.4-<target>.tar.zst.cosign.bundle \
  --certificate-identity-regexp '^https://github.com/1-3-7/disrobe/' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  disrobe-v0.10.4-<target>.tar.zst
```

## Build provenance and SBOM

Every release ships three additional pieces of supply-chain evidence beyond the cosign signature:

- **GitHub-native build provenance.** `release.yml`'s `release` job calls [`actions/attest-build-provenance`](https://github.com/actions/attest-build-provenance) once, over every platform archive, after the build matrix aggregates them. That call produces a signed [SLSA](https://slsa.dev/) provenance predicate (source commit, builder identity, workflow ref) recorded through GitHub's Artifact Attestations API. The predicate is distinct from the cosign signature. Cosign proves the bytes were signed by this repository's GitHub Actions OIDC identity. The attestation additionally proves which workflow run, commit, and trigger produced them. Verify with:

  ```sh
  gh attestation verify disrobe-v0.10.4-<target>.tar.zst --repo 1-3-7/disrobe
  ```

- **SBOM (dependency manifest embedded in the binary).** Every platform binary is built with `cargo auditable build` instead of a plain `cargo build`. That embeds a compact JSON dependency manifest into a linker section of the compiled executable. The manifest survives even if the binary is separated from any release page. Read it back with [`cargo-audit`](https://github.com/rustsec/rustsec):

  ```sh
  cargo audit bin disrobe
  ```

  This covers five of the seven release targets. `x86_64-unknown-linux-gnu` and both macOS and Windows targets build natively with `cargo auditable build` directly. The two cross-compiled targets (`x86_64-unknown-linux-musl`, `aarch64-unknown-linux-gnu`) go through `houseabsolute/actions-rust-cross`, which wraps [`cross`](https://github.com/cross-rs/cross). That action's `determine-cargo-commands.sh` receives its `command` input unquoted in a plain `run:` line. A two-word custom command like `auditable build` collapses to just `auditable`: only `$1` is read, and everything after the first word is silently dropped. cargo-auditable's own CLI then fails without its `build` verb. This is a real limitation in the wrapping action, confirmed by reading its source, not a guess. The musl and aarch64-gnu binaries therefore still ship without an embedded manifest. `cargo-audit` coverage of those two is a disclosed gap, not silently claimed.

- **SBOM (CycloneDX file, release asset).** A separate `sbom` job generates one [CycloneDX](https://cyclonedx.org/) 1.5 JSON SBOM describing the `disrobe` binary's full dependency closure across every shipped target platform (`cargo cyclonedx --target all`), published as `disrobe-<tag>.cyclonedx.json` alongside the binaries. This is the machine-readable format that scanners such as Grype, Dependency-Track, and OSV ingest directly. It gets the same protection as every other release asset: a `SHA256SUMS` entry, its own cosign bundle, and coverage under the build-provenance attestation.

## Independent release verification

`.github/workflows/verify-release.yml` is a separate workflow triggered by `release: published`. A manual `workflow_dispatch` with a `tag` input re-checks an older release. The workflow re-verifies a published release the way an outside stranger would: `contents: read` only, no signing credentials. It downloads the public release assets with `gh release download` and checks every archive and the SBOM against `SHA256SUMS`. It verifies every cosign bundle with `cosign verify-blob`, and it verifies the build-provenance attestation on each archive and the SBOM with `gh attestation verify`. Because it runs as its own separately-triggered job rather than a step appended to the `release.yml` run, it exercises the actual downloadable, publicly-verifiable artifacts, not the same run's internal runner state and credentials.

## Acknowledgements

When a reported issue ships a fix, we add the reporter (with their preferred handle) to the GitHub Security Advisory page and to the release notes for the version that contains the fix.

## License

This policy is published under the same Elastic License 2.0 as the rest of the project. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

### Dependency licenses

`disrobe`'s own dependency-license policy lives in [`deny.toml`](deny.toml) under `[licenses]`: an explicit allowlist (Apache-2.0, MIT, BSD-2/3-Clause, ISC, Zlib, 0BSD, CC0-1.0, Unicode-3.0/DFS-2016, MPL-2.0, CDLA-Permissive-2.0, Elastic-2.0), plus per-crate clarifications and exceptions for the handful of dependencies whose license metadata needs a manual pointer (`ring`, `libbz2-rs-sys`). This is enforced in CI on every push via `EmbarkStudios/cargo-deny-action`. To regenerate the full report yourself:

```sh
cargo deny check licenses
```

That command lists every dependency's resolved license against the policy in `deny.toml` and fails on anything outside the allowlist. There is no separate license-report generator beyond this; `cargo deny check licenses` is the report.

### Optional external backend tools

`disrobe` can optionally invoke a small set of external decompiler/analysis tools as subprocesses when selected with `--backend` (see the attack surface inventory above, and the "Subprocess invocation" item under In scope). Each ships under its own license. This list is informational only, not a compatibility analysis:

| Tool | License (informational) |
|---|---|
| Ghidra | Apache License 2.0 |
| CFR | MIT License |
| Vineflower | Apache License 2.0 |
| Procyon | Apache License 2.0 |
| jadx | Apache License 2.0 |
| ILSpy | MIT License |
| dnSpy / dnSpyEx | GPL-3.0 |
| de4dot | GPL-3.0 |
| Rizin | LGPL-3.0 (core) |

None of these tools are vendored or redistributed by `disrobe`; the CLI shells out to a binary you separately installed. Installing and invoking any of them is your own choice, and compliance with that tool's own license terms, including any copyleft obligations triggered by how you use it, is your responsibility, not `disrobe`'s. This table is not legal advice and is not a compatibility analysis against the Elastic License 2.0; consult your own counsel if you need one.
