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
- **Path traversal.** zip-slip and equivalents on every container kind (zip, tar.{gz,bz2,xz,zst}, 7z, asar, cab, ar, deb, rpm, NSIS, InstallShield, Inno Setup, AppImage, Docker, OCI, Flatpak, Snap, squashfs, cramfs, ext4). Path-sanitization lives in `crates/disrobe-binfmt/src/quota.rs::sanitize_entry_path` and sibling functions.
- **HTTP / gRPC server input handling.** `disrobe serve` (HTTP) and the gRPC surface accept `bytes_b64` only, never a filesystem path. Endpoints reject unknown JSON fields via `#[serde(deny_unknown_fields)]`. Any way to make the server read a file via a client-controlled string is high severity.
- **LSP-stdio input handling.** The `disrobe/analyze` LSP method also takes `bytes_b64` only with `deny_unknown_fields`. Same posture as HTTP.
- **Subprocess invocation.** `disrobe install`, `disrobe doctor --auto-install`, and backends that wrap external tools (CFR, Vineflower, jadx, ILSpy, dnSpy, de4dot, Ghidra, Rizin, ...) construct command lines from configuration and sometimes from user input. Command injection or argument smuggling is in scope.
- **`.dr` envelope handling.** `crates/disrobe-ir/src/envelope.rs` decodes a content-addressed binary format. Adversarial envelopes that cause read-past-end, integer overflow, or BLAKE3-mismatch acceptance are in scope.
- **Supply chain.** Tampering with published binaries, including signature bypass, replay, cosign-bundle manipulation, or a forged build-provenance attestation.

## Out of scope

- **Decompilation output correctness on adversarial input.** `disrobe` sometimes produces wrong output on hostile bytecode; the round-trip metric exists to flag this. A decompile result that is not byte-perfect is not a security bug; it is correctness work. Open a normal issue or PR for these.
- **Expected processing cost on large inputs.** A slow decompile of a 66 MiB Hermes bundle belongs in a performance issue. Inputs that bypass resource limits remain in scope.
- **Issues in third-party tools we wrap.** CFR, Vineflower, jadx, ILSpy, dnSpy, de4dot, Ghidra, Rizin, and friends each have their own security channels. We forward concerns where we can identify the upstream affected.
- **Repository operations outside the `disrobe` source tree.** GitHub platform issues, runner-image issues, and GitHub Actions issues go to GitHub.

## Hardening posture

- `#![forbid(unsafe_code)]` is set crate-by-crate across the parsing surface; the `unsafe` that exists sits at interop boundaries: `disrobe-pyarmor-cextract` (C-level pyo3 / libc interop), `disrobe-wasm` (WASM C-ABI export shims), an audited memory-map in `disrobe-ir`, and one OS env-var call in the CLI install path.
- Workspace clippy gate (`-D warnings -W unreachable_pub -W missing_debug_implementations -W unused`) is required for every commit on `main`.
- `cargo deny check` (advisories / bans / licenses / sources) runs on every push and weekly on a cron via `EmbarkStudios/cargo-deny-action@v2`.
- A dedicated `audit` job runs `cargo-deny check advisories` against the RustSec advisory database on the same triggers (every push to `main` and the weekly Monday 06:00 UTC cron).
- All container extractors share the quota machinery in `crates/disrobe-binfmt/src/quota.rs`: per-entry size cap, aggregate size cap, recursion-depth cap, zip-slip path sanitization.
- `corpus/native/packers/MANIFEST.toml` and sibling registries pin every fixture by BLAKE3; tests verify byte-identity before exercising the parser.
- The HTTP / gRPC / LSP servers never read files from disk based on client input. Only `bytes_b64` is accepted; `#[serde(deny_unknown_fields)]` is enforced; non-loopback HTTP binds emit a `tracing::warn!` banner at startup.
- Every subprocess invocation in the attack surface table below routes its wait and capture through one shared primitive, `disrobe-core::subprocess`. If a caller-set timeout expires, the primitive kills and reaps the child. A caller-set byte cap truncates captured stdout/stderr instead of buffering unbounded output from a hostile or malfunctioning external tool. A pipe read error is treated the same as clean EOF, so the process's real exit code and the output already captured survive instead of being discarded as an indistinguishable timeout. Argv goes through `Command`'s own non-shell argument list, never a shell string, so a path or argument containing shell metacharacters reaches the child literally. The one exception is `mklink_junction`, which shells through `cmd.exe` on Windows and is tracked separately in that table.

## Fuzzing and panic-safety coverage

Coverage-guided fuzzing, property tests, and panic-safety tests exercise different input populations. Only the first category supplies fuzzer coverage feedback.

1. **Continuous coverage-guided fuzzing** uses `cargo-fuzz` / libFuzzer, with targets defined in `fuzz/Cargo.toml`.

    | Target | Scope and checked invariants |
    |---|---|
    | `chain_driver.rs`, `chain_spec_parser.rs` | The `disrobe-core` chain driver and explicit chain parser, under the `chain` feature |
    | `hex_decode.rs` | The shared `disrobe-core::codec::hex::decode_with` policy used by hex-consuming passes |
    | `custom_base64.rs` | Partial and complete caller-supplied byte/Unicode alphabets, both group policies, and malformed alphabet construction |
    | `container_dispatch.rs` | Magic dispatch, structural identification, input classification, and per-format detectors; sanitized paths remain relative with normal components, and quotas reject entries above the per-entry cap |
    | `native_formats.rs` | PE, ELF, Mach-O, and virtual-address image resolution; a located PE header has the required signature and a complete COFF header |
    | `python_bytecode.rs` | The versioned `.pyc` container and marshal reader; reference-table entries cannot claim bytes beyond the stream |
    | `dex_jvm_classfile.rs` | DEX, Java classfiles, Android binary XML/resources, and both bytecode lifters |
    | `cil_metadata.rs` | .NET PE, CLR header, metadata root, tables, heaps, and method bodies, with each parser feeding the next |
    | `wasm_sections.rs` | Module analysis, obfuscator detection, section scanners, and DWARF |
    | `dr_envelope.rs` | Envelope, payload, and sidecar decoders; an encoded envelope decodes unchanged |
    | `nested_dispatch.rs` | Structured recursive container framing; a path hint cannot suppress a format detected without that hint |

    `cargo run -p xtask -- fuzz-seeds` derives seeds and structural truncations from committed `corpus/` samples. Targets use AddressSanitizer, debug assertions, and overflow checks; scheduled campaigns also use libFuzzer fork mode. No undefined-behavior sanitizer run is claimed.

    On-disk extraction (`extract_to`, `detect_and_extract_with_hint`, `carve_recursive`) is outside these fuzz targets. Deterministic resilience tests cover those paths separately.

    Declared coverage-guided targets cover <!-- parse-surface:with-target -->120<!-- /parse-surface --> of <!-- parse-surface:entry-points -->1459<!-- /parse-surface --> untrusted-byte entry points. The inventory identifies <!-- parse-surface:parse-shaped -->597<!-- /parse-surface --> parse-shaped entry points and <!-- parse-surface:reach-recorded -->132<!-- /parse-surface --> entry points named by suites that record seed reach. These counts come from `xtask/data/fuzz_surface.json`, which also lists entries without a target or resilience suite. A target counts only when both `fuzz/coverage.toml` and its source identify the entry point.

    Seed replay satisfies <!-- parse-surface:seed-obligations-satisfied -->23<!-- /parse-surface --> of <!-- parse-surface:seed-obligations-declared -->23<!-- /parse-surface --> declared obligations using committed, content-addressed seeds: <!-- parse-surface:seed-positive-witnesses -->18<!-- /parse-surface --> positive witnesses and <!-- parse-surface:seed-rejection-witnesses -->5<!-- /parse-surface --> expected rejections. The positive witnesses establish semantic reach for <!-- parse-surface:replay-proven -->18<!-- /parse-surface --> parser entry points. A declaration without a positive parser-owned witness remains declared coverage only.

2. **Property-based tests** use `proptest` to generate structured inputs:

    | Test file | Scope |
    |---|---|
    | `crates/disrobe-bytes/tests/properties.rs` | Byte-buffer primitives |
    | `crates/disrobe-emit/tests/c_cc_oracle.rs`, `crates/disrobe-emit/tests/rust_roundtrip.rs` | C and Rust emitter round trips |
    | `crates/disrobe-ir/tests/proptest_envelope.rs` | Envelope decoding |
    | `crates/disrobe-llm-metadata/tests/selection_builder.rs` | Metadata selection |
    | `crates/disrobe-mba/tests/semantic_preservation.rs` | MBA semantic preservation |

3. **Ad-hoc panic-safety unit tests** feed selected or lightly randomized truncated, mutated, and malformed bytes to parsers and require a clean error instead of a panic. A name-based census finds approximately 55 files, depending on the patterns included: `*_never_panics`, `no_panic`, `panic_safety`, `fuzz_decode_*`, and resilience/adversarial/fuzz/malformed filenames. These tests provide no shrinking, accumulated corpus, or coverage feedback.

Dedicated coverage remains absent for `disrobe-pass-py-deob`, `disrobe-pass-pyarmor`, `disrobe-pyarmor-cextract`, `disrobe-pyarmor-pytrace`, `disrobe-nir`, and `disrobe-nir-lift`: they have no dedicated fuzz target, proptest file, or resilience/never-panics test file. Python-obfuscator and PyArmor functional tests include scattered malformed-input assertions; these do not establish dedicated fuzzing coverage for the peelers, native interop, or cross-format lifters.
## Plugin trust model

WASM plugins run under explicit resource and import limits:

- `disrobe-plugin-host` (`crates/disrobe-plugin-host/src/lib.rs`) runs a raw core WASM module through `wasmtime` under three caps: a fuel budget (default 50,000,000, capped at 1,000,000,000), a wall-clock deadline (default 1s, capped at 30s, enforced by an epoch-interrupt watchdog thread), and a memory cap (default 16 MiB, capped at 256 MiB) enforced by a `ResourceLimiter`. If a module imports anything at all, `PluginHost::run` rejects it before instantiation: `first_import` denies the module and `Linker::define_unknown_imports_as_traps` backstops it. A module run through this path has no ambient filesystem, network, or host-function access. It can only transform the input bytes it is given and return output bytes, bounded by the caps above.
- `disrobe-plugin-loader` (`crates/disrobe-plugin-loader/src/lib.rs`, `manifest.rs`) verifies a WASM component against a `minisign` signature from a trusted key before it is even parsed as a component. It then walks the component's declared imports and rejects any import that a TOML manifest (`Manifest::grants`) does not explicitly grant. This is a capability allowlist, not a blanket trust grant. An unsigned, mis-signed, or over-capability-requesting component is rejected before it runs.

`disrobe plugin run`, `verify`, and `list` are available through the `plugin` Cargo feature, included in `full`. The execution path is `PluginHost::load_and_run`: the loader verifies the signature, compiles the component, and validates its imports; `PluginHost::run_component` applies the fuel, time, and memory caps above. The component linker is empty, so a manifest grant permits validation but supplies no host function.

A plugin bundle consists of `<name>.wasm`, `<name>.wasm.minisig`, and `<name>.toml`. There is no plugin registry or automatic distribution. `--trusted-key` names an operator-supplied minisign public-key file. Unsigned or wrong-key components, oversized components/signatures, non-UTF-8 signatures, missing or malformed manifests, ungranted imports, and missing or wrongly typed `run` exports produce distinct typed errors before execution.

Plugin JSON distinguishes authenticated identity from declared metadata. The component's BLAKE3 hash and signing-key ID come from verified bytes. The manifest's `name` and `version` are unsigned: changing either beside a signed component does not invalidate its signature. `disrobe plugin run --format json` reports `manifest_version_authenticated: false`.

The implemented guest contract is `run: func(list<u8>) -> list<u8>`. The richer schema in `schemas/v0/wit/disrobe-plugin@0.1.0.wit` is not implemented: its `pass-descriptor` (`id`, `version`), `descriptor()` export, and five host functions (`log`, `input-bytes`, `cold-field-string`, `cold-field-u64`, `get-annotation`) are neither bound nor called. No host functions are available, and `disrobe auto` does not discover or route to plugins. Invocation requires an explicit operator-supplied path.

**Editor integrations have the host tool's privileges.** The IDA, Ghidra, Binary Ninja, and VS Code integrations under `editors/` invoke the Disrobe CLI as a subprocess. They are not WASM plugins and provide no additional sandbox boundary.

**Analysis correctness remains a trust decision.** The sandbox limits compute, memory, elapsed time, and ambient capabilities. It does not validate the returned analysis. A plugin can return incorrect or misleading bytes while staying within every resource cap, and downstream artifact handling supplies no independent correctness check.

## Attack surface inventory

The tables list parser, subprocess, and network surfaces. The attack-surface check in `cargo run -p xtask -- regen --check` compares their entries against crate manifests, non-test `Command::new` calls, and network dependencies. Unlisted or obsolete entries fail the check.

**Untrusted-input parsers (format / container / bytecode):**

| Family | Crates |
|---|---|
| Native executables and containers | `disrobe-binfmt` (PE/ELF/Mach-O; zip/tar/7z/cab/msi/nsis/deb/rpm/AppImage/... containers; quota + path-sanitization), `disrobe-pass-native` (packers, protectors, disassembly), `disrobe-pass-nativelang` (Nim/Zig/Crystal/D), `disrobe-pass-webview` (Electron ASAR / Tauri / Wails frontend-asset carver from packed desktop binaries), `disrobe-sleigh` (Sleigh instruction decoder / p-code lifter for AArch64, ARM32/Thumb, MIPS32, RISC-V, and PowerPC over raw machine-code bytes), `disrobe-lift-x86` (x86-64 instruction decoder / p-code lifter over raw machine-code bytes via iced-x86), `disrobe-typerec` (integer width and signedness recovery over raw machine-code bytes via iced-x86, with DWARF ground-truth reading in its grading path) |
| .NET / CIL | `disrobe-pass-dotnet` |
| JVM / Android | `disrobe-pass-jvm`, `disrobe-nir-lift` (JVM/Dalvik/CIL/AVM2 bytecode lifters) |
| Python ecosystem | `disrobe-pass-py-decompile`, `disrobe-pass-py-disasm`, `disrobe-pass-py-deob`, `disrobe-pass-pyarmor`, `disrobe-pyarmor-cextract`, `disrobe-pyarmor-pytrace`, `disrobe-pass-pyinstaller`, `disrobe-pass-pyfreeze`, `disrobe-pass-nuitka`, `disrobe-pass-pickle`, `disrobe-py-marshal`, `disrobe-pass-sourcedefender` |
| JavaScript / wasm | `disrobe-pass-js-deob`, `disrobe-pass-wasm-deob` |
| Scripting / VM bytecode / mobile | `disrobe-pass-lua`, `disrobe-pass-ruby`, `disrobe-pass-php`, `disrobe-pass-shell`, `disrobe-pass-scriptlang`, `disrobe-pass-beam`, `disrobe-pass-go`, `disrobe-pass-as3`, `disrobe-pass-swift-objc`, `disrobe-pass-mobile` (React Native, Hermes, Flutter/Dart AOT snapshot, Xamarin, Cordova/Capacitor, NativeScript) |
| Internal envelope / IR | `disrobe-ir` (`.dr` envelope decoder), `disrobe-nir` |

**Subprocess-capable code** (real `std::process::Command` call sites found by grep, non-test):

| Path | What it invokes |
|---|---|
| `crates/disrobe-binfmt/src/external_wrap.rs`, `crates/disrobe-core/src/bin/mock_proc.rs`, `crates/disrobe-tool-process/src/unix.rs` | Legacy direct-child execution, controlled fixtures and contained trusted-tool execution. `external_wrap.rs` must migrate before it can claim descendant containment. `mock_proc.rs` is the controlled process-tree fixture used by core tests. `disrobe-tool-process` owns bounded trusted-tool spawn, independent output capture, process containment and timeout cleanup. Unix tools join a new process group. Windows tools enter a Job Object before their primary thread resumes. |
| `crates/disrobe-cli/src/cli/native.rs`, `crates/disrobe-cli/src/cli/nuitka.rs`, `crates/disrobe-pass-native/src/decompile.rs`, `crates/disrobe-pass-jvm/src/backends.rs` | Optional decompiler/analysis backends (Ghidra, CFR, Vineflower, jadx, ILSpy, dnSpy, de4dot, Rizin) selected with `--backend` |
| `crates/disrobe-cli/src/cli/path_ops.rs` | `mklink_junction` runs `cmd.exe /c mklink /J` for Windows stage mirrors. Shell metacharacter interpretation applies here; this call is outside the shared `disrobe-core::subprocess` helper. Stage paths are canonicalized and constructed from ordinal/pass-ID segments. The destination is existence-checked and its parent created before invocation. |
| `crates/disrobe-cli/src/cli/install/mod.rs` | `disrobe install`'s package-manager / installer action execution, `sudo`-wrapped when the action is admin-required |
| `crates/disrobe-cli/src/cli/doctor/mod.rs`, `crates/disrobe-cli/src/cli/bug_report.rs` | `disrobe doctor` / `disrobe bug-report` probing an installed tool's version banner |
| `crates/disrobe-pass-nuitka/src/frozen.rs` (`verify_recompile`) | Spawns a Python interpreter at a caller-supplied path to check a recovered module recompiles |
| `crates/disrobe-pass-pyarmor/src/dynamic_hook.rs` | `--allow-dynamic` PyArmor key extraction: spawns the located Python interpreter against the obfuscated wrapper under a generated helper script |
| `crates/disrobe-testkit/src/isolate.rs` | Test-support only, and reachable from no shipped target: `disrobe-testkit` is `publish = false` and is consumed exclusively as a dev-dependency, so nothing in the release binary can call this. It re-executes the *running test binary* (`std::env::current_exe`) twice per stress run: once with `--list --ignored --exact <filter>` to prove the worker test exists before any case runs, and once per batch with that filter plus a batch-file path in an environment variable. Both spawns pass a fixed argv with no shell, take their program path from `current_exe` rather than any caller string, get a null stdin, and are killed on a wall-clock watchdog so a case that hangs cannot outlive its batch. |

`crates/disrobe-core/src/recon/git_history.rs`, `crates/disrobe-pass-native/src/pseudo_c.rs`, `crates/disrobe-pass-wasm-deob/src/structured.rs`, and `crates/disrobe-cli/src/cli/config_merge.rs` also call `std::process::Command`. Every call site found there sits inside a `#[cfg(test)]` module (test-only recompile-equivalence grading against a host `rustc`/`git`) and does not ship in the release binary. `crates/disrobe-pass-py-decompile/examples/decomp_one.rs` calls `Command` too. It is an `examples/` binary and is not part of any shipped target.

`crates/disrobe-core/src/format/process.rs` uses the owned contained facade. `crates/disrobe-core/src/subprocess.rs` exposes the bounded legacy direct-child compatibility helper. These adapters do not call `Command::new`, so the inventory table does not list them as spawn sites.

**Network-capable code** (excluding dev/test-only dependencies):

| Direction | Crate | Path |
|---|---|---|
| Inbound (server) | `disrobe-cli` | `disrobe serve`: HTTP via `axum` / `hyper`, gRPC via `tonic`. `bytes_b64`-only bodies, `deny_unknown_fields`, non-loopback bind warns at startup (Boundary 3 in the threat model). Gated behind the `serve` subcommand, not running by default. |
| Outbound (client) | `disrobe-cli` | `crates/disrobe-cli/src/cli/install_deps.rs`: `reqwest` calls to fetch release metadata and download optional backend tools (e.g. Ghidra) during `disrobe install` / `disrobe doctor --auto-install`. Opt-in subcommands, not run implicitly. |
| Outbound (client) | `disrobe-prowl` | OSINT / IOC harvester; queries public web archives and threat-intel feeds via `reqwest`. A dedicated, explicitly-invoked tool, not part of the default parsing path. |

None of the parser crates in the first table above link `reqwest`, `axum`, `hyper`, or `tonic`, and neither does the slim CLI binary itself: a `--no-default-features` build links none of `tokio`, `axum`, `tonic`, `tower-http`, `tokio-util`, `tokio-stream`, `reqwest`, `hyper`, `rustls`, `rmcp` or `keyring`, which a committed CI gate enforces by dependency tree. In the full build, network capability is confined to the CLI's `serve` and `install-deps` paths and the separate `disrobe-prowl` tool. `doctor` performs no network request unless `--auto-install` is selected.

## Cryptography

- Identity hash: BLAKE3 (the workspace-pinned `blake3` crate).
- Stream / file hashing: BLAKE3 incremental.
- Symmetric: AES-CBC / AES-GCM via RustCrypto's `aes` / `aes-gcm` (used only inside specific parsers such as Confidential's swift-decrypt and AES-zip, never on our own envelope format, which is content-addressed not encrypted).
- Asymmetric: WASM plugin signatures use [minisign](https://github.com/jedisct1/minisign) verification against an operator-supplied public key. The release pipeline signs artifacts with [cosign](https://github.com/sigstore/cosign) keyless OIDC.

## Sigstore transparency log

Release artifacts published via the `release.yml` workflow are signed with cosign keyless. Every signature is recorded in the [Rekor public transparency log](https://search.sigstore.dev/). The bundle already carries both the certificate and the signature, so `--bundle` alone is enough to verify a downloaded binary. There is no separate `.sig` file. Verify with:

```sh
cosign verify-blob \
  --bundle disrobe-v0.10.6-<target>.tar.zst.cosign.bundle \
  --certificate-identity-regexp '^https://github.com/1-3-7/disrobe/' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  disrobe-v0.10.6-<target>.tar.zst
```

## Build provenance and SBOM

Every release ships three additional pieces of supply-chain evidence beyond the cosign signature:

- **GitHub-native build provenance.** `release.yml`'s `release` job calls [`actions/attest-build-provenance`](https://github.com/actions/attest-build-provenance) once, over every platform archive, after the build matrix aggregates them. That call produces a signed [SLSA](https://slsa.dev/) provenance predicate (source commit, builder identity, workflow ref) recorded through GitHub's Artifact Attestations API. The predicate is distinct from the cosign signature. Cosign proves the bytes were signed by this repository's GitHub Actions OIDC identity. The attestation additionally proves which workflow run, commit, and trigger produced them. Verify with:

  ```sh
  gh attestation verify disrobe-v0.10.6-<target>.tar.zst --repo 1-3-7/disrobe
  ```

- **SBOM (dependency manifest embedded in the binary).** Five of the seven platform binaries use `cargo auditable build`. It embeds a compact dependency manifest in an executable section, which remains readable when the binary is separated from its release archive. Inspect it with [`cargo-audit`](https://github.com/rustsec/rustsec):

  ```sh
  cargo audit bin disrobe
  ```

  The native `x86_64-unknown-linux-gnu`, macOS, and Windows builds carry this manifest. The two cross-compiled targets, `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-gnu`, use `houseabsolute/actions-rust-cross` and ship without it. Their dependency coverage comes from the separate CycloneDX release asset; embedded-manifest auditing is unavailable for those binaries.

- **SBOM (CycloneDX file, release asset).** A separate `sbom` job generates one [CycloneDX](https://cyclonedx.org/) 1.5 JSON SBOM describing the `disrobe` binary's full dependency closure across every shipped target platform (`cargo cyclonedx --target all`), published as `disrobe-<tag>.cyclonedx.json` alongside the binaries. This is the machine-readable format that scanners such as Grype, Dependency-Track, and OSV ingest directly. It gets the same protection as every other release asset: a `SHA256SUMS` entry, its own cosign bundle, and coverage under the build-provenance attestation.

## Independent release verification

`.github/workflows/verify-release.yml` runs independently on `release: published`; `workflow_dispatch` with a `tag` rechecks an older release. With `contents: read` and no signing credentials, it downloads published assets and verifies each archive and the SBOM against `SHA256SUMS`, the cosign bundle, and GitHub build-provenance attestations. This checks the publicly downloadable bytes after publication.

## Acknowledgments

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

None of these tools are vendored or redistributed by `disrobe`; the CLI shells out to a binary you separately installed. Installing and invoking any of them is your own choice, and compliance with that tool's own license terms, including any copyleft obligations triggered by how you use it, is your responsibility, not `disrobe`'s. This table is not a compatibility analysis against the Elastic License 2.0; consult your own counsel if you need one.
