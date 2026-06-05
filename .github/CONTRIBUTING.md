# Contributing

`disrobe` is a deterministic multi-language deobfuscator and decompiler suite. The same input bytes produce the same output bytes on every machine and every run. Keep that one rule in mind and the rest of this document is detail.

## Getting started

```
git clone https://github.com/1-3-7/disrobe
cd disrobe
cargo build --workspace
cargo test --workspace
```

You need Rust stable; `rust-toolchain.toml` pins the version. Builds that touch the pyo3 bindings need a Python on `PATH`, and `PYO3_PYTHON` pins a specific one. `lefthook` runs the pre-commit checks:

```
lefthook install
```

## Workspace map

Around 33 crates, layered core -> ir -> passes -> surfaces.

**Core and plumbing**

- `disrobe-core` - shared traits, error types, the capability model, and pass-dispatch primitives.
- `disrobe-ir` - the five-rung ladder IR (Raw / Disasm / MIR / HIR / Surface), the `.dr` envelope codec, and capability negotiation.
- `disrobe-binfmt` - container and archive detection and extraction (zip, tar, 7z, asar, squashfs, NSIS, apk, ipa, ...).
- `disrobe-py-marshal` - the CPython `marshal` codec and `.pyc` encoder/decoder, spanning Python 2.7 through 3.15.
- `disrobe-llm-metadata` - the versioned LLM metadata envelope and the per-pass emitter trait behind `--llm`.
- `disrobe-validator` - the corpus walker and benchmark harness; asserts byte-level determinism and exports HTML/JSON reports.

**Python passes**

- `disrobe-pass-pyarmor` - PyArmor v6/v7 dynamic-hook plus v8/v9-pro static unpack.
- `disrobe-pyarmor-cextract` - C-level `PyEval_EvalCode` intercept (PEP 669 / settrace) for v6/v7 user-code capture.
- `disrobe-pyarmor-pytrace` - Python-level audit-hook and `sys.settrace` companion to cextract.
- `disrobe-pass-pyinstaller` - PyInstaller 2.1 through 6.x extract plus AES-CTR/CFB decrypt.
- `disrobe-pass-pyfreeze` - cx_Freeze / py2exe / shiv / pex / PyOxidizer / Briefcase detect and extract.
- `disrobe-pass-nuitka` - `--onefile` and `--standalone` payload extract plus symbol scan.
- `disrobe-pass-py-deob` - obfuscator peel plus AST constant-fold and dead-branch cleanup.
- `disrobe-pass-py-disasm` - the `.pyc` disassembler (CPython 1.0 through 3.15 plus PyPy / MicroPython / Jython / IronPython).
- `disrobe-pass-py-decompile` - the native `.pyc`-to-source engine with frame-tree reconstruction and round-trip verification.
- `disrobe-pass-sourcedefender` - `.pye` envelope structure parse and detect (the KDF is unvalidated against the commercial tool, so it stays detect-only until a known-answer vector lands).

**Other ecosystems**

- `disrobe-pass-js-deob` - JS/TS string-array decode, unminify, scope-aware rename, and bundle splitting.
- `disrobe-pass-wasm-deob` - WebAssembly analyze and lift (Rust / TS / WAT / C) plus 5 obfuscator families.
- `disrobe-pass-jvm` - in-house classfile and dex parse, ProGuard/R8 mapping replay, and protector detect and structural peel, with headless CFR / Vineflower / Procyon / jadx wraps.
- `disrobe-pass-dotnet` - in-house PE/CLR/table-stream parse, obfuscator reversers (ConfuserEx2 constant decrypt, ...), and R2R header classify, with headless ILSpy / dnSpyEx / de4dot wraps.
- `disrobe-pass-native` - PE / ELF / Mach-O symbol recovery and clean-room packer decoders (UPX / Petite / kkrunchy / MEW via an in-house stub emulator), with a headless Ghidra wrap.
- `disrobe-pass-go` - Go binary recovery: pclntab, moduledata, garble report, and `embed.FS` extraction.
- `disrobe-pass-swift-objc` - Swift and Objective-C class-dump, SwiftShield undo, and Confidential XOR-decrypt.
- `disrobe-pass-mobile` - React Native / Hermes / Flutter / Cordova / Capacitor / NativeScript / Xamarin.
- `disrobe-pass-lua` - Lua 5.1 through 5.4 / LuaJIT / Luau / GLua decompile and obfuscator peel.
- `disrobe-pass-php` - encoder decode (phar / ionCube / SourceGuardian / Zend Guard) and eval-chain peel.
- `disrobe-pass-ruby` - MRI / YARV / mruby / JRuby / TruffleRuby / Ruby2Exe / Ocra analysis.
- `disrobe-pass-beam` - BEAM (Erlang / Elixir) IFF chunk parse, Core Erlang lift, and Code chunk disasm.
- `disrobe-pass-as3` - ActionScript 3 SWF parse and DoABC tag disasm.
- `disrobe-pass-shell` - shell-script deobfuscation.

**Surfaces**

- `disrobe-cli` - the `disrobe` binary: every subcommand, the HTTP/gRPC/LSP `serve` daemon, and the chain orchestrator.
- `disrobe-python` - pyo3 bindings exposing the library as the importable `disrobe` module.

## Branch model

`main` is always releasable. Work in feature branches, open a PR, and squash-merge when green. Branch names: `pass/<name>`, `fix/<slug>`, `feat/<slug>`, `refactor/<slug>`. Keep them short-lived.

## Adding a new pass crate

1. Decide which IR rung your pass targets (Raw=0 through Surface=4) and what `REQUIRES` / `PRODUCES` mean in the capability system; see `crates/disrobe-ir/src/lib.rs`.
2. Create `crates/disrobe-pass-<name>/`. The minimum is a `Cargo.toml` with workspace dependency inheritance and a `lib.rs` that registers a `PassDescriptor`. Add a `chain` feature and a `chain_detector` module if it should join the auto-chain.
3. Wire it into `disrobe-cli`: add the crate as an `optional = true` dependency, add a matching `<ecosystem>` feature under `[features]`, declare the CLI sub-module behind `#[cfg(feature = "...")]`, gate the `Cmd` variant and dispatch arm the same way, and register it in the chain registry (`cli/chain_v1.rs`) under that cfg. Document the new flag in the README and the relevant docs page.
4. Emit at least `--emit source` and `--emit report`. Output must be deterministic: the same input bytes produce the same output bytes.
5. Add a fixture under `corpus/` (next section) and a test that pins behavior against it.
6. Benchmark with `cargo bench -p disrobe-pass-<name>` and note the baseline in the PR.

**Grey-zone protectors** (commercial obfuscators with active legal programs: VMProtect, Themida, certain DRM stacks) require an issue first. A research review runs before any pass targeting one of these ships. This is not about discouraging the work; it documents the statutory basis before code lands.

## Adding a fixture

Fixtures live under `corpus/<ecosystem>/`. Real-tool-generated artifacts are preferred over synthetic ones. When a fixture is heavy or platform-built it stays gitignored and a regeneration recipe ships instead.

1. Add a generator: extend `corpus/generate.sh` / `corpus/generate.ps1`.
2. Record provenance in the ecosystem's `MANIFEST.toml`: `schema_version`, a `description`, and one `[[fixtures]]` block per artifact with `path`, `format`, `tool`, and `provenance`. Byte-identical reproducibility is the goal; note where a fixture cannot be reproduced cross-host.
3. Small reproducible binaries may be committed (un-ignore with a `!` negation in `.gitignore`); large or non-reproducible ones stay ignored. Tests that depend on a gitignored fixture are marked `#[ignore]` with a regeneration hint in the message.

## The `--llm` sidecar protocol

Every pass can emit a versioned metadata sidecar alongside its normal output. The schema is `disrobe.metadata.llm.v1` (see `disrobe-llm-metadata`). Selection is additive:

- Packs: `--metadata-pack-1` (ast + disasm + symbols + strings) through `--metadata-pack-4` (pack-3 + confidence + opcode-coverage + pii-map + decryption-keys, auth-gated). `--llm` aliases pack-4.
- Categories: granular toggles like `--ast`, `--disasm`, `--cfg`, `--dfg`, `--symbols`, `--strings`, `--types`, `--imports`, `--constants`, and `--signatures` compose with the packs.

A pass implements `LlmMetadataEmitter::emit_metadata(&selection)`; the CLI writes the bundle next to the primary artifact with a per-pass `PipelineStep` provenance record (input hash, consumed and produced rungs, duration). The bundle is deterministic and never phones home.

## Local verify chain

Run the full chain before you push; CI runs the same with `RUSTFLAGS=-D warnings`:

```
cargo check --workspace --all-features
cargo check --workspace --no-default-features
cargo clippy --workspace --all-features --all-targets -- -D warnings -W unreachable_pub -W missing_debug_implementations -W unused
cargo fmt --all -- --check
cargo test --workspace            # run per-crate if RAM is tight
cargo deny check
typos
```

Determinism rules the linter enforces:

- `HashMap` and `HashSet` are banned from emit paths via `clippy.toml`. Use `IndexMap` / `IndexSet`, or `BTreeMap` / `BTreeSet` for sorted output.
- No `SystemTime::now()` or unseeded randomness inside a pass. Route through `disrobe_core::time` and `disrobe_core::rng`.
- No `.unwrap()` in library code. `.expect("invariant: ...")` is acceptable when the invariant is genuinely unbreakable.
- Self-document through naming. Public items carry `///` doc-comments; `//` comments do not ship.

## Security routing

Found a vulnerability (a sandbox escape, a path traversal in an extractor, a pass that writes outside its declared output directory)? Do not open a public issue. Follow the private disclosure process in [SECURITY.md](../SECURITY.md). Include a minimal reproducer (input bytes, command line, expected versus observed behavior), the `disrobe --version` output, and the OS and architecture.

## Commit messages

Imperative mood, 72-character subject line, no trailing period. The body is optional; use it for non-obvious motivation, not for restating the diff. Commit with a noreply email so your address is not exposed:

```
git -c user.email="<id>+<handle>@users.noreply.github.com" commit -m "Add PyArmor v9 co_code reconstruction"
```

Never attribute authorship to anyone not listed in `NOTICE`, and never add a co-author trailer.

## Release policy

Releases are prebuilt binaries only, cut by `.github/workflows/release.yml` on a `vX.Y.Z` tag or a manual dispatch. The workflow cross-builds per-target artifacts with build attestations and publishes a GitHub release. `disrobe` is not published to crates.io, PyPI, Homebrew, or winget; there is nothing to install from a registry. To run a release build from source: `cargo build --release --bin disrobe`.

## What will not merge

- Any pass that produces non-deterministic output.
- Code with `// TODO`, `// FIXME`, `unimplemented!()`, or `todo!()` in a non-stub position.
- Anything that phones home, writes outside the declared output directory, or modifies the input.
- Attribution of authorship to anyone not listed in `NOTICE`.
