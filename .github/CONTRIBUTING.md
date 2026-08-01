# Contributing

`disrobe` is a deterministic multi-language deobfuscator and decompiler suite. The same input bytes produce the same output bytes on every machine and every run. Every rule below follows from that one.

## Getting started

```
git clone https://github.com/1-3-7/disrobe
cd disrobe
cargo build --workspace
cargo test --workspace
```

`rust-toolchain.toml` pins the exact Rust version so your local `rustfmt` and `clippy` match CI byte-for-byte. Builds that touch the pyo3 bindings need a Python on `PATH`. Set `PYO3_PYTHON` to pin a specific one. Install the git hooks once with:

```
cargo xtask setup-hooks
```

That points git at `lefthook`, which runs the pre-commit checks and a pre-push pre-mortem (`cargo xtask prepush`). The pre-push gate is the single source of truth shared with CI. It checks formatting on every changed crate (`cargo fmt -p <crate> -- --check`) and runs `cargo clippy --workspace --all-targets -- -D warnings`. When a change touches a generator or its inputs, the gate also re-checks generated-artifact freshness. The first failure stops the push and prints the exact fix for whatever drifted.

Run `cargo xtask prepush --full` before a release to gate every crate unscoped. `LEFTHOOK=0 git push` or `git push --no-verify` skips it in an emergency.

## Workspace map

The workspace has 61 crates under `crates/`, layered core -> ir -> passes -> surfaces.

**Core and plumbing**

- `disrobe-core` - shared traits (`Pass`, `Detector`), error types, the chain detector/registry/precedence machinery, and pass-dispatch primitives.
- `disrobe-ir` - the five-rung ladder IR (Raw / Disasm / MIR / HIR / Surface), the `.dr` envelope codec, and the transcode registry.
- `disrobe-binfmt` - container and archive detection and extraction across 98 in-tree formats.
- `disrobe-py-marshal` - the CPython `marshal` codec and `.pyc` encoder/decoder, spanning Python 1.0 through 3.15.
- `disrobe-llm-metadata` - the versioned deterministic metadata envelope and the per-pass emitter trait behind `--metadata-pack-*` / `--llm`.
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
- `disrobe-pass-native` - PE / ELF / Mach-O symbol recovery and in-house packer decoders (UPX / Petite / kkrunchy / MEW via a stub emulator), with a headless Ghidra wrap.
- `disrobe-pass-go` - Go binary recovery: pclntab, moduledata, garble report, and `embed.FS` extraction.
- `disrobe-pass-swift-objc` - Swift and Objective-C class-dump, SwiftShield undo, and explicit-key single-byte XOR blob decoding.
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

`main` is always releasable. Work in a feature branch and open a PR. Squash-merge when CI is green. Name the branch `pass/<name>` or `<area>/<slug>`, and keep it short-lived.

## Adding a new pass crate

1. Decide which IR rung the pass targets (Raw=0 through Surface=4). Work out its `REQUIRES` / `PRODUCES` in the capability system; see `crates/disrobe-ir/src/lib.rs`.
2. Create `crates/disrobe-pass-<name>/`. The minimum is a `Cargo.toml` with workspace dependency inheritance and a `lib.rs` that registers a `PassDescriptor`. If the pass should join the auto-chain, add a `chain` feature and a `chain_detector` module.
3. Wire it into `disrobe-cli`. Add the crate as an `optional = true` dependency, plus a matching `<ecosystem>` feature under `[features]`. Declare the CLI sub-module behind `#[cfg(feature = "...")]`, and gate the `Cmd` variant and dispatch arm the same way. Register the pass in the chain registry (`cli/chain_v1.rs`) under that cfg. Document the new flag in the README and the relevant docs page.
4. Emit at least `--emit source` and `--emit report`. Output must be deterministic: the same input bytes produce the same output bytes.
5. Add a fixture under `corpus/` (next section) and a test that pins behavior against it.
6. Benchmark with `cargo bench -p disrobe-pass-<name>` and note the baseline in the PR.

**Gray-zone protectors** (commercial obfuscators with active legal programs: VMProtect, Themida, certain DRM stacks) require an issue first. Any pass that targets one of them gets a research review before it ships. The review is not there to discourage the work; it documents the statutory basis before code lands.

## Adding a fixture

Fixtures live under `corpus/<ecosystem>/`. Prefer an artifact generated by the real tool over a synthetic one. If a fixture is heavy or platform-built, it stays gitignored and a regeneration recipe ships instead.

1. Add a generator: extend `corpus/generate.sh` / `corpus/generate.ps1`.
2. Record provenance in the ecosystem's `MANIFEST.toml`: `schema_version`, a `description`, and one `[[fixtures]]` block per artifact with `path`, `format`, `tool`, and `provenance`. Aim for byte-identical reproducibility, and note where a fixture cannot be reproduced cross-host.
3. Small reproducible binaries may be committed; un-ignore each with a `!` negation in `.gitignore`. Large or non-reproducible fixtures stay ignored. Mark any test that depends on a gitignored fixture `#[ignore]`, and put a regeneration hint in the message.

## The metadata sidecar protocol

Every pass can emit a versioned metadata sidecar alongside its normal output. The schema is `disrobe.metadata.llm.v1` (see `disrobe-llm-metadata`). The schema id is a stable API name; the payload is deterministic metadata, not model output. Selection is additive:

- Packs: `--metadata-pack-1` (ast + disasm + symbols + strings) through `--metadata-pack-4` (pack-3 + confidence + opcode-coverage + pii-map + decryption-keys, auth-gated). `--llm` aliases pack-4.
- Categories: granular toggles like `--ast`, `--disasm`, `--cfg`, `--dfg`, `--symbols`, `--strings`, `--types`, `--imports`, `--constants`, and `--signatures` compose with the packs.

A pass implements `LlmMetadataEmitter::emit_metadata(&selection)`. The CLI writes the bundle next to the primary artifact, with a per-pass `PipelineStep` provenance record (input hash, consumed and produced rungs, duration). The bundle is deterministic and never phones home.

## Documentation and the wiki

The docs live under `docs/src` and are the single source of truth. mdBook renders them to the docs site. `scripts/wiki_sync.py` and the `wiki-sync` workflow generate the GitHub wiki from `docs/src` on every push to `main` that touches `docs/`. Do not edit wiki pages directly, because the next sync overwrites them. Edit the matching file under `docs/src`, then regenerate locally to preview:

```
python scripts/wiki_sync.py --out ./.wiki-build       # build the wiki tree
python scripts/wiki_sync.py --check --out ./.wiki-build  # fail on drift
```

## Local verify chain

Run the full chain before you push; CI runs the same with `RUSTFLAGS=-D warnings`:

```
cargo check --workspace --all-features
cargo check --workspace --no-default-features
cargo clippy --workspace --all-features --all-targets -- -D warnings -W unreachable_pub -W missing_debug_implementations -W unused
cargo fmt -p <crate> -- --check
cargo test --workspace            # run per-crate if RAM is tight
cargo deny check
typos
cargo run -p xtask -- regen --check   # every generated artifact must be byte-fresh
```

Determinism rules the linter enforces:

- `HashMap` and `HashSet` are banned from emit paths via `clippy.toml`. Use `IndexMap` / `IndexSet`, or `BTreeMap` / `BTreeSet` for sorted output.
- No `SystemTime::now()` or unseeded randomness inside a pass. Route through `disrobe_core::time` and `disrobe_core::rng`.
- No `.unwrap()` or `.expect()` in production library code. Tests may use them when they make the failing condition clearer than manual error plumbing.
- The source carries no comments. Names and structure do the explaining. Durable rationale and context live in the crate's `INFORMATION.md`, not inline.

## Security routing

If you find a vulnerability, do not open a public issue. Examples are a sandbox escape, a path traversal in an extractor, and a pass that writes outside its declared output directory. Follow the private disclosure process in [SECURITY.md](../SECURITY.md). Include a minimal reproducer (input bytes, command line, expected versus observed behavior), the `disrobe --version` output, and the OS and architecture.

## Commits

Write the subject in lowercase with plain, specific words. Say what changed, and do not use `type:` prefixes. The body is optional and carries non-obvious motivation only, never a restatement of the diff. Use a noreply email so your address stays private:

```
git -c user.email="<id>+<handle>@users.noreply.github.com" commit -m "add pyarmor v9 co_code reconstruction"
```

Do not attribute authorship to anyone not listed in `NOTICE`, and do not add a co-author trailer.

## Release policy

Releases are prebuilt binaries only, cut by `.github/workflows/release.yml` on a `vX.Y.Z` tag or a manual dispatch. The workflow cross-builds per-target artifacts with build attestations and publishes a GitHub release. `disrobe` is not published to crates.io, PyPI, Homebrew, or winget; there is nothing to install from a registry. To run a release build from source: `cargo build --release --bin disrobe`.

## What will not merge

- Any pass that produces non-deterministic output.
- Code with `// TODO`, `// FIXME`, `unimplemented!()`, or `todo!()` in a non-stub position.
- Anything that phones home, writes outside the declared output directory, or modifies the input.
- Attribution of authorship to anyone not listed in `NOTICE`.
