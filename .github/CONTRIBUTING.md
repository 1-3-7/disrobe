# Contributing

`disrobe` is a deterministic, multi-language deobfuscator & decompiler suite. same input bytes
in, same output bytes out, no exceptions. if you keep that one rule in your head the rest of
this doc is detail.

## Getting started

```
git clone https://github.com/1-3-7/disrobe
cd disrobe
cargo build --workspace
cargo test --workspace
```

you'll need Rust stable (see `rust-toolchain.toml` for the pinned version). builds that touch
the pyo3 bindings need a Python on `PATH`; set `PYO3_PYTHON` to pin one. `lefthook` is
recommended for the pre-commit checks:

```
cargo install lefthook
lefthook install
```

## Workspace map

~33 crates, layered core -> ir -> passes -> surfaces. one line each:

**core & plumbing**

- `disrobe-core` - shared traits, error types, capability model & pass-dispatch primitives.
- `disrobe-ir` - five-rung ladder IR (Raw / Disasm / MIR / HIR / Surface), `.dr` envelope codec, capability negotiation & migration shims.
- `disrobe-binfmt` - container & archive detector / extractor (zip, tar, 7z, asar, squashfs, NSIS, apk, ipa, ...).
- `disrobe-py-marshal` - CPython `marshal` codec & `.pyc` encoder/decoder spanning Python 2.7 .. 3.15.
- `disrobe-llm-metadata` - versioned LLM metadata envelope + per-pass emitter trait for the `--llm` bundle.
- `disrobe-validator` - corpus walker + benchmark harness; asserts byte-level determinism & exports HTML/JSON reports.

**Python passes**

- `disrobe-pass-pyarmor` - PyArmor v6/v7 (dyn-hook) + v8/v9-pro static unpack.
- `disrobe-pyarmor-cextract` - C-level `PyEval_EvalCode` intercept (PEP 669 / settrace) for v6/v7 user-code capture.
- `disrobe-pyarmor-pytrace` - Python-level audit-hook + `sys.settrace` fallback companion to cextract.
- `disrobe-pass-pyinstaller` - PyInstaller 2.1 .. 6.x extract + AES-CTR/CFB decrypt.
- `disrobe-pass-pyfreeze` - cx_Freeze / py2exe / shiv / pex / PyOxidizer / Briefcase detect + extract.
- `disrobe-pass-nuitka` - `--onefile` / `--standalone` payload extract + symbol scan.
- `disrobe-pass-py-deob` - obfuscator peel + ruff-AST constant-fold & dead-branch cleanup.
- `disrobe-pass-py-disasm` - `.pyc` disassembler (CPython 1.0 .. 3.15 + PyPy / MicroPython / Jython / IronPython).
- `disrobe-pass-py-decompile` - native `.pyc` -> source engine with frame-tree + round-trip verification.
- `disrobe-pass-sourcedefender` - `.pye` envelope structure parse + detect (the KDF is unvalidated against the commercial tool; labelled detect-only until a real `.pye` known-answer vector lands).

**other ecosystems**

- `disrobe-pass-js-deob` - JS/TS string-array + unminify + scope-aware rename + bundle splitter.
- `disrobe-pass-wasm-deob` - WebAssembly analyze / lift (Rust / TS / WAT / C) + 5 obfuscator families.
- `disrobe-pass-jvm` - in-house classfile / dex parse + ProGuard/R8 mapping replay + protector detect & structural peel, with headless CFR / Vineflower / Procyon / JADX wraps.
- `disrobe-pass-dotnet` - in-house PE/CLR/table-stream parse + 20+ obfuscator reversers (ConfuserEx2 constant decrypt, ...) + R2R header classify, with headless ILSpy / dnSpyEx / de4dot wraps.
- `disrobe-pass-native` - PE / ELF / Mach-O symbol recovery + clean-room packer decoders (UPX / Petite / kkrunchy / MEW via an in-house stub emulator) + headless Ghidra wrap.
- `disrobe-pass-go` - Go binary recovery: pclntab, moduledata, garble report, `embed.FS` extraction.
- `disrobe-pass-swift-objc` - Swift / Objective-C class-dump + SwiftShield undo + Confidential XOR-decrypt.
- `disrobe-pass-mobile` - React Native / Hermes / Flutter / Cordova / Capacitor / NativeScript / Xamarin.
- `disrobe-pass-lua` - Lua 5.1 .. 5.4 / LuaJIT / Luau / GLua decompile + obfuscator peel.
- `disrobe-pass-php` - encoder decode (phar / ionCube / SourceGuardian / ZendGuard) + eval-chain peel.
- `disrobe-pass-ruby` - MRI / YARV / mruby / JRuby / TruffleRuby / Ruby2Exe / Ocra flavor analysis.
- `disrobe-pass-beam` - BEAM (Erlang / Elixir) IFF chunk parse + Core Erlang lift + Code chunk disasm.
- `disrobe-pass-as3` - ActionScript 3 SWF parse + DoABC tag disasm.
- `disrobe-pass-shell` - shell-script deobfuscation pass.

**surfaces**

- `disrobe-cli` - the `disrobe` binary: every subcommand, the HTTP/gRPC/LSP `serve` daemon & the chain orchestrator.
- `disrobe-python` - pyo3 bindings exposing the same library code as the importable `disrobe` module.

## Branch model

`main` is always releasable. work in feature branches, open a PR, squash-merge when green.
branch naming: `pass/<name>`, `fix/<slug>`, `feat/<slug>`, `refactor/<slug>`. keep them
short-lived.

## Adding a new pass crate

1. understand the IR rung your pass targets (Raw=0 .. Surface=4) & what `REQUIRES` / `PRODUCES` mean in the capability system - see `crates/disrobe-ir/src/lib.rs`.
2. create `crates/disrobe-pass-<name>/`. minimum viable crate: a `Cargo.toml` with workspace dep inheritance & a `lib.rs` that registers a `PassDescriptor`. add a `chain` feature & a `chain_detector` module if it should join the auto-chain.
3. wire it into `disrobe-cli`: add the crate as an `optional = true` dependency, add a matching `<ecosystem>` feature to `[features]`, declare the cli sub-module behind `#[cfg(feature = "...")]`, gate the `Cmd` variant + dispatch arm the same way & register it in the chain registry (`cli/chain_v1.rs`) under that cfg. document the new flag in this file (the README is generated & off-limits).
4. emit at least `--emit source` & `--emit report`. output must be deterministic: same input bytes -> same output bytes.
5. add a fixture under `corpus/` (next section) & a test that pins behaviour against it.
6. benchmark with `cargo bench -p disrobe-pass-<name>` & note the baseline in the PR description.

**grey-zone protectors** (commercial obfuscators with active legal programs - VMProtect, Themida,
certain DRM stacks): open an issue first. a research review runs before a pass targeting one of
these ships. this isn't about discouraging the work; it's about documenting the statutory basis
before any code lands.

## Adding a fixture

fixtures live under `corpus/<ecosystem>/`. real-tool-generated artifacts are preferred over
synthetic ones; when a fixture is heavy or platform-built it stays gitignored & a regen script
ships instead.

1. add a generator: extend `corpus/generate.sh` / `corpus/generate.ps1` (or drop a dedicated `scripts/regen-*.sh` for platform-specific tooling like the Mach-O slices).
2. record provenance in the ecosystem's `MANIFEST.toml` - `schema_version`, a `description`, & one `[[fixtures]]` block per artifact with `path`, `format`, `tool` & `provenance`. byte-identical reproducibility is the goal; note it when a fixture can't be reproduced cross-host.
3. small reproducible binaries may be committed (un-gitignore with a `!` negation); large or non-reproducible ones stay ignored & lean on the regen script. tests that depend on a gitignored fixture are marked `#[ignore]` with a regen hint in the message.

## The `--llm` sidecar protocol

every pass can emit a versioned metadata sidecar alongside its normal output. the schema is
`disrobe.metadata.llm.v1` (see `disrobe-llm-metadata`). selection is additive:

- packs: `--metadata-pack-1` (ast + disasm + symbols + strings) through `--metadata-pack-4` (pack-3 + confidence + opcode-coverage + pii-map + decryption-keys, auth-gated). `--llm` aliases pack-4.
- categories: granular toggles like `--ast`, `--disasm`, `--cfg`, `--dfg`, `--symbols`, `--strings`, `--types`, `--imports`, `--constants`, `--signatures` compose with the packs.

a pass implements `LlmMetadataEmitter::emit_metadata(&selection)`; the cli writes the bundle next
to the primary artifact with a per-pass `PipelineStep` provenance record (input hash, consumed &
produced rungs, duration). the bundle is deterministic & never phones home.

## Local verify chain

run the full chain before you push; CI runs the same with `RUSTFLAGS=-D warnings`:

```
cargo check --workspace --all-features
cargo check --workspace --no-default-features
cargo clippy --workspace --all-features --all-targets -- -D warnings -W unreachable_pub -W missing_debug_implementations -W unused
cargo fmt --all -- --check
cargo test --workspace            # unit + integration; run per-crate if RAM is tight
cargo deny check                  # advisories + licenses + bans + sources
typos
```

determinism rules the linter also enforces:

- `HashMap` / `HashSet` are banned from emit paths via `clippy.toml`. use `IndexMap` / `IndexSet` (or `BTreeMap` / `BTreeSet` for sorted output).
- no `SystemTime::now()` or unseeded randomness inside a pass. route through `disrobe_core::time` & `disrobe_core::rng`.
- no `.unwrap()` in library code; `.expect("invariant: ...")` is acceptable when the invariant is genuinely unbreakable.
- self-document via naming. WHY / gotchas / invariants go in `INFORMATION.md`, not in `//` comments. `///` doc-comments on public items are fine.

## Push-block hook & allow-push

this repo carries a PreToolUse guard that blocks every remote-mutating git/gh call (push, PR
create, release, tag push) from inside an agent session by default. the guard consumes a
single-use token:

```
bash .claude/allow-push.sh "first release of disrobe"   # mints one token
```

the next push the agent runs consumes & deletes the token, then the block is back. a
`.claude/push-lockout` file hard-disables the opt-in entirely; remove it to lift the lockout.
human contributors pushing from their own shell are unaffected - this only gates the
in-session agent.

## Security routing

found a vulnerability - a sandbox escape, a path-traversal in an extractor, a pass that writes
outside its declared output dir - do not open a public issue. follow the private disclosure
process in [SECURITY.md](../SECURITY.md). include a minimal reproducer (input bytes, command
line, expected vs observed behavior), the `disrobe --version` output & the OS / arch.

## Commit messages

imperative mood, 72-character subject line, no period. body is optional; use it for non-obvious
motivation, not for restating the diff. commit as yourself with a noreply email so the address
isn't exposed:

```
git -c user.email="<id>+<handle>@users.noreply.github.com" commit -m "Add PyArmor v9 co_code reconstruction"
```

never attribute authorship to anyone not listed in `NOTICE`. never add a co-author trailer
unless the project settings opt into it.

## Release policy

releases are prebuilt binaries only, cut by `.github/workflows/release.yml` on a `vX.Y.Z` tag
(or manual dispatch). the workflow cross-builds per-target artifacts with build attestations &
publishes a GitHub release. `disrobe` is **not** published to crates.io, PyPI, Homebrew or winget
- there is nothing to `cargo install` or `pip install` from a registry. to run a release build
from source: `cargo build --release --bin disrobe`.

## What won't merge

- any pass that produces non-deterministic output.
- code with `// TODO`, `// FIXME`, `unimplemented!()` or `todo!()` in a non-stub position.
- anything that phones home, writes outside the declared output directory, or modifies the input.
- attribution of authorship to anyone not listed in `NOTICE`.
