# Installation

`disrobe` is distributed two ways: **prebuilt binaries** from the GitHub Releases tab, and **build from source** with a single Rust toolchain. There is intentionally no PyPI/npm/Homebrew/crates.io/Docker channel for the binary itself; GitHub Releases is the canonical distribution point.

## Prebuilt binaries (recommended)

Each tagged release attaches prebuilt, statically-linkable binaries for the common targets, alongside `SHA256SUMS`, a cosign keyless signature bundle per archive, a GitHub build-provenance attestation, and a CycloneDX SBOM. See [Security](security.md#verifying-release-artifacts) for the full verification story.

| OS | Architectures |
|---|---|
| Windows 10/11 | x86-64, ARM64 |
| Linux (glibc + musl) | x86-64, ARM64 |
| macOS 13+ | x86-64, ARM64 (Apple Silicon) |

1. Download the archive for your platform from the [Releases page](https://github.com/1-3-7/disrobe/releases).
2. Verify the checksum:

   ```sh
   sha256sum -c SHA256SUMS        # Linux / macOS
   ```

3. (Optional) verify the cosign signature against the Sigstore transparency log:

   ```sh
   cosign verify-blob \
     --certificate-identity-regexp '^https://github.com/1-3-7/disrobe/' \
     --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
     --bundle    disrobe-<version>-<target>.tar.zst.cosign.bundle \
     disrobe-<version>-<target>.tar.zst
   ```

4. Extract and place `disrobe` (`disrobe.exe` on Windows) anywhere on your `PATH`.

## Build from source

Building requires **Rust 1.95 or newer** (stable). That is the only build dependency for the core; the optional external backends are fetched separately (see below).

```sh
git clone https://github.com/1-3-7/disrobe
cd disrobe
cargo build --release
./target/release/disrobe --version
```

A release build takes roughly four to six minutes on commodity hardware. The binary lands at `target/release/disrobe`; copy it onto your `PATH`.

### Per-OS notes

- **Windows:** the binary is `disrobe.exe`.
- **Linux:** the musl build is fully static; the glibc build needs a matching glibc.
- **macOS:** x86-64 and ARM64 (Apple silicon) archives are published separately. Gatekeeper may quarantine an unsigned download; clear it with `xattr -d com.apple.quarantine disrobe`.

## The dependency boundary

Building and running `disrobe` are one dependency set. Grading and reproducing its published numbers are two others, and the three never blur together.

| Category | What is in it | What breaks without it |
|---|---|---|
| Core (build and run) | Rust 1.95+ stable, nothing else | Nothing; `cargo build --release` produces the full binary |
| Optional backend | Ghidra, CFR, jadx, ILSpy, de4dot, and others, selected with `--backend <tool>` | One feature: that pass falls back to the in-house default, which still runs |
| Grading only | CPython, `javac`, the real JVM verifier, wasmtime, `lua`/`luac`, MRI, the .NET SDK, and the Go toolchain | One grade: the recovery is unaffected, but that ecosystem's number cannot be regraded locally |
| Benchmark repro only | The pinned competing tools in `evidence/competitors/` | One number: the head-to-head row cannot be reproduced; `disrobe`'s own recovery is unaffected |

The per-ecosystem list for the last two rows is in [evidence/README.md](https://github.com/1-3-7/disrobe/blob/main/evidence/README.md).

## Slim build

`cargo build --release` produces the full everything-binary: every language and format pass compiled in. For a smaller artifact, opt into a slim build that keeps the always-on core (Python bytecode, native PE / ELF / Mach-O, and the container and format layer) and drops the optional passes:

```sh
cargo build -p disrobe-cli --release --no-default-features
# same build, shorter
cargo build-slim
```

Slim drops the optional language and format passes (JavaScript / TypeScript, WebAssembly, JVM / Android, .NET, Go, Lua, PHP, Ruby, BEAM, Swift, AS3, and more) and the multi-stage `auto` chain. Dropping them also drops large dependency trees such as the embedded JavaScript engine and the WebAssembly toolchain. On a Windows release build that trims the binary from about 75 MB to 49 MB, roughly a third smaller; the exact figure varies by platform and toolchain. The `wasm` subcommand still parses in a slim binary. If you run it, it reports why the pass is missing:

```text
$ disrobe wasm decompile app.wasm
Error: the `wasm` pass is not compiled into this binary (slim build); rebuild with default features (feature `wasm`)
```

Layer specific passes back onto a slim base with `--features`, for example `--no-default-features --features wasm,jvm`.

## Verifying the install

```sh
disrobe --version          # print the version
disrobe passes             # list every registered pass with a one-line summary
disrobe --help             # full subcommand surface
disrobe <pass> --help      # drill into any pass, e.g. `disrobe py --help`
```

## Optional external backends

`disrobe`'s in-house passes run with zero external dependencies. A subset of capabilities, however, wrap mature external tools headlessly: Ghidra for native decompilation; CFR / Vineflower / Procyon / jadx for the JVM and Android; ILSpy / dnSpy / de4dot for .NET; Rizin and friends elsewhere. These are never the product for bytecode languages (`disrobe` ships its own in-house decompilers there) and are always optional.

Probe what is installed and what is missing:

```sh
disrobe doctor                 # probe ~50 optional external tools
disrobe doctor --auto-install  # install every missing tool with a known action
```

Install a single tool through your platform's native package manager (`winget` / `brew` / `apt` / `dnf` / `pacman` / `apk`). `disrobe` never installs itself this way; it only fetches the optional backends:

```sh
disrobe install --list         # list every known tool + per-platform package name
disrobe install ghidra
disrobe install upx
```

Heavyweight dependencies that ship as upstream release archives rather than OS packages (Ghidra, for instance) have a dedicated installer:

```sh
disrobe install-deps ghidra
disrobe install-deps --all
```

## Shell completions and man pages

```sh
disrobe completions bash --install        # also: zsh, fish, powershell, elvish
disrobe man --out ./man                   # one .1 page per subcommand
```
