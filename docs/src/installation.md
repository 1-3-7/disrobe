# Installation

Install `disrobe` from **GitHub Releases** or build the CLI from source. GitHub Releases is the canonical distribution point for the standalone binary; the Python bindings are a separate integration.

## Prebuilt binaries (recommended)

Each tagged release includes prebuilt binaries for the common targets, alongside `SHA256SUMS`, a cosign keyless signature bundle per archive, a GitHub build-provenance attestation, and a CycloneDX SBOM. See [Security](security.md#verifying-release-artifacts) for artifact verification.

| OS | Architectures |
|---|---|
| Windows 10/11 | x86-64, ARM64 |
| Linux (glibc) | x86-64, ARM64 |
| Linux (musl) | x86-64 |
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

The workspace declares **Rust 1.95** as its minimum supported version. Use the repository's selected
Rust toolchain and a linker/C toolchain for your target; native dependencies also compile during the
build. On Windows with the MSVC target, install the Visual C++ build tools and Windows SDK. Optional
analysis backends and the language runtimes used by grading tests are separate prerequisites.

```sh
git clone https://github.com/1-3-7/disrobe
cd disrobe
cargo build --locked --release -p disrobe-cli --bin disrobe
./target/release/disrobe --version
```

The binary lands at `target/release/disrobe`; copy it onto your `PATH`.

### Per-OS notes

- **Windows:** the binary is `disrobe.exe`.
- **Linux:** the musl build is fully static; the glibc build needs a matching glibc.
- **macOS:** x86-64 and ARM64 (Apple silicon) archives are published separately. Gatekeeper may quarantine an unsigned download; clear it with `xattr -d com.apple.quarantine disrobe`.

## The dependency boundary

The required tools depend on whether you are building the CLI, selecting an external backend,
or reproducing a measurement.

| Category | What is in it | What breaks without it |
|---|---|---|
| CLI build | Supported Rust toolchain and target linker/C toolchain | The CLI cannot be built until its compiler and native dependency prerequisites are present |
| Optional backend | Ghidra, CFR, jadx, ILSpy, de4dot, and others, selected by the command's backend option | Behavior depends on the command's selection and fallback contract; inspect the reported backend, especially when the requested tool is unavailable |
| Grading only | CPython, `javac`, the real JVM verifier, wasmtime, `lua`/`luac`, MRI, the .NET SDK, and the Go toolchain | One grade: the recovery is unaffected, but that ecosystem's number cannot be regraded locally |
| Benchmark repro only | The pinned competing tools in `evidence/competitors/` | One number: the head-to-head row cannot be reproduced; `disrobe`'s own recovery is unaffected |

The per-ecosystem list for the last two rows is in [evidence/README.md](https://github.com/1-3-7/disrobe/blob/main/evidence/README.md).

## Slim build

The CLI's default features select the full build. For a smaller artifact, the slim build keeps
the always-on core and drops optional passes. A command can remain visible in help while its
implementation reports that the corresponding feature was not compiled in:

```sh
cargo build -p disrobe-cli --release --no-default-features
# same build, shorter
cargo build-slim
```

Slim excludes optional language passes and their dependencies, including the embedded JavaScript
and WebAssembly toolchains. It also excludes optional service and collection surfaces. The
dependency-tree gate enforces the expected crate graph for the selected features.

Binary size and command availability depend on the target, source revision and selected features.
Compare builds of the same revision with the same compiler and profile before claiming a size
reduction. Some commands are omitted from help; others, including `wasm`, remain declared and
report the missing feature when invoked:

```text
$ disrobe wasm decompile app.wasm
Error: the `wasm` pass is not compiled into this binary (slim build); rebuild with default features (feature `wasm`)
```

Layer specific passes back onto a slim base with `--features`, for example `--no-default-features --features wasm,jvm`.

## Verifying the install

```sh
disrobe --version          # print the version
disrobe passes             # direct families plus auto-chain pass IDs
disrobe --help             # full subcommand surface
disrobe <pass> --help      # drill into any pass, e.g. `disrobe py --help`
```

## Optional external backends

Disrobe includes its own recovery engines for native code and the supported bytecode languages. External backends add rendering and analysis paths: Ghidra for native decompilation; CFR, Vineflower, Procyon, and JADX for JVM and Android inputs; ILSpy, dnSpy, dnSpyEx, and de4dot for .NET. Backend selection is command-specific. In particular, JVM and .NET `--backend auto` can invoke an installed tool; the corresponding JVM and .NET `disrobe auto` passes use their in-process engines. Recompilation checks have separate compiler/interpreter prerequisites, as listed above.

Probe what is installed and what is missing:

```sh
disrobe doctor                 # probe 46 to 51 external tools depending on the platform
disrobe doctor --auto-install  # install every missing tool that has a known install action
```

A missing tool with no install action (a commercial tool, a tool that ships bundled with another
tool, a platform-exclusive tool, or a tool preinstalled by the operating system) is not silently
dropped. `--auto-install` records it as a skip with a typed reason, in both text and `--json`
output.

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
