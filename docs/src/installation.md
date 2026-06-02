# Installation

disrobe is distributed two ways: **prebuilt binaries** from the GitHub Releases tab, and **build from source** with a single Rust toolchain. There is intentionally no PyPI/npm/Homebrew/crates.io/Docker channel for the binary itself; GitHub Releases is the canonical distribution point.

## Prebuilt binaries (recommended)

Each tagged release attaches prebuilt, statically-linkable binaries for the common targets, alongside `SHA256SUMS`, a cosign keyless signature, and a minisign signature.

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
     --signature disrobe-<version>-<target>.tar.zst.sig \
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

## Verifying the install

```sh
disrobe --version          # print the version
disrobe passes             # list every registered pass with a one-line summary
disrobe --help             # full subcommand surface
disrobe <pass> --help      # drill into any pass, e.g. `disrobe py --help`
```

## Optional external backends

disrobe's in-house passes run with zero external dependencies. A subset of capabilities, however, wrap best-in-class external tools headlessly: Ghidra for native decompilation; CFR / Vineflower / Procyon / jadx for the JVM and Android; ILSpy / dnSpy / de4dot for .NET; Rizin and friends elsewhere. These are never the product for bytecode languages (disrobe ships its own in-house decompilers there) and are always optional.

Probe what is installed and what is missing:

```sh
disrobe doctor                 # probe ~50 optional external tools
disrobe doctor --auto-install  # install every missing tool with a known action
```

Install a single tool through your platform's native package manager (`winget` / `brew` / `apt` / `dnf` / `pacman` / `apk`). disrobe never installs itself this way; it only fetches the optional backends:

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
