# Rust

`disrobe rust inventory` lists what a rustc-built PE, ELF or Mach-O binary was made from: the rustc release, the crates and versions whose code it contains, the dependency graph when cargo-auditable embedded one, and how many Rust symbols each crate contributes when a symbol table survives. It needs no cargo-auditable data to work; the first two come from the source paths rustc compiles into panic messages.

## At a glance

| Layer | Coverage |
|---|---|
| Binary formats | PE, ELF and thin Mach-O, graded on x86-64 builds; a universal Mach-O is refused with `DR-RUSTINV-0002` until one slice is extracted |
| rustc release | `/rustc/<commit>/library/...` panic paths, matched against a bundled table of the 141 stable releases from 1.0.0 to 1.99.0; any other commit is reported by its hash with no release |
| Crates from paths | crates.io and other registries (`registry/src/<index>-<hash>/<crate>-<version>/`), git checkouts (`git/checkouts/<repository>-<hash>/<revision>/`), `vendor/` directories, path dependencies outside the workspace and workspace members, with either path separator |
| Dependency graph | the zlib-compressed `.dep-v0` section cargo-auditable writes into all three formats: every package with source, build or runtime kind and root flag, and every dependency edge |
| Symbols | legacy (`_ZN...17h<hash>E`) and v0 (`_R`) symbols demangled by rustc-demangle and counted per crate |
| Evidence | every rustc commit and crate carries the file offset and exact text it was read from; every per-crate symbol count carries an example symbol with its table index |

## Commands

```sh
disrobe rust inventory app
disrobe rust inventory app.exe --json > app-rust.json
```

Text output for the auditable PE fixture (paths shortened):

```text
rust inventory: pe-1.95.0-release-auditable.exe (Pe, 674816 bytes)
rustc: 1.95.0 59807616e1fa2540724bfbac14d7976d7e4a3860  52 paths  @0x85dc0 /rustc/59807616.../library\panic_abort\src\lib.rs
crates: 10
  aho-corasick 1.1.5  registry index.crates.io-1949cf8c6b5b557f  20 paths  @0x86972 registry\src\...\aho-corasick-1.1.5\src\ahocorasick.rs
  gitdep -  git gitdep-8ea555ce1129ba1e rev 099202b  1 path  @0x85f21 git\checkouts\gitdep-8ea555ce1129ba1e\099202b\src\lib.rs
  pathdep -  path /build\pathdep  1 path  @0x85e86 /build\pathdep\src\lib.rs
  rustinv -  workspace rustinv  1 path  @0x85580 rustinv\src\main.rs
  ...
auditable: .dep-v0 @0xa3800, 340 bytes compressed, 1270 bytes JSON, format 1: 16 packages, 23 edges
  rustinv 0.3.1 (local, runtime, root) -> [anyhow 1.0.102, gitdep 0.2.0, pathdep 1.4.0, regex 1.12.3, serde 1.0.228]
  ...
symbols: no symbol table
```

`--json` prints the same inventory as one JSON document: `rustc`, `crates`, `auditable` (`status` is `absent`, `present` or `refused` with a typed reason), `symbols` and a `truncated` record for the scan limits.

## Coverage and fidelity

rustc builds the standard library with its source directory remapped to `/rustc/<commit>`, so every binary that links std carries that commit in the file names of std's panic locations. The release table is derived from the `X.Y.Z` tags of the rust-lang/rust repository, peeling annotated tags to the commit `rustc -vV` reports; `crates/disrobe-pass-nativelang/tests/support/derive_rustc_releases.py` regenerates it. A nightly, beta or self-built compiler has a commit outside the table, and the inventory reports that commit without naming a release.

Cargo passes each dependency's source path to rustc, and the path stays in the binary wherever a crate can panic. A registry path names the index directory, the crate and the version; a git checkout path names the repository directory, cargo's URL hash and the abbreviated commit. Matching starts at the `registry` or `git` component rather than at `.cargo`, so a `CARGO_HOME` such as the `/usr/local/cargo` of the official container images is read the same way. Path dependencies outside the workspace keep an absolute path and workspace members a relative one, which is how the two are told apart.

Rust string constants are not separated in the binary, so a local path can sit directly after an unrelated message. The start of a local path is therefore taken from the panic location record that points at it and gives its length. That record holds an in-place pointer in PE, Mach-O and non-PIE images (chained-fixup bits are masked off in Mach-O) and a relocation addend in a position-independent ELF. `path_start` records whether a local path was confirmed this way (`location-record`) or is the whole printable run around it (`printable-run`). Every local path in the graded PE, ELF and Mach-O builds resolves through its location record.

The cargo-auditable graph is decoded through the same bounded parser `disrobe native sbom` uses, then checked for dependency indices out of range, self edges and unknown kinds. A section that fails any check is reported as refused with its reason, and the path and symbol results are still returned.

A symbol counts toward the crate its demangled path starts with. For `<T as Trait>::item` and `<T>::item` the self type decides when it is a path and the trait decides otherwise, so `<&T as core::fmt::Debug>::fmt` counts toward `core`.

Six committed builds of one program with serde 1.0.228, regex 1.12.3, anyhow 1.0.102, a git dependency and a path dependency grade every layer: rustc 1.95.0 and 1.96.1, release and dev profiles, stripped and unstripped, legacy and v0 mangling, PE, ELF and Mach-O, three of them built with cargo-auditable 0.7.7 (`corpus/native/rust-inventory/MANIFEST.toml` records each build). The references are produced by other tools: `rustc -vV` for the commit and release, the build's `Cargo.lock` for crate names, versions and sources, rust-audit-info 0.5.4 for the package graph, and llvm-nm 22.1.2 with LLVM's own demanglers for the symbol counts. All six match exactly, and each grade has a control that turns it red when one expected version, release or count changes.

## Limits

- A crate appears in the path inventory only if its code can panic in the binary. In the graded builds, serde contributes no panic path (its code lives in `serde_core`, which does), and build-only crates such as proc macros never reach the binary.
- Git and local crates are named after their directory, not their manifest, and carry no version; the cargo-auditable graph, when present, has both.
- A package at the workspace root compiles as `src/main.rs`, which names no directory, so it is listed without a name.
- Paths are read as printable ASCII. A non-ASCII directory above the crate root shortens the reported root but not the crate name.
- MSVC-linked PE files keep their symbols in the PDB, so they report no symbol table; stripped ELF and Mach-O files report none either.
- Generic code counts toward the crate that defines it, not the crate that instantiated it.
- The standard library's own vendored dependencies (`/rust/deps/...`) and local rust-src paths are recognised and left out of the crate list.
