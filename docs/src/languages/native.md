# Native (PE / ELF / Mach-O)

**disrobe** does **not** compete with Ghidra, IDA, or Binary Ninja on raw decompilation. It is the unpack, symbol-recovery, and chain-detect layer that feeds those tools cleaner input — and it wraps Ghidra headlessly when you want a full decompile in one command.

## Symbol recovery and dumping

```sh
disrobe native symbols app.exe --out symbols.json
```

Dumps symbols, sections, segments, imports, and debug info from a PE / ELF / Mach-O. Demangles and restores Rust and C++ symbols across x86 / ARM / RISC-V / MIPS / PowerPC / SPARC / eBPF, reading DWARF, PDB, and STABS debug formats.

## Unpacking native packers

```sh
disrobe native unpack packed.exe --out unpacked.bin
```

Detects the runtime packer and unpacks it. Clean-room decoders cover UPX (byte-identical), MPRESS, NSPack, FSG, Petite, kkrunchy, and MEW. The commercial tier (VMProtect, Themida, Enigma, and 15+ others) is honest detect-only by design — **disrobe** reports the packer and carves what it can rather than fabricating an unpack. Per-fixture recovery scores are pinned in `corpus/native/packers/MANIFEST.toml`.

## Forensic primitives

```sh
disrobe native entropy app.exe --out entropy.json        # 4KB sliding-window Shannon entropy
disrobe native signatures app.exe --out sigs.json        # AES T-tables, SHA/MD5 IV+K, ChaCha20 sigma
disrobe native signatures app.exe --flirt db.sig         # match against an IDA FLIRT database
disrobe native fingerprint app.exe                       # crypto + FLIRT + string-xref sidecar
disrobe native graph app.exe --out imports.dot           # import/export table as Graphviz DOT
disrobe native sbom app.exe --out app.cyclonedx.json     # CycloneDX 1.5 SBOM from cargo-auditable metadata
```

## Full decompile via Ghidra

```sh
disrobe native decompile app.exe --out decompiled/
```

Runs Ghidra headlessly (install it with `disrobe install-deps ghidra`) and returns pseudo-C alongside the standardized emits. This is the one place where an external native engine is the legitimate primary — **disrobe**'s job is to hand it a clean, unpacked, symbol-rich input.
