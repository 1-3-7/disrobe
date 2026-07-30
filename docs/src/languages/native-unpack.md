# Native unpacking and devirtualization

`disrobe` detects the runtime packer on a PE / ELF / Mach-O and unpacks it, driving stub-based packers through an in-house x86 emulator, and lifts bytecode-VM protected code back to IR and pseudo-code.

For symbol recovery, disassembly, identification, and forensics see the [native guide](./native.md); for the in-tree decompiler see [native decompile](./native-decompile.md).

## At a glance

| Tier | Support |
|---|---|
| In-house decoders | UPX, MPRESS, Petite, MEW, ASPack, PECompact, FSG, NSPack, kkrunchy and kkrunchy classic |
| Stub emulation | Yoda's Crypter is driven to its original entry point through the in-house x86 stub emulator. The same emulator drives <!-- packer-roster:stub-eval-pending -->ASProtect, Morphine, nPack, NeoLite, PolyCryptor, Warzone Crypter<!-- /packer-roster -->, whose tier records the emulator as validated against spec-built stubs with real-sample recovery still unproven |
| Detect and carve | <!-- packer-roster:grey-zone-detect-and-carve -->Yoda's Protector, VMProtect, Themida / WinLicense<!-- /packer-roster --> |
| Detect only, no static recovery | <!-- packer-roster:grey-zone-detect-only -->PE-Protector, PELock, Enigma Protector, Armadillo, Obsidium, WinLicense<!-- /packer-roster --> |
| Bytecode-VM devirtualization | Interpreter located, handler micro-ops fingerprinted behaviorally, opcode table recovered, VM CFG reconstructed, bytecode lifted to re-executable IR plus pseudo-code |
| Devirtualization grade | Recovered IR re-executes to the same outputs as the original across arithmetic, loop, and branch programs, lifted from machine code alone (`vm_devirt_oracle.rs`) |
| Per-fixture scores | Pinned in `corpus/native/packers/MANIFEST.toml` |

## Commands

```sh
disrobe native unpack packed.exe --out unpacked.bin
disrobe native devirt protected.exe --out recovered/
```

`native devirt` writes the recovered listing, the pseudo-code, and a `devirt.manifest.json` (schema `disrobe.native.devirt/v1`) into the output directory.

## Coverage and fidelity

### Packers

In-house decoders cover UPX (`.text` and `.pdata` byte-identical, ~96% whole loaded image), MPRESS, Petite, MEW, ASPack, and PECompact, plus NSPack, FSG and Petite, each of which ships a committed original and packed pair so its byte-recovery figure re-derives from a clean checkout; kkrunchy and kkrunchy classic ship committed fixtures and recover their payload at a pinned 100.00% floor from a clean checkout.

On committed samples ASPack and PECompact rebuild the decompressed section image at its load RVA: the section report confirms the recovered `.text` byte-identical and the import table >=98% byte-identical to the original, both gated in CI, while the packed `.text` of near-random entropy and zero resolvable calls drops to ~6.2-6.5 with hundreds of disassembler-resolvable intra-code calls. Because the whole rebuild is a loaded-memory image rather than a disk-aligned file, the bench marks whole-output byte-identity n/a. MEW rebuilds a flat image of the committed Sysinternals samples, read as the entropy drop to ~4.2-4.9 and tens of thousands of decoded instructions.

Yoda's Crypter is recovered by driving its unpack stub through the in-house x86 stub emulator: the stream decryptor runs to the original entry point inside the emulator, then the reconstructed sections are read back and sliced byte-for-byte, so its `.rsrc` recovers byte-identical and its `.text` decrypts to full plaintext. The same emulator drives <!-- packer-roster:stub-eval-pending -->ASProtect, Morphine, nPack, NeoLite, PolyCryptor, Warzone Crypter<!-- /packer-roster -->, which sit one tier lower: the emulator is validated against spec-built stubs, and no vendor-packed sample in the corpus proves recovery on a real one.

Per-fixture recovery scores are pinned in `corpus/native/packers/MANIFEST.toml`.

### Bytecode-VM devirtualization

`disrobe native devirt` targets the bytecode-VM tier rather than the compression tier. It locates the interpreter, fingerprints each handler's micro-op behaviorally by probing it through the in-tree x86 emulator (so a per-build handler permutation does not break the lift), recovers the handler-to-opcode table, reconstructs the VM CFG, and lifts the handler bytecode to a re-executable IR plus pseudo-code.

The lifter is validated end-to-end on a self-authored Tigress-shape bytecode VM: the recovered IR re-executes to the same outputs as the original across arithmetic, loop, and branch programs, lifted from machine code alone (`vm_devirt_oracle.rs`).

## Limits

- FSG, NSPack, and Petite decode through their in-house decoders but ship no committed fixture (their samples live under the gitignored `.developer/` tree), so no number reproduces from a checkout.
- Yoda's Protector is detect + resource-carve, its stream key being a runtime-only value absent from the file.
- On UPX and NSPack the whole-image residual is the loader-rebuilt zone (bound import address table and base relocations): those addresses are resolved by the OS loader at run time and are not present in the packed stream, not a decoder gap.
- The virtualizing protector tier (VMProtect, Themida, Enigma, and 15+ others) is detect-and-carve: the stub is still driven through the emulator, but the original code is decrypted only by a per-machine key assembled after the stub validates an un-instrumented host (RDTSC deltas, debugger-handler identity, BOUND/FPU exception fingerprints). That key is not present in the file, so faithful recovery is an information-theoretic wall; `disrobe` carves what survives in place and reports the wall rather than fabricating an unpack.
- The commercial VM front-ends (VMProtect, Themida, Code Virtualizer, Enigma, WinLicense, PELock) mutate their handler set per build. The lifter is the generic engine and the Tigress-shape VM is its validated level, but `disrobe` ships no per-family devirtualizer for the commercial protectors, so those are detected and section-carved rather than lifted back to source.
- A handler stream assembled at run time from a per-machine key, or fetched over the network, is an information-theoretic residual. Protector identification and section carve stay available for every family.
