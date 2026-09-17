# Native unpacking and devirtualization

`disrobe` detects the runtime packer on a PE / ELF / Mach-O and unpacks it, driving stub-based packers through an in-house x86 emulator, and lifts bytecode-VM protected code back to IR and pseudo-code.

For symbol recovery, disassembly, identification, and forensics see the [native guide](./native.md); for the in-tree decompiler see [native decompile](./native-decompile.md).

## At a glance

| Tier | Support |
|---|---|
| In-house decoders | UPX, MPRESS, Petite, MEW, ASPack, PECompact, FSG, NSPack, kkrunchy and kkrunchy classic |
| Stub emulation | Yoda's Crypter is driven to its original entry point through the in-house x86 stub emulator. The same emulator drives <!-- packer-roster:stub-eval-pending -->ASProtect, Morphine, nPack, NeoLite, PolyCryptor, Warzone Crypter<!-- /packer-roster -->, whose tier records the emulator as validated against spec-built stubs with real-sample recovery still unproven |
| Detect and carve | <!-- packer-roster:grey-zone-detect-and-carve -->Yoda's Protector, VMProtect, Themida / WinLicense<!-- /packer-roster -->. The Rust `recover_detected` helper exposes single-input protected-section recovery for VMProtect and Themida; the Themida route also accepts `.winlice` images and labels them WinLicense. CLI and auto remain detect-only for these families. Yoda's Protector exposes an original-assisted comparison carve and an emulator report, but no single-input recovered-image route |
| Detect only, no static recovery | <!-- packer-roster:grey-zone-detect-only -->PE-Protector, PELock, Enigma Protector, Armadillo, Obsidium, WinLicense<!-- /packer-roster -->. These direct packer routes emit no recovered image |
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

- FSG, NSPack, and Petite each ship one committed packed-and-original pair, and the published figures for them are measured on those pairs alone. Their larger samples, and the extra MPRESS and UPX megafiles beside them, are kept out of the tree on size or license; every such path is marked `local` in `corpus/native/packers/MANIFEST.toml` with a recipe for rebuilding or refetching it, and no figure is published for any of them, because nothing in a checkout re-derives one.
- Yoda's Protector is classified as detect-and-carve. Its original-assisted comparison carve reports surviving sections. On the committed fixtures, the `.yP` emulator derives the image-resident RC4 key but halts before `CryptDecrypt`; replaying that key directly over the carved on-disk sections does not recover plaintext because they contain an RC4-encrypted compressed stream. No single-input `recover_detected` route emits a recovered image for this family.
- On UPX and NSPack the whole-image residual is the loader-rebuilt zone (bound import address table and base relocations): those addresses are resolved by the OS loader at run time and are not present in the packed stream, not a decoder gap.
- VMProtect and Themida have single-input detect-and-carve routes through the Rust `recover_detected` helper. It emits bounded verbatim `.vmp*`, `.themida`, or `.winlice` protected-section artifacts. A `.winlice` image handled by the Themida carver is reported as WinLicense. CLI and auto remain detect-only, and neither helper route reconstructs the original code.
- The direct Enigma Protector, WinLicense, PELock, PE-Protector, Armadillo, and Obsidium packer routes are detect-only and emit no recovered image. WinLicense can reach a carve only when the Themida route recognizes its `.winlice` section.
- The generic VM lifter is validated on the Tigress-shape VM. `disrobe` ships no per-family devirtualizer that lifts these commercial protector families back to source.
