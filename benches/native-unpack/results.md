# Native unpack: disrobe-recovered code, measured in-tree

Each committed packer sample under `corpus/native/packers/` is run through `disrobe-pass-native`'s unpack API. No external tool participates: byte-identity is a direct compare against the committed known-good original, Shannon entropy is computed over the executable section, and the disassembler signals come from disrobe's own in-house disassembler (`disrobe_pass_native::disassemble` for the instruction count, the same iced-x86 structured decode the native pass uses in `desync.rs` for resolved call targets).

Regenerate with `cargo run -p disrobe-bench-native-unpack`; `--check` fails if the committed table drifts from a fresh run.

## Signals

- byte-identity: percentage of the recovered `.text` that is byte-for-byte the committed original `.text`. Only meaningful where the recovered output is disk-section-aligned (UPX clean unpack, Yoda's Crypter section decrypt); the overlay and flat-dump rebuilds expose a decompressed loaded-memory image with no disk-aligned reference, marked `n/a`.
- entropy (bits/byte): compressed payloads sit near 8.0; native x86 code is roughly 5.5 to 6.5, padded dumps lower.
- instructions: linear-sweep count of decoded instructions from `disrobe_pass_native::disassemble(Arch::X86, ...)`.
- intra-calls: distinct near-`call` targets that land inside the executable section, a proxy for real resolved functions a recursive disassembler would follow.

| packer | binary | byte-identity | entropy (packed -> unpacked) | instructions (packed -> unpacked) | intra-calls (packed -> unpacked) | notes |
|---|---|---|---|---|---|---|
| UPX | hello (Rust x64) | .text 100.00% (73160 B, 0 diff) | 7.89 -> 6.40 | 20394 -> 31388 | 0 -> 201 | NRV2B method, CT filter 0x49, UCL adler verified |
| ASPack | Clockres (Sysinternals) | n/a (decompressed-image overlay, no disk-aligned ref) | 7.99 -> 6.48 | 12451 -> 10031 | 0 -> 180 | phase-2 stub emulation overlays decompressed section at load RVA |
| ASPack | AccessEnum (Sysinternals) | n/a (decompressed-image overlay, no disk-aligned ref) | 7.95 -> 6.36 | 6295 -> 5443 | 0 -> 52 | phase-2 stub emulation overlays decompressed section at load RVA |
| PECompact | Clockres (Sysinternals) | n/a (decompressed-image overlay, no disk-aligned ref) | 7.99 -> 6.52 | 17917 -> 15044 | 0 -> 261 | phase-2 stub emulation overlays decompressed section at load RVA |
| PECompact | AccessEnum (Sysinternals) | n/a (decompressed-image overlay, no disk-aligned ref) | 7.98 -> 6.19 | 13544 -> 12093 | 0 -> 110 | phase-2 stub emulation overlays decompressed section at load RVA |
| MEW | Clockres (Sysinternals) | n/a (flat-dumped image, no disk-aligned ref) | n/a -> 4.27 | n/a -> 81101 | n/a -> 340 | aPLib + LZMA1 rebuild of flat dumped PE32, OEP stamped |
| MEW | AccessEnum (Sysinternals) | n/a (flat-dumped image, no disk-aligned ref) | n/a -> 4.85 | n/a -> 95968 | n/a -> 120 | aPLib + LZMA1 rebuild of flat dumped PE32, OEP stamped |
| MEW | Autologon (Sysinternals) | n/a (flat-dumped image, no disk-aligned ref) | n/a -> 4.20 | n/a -> 79620 | n/a -> 302 | aPLib + LZMA1 rebuild of flat dumped PE32, OEP stamped |
| kkrunchy | hello (NASM PE32, classic) | n/a (decompressed standalone PE, no disk-aligned ref) | 5.64 -> 1.81 | 225 -> 241 | 2 -> 0 | classic CCA range-coder decode, standalone PE emitted |
| Yoda's Crypter | Clockres (Sysinternals) | .rsrc 100.00% (1536 B, 0 diff) | 7.99 -> 6.61 | 25832 -> 22265 | 0 -> 329 | .rsrc recovers byte-identical; .text decrypts to 100.00% plaintext through the stub emulator |
| Yoda's Crypter | AccessEnum (Sysinternals) | .rsrc 100.00% (12288 B, 0 diff) | 7.12 -> 6.34 | 10256 -> 9835 | 0 -> 110 | .rsrc recovers byte-identical; .text decrypts to 100.00% plaintext through the stub emulator |
| Yoda's Protector | Clockres (Sysinternals) | walled (no key in artifact) | n/a | n/a | n/a | info-theoretic wall: decryptor never runs (content bytes mutated by stub = 0), runtime-only key; resources recover 100.0% in place |
| Yoda's Protector | AccessEnum (Sysinternals) | walled (no key in artifact) | n/a | n/a | n/a | info-theoretic wall: decryptor never runs (content bytes mutated by stub = 0), runtime-only key; resources recover 97.5% in place |
| FSG | not committed | skipped | - | - | - | FSG 2.0 fixtures live under gitignored .developer/, not committed |
| NSPack | not committed | skipped | - | - | - | NSPack 3.7 fixtures live under gitignored .developer/, not committed |
| Petite | not committed | skipped | - | - | - | Petite 2.x fixtures live under gitignored .developer/, not committed |
| MPRESS | not committed | skipped | - | - | - | MPRESS 2.19 fixtures live under gitignored .developer/, not committed |

## Reading the table

- UPX: clean in-place unpack; the recovered `.text` is byte-identical to the committed original and entropy falls from near-random to code-like. The relative-call column reads 0 for this Rust binary because its intra-module calls are encoded such that a flat linear sweep at the dumped base does not resolve them; the instruction-count jump is the recovery signal.
- ASPack / PECompact: the packed `.text` is near-random with zero resolvable calls; after the phase-2 overlay the same section at the same RVA decodes to dozens to hundreds of real intra-code calls with entropy below 6.6.
- MEW: the packed image carries no analyzable executable section (the `MEW` section is virtual-only, shown as `n/a`); the rebuilt PE exposes a large `.text` that decodes to tens of thousands of instructions with hundreds of intra-code calls.
- kkrunchy classic: the decompressed `hello` is tiny and calls imports directly, so the call signal is zero on both sides; the entropy collapse and recovered instruction count are the recovery signal.
- Yoda's Crypter: `.rsrc` recovers byte-identical to the committed original (the byte-identity column) and `.text` decrypts to full plaintext through the stub emulator (the note's plaintext fraction), its entropy dropping from near-random to code-like. This is asserted in `crates/disrobe-pass-native/tests/packer_real_samples.rs`.
- Yoda's Protector: a polymorphic protector walled honestly. The decryptor provably never runs (content bytes mutated by the stub = 0) because the stream key is a runtime-only value absent from the file; resources still recover in place. No byte-identity is claimed because none can be measured.

Packers with no committed sample (FSG, NSPack, Petite, MPRESS) are listed as skipped: their fixtures live under the gitignored `.developer/` tree and are not part of the committed corpus, so no number is produced for them here.

The same per-packer measurements are asserted as CI gates in `crates/disrobe-pass-native/tests/native_unpack_disasm.rs` and `crates/disrobe-pass-native/tests/upx_unpack_all.rs`.
