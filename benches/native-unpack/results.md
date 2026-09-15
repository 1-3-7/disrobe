# Native unpacking measurements

The samples below are statically recovered through `disrobe-pass-native`'s unpack API. Section bytes are compared with committed originals where an aligned reference exists. Entropy, instruction counts, and call targets describe the selected code span. The four FSG, NSPack, Petite, and MPRESS packed spans are their file-backed entry-point sections; FSG's section has no execute flag. Instruction counts use `disrobe_pass_native::disassemble`, and call targets use iced-x86 decoding.

Regenerate with `cargo run -p disrobe-bench-native-unpack`; `--check` fails if the committed table drifts from a fresh run.

## Signals

- byte-identity: percentage of the named recovered section that is byte-for-byte the committed original section. Loaded-memory outputs are compared at the original section RVAs with the original section span as the denominator; rows without an independent, aligned original remain `n/a`.
- entropy (bits/byte): Shannon entropy of the selected span, from 0 for identical bytes to 8 for a uniform byte distribution. Padding and compressed data affect this value.
- instructions: linear-sweep count decoded using each fixture's x86 or x86-64 architecture. Data in the selected span can also decode as instructions.
- intra-calls: distinct near-`call` targets inside the selected span. This counts candidate function entries, not confirmed functions.

| packer | binary | byte-identity | entropy (packed -> unpacked) | instructions (packed -> unpacked) | intra-calls (packed -> unpacked) | notes |
|---|---|---|---|---|---|---|
| UPX | hello (Rust x64) | .text 100.00% (73160 B, 0 diff) | 7.89 -> 6.40 | 18191 -> 20847 | 3 -> 201 | NRV2B method, CT filter 0x49, UCL adler verified |
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
| Yoda's Protector | Clockres (Sysinternals) | walled (no key in artifact) | n/a | n/a | n/a | runtime key unavailable; the stub emulator mutates 0 content bytes; resources recover 100.0% in place |
| Yoda's Protector | AccessEnum (Sysinternals) | walled (no key in artifact) | n/a | n/a | n/a | runtime key unavailable; the stub emulator mutates 0 content bytes; resources recover 97.5% in place |
| FSG | Hash (PackingData x86) | .text 100.00% (18188 B, 0 diff) | 4.61 -> 6.54 | 253 -> 6236 | 3 -> 40 | FSG 2.0 aPLib block recovery; packed metrics cover the entry-point section; content recovery 54621/60060 (90.94%) against the committed original |
| NSPack | hash (PackingData x86) | .text 100.00% (18188 B, 0 diff) | 0.64 -> 6.54 | 58 -> 6236 | 0 -> 40 | NSPack 3.7 range-decoder recovery; packed metrics cover the entry-point section; content recovery 57721/60060 (96.11%) against the committed original |
| Petite | hello (Rust x86) | .text 100.00% (70796 B, 0 diff) | 7.98 -> 6.56 | 19753 -> 23538 | 3 -> 229 | Petite 2.4 bounded stub emulation; packed metrics cover the entry-point section; content recovery 86986/89648 (97.03%) against the committed original |
| MPRESS | gauntlet_target (Rust x64) | .text 100.00% (73160 B, 0 diff) | 6.09 -> 6.40 | 1167 -> 20847 | 1 -> 201 | MPRESS 2.19 LZMAT decode and branch unfilter; packed metrics cover the entry-point section; content recovery 97477/102236 (95.35%) against the committed original |

## Reading the table

- UPX: the recovered `.text` is byte-identical to the committed original. Both packed and recovered spans are decoded as x86-64.
- ASPack / PECompact: the packed `.text` is near-random with zero resolvable calls; after the phase-2 overlay the same section at the same RVA decodes to dozens to hundreds of real intra-code calls with entropy below 6.6.
- MEW: the packed image carries no analyzable executable section (the `MEW` section is virtual-only, shown as `n/a`); the rebuilt PE exposes a large `.text` that decodes to tens of thousands of instructions with hundreds of intra-code calls.
- kkrunchy classic: the decompressed `hello` is tiny and calls imports directly, so the call signal is zero on both sides; the entropy collapse and recovered instruction count are the recovery signal.
- Yoda's Crypter: `.rsrc` recovers byte-identical to the committed original (the byte-identity column) and `.text` decrypts to full plaintext through the stub emulator (the note's plaintext fraction), its entropy dropping from near-random to code-like. This is asserted in `crates/disrobe-pass-native/tests/packer_real_samples.rs`.
- Yoda's Protector: the stream key is a runtime value absent from the file. The bounded stub emulator mutates zero content bytes; resources recover in place, while encrypted code remains unavailable for byte-identity comparison.
- FSG, NSPack, Petite, and MPRESS: one committed packed/original pair per family is measured through the public in-process recovery API. The fixed population is FSG `Hash.packed.fsg.exe` / `Hash.original.exe`, NSPack `hash.packed.nspack.exe` / `hash.original.exe`, Petite `hello.exe` / `hello.original.exe`, and MPRESS `gauntlet/gauntlet_target.packed.mpress219.exe` / `gauntlet/gauntlet_target.original.exe`. Each input is checked against its pinned size and SHA-256 before recovery. A missing, unreadable, malformed, mutated, or unrecoverable member fails regeneration rather than shrinking this population.

The benchmark's `committed_family_population_is_measured_from_known_originals` test checks the four added families. Related recovery checks live in `crates/disrobe-pass-native/tests/native_unpack_disasm.rs`, `crates/disrobe-pass-native/tests/packer_real_samples.rs`, and `crates/disrobe-pass-native/tests/upx_unpack_all.rs`.
