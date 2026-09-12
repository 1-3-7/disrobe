# Packed vs disrobe-unpacked: static recovery

Each fixture is a real packed PE from `corpus/native/packers/`. The CLI `native unpack` and
`native export --format ghidra|ida|json` arms run the stub-emulated phase-2 decompressor and rebuild
a loadable PE: ASPack and PECompact overlay the decompressed sections back at their load RVA and
restore the OEP, MEW rebuilds a flat dumped PE32 from the aPLib/LZMA payload with the OEP stamped,
and kkrunchy classic emits the decompressed program as a standalone PE.

## Disassembler-based deltas (iced-x86, no Ghidra required)

The executable section of the packed file and of the rebuilt PE are pulled with the `object` crate
and fed to the same iced-x86 decoder disrobe uses on the disasm rung. Three independent signals,
packed -> rebuilt:

- entropy: Shannon bits/byte over the executable section (compressed data sits near 8.0; native code
  is roughly 5.5 to 6.5, padded dumps lower).
- valid instructions: linear-sweep count of non-invalid x86 decodes.
- intra-section calls: distinct near-`call` targets that land inside the section, a proxy for real
  resolved functions a recursive disassembler would follow.

| packer | binary | entropy | valid instructions | intra-section calls |
|---|---|---|---|---|
| UPX | hello (Rust) | 7.89 -> 5.83 | 19914 -> 50470 | 0 -> 0 |
| ASPack | Clockres | 7.99 -> 6.48 | 12103 -> 10028 | 0 -> 180 |
| ASPack | AccessEnum | 7.95 -> 6.36 | 6113 -> 5443 | 0 -> 52 |
| PECompact | Clockres | 7.99 -> 6.52 | 17403 -> 15042 | 0 -> 261 |
| PECompact | AccessEnum | 7.98 -> 6.19 | 13162 -> 12040 | 0 -> 110 |
| MEW | Clockres | n/a -> 4.27 | 0 -> 80921 | 0 -> 340 |
| MEW | AccessEnum | n/a -> 4.85 | 0 -> 95845 | 0 -> 120 |
| MEW | Autologon | n/a -> 4.20 | 0 -> 79462 | 0 -> 302 |
| kkrunchy | hello (NASM, classic) | 5.64 -> 1.81 | 224 -> 241 | 2 -> 0 |

Reading the table:

- ASPack and PECompact: the packed `.text` is near-random (entropy ~8.0) with zero resolvable calls;
  after the overlay the same section at the same RVA decodes to dozens to hundreds of real intra-code
  calls and its entropy drops below 6.6. The earlier phase-1 carve left the still-compressed bytes in
  place, so this is the load-bearing fix.
- MEW: the packed image carries no executable section at all (the `MEW` section is virtual-only), so a
  disassembler has nothing to chew on; the rebuilt PE exposes a 188 to 217 KB `.text` that decodes to
  tens of thousands of instructions with hundreds of intra-code calls, OEP landing inside it.
- kkrunchy classic: the decompressed `hello` is a tiny program with no internal calls (it calls
  imports directly), so the call signal is zero on both sides; the entropy collapse from 5.64 to 1.81
  and the recovered instruction count are the recovery signal. This replaces the prior regression
  where the CLI fed a fragment of the rebuilt stub PE into the packed file's section table and a
  disassembler saw fewer functions than on the packed original.
- UPX: unchanged baseline, recovered in place; relative-call resolution differs for this Rust binary
  so the call column reads 0, but the instruction count more than doubles and entropy falls.

`n/a` means the packed file exposes no analyzable executable section to measure.

The per-packer assertions live in `crates/disrobe-pass-native/tests/native_unpack_disasm.rs`.

## Optional: headless Ghidra cross-check

When a Ghidra install is available (the prior run used Ghidra 12.1.2 out of tree), the same rebuilt
PEs can be cross-checked under `analyzeHeadless` with the committed `DisrobeMetrics.java` post-script.
Regenerate with `benches/ghidra-unpack/ghidra-unpack-benchmark.ps1 -GhidraHome <dir>`.

```
disrobe native export --format ghidra <packed> --out <dir>
analyzeHeadless <proj> <name> -import <bin> -postScript DisrobeMetrics.java <out.json> -deleteProject -overwrite
```
