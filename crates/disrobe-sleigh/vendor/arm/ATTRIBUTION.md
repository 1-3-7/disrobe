# ARM Sleigh specification attribution

These files are derived from the ARM language module in the NSA Ghidra repository at commit `7462bcec30b597b0b51f549f0bb39a63a942c577`.

Upstream paths:

- `Ghidra/Processors/ARM/data/languages/ARM7_le.slaspec`
- `Ghidra/Processors/ARM/data/languages/ARM.sinc`
- `Ghidra/Processors/ARM/data/languages/ARMinstructions.sinc`
- `Ghidra/Processors/ARM/data/languages/ARMTHUMBinstructions.sinc`

The scalar entrypoint omits the upstream `SIMD`, `VFPv3`, and `VFPv4` definitions. This leaves the upstream A32 and Thumb constructor tables active without pulling in the unrelated NEON and VFP table. The included `.sinc` files retain upstream semantic content with LF line endings.

The files are licensed under Apache License 2.0. `LICENSE` and `NOTICE` are preserved from that Ghidra revision.
