# MIPS Sleigh specification attribution

These files are derived from the MIPS language module in the NSA Ghidra repository at commit `7462bcec30b597b0b51f549f0bb39a63a942c577`.

Upstream paths:

- `Ghidra/Processors/MIPS/data/languages/mips32le.slaspec`
- `Ghidra/Processors/MIPS/data/languages/mips32be.slaspec`
- `Ghidra/Processors/MIPS/data/languages/mips.sinc`
- `Ghidra/Processors/MIPS/data/languages/mips32Instructions.sinc`
- `Ghidra/Processors/MIPS/data/languages/mipsfloat.sinc`

The scalar entrypoints omit the upstream MIPS16, microMIPS, MT, and DSP includes. The included `.sinc` files retain the upstream MIPS32 integer and floating-point constructor tables with LF line endings.

The files are licensed under Apache License 2.0. `LICENSE` and `NOTICE` are preserved from that Ghidra revision.
