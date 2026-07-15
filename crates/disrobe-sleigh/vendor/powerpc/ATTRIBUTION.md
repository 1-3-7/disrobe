# PowerPC Sleigh specification attribution

These files are derived from the PowerPC language module in the NSA Ghidra repository at commit `7462bcec30b597b0b51f549f0bb39a63a942c577`.

Upstream paths:

- `Ghidra/Processors/PowerPC/data/languages/ppc_32_be.slaspec`
- `Ghidra/Processors/PowerPC/data/languages/ppc_common.sinc`
- `Ghidra/Processors/PowerPC/data/languages/ppc_instructions.sinc`
- `Ghidra/Processors/PowerPC/data/languages/lmwInstructions.sinc`
- `Ghidra/Processors/PowerPC/data/languages/lswInstructions.sinc`
- `Ghidra/Processors/PowerPC/data/languages/mulhwInstructions.sinc`
- `Ghidra/Processors/PowerPC/data/languages/stmwInstructions.sinc`
- `Ghidra/Processors/PowerPC/data/languages/stswiInstructions.sinc`

The scalar entrypoint omits the upstream Altivec and G2 includes. `ppc_common.sinc` omits the embedded-controller constructor include. The remaining files are unchanged apart from LF line endings.

Upstream SHA-256 values are `34704113e76a9994c4f820f9bbefc0b4af77fb31fb45e44d91efc4e1c658f583` for `ppc_32_be.slaspec`, `7b52beb022ff2a95644b909ba06c0d8de65c947793a95a8b2195f7a8e2fad594` for `ppc_common.sinc`, `ae2f0a3c90c4058e53b1c9473c725c0c2fbc781e991da6390f80928ca933e0b5` for `ppc_instructions.sinc`, `f8a83e8da0195d8ddee5bfe05c4bcea56cf4f13ccecd5a1c724fa1a61f487de6` for `lmwInstructions.sinc`, `e963045970031f0cffbafe812cfa9f6c4370200f30b11d713d97af9417dd1ff5` for `lswInstructions.sinc`, `73c5f3a868121b3d7e82dd4595d30b06265f33fc03629f7295db12e4cc67ac27` for `mulhwInstructions.sinc`, `f9e89a3a587ccbacf81f2d2e1a86ab34010990482b0bceff7fe6c3a4632b0b28` for `stmwInstructions.sinc`, and `bd974356b4f9a52f89285f2dd6fd168ef259832df5d6ac8142302784809003c3` for `stswiInstructions.sinc`. The normalized entrypoint SHA-256 is `9cfee6d272aba03d06cf15744473bf60517c03442b901226e2b590b6acdc4ed4`. The normalized `ppc_common.sinc` SHA-256 is `0549e5989b76cbec47626690d4db1e76e8035c78b191022521213cc5d0640b04`.

The files are licensed under Apache License 2.0. `LICENSE` and `NOTICE` are preserved from that Ghidra revision.
