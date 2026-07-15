# RISC-V Sleigh specification attribution

These files are derived from the RISC-V language module in the NSA Ghidra repository at commit `7462bcec30b597b0b51f549f0bb39a63a942c577`.

Upstream paths:

- `Ghidra/Processors/RISCV/data/languages/riscv.ilp32d.slaspec`
- `Ghidra/Processors/RISCV/data/languages/riscv.lp64d.slaspec`
- `Ghidra/Processors/RISCV/data/languages/riscv.reg.sinc`
- `Ghidra/Processors/RISCV/data/languages/riscv.table.sinc`
- `Ghidra/Processors/RISCV/data/languages/riscv.rv32i.sinc`
- `Ghidra/Processors/RISCV/data/languages/riscv.rv32a.sinc`
- `Ghidra/Processors/RISCV/data/languages/riscv.rv32m.sinc`
- `Ghidra/Processors/RISCV/data/languages/riscv.rv32f.sinc`
- `Ghidra/Processors/RISCV/data/languages/riscv.rv32d.sinc`
- `Ghidra/Processors/RISCV/data/languages/riscv.rv64i.sinc`
- `Ghidra/Processors/RISCV/data/languages/riscv.rv64a.sinc`
- `Ghidra/Processors/RISCV/data/languages/riscv.rv64m.sinc`
- `Ghidra/Processors/RISCV/data/languages/riscv.rv64f.sinc`
- `Ghidra/Processors/RISCV/data/languages/riscv.rv64d.sinc`
- `Ghidra/Processors/RISCV/data/languages/riscv.csr.sinc`
- `Ghidra/Processors/RISCV/data/languages/riscv.rvc.sinc`
- `Ghidra/Processors/RISCV/data/languages/riscv.zi.sinc`

The four scalar entrypoints provide RV32 and RV64 base or compressed profiles. The base entrypoints activate I, M, A, F, D, Zicsr, and Zifencei tables with four-byte alignment. The compressed entrypoints add C and use two-byte alignment. The register file omits the upstream 4,096-entry CSR declaration because CSR effects use the typed `riscv_csr_v1` boundary rather than direct CSR registers, and takes alignment from its entrypoint. Integer, floating-point, vector, context, and token declarations otherwise retain upstream order. The A, C, F, D, and Zifencei `.sinc` files are byte-identical to upstream. The CSR fragment differs only by omission of one terminal blank line.

Upstream SHA-256 values are `143f28d1027603e3d0f4badc61ea1d75ea6e22fc5a5c75ba961e74ef5a856a4d` for `riscv.reg.sinc`, `be18c3ad20371b0f828ab79d5b16bdad6568f95dac71a98f782df8615a803d24` for `riscv.table.sinc`, `8359414fcf54e561e1244868c2608f351f773c78073721589dd0032b2663ddc3` for `riscv.rv32i.sinc`, `530ab457c9e2c16c6abf9c6be22dbb74f39e55e1808129625df2dcc90c632956` for `riscv.rv32a.sinc`, `cc073f777f7b26517fe94acac582c084a6165cfdd72fc4afcd2b518ceecf322f` for `riscv.rv32m.sinc`, `67428aa6d1cc1b831e19c68bf77f9ba95eef0a3f64a2bdc8a7b82e2b8a8d5b46` for `riscv.rv64i.sinc`, `36b176cb9dad85413011eb0fff61252cc16efe3c809fe4e7b5b71f13517d4db7` for `riscv.rv64a.sinc`, `8a41cd18b1126cc0861f0d50f4aed445c9f573ae3cf30fe59190e352cc9f9bef` for `riscv.rv64m.sinc`, and `b01f8c3ed38005724c2d410701fbe5f64c7743f5a14dce228914ba3c7707df4b` for `riscv.rvc.sinc`.

The added upstream SHA-256 values are `f0fc256ba93ce4774fe4c95cea00562073642bb9678f3e56d4e53f8901621eb3` for `riscv.rv32f.sinc`, `a2ad789c6391dadbb3c3e7268fcb9d2473ee9b39b1477111ec283ae16b597224` for `riscv.rv32d.sinc`, `8c178c2f66ed030a449d495e96ca6f6582ecb93b3d2fdc5438f554f5ce69d269` for `riscv.rv64f.sinc`, `a7e6f3a71f39e5d17207dc1b0b38d129c755a68a42ce979ed2f7ea665ed14241` for `riscv.rv64d.sinc`, `2c57e6a8d5ee4f383174edbe7f1ab17675583732b4dbc87a515f44454c551232` for `riscv.csr.sinc`, and `aa438b3ce35865cb6e83e61ef3ef282f087d0535036d2ee3edb3471578901a48` for `riscv.zi.sinc`.

The local SHA-256 values are `dd98a055426fefe5cc3916b3c18d8d6facede3a79d524203343069141815a952` for the parameterized `riscv.reg.sinc`, `aa35fb1334a48ba5a5a82a8ba69b38c3e036091d4430091f8e72bcbfb73f90ca` for `riscv32.slaspec`, `f002fa58c6b2be32d63db513c6615df9f91fb602c23282b747b4dda75bcc9818` for `riscv64.slaspec`, `58cc570533606344d1f419e028dcc7fab9cfa99af29dc7c5e00881a51e38128d` for `riscv32c.slaspec`, and `6daea1db5e86e27a122dc4e8ea98d4db61a6c76da21cdd3fd27701d8a188141b` for `riscv64c.slaspec`.

The local fragment SHA-256 values are `f0fc256ba93ce4774fe4c95cea00562073642bb9678f3e56d4e53f8901621eb3` for `riscv.rv32f.sinc`, `a2ad789c6391dadbb3c3e7268fcb9d2473ee9b39b1477111ec283ae16b597224` for `riscv.rv32d.sinc`, `8c178c2f66ed030a449d495e96ca6f6582ecb93b3d2fdc5438f554f5ce69d269` for `riscv.rv64f.sinc`, `a7e6f3a71f39e5d17207dc1b0b38d129c755a68a42ce979ed2f7ea665ed14241` for `riscv.rv64d.sinc`, `e5120bef3ca68ba338abd749192c2776b43e49cce25855e784f48bc76cdf2a27` for `riscv.csr.sinc`, and `aa438b3ce35865cb6e83e61ef3ef282f087d0535036d2ee3edb3471578901a48` for `riscv.zi.sinc`.

The files are licensed under Apache License 2.0. `LICENSE` and `NOTICE` are preserved from that Ghidra revision.
