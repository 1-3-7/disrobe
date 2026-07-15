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
- `Ghidra/Processors/RISCV/data/languages/riscv.rv64i.sinc`
- `Ghidra/Processors/RISCV/data/languages/riscv.rv64a.sinc`
- `Ghidra/Processors/RISCV/data/languages/riscv.rv64m.sinc`
- `Ghidra/Processors/RISCV/data/languages/riscv.rvc.sinc`

The four scalar entrypoints provide RV32 and RV64 base or compressed profiles. The base entrypoints activate I, M, and A tables with four-byte alignment. The compressed entrypoints activate I, M, A, and C tables with two-byte alignment. The register file omits the upstream 4,096-entry CSR declaration because these profiles have no privileged or CSR constructors, and takes alignment from its entrypoint. Integer, floating-point, vector, context, and token declarations otherwise retain upstream order. The A and C `.sinc` files are byte-identical to upstream.

Upstream SHA-256 values are `143f28d1027603e3d0f4badc61ea1d75ea6e22fc5a5c75ba961e74ef5a856a4d` for `riscv.reg.sinc`, `be18c3ad20371b0f828ab79d5b16bdad6568f95dac71a98f782df8615a803d24` for `riscv.table.sinc`, `8359414fcf54e561e1244868c2608f351f773c78073721589dd0032b2663ddc3` for `riscv.rv32i.sinc`, `530ab457c9e2c16c6abf9c6be22dbb74f39e55e1808129625df2dcc90c632956` for `riscv.rv32a.sinc`, `cc073f777f7b26517fe94acac582c084a6165cfdd72fc4afcd2b518ceecf322f` for `riscv.rv32m.sinc`, `67428aa6d1cc1b831e19c68bf77f9ba95eef0a3f64a2bdc8a7b82e2b8a8d5b46` for `riscv.rv64i.sinc`, `36b176cb9dad85413011eb0fff61252cc16efe3c809fe4e7b5b71f13517d4db7` for `riscv.rv64a.sinc`, `8a41cd18b1126cc0861f0d50f4aed445c9f573ae3cf30fe59190e352cc9f9bef` for `riscv.rv64m.sinc`, and `b01f8c3ed38005724c2d410701fbe5f64c7743f5a14dce228914ba3c7707df4b` for `riscv.rvc.sinc`.

The local SHA-256 values are `dd98a055426fefe5cc3916b3c18d8d6facede3a79d524203343069141815a952` for the parameterized `riscv.reg.sinc`, `0526b5df5c97df06b6eb92900ef35e31a8c1f6179c1fe73eb2c3212f08bd03e4` for `riscv32.slaspec`, `ee0592f08e4682ec33f4e219b462c8249ed5d22b8335fcd824c313b573348093` for `riscv64.slaspec`, `bd60290c0d225ca1d3e59d98f9dbfbb44cba516b4a0ad568e5041c4b1d86615d` for `riscv32c.slaspec`, and `d252148363ba24071d62bc6aa46dfef37744d63ca7fb21d400df4cade29d6a37` for `riscv64c.slaspec`.

The files are licensed under Apache License 2.0. `LICENSE` and `NOTICE` are preserved from that Ghidra revision.
