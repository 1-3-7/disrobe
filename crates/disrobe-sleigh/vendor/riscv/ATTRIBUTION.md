# RISC-V Sleigh specification attribution

These files are derived from the RISC-V language module in the NSA Ghidra repository at commit `7462bcec30b597b0b51f549f0bb39a63a942c577`.

Upstream paths:

- `Ghidra/Processors/RISCV/data/languages/riscv.ilp32d.slaspec`
- `Ghidra/Processors/RISCV/data/languages/riscv.lp64d.slaspec`
- `Ghidra/Processors/RISCV/data/languages/riscv.reg.sinc`
- `Ghidra/Processors/RISCV/data/languages/riscv.table.sinc`
- `Ghidra/Processors/RISCV/data/languages/riscv.rv32i.sinc`
- `Ghidra/Processors/RISCV/data/languages/riscv.rv32m.sinc`
- `Ghidra/Processors/RISCV/data/languages/riscv.rv64i.sinc`
- `Ghidra/Processors/RISCV/data/languages/riscv.rv64m.sinc`

The two scalar entrypoints activate only RV32I or RV64I and their matching M extension tables. The register file omits the upstream 4,096-entry CSR declaration because this profile has no privileged or CSR constructors, and sets four-byte instruction alignment for the I/M-only profile. Integer, floating-point, vector, context, and token declarations otherwise retain upstream order. The remaining `.sinc` files are unchanged apart from LF line endings.

Upstream SHA-256 values are `143f28d1027603e3d0f4badc61ea1d75ea6e22fc5a5c75ba961e74ef5a856a4d` for `riscv.reg.sinc`, `be18c3ad20371b0f828ab79d5b16bdad6568f95dac71a98f782df8615a803d24` for `riscv.table.sinc`, `8359414fcf54e561e1244868c2608f351f773c78073721589dd0032b2663ddc3` for `riscv.rv32i.sinc`, `cc073f777f7b26517fe94acac582c084a6165cfdd72fc4afcd2b518ceecf322f` for `riscv.rv32m.sinc`, `67428aa6d1cc1b831e19c68bf77f9ba95eef0a3f64a2bdc8a7b82e2b8a8d5b46` for `riscv.rv64i.sinc`, and `8a41cd18b1126cc0861f0d50f4aed445c9f573ae3cf30fe59190e352cc9f9bef` for `riscv.rv64m.sinc`. The normalized `riscv.reg.sinc` SHA-256 is `2137f56a387a2fd12526106a548e51a9700c943c4a1dfb07f39b432195493dc9`. The scalar entrypoint SHA-256 values are `d5433eaec636f6e2c835e5de37878dbfd373ba77251f6b6a0fa19e23d63b19a7` for `riscv32.slaspec` and `9d86dc22c5f6e00089ca5474f5ae5b6a1a075b4f9ad63f9551383c5a7d3d2a9d` for `riscv64.slaspec`.

The files are licensed under Apache License 2.0. `LICENSE` and `NOTICE` are preserved from that Ghidra revision.
