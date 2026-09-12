# Ghidra AArch64 Sleigh attribution

These processor specification files are derived from the [National Security Agency Ghidra repository](https://github.com/NationalSecurityAgency/ghidra) at commit `7462bcec30b597b0b51f549f0bb39a63a942c577`:

- `Ghidra/Processors/AARCH64/data/languages/AARCH64.slaspec`
- `Ghidra/Processors/AARCH64/data/languages/AARCH64instructions.sinc`
- `Ghidra/Processors/AARCH64/data/languages/AARCH64neon.sinc`
- `Ghidra/Processors/AARCH64/data/languages/AARCH64_base_PACoptions.sinc`
- `Ghidra/Processors/AARCH64/data/languages/AARCH64base.sinc`
- `Ghidra/Processors/AARCH64/data/languages/AARCH64ldst.sinc`

The vendored `AARCH64instructions.sinc` omits the include directive for `AARCH64sve.sinc` and keeps the one for `AARCH64neon.sinc` at its upstream position. The complete upstream `AARCH64neon.sinc` contributes 1816 SIMD and floating-point constructors. Disrobe adds five RCpc3 SIMD and floating-point `STLUR` constructors for the `b`, `h`, `s`, `d`, and `q` register widths, bringing the local file to 1821 constructors. The SVE constructors do not compile because `AARCH64sve.sinc` is not vendored. No other Ghidra processor files are vendored.

Normalizing the upstream `AARCH64neon.sinc` is byte-preserving, so its normalized base hash remains `9bedaa46f0b312debd7a48d43942a7f77d4f14122e9a22e8d63c1fbc9ed693ef`. The five local constructors change the current vendored hash to `914b3e4c609ebcbe0e4314dcf555a35bae7f80e0000c85366f7423aec3978dd7`. Compiling the locally extended file takes the `instruction` table to 2806 constructors, which remains within the 4096-constructor `MAX_TABLE_CONSTRUCTORS` bound in `crates/disrobe-sleigh/src/compiler.rs`.

The upstream Git blob bytes have these SHA-256 values:

```text
99381f51825b672b70e1006a111462e77c2384f5a1ea4e6b63669bc5027b3439  AARCH64.slaspec
fde6454c27ed9c2ab99cbdc403af8d188b7cf3a044468b9d9569654afcf04683  AARCH64instructions.sinc
9bedaa46f0b312debd7a48d43942a7f77d4f14122e9a22e8d63c1fbc9ed693ef  AARCH64neon.sinc
6b7c77988212836deec88f4905d7db38623ecc69f2a608b760b22489c15a0aea  AARCH64_base_PACoptions.sinc
a02ec3681ebb32fe13c294ed146407a0017d4b1f5dcad25b170da92eb76bc39b  AARCH64base.sinc
bc2a55815b9368a0a8d1a14e165e32e39cce54337575c7eae287e4e008ec6aa8  AARCH64ldst.sinc
```

The vendored text uses LF line endings, removes trailing horizontal whitespace, and ends with one newline. After that normalization, the `AARCH64instructions.sinc` include removal, and the five local `AARCH64neon.sinc` constructors described above, the current vendored files have these SHA-256 values:

```text
8f70a0948ed6c9eecf7f220e22628472b220c047c5aae5f29e8ccd2a426e4535  AARCH64.slaspec
88388e03dd5cc0110479e50f915648d7054429e8be9f795cfb5254cd87094760  AARCH64instructions.sinc
914b3e4c609ebcbe0e4314dcf555a35bae7f80e0000c85366f7423aec3978dd7  AARCH64neon.sinc
772bbb09f019fede150d421104720f6ccad76b616988ed8914b0fdbbb59f2de2  AARCH64_base_PACoptions.sinc
b55c9d631592f1ab0620eb52390aceae433cd98c6f66c5f94eec0b388761e44b  AARCH64base.sinc
bc2a55815b9368a0a8d1a14e165e32e39cce54337575c7eae287e4e008ec6aa8  AARCH64ldst.sinc
```

The copied source is distributed under Apache License 2.0. The upstream `LICENSE` and `NOTICE` files are preserved in this directory.
