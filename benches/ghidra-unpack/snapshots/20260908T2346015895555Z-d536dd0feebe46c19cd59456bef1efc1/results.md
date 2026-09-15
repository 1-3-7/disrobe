# Headless Ghidra: packed vs disrobe-unpacked

Toolchain: Ghidra 12.1.2 from archive SHA-256 b62e81a0390618466c019c60d8c2f796ced2509c4c1aea4a37644a77272cf99d; JVM 25.0.4 (Eclipse Adoptium); source d9d9a48384a4fc6239488b76991cfcacaf471804 with identity SHA-256 6752130d2d5fa7354c593899513a71054628e94953e2c92499554d32965548c9; 6 fixtures measured at 2026-09-08T23:46:01.3873168Z.

Ghidra 12.1.2, `analyzeHeadless` default analysis. Each fixture is a packed PE from `corpus/native/packers/`. The unpacked column is the loadable PE that `disrobe native export --format ghidra` rebuilds; the packed column is the original packed file. The post-script attempts every non-thunk, non-external function with four workers and a 45-second timeout per function. Both columns use these same settings. Metrics come from `benches/ghidra-unpack/DisrobeMetrics.java`. Regenerate with `benches/ghidra-unpack/ghidra-unpack-benchmark.ps1 -GhidraHome <dir> -GhidraArchive <zip>`.

| packer | binary | functions | instructions | decompiled | strings | imports | exec bytes |
|---|---|---|---|---|---|---|---|
| UPX | hello (Rust) | 4 -> 290 | 225 -> 19060 | 4 -> 287 | 23 -> 179 | 12 -> 12 | 122880 -> 170058 |
| ASPack | Clockres | 5 -> 243 | 58 -> 10544 | 5 -> 210 | 48 -> 116 | 8 -> 8 | 77824 -> 77824 |
| ASPack | AccessEnum | 5 -> 101 | 73 -> 5781 | 5 -> 101 | 62 -> 195 | 14 -> 14 | 45056 -> 45056 |
| PECompact | Clockres | 2 -> 306 | 148 -> 14603 | 1 -> 267 | 27 -> 27 | 4 -> 4 | 147456 -> 147456 |
| PECompact | AccessEnum | 2 -> 186 | 155 -> 9278 | 2 -> 186 | 52 -> 53 | 15 -> 15 | 180224 -> 180224 |
| kkrunchy | hello (NASM, classic) | 4 -> 1 | 149 -> 10 | 4 -> 1 | 3 -> 4 | 2 -> 3 | 70944 -> 4096 |

Commands:

```
disrobe native export --format ghidra <packed> --out <dir>
analyzeHeadless <proj> <name> -import <bin> -postScript DisrobeMetrics.java <out.json> -deleteProject -overwrite
```

These counts describe what Ghidra analyzes in each image. A decompiled function has a completed, nonempty C rendering; that count does not establish source correctness. Per-function failures remain in decompile_attempts in the JSON report. Byte recovery is measured separately in the native-unpack benchmark.

This is a public export of the recorded measurement. Local installation paths use named placeholders. [Export provenance](public-export.json) retains the original checksums and describes the transformations; the full working-tree patch is omitted.
