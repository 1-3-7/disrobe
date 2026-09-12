# Ruby

`disrobe` analyzes Ruby artifacts and recovers source from YARV and mruby bytecode. The YARV benchmark recompiles recovered source with MRI and measures opcode-name overlap.

## At a glance

| Layer | Coverage |
|---|---|
| Flavors detected | MRI source, YARV binary (`YARB` magic), mruby RITE, JRuby `.class`, TruffleRuby AOT, Ruby2Exe, Ocra |
| YARV | IBF reader (iseqs, object table, literals) plus a decompiler driven by per-version opcode tables for Ruby 2.6 through 3.4 |
| mruby | RITE reader covering format versions 0001-0007, 0030, 0200, and 0300, with irep disassembly and decompilation |
| Measured recovery | Original opcode-name multiset recall after recompilation: <!-- m:ruby_greeter_pct -->100%<!-- /m --> on a greeter fixture and <!-- m:ruby_megafile_pct -->98.67%<!-- /m --> on a mixed-construct megafile |
| Output | Analysis JSON; a `.rb` source file for YARV and recovered mruby bodies, with a YARV disassembly trailer when available |

## Commands

```sh
disrobe ruby decompile app.bin --out app-ruby.json
disrobe ruby detect app.bin
```

`decompile` sniffs the flavor, runs the matching analyzer, and writes the analysis JSON (default `./out/<stem>-ruby.json`). For YARV, or for mruby when a body is recovered, it also writes a `.rb` source file beside the JSON; YARV output includes a disassembly trailer when available. `detect` reports the flavor and exits without writing output.

## Coverage and fidelity

For MRI source the summary reports token and definition counts. For YARV it adds the IBF header fields, iseq and object counts, instruction count, decompile fidelity, and statement count. For mruby it reports the compiler version string, irep count, instruction count, and whether a body was recovered.

The benchmark compiles the original and recovered sources with MRI, then counts opcode names across their instruction sequences. For each name, the smaller of the two counts contributes to the numerator; the denominator contains every original opcode occurrence. The stored results are 79 of 79 for the greeter and 23648 of 23966 for the megafile.

This comparison ignores instruction order, operands, constants, branch targets, and instruction ownership. Additional recovered instructions do not reduce the score. MRI compiles both sources without executing either program, so the result measures opcode-name recall rather than behavioral equivalence.

Ruby2Exe and Ocra self-extracting packages are detected as their own flavors. Analysis records their embedded-payload offsets and lengths; for Ocra opcode streams it also parses contained file records.

## Limits

- JRuby `.class` files are classified but not decompiled here. JVM-class material belongs to the [JVM guide](./jvm-android.md).
- TruffleRuby AOT images are classified but not decompiled here. Their native code belongs to the [native guide](./native.md).
