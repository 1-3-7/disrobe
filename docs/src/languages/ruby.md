# Ruby

`disrobe` analyzes the Ruby artifact formats listed below and decompiles YARV and mruby bytecode toward source. A recompile-equivalence gate on a real MRI interpreter measures YARV recovery.

## At a glance

| Layer | Coverage |
|---|---|
| Flavors detected | MRI source, YARV binary (`YARB` magic), mruby RITE, JRuby `.class`, TruffleRuby AOT, Ruby2Exe, Ocra |
| YARV | IBF reader (iseqs, object table, literals) plus a decompiler driven by per-version opcode tables for Ruby 2.6 through 3.4 |
| mruby | RITE reader covering format versions 0001-0007, 0030, 0200, and 0300, with irep disassembly and decompilation |
| Fidelity | <!-- m:ruby_greeter_pct -->100%<!-- /m --> opcode-multiset equivalence on a greeter fixture; <!-- m:ruby_megafile_pct -->98.67%<!-- /m --> on a mixed-construct megafile (gate floor, CI-enforced) |
| Output | Analysis JSON; a `.rb` source file for YARV and recovered mruby bodies, with a YARV disassembly trailer when available |

## Commands

```sh
disrobe ruby decompile app.bin --out app-ruby.json
disrobe ruby detect app.bin
```

`decompile` sniffs the flavor, runs the matching analyzer, and writes the analysis JSON (default `./out/<stem>-ruby.json`). For YARV, or for mruby when a body is recovered, it also writes a `.rb` source file beside the JSON; YARV output includes a disassembly trailer when available. `detect` reports the flavor and exits without writing output.

Output shape (illustrative):

```text
ruby decompile: OK
  input:        app.bin
  flavor:       YarvBinary
  yarv header:  major=3 minor=4
  yarv iseqs:   12
  yarv bodies:  12
  yarv objects: 34
  yarv literals:18
  yarv insns:   97
  yarv decomp:  Lossless
  yarv stmts:   23
  decompiled:   ./out/app.rb (yarv)
  wrote:        ./out/app-ruby.json
```

## Coverage and fidelity

For MRI source the summary reports token and definition counts. For YARV it adds the IBF header fields, iseq and object counts, instruction count, decompile fidelity, and statement count. For mruby it reports the compiler version string, irep count, instruction count, and whether a body was recovered.

A committed recompile-equivalence oracle compiles the recovered YARV source on the matching interpreter and diffs the opcode multiset. The gate asserts 100% equivalence on the greeter fixture and at least 98% on the megafile fixture; both run in CI.

Ruby2Exe and Ocra self-extracting packages are detected as their own flavors. Analysis records their embedded-payload offsets and lengths; for Ocra opcode streams it also parses contained file records.

## Limits

- JRuby `.class` files are classified but not decompiled here. JVM-class material belongs to the [JVM guide](./jvm-android.md).
- TruffleRuby AOT images are classified but not decompiled here. Their native code belongs to the [native guide](./native.md).
