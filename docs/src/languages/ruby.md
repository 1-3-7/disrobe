# Ruby

disrobe analyzes the full spread of Ruby artifact formats and decompiles YARV and mruby bytecode to source.

```sh
disrobe ruby analyze app.rb
disrobe ruby detect app.bin
```

`analyze` handles MRI source, YARV binary, mruby RITE, JRuby class files, TruffleRuby AOT, Ruby2Exe, and Ocra packages. `detect` reports the flavor and exits. disrobe's edge over the abandoned field (yarvdis is disasm-only, rb-decompile is dead) is source-level decompilation of MRI/YARV 1.9-3.4 and mruby.
