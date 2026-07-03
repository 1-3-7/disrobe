# BEAM (Erlang / Elixir)

**disrobe** parses BEAM IFF files, recovers Erlang or Elixir source when debug chunks survive, lifts to Core Erlang otherwise, and disassembles the Code chunk per instruction. A flat text disassembly listing lands beside the JSON automatically.

## At a glance

| Layer | Coverage |
|---|---|
| Chunks | `AtU8` (short and long form), `Code`, `StrT`, `Attr`, `CInf`, `Dbgi`, `Docs`, `ExpT`, `ImpT`, `LocT`, `FunT`, `Line`, `LitT` (zlib-deflated on OTP 26 and earlier, raw on OTP 27+); unknown chunks are preserved verbatim |
| Source recovery | Erlang abstract code when present, Elixir source from a `Dbgi` form, best-effort Core Erlang lift as the floor; provenance is recorded in `recovered_from` |
| Disassembly | Per-instruction Code-chunk trace including the `bs_match` (opcode 182) command list; a flat `.txt` listing lands beside the JSON |
| Containers | `.ez` archives extract through the container layer |

## Parsing

```sh
disrobe beam parse module.beam --out ./out/module-beam.json
```

Reports the module name, atom / export / import / fun counts, which optional chunks are present, and any unrecognized chunk names.

Output shape (illustrative):

```text
beam parse: OK
  module:       my_module
  atoms:        42
  exports:      8
  imports:      15
  funs:         3
  wrote:        ./out/module-beam.json
```

## Lifting to source

```sh
disrobe beam lift module.beam --out out/module-beam-lift/
```

Writes three files: `<stem>.<ext>` (recovered Erlang or Elixir source, extension derived from `recovered_from`), `<stem>.surface.json` (the surface record with provenance), and `<stem>.core.json` (lifted Core Erlang functions), plus a `manifest.json` linking them.

When a `Dbgi` chunk is present the original forms are recovered directly and labelled `AbstractCode` (Erlang) or `ElixirDbgiForm` (Elixir). Without it the output is a best-effort Core Erlang lift labelled `CoreLifted`.

Output shape (illustrative):

```text
beam lift: OK
  module:       my_module
  core fns:     8
  recovered:    AbstractCode
  source:       ./out/module-beam-lift/module.erl
  surface:      ./out/module-beam-lift/module.surface.json
  core erlang:  ./out/module-beam-lift/module.core.json
  manifest:     ./out/module-beam-lift/manifest.json
```

## Disassembling

```sh
disrobe beam disasm module.beam --out ./out/module-beam.disasm.json
```

Emits the per-instruction Code-chunk trace as JSON and a flat `.txt` listing beside it. Opcodes beyond the known table fail with an explicit `DR-BEAM-0012` error naming the offending opcode rather than silently skipping bytes.

Output shape (illustrative):

```text
beam disasm: OK
  input:        module.beam
  instructions: 214
  wrote:        ./out/module-beam.disasm.json
  listing:      ./out/module-beam.disasm.txt
```
