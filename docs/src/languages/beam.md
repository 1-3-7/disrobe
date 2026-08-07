# BEAM (Erlang / Elixir)

`disrobe` parses BEAM IFF files, recovers Erlang or Elixir source when debug chunks survive, lifts to Core Erlang otherwise, and disassembles the Code chunk per instruction.

## At a glance

| Layer | Coverage |
|---|---|
| Chunks | `AtU8` (short and long form), `Code`, `StrT`, `Attr`, `CInf`, `Dbgi`, `Docs`, `ExpT`, `ImpT`, `LocT`, `FunT`, `Line`, `LitT` (zlib-deflated on OTP 26 and earlier, raw on OTP 27+); unknown chunks are preserved verbatim |
| Source recovery | Erlang abstract code when present, Elixir source from a `Dbgi` form, best-effort Core Erlang lift as the floor; provenance is recorded in `recovered_from` |
| Disassembly | Per-instruction Code-chunk trace including the `bs_match` (opcode 182) command list; a flat `.txt` listing lands beside the JSON |
| Containers | `.ez` archives extract through the container layer |

## Commands

```sh
disrobe beam parse module.beam --out ./out/module-beam.json
disrobe beam lift module.beam --out out/module-beam-lift/
disrobe beam disasm module.beam --out ./out/module-beam.disasm.json
```

Output shapes below are illustrative.

`parse` reports the module name, atom / export / import / fun counts, which optional chunks are present, and any unrecognized chunk names.

```text
beam parse: OK
  module:       my_module
  atoms:        42
  exports:      8
  imports:      15
  funs:         3
  wrote:        ./out/module-beam.json
```

`lift` writes three files: `<stem>.<ext>` (recovered Erlang or Elixir source, extension derived from `recovered_from`), `<stem>.surface.json` (the surface record with provenance), and `<stem>.core.json` (lifted Core Erlang functions), plus a `manifest.json` linking them.

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

`disasm` emits the per-instruction Code-chunk trace as JSON and a flat `.txt` listing beside it.

```text
beam disasm: OK
  input:        module.beam
  instructions: 214
  wrote:        ./out/module-beam.disasm.json
  listing:      ./out/module-beam.disasm.txt
```

## Coverage and fidelity

When a `Dbgi` chunk is present the original forms are recovered directly and labeled `AbstractCode` (Erlang) or `ElixirDbgiForm` (Elixir). Each lift records where its source came from in `recovered_from`, so a caller can tell a recovered original from a lift.

For stripped BEAM, <!-- m:beam_recompile_frac -->18 / 19<!-- /m --> committed corpus entries recover to Core Erlang source that recompiles under Erlang/OTP 27.3.4, preserves the original export set, and returns the same result from the entry's committed `test/0` battery. Each corpus entry is an Erlang module compiled from committed source; the gate removes both `Dbgi` and `Docs` before recovery so neither source path can participate.

This is a `test/0` recompile-execution differential, not a claim of equivalence for every input to every exported function. The original and recovered source are compiled independently by real `erlc`; real `erl` then compares exit status and stdout. A mutation control replaces a recovered `test/0` with one that raises while still recompiling with matching exports, and requires the runtime leg to reject it.

The Linux CI test leg pins OTP 27.3.4 and makes missing `erlc` or `erl` fatal. macOS and Windows retain explicit optional reporting when that toolchain is absent. Reproduce the Linux gate with:

```sh
DISROBE_REQUIRE_ERLANG=1 cargo test -p disrobe-pass-beam --test erlc_recompile_equivalence -- --nocapture
```

## Limits

- Without a `Dbgi` chunk the original source is not in the file. The output is then a best-effort Core Erlang lift labeled `CoreLifted`, not the original text.
- An opcode beyond the known table fails with an explicit `DR-BEAM-0012` error naming the offending opcode rather than silently skipping bytes.
