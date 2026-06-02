# BEAM (Erlang / Elixir)

`disrobe` parses BEAM IFF files, lifts them to Core Erlang, recovers Elixir source from debug-info chunks, and disassembles the Code chunk.

```sh
disrobe beam parse module.beam        # report sections: AtU8, Code, ExpT, ImpT, FunT, Dbgi, Docs, LitT, ...
disrobe beam lift module.beam         # lift to Core Erlang surface (best-effort)
disrobe beam disasm module.beam       # per-instruction Code chunk trace
```

The parser covers the full chunk set and the OTP-26/28/29 long-form AtU8 atom table, the OTP-28+ `LitT` raw-payload branch, and BEAM opcode 182 (`bs_match/3`). When a `Dbgi` chunk is present, `disrobe` recovers Elixir source from it directly; otherwise it lifts to Core Erlang. `.ez` archives extract through the container layer.
