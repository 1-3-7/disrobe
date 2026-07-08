# DR-BINFMT-0065

**eszip module-graph archive parse failed**

the Deno eszip module-graph archive did not parse.

## Common causes

- truncated eszip archive
- unsupported eszip version

## Common fixes

- confirm the input is a Deno eszip v2 through v2.3 archive

## Source

Emitted from `crates/disrobe-binfmt/src/error.rs`.

Look this up at runtime with `disrobe explain DR-BINFMT-0065`.
