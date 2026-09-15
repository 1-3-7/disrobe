# DR-MARSHAL-0012

**marshal writer length overflow**

payload exceeded the marshal u32 size field max.

## Common causes

- asked to encode oversize payload

## Common fixes

- split into smaller chunks

## Source

Emitted from `crates/disrobe-py-marshal/src/error.rs`.

Look this up at runtime with `disrobe explain DR-MARSHAL-0012`.
