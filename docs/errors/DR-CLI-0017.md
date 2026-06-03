# DR-CLI-0017

**input is not a nuitka --onefile build**

no KA[XY] onefile payload header was detected.

## Common causes

- binary is a Nuitka --standalone build
- binary is not a Nuitka build at all

## Common fixes

- use `nuitka symbols` for --standalone builds
- run `nuitka detect` first to confirm flavor

## Source

Emitted from `crates/disrobe-cli/src/cli/nuitka.rs`.

Look this up at runtime with `disrobe explain DR-CLI-0017`.
