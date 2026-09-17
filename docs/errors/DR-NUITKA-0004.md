# DR-NUITKA-0004

**nuitka onefile magic mismatch**

expected KA[XY] magic was not present.

## Common causes

- not a --onefile build

## Common fixes

- use `nuitka symbols` instead

## Source

Emitted from `crates/disrobe-pass-nuitka/src/error.rs`.

Look this up at runtime with `disrobe explain DR-NUITKA-0004`.
