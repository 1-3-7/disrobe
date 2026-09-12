# DR-BINFMT-0068

**minidump parse failed**

the Windows minidump did not parse.

## Common causes

- truncated minidump
- missing stream directory

## Common fixes

- confirm the input is a Windows .dmp minidump

## Source

Emitted from `crates/disrobe-binfmt/src/error.rs`.

Look this up at runtime with `disrobe explain DR-BINFMT-0068`.
