# DR-PYINST-0005

**zlib inflate failed for entry**

a compressed TOC entry could not be decompressed.

## Common causes

- corrupt compressed entry
- encrypted entry from a legacy build

## Common fixes

- verify the archive is intact and identify its producer version; upstream PyInstaller removed bytecode encryption in 6.0

## Source

Emitted from `crates/disrobe-pass-pyinstaller/src/error.rs`.

Look this up at runtime with `disrobe explain DR-PYINST-0005`.
