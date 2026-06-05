# DR-PYINST-0005

**zlib inflate failed for entry**

a compressed TOC entry could not be decompressed.

## Common causes

- entry was AES-encrypted with no key provided

## Common fixes

- if PyInstaller >= 6.0, decrypt with the bundled key first

## Source

Emitted from `crates/disrobe-pass-pyinstaller/src/error.rs`.

Look this up at runtime with `disrobe explain DR-PYINST-0005`.
