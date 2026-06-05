# DR-PYINST-0008

**PyInstaller PYZ TOC marshal decode**

the PYZ table-of-contents marshal payload did not parse.

## Common causes

- wrong python version assumed
- corrupted PYZ

## Common fixes

- use `pyinstaller detect` to confirm pyver

## Source

Emitted from `crates/disrobe-pass-pyinstaller/src/error.rs`.

Look this up at runtime with `disrobe explain DR-PYINST-0008`.
