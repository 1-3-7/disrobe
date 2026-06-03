# DR-PYINST-0007

**PyInstaller bad PYZ magic**

the inner PYZ archive did not start with `PYZ\0`.

## Common causes

- corrupted archive

## Common fixes

- re-fetch sample

## Source

Emitted from `crates/disrobe-pass-pyinstaller/src/error.rs`.

Look this up at runtime with `disrobe explain DR-PYINST-0007`.
