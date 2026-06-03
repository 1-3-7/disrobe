# DR-PYINST-0006

**PyInstaller AES decrypt failed**

AES decryption produced invalid plaintext.

## Common causes

- wrong key
- PyInstaller >= 6.0 with custom key derivation

## Common fixes

- supply key via PyInstaller hooks fork
- file an issue

## Source

Emitted from `crates/disrobe-pass-pyinstaller/src/error.rs`.

Look this up at runtime with `disrobe explain DR-PYINST-0006`.
