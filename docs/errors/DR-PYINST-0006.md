# DR-PYINST-0006

**PyInstaller AES decrypt failed**

AES decryption produced invalid plaintext.

## Common causes

- wrong key
- legacy encrypted build or custom bootloader

## Common fixes

- verify the key and producer version; upstream PyInstaller removed bytecode encryption in 6.0
- file an issue with the diagnostic

## Source

Emitted from `crates/disrobe-pass-pyinstaller/src/error.rs`.

Look this up at runtime with `disrobe explain DR-PYINST-0006`.
