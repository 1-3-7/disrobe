# DR-PYINST-0001

**PyInstaller MEI cookie not found**

the MEI cookie magic was not located in the binary.

## Common causes

- binary is not a PyInstaller build
- binary was repacked / stripped

## Common fixes

- confirm with strings | grep MEI
- try `nuitka detect` / `pyfreeze detect` instead

## Source

Emitted from `crates/disrobe-pass-pyinstaller/src/error.rs`.

Look this up at runtime with `disrobe explain DR-PYINST-0001`.
