# DR-CLI-0001

**cannot read pyarmor wrapper file**

the path given to `pyarmor unpack` could not be read as a UTF-8 text file.

## Common causes

- file does not exist
- permission denied
- path points at a binary instead of the wrapper .py

## Common fixes

- verify the path with `ls`/`dir`
- check filesystem permissions
- pass the wrapper .py emitted by `pyarmor obfuscate`, not the runtime DLL/SO

## Source

Emitted from `crates/disrobe-cli/src/cli/pyarmor.rs`.

Look this up at runtime with `disrobe explain DR-CLI-0001`.
