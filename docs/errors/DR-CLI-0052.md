# DR-CLI-0052

**pyc body is not a code object**

the marshalled root object was not a CodeObject.

## Common causes

- malformed .pyc
- wrong tool used to produce the file

## Common fixes

- verify the .pyc was produced by a supported Python version and regenerate it from trusted source if available

## Source

Emitted from `crates/disrobe-cli/src/cli/py/mod.rs`.

Look this up at runtime with `disrobe explain DR-CLI-0052`.
