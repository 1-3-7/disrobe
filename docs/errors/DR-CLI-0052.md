# DR-CLI-0052

**pyc body is not a code object**

the marshalled root object was not a CodeObject.

## Common causes

- malformed .pyc
- wrong tool used to produce the file

## Common fixes

- verify with `python -m dis` for sanity

## Source

Emitted from `crates/disrobe-cli/src/cli/py.rs`.

Look this up at runtime with `disrobe explain DR-CLI-0052`.
