# DR-PYFRZ-0018

**pyfreeze quota exceeded**

extraction quota guard tripped on an entry.

## Common causes

- zip-bomb-style archive

## Common fixes

- raise quota via env or refuse the sample

## Source

Emitted from `crates/disrobe-pass-pyfreeze/src/error.rs`.

Look this up at runtime with `disrobe explain DR-PYFRZ-0018`.
