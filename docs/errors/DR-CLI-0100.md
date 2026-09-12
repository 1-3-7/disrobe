# DR-CLI-0100

**auto: chain exceeded max depth**

the sniffer-chain hit its depth cap before reaching a terminal artifact.

## Common causes

- deeply nested wrappers
- cycle (same hash twice)

## Common fixes

- raise `--max-depth`
- inspect intermediate stages under out/

## Source

Emitted from `crates/disrobe-cli/src/cli/auto.rs`.

Look this up at runtime with `disrobe explain DR-CLI-0100`.
