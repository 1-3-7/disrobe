# DR-CLI-0101

**auto: cycle detected**

the sniffer-chain produced a stage whose BLAKE3 hash matched a prior stage.

## Common causes

- pass that returns identity on its own output
- recursive self-wrapping

## Common fixes

- report the input - disrobe should grow a guard for this family

## Source

Emitted from `crates/disrobe-cli/src/cli/auto.rs`.

Look this up at runtime with `disrobe explain DR-CLI-0101`.
