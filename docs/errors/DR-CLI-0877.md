# DR-CLI-0877

**a pass panicked; its input is recorded as failed**

a pass or a batch entry panicked while processing one input. The run continues: the chain records an Error verdict for that pass and a directory run records the entry as failed, so `chain.json` and `manifest.json` are still written.

## Common causes

- a malformed input reached an unchecked path in a pass

## Common fixes

- report the input with `disrobe bug-report --out <PATH>`
- rerun the other inputs; they are unaffected

## Source

Emitted from `crates/disrobe-cli/src/cli/isolate.rs`.

Look this up at runtime with `disrobe explain DR-CLI-0877`.
