# DR-CLI-0120

**bug-report: cannot write report**

could not write the bug report to disk.

## Common causes

- disk full
- permission denied

## Common fixes

- pick a writable `--out` or pipe to stdout via `--out -`

## Source

Emitted from `crates/disrobe-cli/src/cli/bug_report.rs`.

Look this up at runtime with `disrobe explain DR-CLI-0120`.
