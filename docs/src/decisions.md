# Architecture decisions

Lightweight ADRs recording why a foundational choice was made, not just what it is. Source lives under [`docs/decisions/`](https://github.com/1-3-7/disrobe/tree/main/docs/decisions) at the repo root, alongside this book rather than inside it.

- [1. Implement disrobe in Rust](https://github.com/1-3-7/disrobe/blob/main/docs/decisions/0001-language-rust.md)
- [2. Model every recovery as a five-rung IR ladder](https://github.com/1-3-7/disrobe/blob/main/docs/decisions/0002-ir-ladder.md)
- [3. Make the `.dr` envelope content-addressed, not timestamp-addressed](https://github.com/1-3-7/disrobe/blob/main/docs/decisions/0003-dr-envelope.md)
- [4. Gate pass composition with an explicit capability model](https://github.com/1-3-7/disrobe/blob/main/docs/decisions/0004-capability-passes.md)
- [5. Ship a first-class metadata sidecar mode with provenance](https://github.com/1-3-7/disrobe/blob/main/docs/decisions/0005-llm-mode.md)
