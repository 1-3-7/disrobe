# Capability ledger

One row per graded capability: the exact CLI command that exercises it and the
non-circular oracle that proves it. A capability earns a row only once a real
oracle (recompile-to-equivalence, a real interpreter or compiler, or a
ground-truth diff) grades it against something other than disrobe's own output.

| Capability | CLI command | Oracle (non-circular) | Grading harness |
|---|---|---|---|
| Native x86-64 to C / to Rust pseudocode decompilation (in-tree, no external dependency) | `disrobe native decompile <bin> --backend native --format c\|rust` | Execution-differential recompilation: each recovered function is recompiled with real gcc, clang, and rustc and run against the original over a random-input battery, asserting identical output (MS x64 and SysV ABIs). The CLI prints an honest per-function coverage report ("recovered N/M function(s)") and lists every declined or sound-rejected function with its reason. | `crates/disrobe-pass-native/tests/pseudo_c_leaf_oracle.rs`, `crates/disrobe-pass-native/tests/pseudo_c_wholeprog_oracle.rs` |
