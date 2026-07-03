# Diff and guard tooling

**disrobe** treats recovered artifacts as a forensic baseline you can diff across versions and protect against tampering. Two command families support this: `disrobe diff` and `disrobe guard`.

## `disrobe diff`: structural chain diff

```sh
disrobe diff left/chain.json right/chain.json
```

Structurally diffs two `chain.json` documents, the topology descriptors written by `disrobe auto` / `disrobe chain`. It compares the passes that ran, each stage's BLAKE3 output hash, byte sizes, and per-stage verdicts. This is how you answer "did upgrading the PyArmor pass change what we recover from this sample?" without eyeballing two output trees.

There is also a parallel `disrobe envelope diff` for two `.dr` envelopes directly, which compares version, rung, flags, root hash, producer, capability set, and provenance.

## `disrobe guard`: ground-truth protection

In a recovery workspace, the byte-exact stage outputs (`out/**/stages`, `out/**/final`) are ground truth; an analyst or an agent should never edit them in place, because that would silently corrupt the provenance chain. `disrobe guard` enforces this.

### `guard verify`: hash verification

```sh
disrobe guard verify subject/chain.json --reference reference/chain.json
```

Verifies that a subject `chain.json`'s per-stage output hashes match a committed reference. Use it in CI to assert that a recovery is reproducible: re-run the chain, then verify the new `chain.json` against the checked-in reference.

### `guard check`: edit denial

```sh
disrobe guard check out/final/module.py
disrobe guard check some/path --root extra/protected/subtree --root other/protected
```

Decides whether a path about to be written or edited is inside a protected ground-truth subtree. It denies writes to `out/**/stages`, `out/**/final`, and any `.disrobe-stage-lock`-marked path, and allows writes elsewhere. `--root` adds extra protected subtrees; it is repeatable and also accepts comma-separated values.

This is the command wired into the agent settings hook that `disrobe init --ide claude` generates: a `PreToolUse` hook calls `disrobe guard check` and denies edits to the `01-*/` and `02-*/` stage directories, so a coding agent working in a recovery workspace cannot accidentally rewrite the ground truth it is supposed to be analyzing.
