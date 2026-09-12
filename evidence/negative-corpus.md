# Labelled negative corpus

Every other corpus in this repository measures what `disrobe` recovers. This one measures what it
must refuse. A recovery tool that returns plausible output for input it cannot actually handle is
worse than one that declines, because an analyst has no way to tell the two apart.

Each member carries a label naming the outcome it must produce. The label is a typed refusal that
names a reason, or a recovery with an exact entry count and an exact set of integrity violations.
No member is graded as "did not crash".

## Where it lives

| Part | Path |
|---|---|
| Members and manifest | `corpus/negative/binfmt/` |
| Harness | `crates/disrobe-binfmt/tests/negative_corpus.rs` |

Run it with:

```sh
cargo test -p disrobe-binfmt --test negative_corpus
```

## The manifest

`corpus/negative/binfmt/manifest.json` is the single source of truth for what each member means.
The harness reads it through a serde schema with `deny_unknown_fields`, so an unrecognised key is a
hard error rather than a silently ignored line. Every field that names a behaviour is an enum, not
free text: the hostile shape, the parser entry point, the builder, the error identity, and the
outcome vocabulary are all closed sets that the harness matches exhaustively.

Each member records:

- `blake3`, the digest the member is pinned to. The harness asserts that the committed bytes hash to
  it and that the named builder still reproduces those exact bytes. The digest is the pin; it is
  never recomputed from the file, so a member cannot drift into a different hostile shape and stay
  green.
- `builder`, the deterministic function in the harness that produced the bytes, and
  `authored_reason`, why the member exists and what the correct outcome is.
- `accepted`, the set of outcomes that satisfy the member. A set of exactly one is the normal case.
  A member that accepts more than one must state why in `multiple_outcome_reason`, and the harness
  refuses a member that omits it.

Changing an expected outcome means editing the manifest, so the manifest edit is the review point.
There is no regenerate mode.

## Outcome vocabulary

| Outcome | Meaning | Asserted |
|---|---|---|
| `refuse` | The reader declines and names why. | Error identity and a substring of the reason. |
| `unsupported_version` | The declared version is one the reader does not implement. | Error identity and a substring of the reason. |
| `partial` | The reader returns a specific recovery. | Exact entry count and exact violation set. |
| `detect_only` | Classification names a format and recovery declines. | Detected kind, error identity, and reason. |

A panic satisfies no outcome and is a distinct failure class. A member that exceeds its wall-clock
bound is a failure, never a skip.

## Why the reason is asserted, not only the error type

Most `disrobe-binfmt` errors are one variant per format carrying a message, so several unrelated
malformations of the same format share an error variant. Matching the variant alone would let a
member pass on another member's rejection path. The harness therefore asserts the reason text too.

This is not theoretical. Disabling the per-entry expansion-ratio cap leaves
`zip-declared-ratio-bomb` with no recovered member, but moves its violation to the aggregate-ratio
guard. A check that asserted only the empty output would have stayed green through that regression.
The harness reports the changed reason:

```text
[WRONG OUTCOME] `zip-declared-ratio-bomb` (shape ExpansionRatioBomb, target ZipExtract)
    declared: [Partial { entries: 0, violations: ["... per-entry expansion ratio 16384 exceeds cap 100"] }]
    observed: Recovered { entries: 0, violations: ["... aggregate expansion ratio 16384 exceeds cap 10"] }
```

## Bounds

Each member runs in its own thread with a 10 second wall-clock bound and its own scratch directory.
Members run four at a time. A member that hangs is reported as a timeout against its own name and
does not stall the suite. After the run the harness walks the whole scratch tree and asserts that
every file written sits under the directory of the member that wrote it, which is how the
path-traversal member is proven contained.

## Coverage

The harness asserts that every hostile shape in its closed `Shape` enum has at least one member, and
that every outcome in the vocabulary has at least one member. A shape cannot silently drop out of
the roster, and an outcome nobody exercises is an unproven claim rather than a passing row.

| Shape | Member | Expected outcome |
|---|---|---|
| Truncated header | `asar-truncated-prefix` | Refuse, asar header, truncated prefix |
| Declared size exceeds file | `asar-json-length-past-end` | Refuse, asar header, header extends past file end |
| Overlapping sections | `pe64-sections-overlap` | Refuse, native parse, sections overlap |
| Self-referential offset | `romfs-node-next-points-at-itself` | Partial, exactly 1 file |
| Cyclic offset | `romfs-directory-child-cycle` | Partial, exactly 0 files |
| Zero-length member | `zero-length-file` | Refuse, zip, no end-of-central-directory record |
| Expansion ratio bomb | `zip-declared-ratio-bomb` | Partial, 0 entries, one quota violation naming per-entry ratio 16384 over a cap of 100 |
| Declared count near type maximum | `uzip-block-count-near-u32-max` | Refuse, uzip, table of contents runs past end of image |
| Magic matches, body is another format | `zip-magic-body-is-elf` | Detect only, classified as zip, recovery declines |
| Valid but empty | `zip-valid-empty-archive` | Partial, exactly 0 entries, no violation |
| Path traversal name | `zip-entry-name-parent-traversal` | Partial, 0 entries, one named zip-slip violation |
| Unsupported declared version | `squashfs-unsupported-major-version` | Unsupported version, squashfs major 7 |

## Safety

No member is live malware. Every member is built programmatically by a function in the harness, is a
few hundred bytes or less, and is never executed. The ratio-bomb member lies in its declared sizes
rather than carrying an expanding payload, so it trips the quota without any real expansion.

## Scope

This corpus is labelled and deterministic. It does not replace fuzzing, which searches. It currently
covers the container and binary-format readers in `disrobe-binfmt`. Extending it to another crate
means a sibling manifest and a harness for that crate's entry points.
