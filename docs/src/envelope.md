# The `.dr` envelope

The `.dr` envelope is `disrobe`'s content-addressed wire format. Every recovered artifact can be persisted as one, and the chain runner uses envelopes internally to pass work between stages. The format is designed for one thing above all: **deterministic, verifiable, offline-composable caching**.

## Anatomy

A `.dr` envelope has three parts:

1. **Hot payload (rkyv).** The primary data, serialized with rkyv 0.8 for zero-copy access. An envelope can be `mmap`-ed and the payload read without a deserialize pass — measured at roughly 21 ns to "deserialize" a cached envelope, because there is effectively nothing to deserialize.
2. **Cold sidecar (postcard).** Secondary metadata serialized with postcard, kept out of the hot path so the common case stays fast.
3. **BLAKE3 root hash.** A content hash over the payload that is the envelope's identity. Two envelopes with the same root hash are byte-identical by construction.

Every envelope also carries its schema **version**, its IR **rung** ([see the ladder](./ir-ladder.md)), its **capability set**, and a **provenance** record describing which pass produced it.

## Why content-addressed, not timestamp-addressed

Because the identity is the BLAKE3 hash of the content, a cache hit is provably the same bytes — not "probably the same, modified at the same time." This is what makes `--no-cache` an optimization toggle rather than a correctness toggle: with the cache on or off, the output is identical. It is also what lets chains compose offline: a downstream pass can trust that an upstream envelope it pulled from cache is exactly what would have been produced live.

## Working with envelopes

```sh
# Create an envelope from a source file
disrobe envelope create source.bin --out source.dr

# Inspect: version, rung, capabilities, provenance, root hash
disrobe envelope inspect source.dr

# Verify the BLAKE3 root against the payload
disrobe envelope verify source.dr
disrobe verify source.dr               # convenience alias

# Structurally diff two envelopes
disrobe envelope diff a.dr b.dr        # version, rung, flags, root hash, producer, capabilities, provenance

# Validate a migration is sound before performing it
disrobe envelope migrate-check a.dr --to-version 0.9.0 --to-rung surface
```

`migrate-check` answers a precise question: can this envelope be transcoded from its `(version, rung)` to the target `(version, rung)` such that a transcode path exists *and* every `Requires` capability remains satisfiable? It is how `disrobe` stays sound across schema bumps without silently dropping capability guarantees.

## Transcoding across schema versions

`disrobe-ir` carries a transcode registry keyed on `(from_version, from_rung, to_version, to_rung)`. Identity transcodes are registered for every rung at every version, and real transcodes are registered for the migration paths `disrobe` supports. Transcoding never changes the rung implicitly — a transcode moves an envelope across schema versions while it stays at the same rung, which keeps the operation auditable.

## Hardening

The envelope decoder parses a content-addressed binary format and is treated as a security-sensitive surface. Adversarial envelopes that attempt read-past-end, integer overflow, or BLAKE3-mismatch acceptance are in scope for the [security policy](./security.md). The decoder lives in `crates/disrobe-ir/src/envelope.rs` and is fuzzed.
