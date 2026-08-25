# The `.dr` envelope

The `.dr` envelope is `disrobe`'s content-addressed IR wire format. A caller can persist a supported artifact as one, inspect or verify it without running a recovery pass, and pass it to consumers that accept its rung. The chain runner uses `disrobe-core::Artifact` between stages and writes separate `chain.json` and `recovery.json` records; it does not require every stage to become a `.dr` file.

## Anatomy

A `.dr` envelope has three parts:

1. **Hot payload (rkyv).** The primary typed IR data, serialized with rkyv 0.8. The mmap reader validates the header, declared lengths, and root hash before exposing the archived payload for zero-copy access.
2. **Cold sidecar (postcard).** Secondary metadata serialized with postcard, kept out of the hot path so the common case stays fast.
3. **BLAKE3 root hash.** A content hash over both the hot and cold bytes. Equal roots identify equal payload and sidecar bytes. The root does not include the header fields, so it is not by itself a claim that two complete envelope files are byte-identical.

The fixed header also carries the schema **version**, IR **rung** ([see the ladder](./ir-ladder.md)), flags, hot and cold lengths, and root hash. The postcard sidecar stores the producer, producer version, capability set, and string provenance map. MBA outputs that use the peephole table record its deterministic rule-pack content ID in provenance and in the corresponding chain artifact record; this identifies the exact table and audit data used for that result.

## Why content-addressed, not timestamp-addressed

The root binds the typed payload and sidecar to their bytes rather than to a path or timestamp. `disrobe envelope verify` recomputes that root and rejects a mismatch. Cache entries use a separate key derived from the operation, input bytes, and effective configuration, and the cache reader validates its own stored checksum before returning a hit.

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

# Validate one envelope against another envelope's version and rung
disrobe envelope migrate-check source.dr target.dr
```

`migrate-check` answers a precise question: can the source envelope be transcoded to the target envelope's `(version, rung)` through a registered path while every `Requires` capability remains satisfiable? It validates the proposed transition; it does not rewrite either input.

## Transcoding across schema versions

`disrobe-ir` carries a transcode registry keyed on `(from_version, from_rung, to_version, to_rung)`. Identity transcodes are registered for every current rung. A non-identity transition succeeds only when the caller requests a registered path and its capability requirements remain satisfiable; no implicit rung change occurs.

## Hardening

The envelope decoder parses a content-addressed binary format and is treated as a security-sensitive surface. Adversarial envelopes that attempt read-past-end, integer overflow, or BLAKE3-mismatch acceptance are in scope for the [security policy](./security.md). The decoder lives in `crates/disrobe-ir/src/envelope.rs` and is fuzzed.
