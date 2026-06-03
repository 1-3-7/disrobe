# 3. Make the `.dr` envelope content-addressed, not timestamp-addressed

- Status: accepted
- Date: 2025-09-15
- Deciders: project maintainer

## Context and Problem Statement

Passes hand work to each other, and recovered artifacts are cached and replayed. We need a wire format that lets the chain runner move an artifact between stages and lets a cache return a previously-computed result. The central question is what an envelope's **identity** should be. If identity is a timestamp or a path, a cache hit means "probably the same, modified at the same time" - which is not good enough for a tool whose output is used as a forensic baseline and as a `disrobe diff` input across versions. The format also has to be fast enough that caching is an unambiguous win, and composable offline so a downstream pass can trust an upstream envelope pulled from cache.

## Decision Drivers

- A cache hit must be **provably** the same bytes, not heuristically the same.
- Reading a cached envelope must be near-free, so the cache is always worth using.
- Secondary metadata must not slow the common hot-path read.
- The format must carry enough self-description (version, rung, capabilities, provenance) to be auditable and migratable across schema bumps.

## Considered Options

1. **Content-addressed: BLAKE3 root over an rkyv hot payload + a postcard cold sidecar.** Identity is the hash of the content. Hot payload is zero-copy via rkyv 0.8; cold metadata is kept out of the hot path via postcard.
2. **Timestamp/path-addressed cache.** Identity is `(path, mtime)`. Simple, but a hit is only probabilistically correct and is useless across machines or after a touch.
3. **Single-format serialization (e.g. all-JSON or all-protobuf).** Self-describing and portable, but no zero-copy read path and no clean hot/cold split, so caching pays a deserialize cost on every hit.

## Decision Outcome

Chosen option: **content-addressed, three-part envelope**. Each `.dr` carries (1) a **hot payload** serialized with rkyv 0.8 for zero-copy `mmap`-and-read access - effectively nothing to deserialize on a cache hit - (2) a **cold sidecar** in postcard for secondary metadata kept off the hot path, and (3) a **BLAKE3 root hash** over the payload that *is* the envelope's identity. Every envelope also carries its schema version, IR rung, capability set, and a provenance record naming the producing pass.

## Consequences

- **Good:** because identity is the BLAKE3 hash of the content, two envelopes with the same root are byte-identical *by construction*. This makes `--no-cache` an **optimization** toggle, not a **correctness** toggle: output is identical with the cache on or off. It also lets chains compose offline - a downstream pass can trust that a cached upstream envelope is exactly what a live run would have produced.
- **Good:** the zero-copy rkyv read makes cache hits near-free, so caching is unconditionally worth enabling.
- **Good:** the self-describing header (version + rung + capabilities + provenance) enables `disrobe envelope inspect`, `verify`, `diff`, and `migrate-check`, and lets transcoding move an envelope across schema versions while it stays at the same rung.
- **Bad / accepted cost:** the envelope decoder is now a security-sensitive surface - it decodes a content-addressed binary format from potentially adversarial sources. Read-past-end, integer overflow, and BLAKE3-mismatch acceptance are all in scope; the decoder (`crates/disrobe-ir/src/envelope.rs`) is fuzzed against exactly these.
- **Bad / accepted cost:** rkyv's zero-copy layout pins us to careful versioning discipline; schema changes require registered transcode paths rather than ad-hoc field tweaks.
