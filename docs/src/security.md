# Security

This is the short form. The full security policy lives in [SECURITY.md](https://github.com/1-3-7/disrobe/blob/main/SECURITY.md).

## Reporting a vulnerability

**Do not open a public issue for security reports.** Use GitHub's private advisory channel:

Report at: <https://github.com/1-3-7/disrobe/security/advisories/new>

Include a description and impact, a minimal reproducer (input bytes, command line, expected vs observed), the `disrobe --version` output, the OS/arch, and whether you have a candidate fix. Reports are acknowledged within 72 hours; high-severity fixes target 30 days, with same-week turnaround for parsing-of-untrusted-input issues. Reporters are credited (with their preferred handle) in the advisory and release notes; anonymous reports are welcome.

## In scope

- **Memory safety in the parsing surface.** Any panic/abort on adversarial input that is not a clean `Result::Err`; any heap corruption is high severity.
- **Resource exhaustion.** Zip-bombs, decompression bombs, recursion bombs, and malformed-length-field bombs: bypasses of the `crates/disrobe-binfmt/src/quota.rs` quotas.
- **Path traversal.** zip-slip and equivalents on every container extraction path.
- **Server input handling.** `disrobe serve` (HTTP/gRPC/LSP/MCP) accepts `bytes_b64` only; any way to make it read a file via a client-controlled string is high severity.
- **Subprocess invocation.** Command injection or argument smuggling in backend invocation.
- **`.dr` envelope handling.** Read-past-end, integer overflow, or BLAKE3-mismatch acceptance.
- **Supply chain.** Tampering with published binaries, signature bypass, replay, cosign-bundle manipulation, or a forged build-provenance attestation.

## Out of scope

- Decompilation output correctness on adversarial input: that is correctness work flagged by the round-trip metric, not a security bug. File a normal issue.
- Compute exhaustion from legitimate input (a slow decompile of a 66 MiB bundle is not a vulnerability).
- Issues in third-party tools `disrobe` wraps: report to their upstreams.

## Hardening posture

The default parsing path is Rust and keeps `unsafe` out of format decoders. Unsafe blocks are restricted to audited boundary code such as C interop, WASM exports, archive/io shims, build/install helpers, and native-loader interfaces. Strict clippy runs on every commit. `cargo deny` runs on every push plus weekly; `cargo audit` runs weekly. Shared container quota machinery, BLAKE3-pinned fixtures, loopback-default servers, and a warning banner on non-loopback binds backstop the runtime surface. Branch protection on `main` requires review, green CI, linear history, and no force-push.

## Verifying release artifacts

Release binaries are signed with cosign keyless OIDC and recorded in the Rekor transparency log:

```sh
cosign verify-blob \
  --certificate-identity-regexp '^https://github.com/1-3-7/disrobe/' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  --bundle    disrobe-<version>-<target>.tar.zst.cosign.bundle \
  disrobe-<version>-<target>.tar.zst
```

Each binary is also built with `cargo auditable`, which embeds a dependency manifest readable with `cargo audit bin disrobe` (five of seven targets; the two cross-compiled Linux targets are a disclosed gap, see [SECURITY.md](https://github.com/1-3-7/disrobe/blob/main/SECURITY.md#build-provenance-and-sbom)). A CycloneDX SBOM ships as a release asset. GitHub build-provenance attestations are verifiable with `gh attestation verify disrobe-<version>-<target>.tar.zst --repo 1-3-7/disrobe`. `.github/workflows/verify-release.yml` independently re-checks all of this against every published release.
