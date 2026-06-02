# Security

The full security policy lives in [SECURITY.md](https://github.com/1-3-7/disrobe/blob/main/SECURITY.md). This page summarizes it.

## Reporting a vulnerability

**Do not open a public issue for security reports.** Use GitHub's private advisory channel:

→ <https://github.com/1-3-7/disrobe/security/advisories/new>

Include a description and impact, a minimal reproducer (input bytes, command line, expected vs observed), the `disrobe --version` output, the OS/arch, and whether you have a candidate fix. Reports are acknowledged within 72 hours; high-severity fixes target 30 days, with same-week turnaround for parsing-of-untrusted-input issues. Reporters are credited (with their preferred handle) in the advisory and release notes; anonymous reports are welcome.

## In scope

- **Memory safety in the parsing surface.** Any panic/abort on adversarial input that is not a clean `Result::Err`; any heap corruption is high severity.
- **Resource exhaustion.** Zip-bombs, decompression bombs, recursion bombs, malformed-length-field bombs — bypasses of the `crates/disrobe-binfmt/src/quota.rs` quotas.
- **Path traversal.** zip-slip and equivalents on any of the 26 container formats.
- **Server input handling.** `disrobe serve` (HTTP/gRPC/LSP/MCP) accepts `bytes_b64` only; any way to make it read a file via a client-controlled string is high severity.
- **Subprocess invocation.** Command injection or argument smuggling in backend invocation.
- **`.dr` envelope handling.** Read-past-end, integer overflow, or BLAKE3-mismatch acceptance.
- **Supply chain.** Tampering with published binaries, signature bypass, replay, cosign-bundle manipulation.

## Out of scope

- Decompilation output correctness on adversarial input — that is correctness work flagged by the round-trip metric, not a security bug. File a normal issue.
- Compute exhaustion from legitimate input (a slow decompile of a 67 MiB bundle is not a vulnerability).
- Issues in third-party tools disrobe wraps — report to their upstreams.

## Hardening posture

`#![forbid(unsafe_code)]` workspace-wide (except the two pyo3-interop crates). Strict clippy gate on every commit. `cargo deny` on every push plus weekly; `cargo audit` weekly. Shared container quota machinery. BLAKE3-pinned fixtures. Loopback-default servers with a warning banner on non-loopback binds. Branch protection on `main` (1 approval + green CI + linear history + no force-push).

## Verifying release artifacts

Release binaries are signed with cosign keyless OIDC (recorded in the Rekor transparency log) and minisign:

```sh
cosign verify-blob \
  --certificate-identity-regexp '^https://github.com/1-3-7/disrobe/' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  --signature disrobe-<version>-<target>.tar.zst.sig \
  --bundle    disrobe-<version>-<target>.tar.zst.cosign.bundle \
  disrobe-<version>-<target>.tar.zst
```
