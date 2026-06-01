# Security policy

`disrobe` is a deobfuscator & decompiler suite. By the nature of the work it parses adversarial binary input - protector output, packed PE, obfuscated bytecode, exotic encoders - & emits derived artifacts. Hardening the parsing surface is a first-class concern.

## Supported versions

Security fixes ship on the `main` branch. Tagged releases (`v0.x.y`) snapshot known-good states. There is no LTS branch & no back-porting policy.

| Version  | Status        | Security fixes |
| -------- | ------------- | -------------- |
| `main`   | active        | yes (rolling)  |
| `0.9.x`  | current minor | yes            |
| `< 0.9`  | pre-release   | no             |

## Reporting a vulnerability

**Do not open a public issue for security reports.** Use GitHub's private security advisory channel:

-> <https://github.com/1-3-7/disrobe/security/advisories/new>

Include in the report:

- A description of the issue & its impact.
- A minimal reproducer (input bytes, command line, expected vs observed behavior).
- The `disrobe --version` output & the OS / arch.
- Whether you have a candidate fix.

We acknowledge reports within **72 hours** & aim to ship a fix within **30 days** for high-severity issues. Critical issues affecting parsing of untrusted input get same-week turnaround. We publish a GitHub Security Advisory & a CVE (where applicable) when the fix lands.

If you want to disclose publicly after the fix ships, we credit you in the advisory & in the release notes. Anonymous reports are welcome.

## In scope

The reporting channel covers any issue in the disrobe source tree that affects an instance running locally or in a CI:

- **Memory safety in the parsing surface.** disrobe is pure-Rust (`unsafe_code = "deny"` workspace-wide; the only `unsafe` lives in `crates/disrobe-pyarmor-cextract/` & `disrobe-pyarmor-pytrace/` for C-level pyo3 interop, gated behind explicit features). Any panic / abort on adversarial input that is not a clean `Result::Err` is in scope. Any heap corruption is high severity.
- **Resource exhaustion on adversarial input.** Zip-bombs, decompression bombs, container-recursion bombs, malformed-length-field bombs. disrobe's binfmt layer (`crates/disrobe-binfmt/src/quota.rs`) enforces per-entry & aggregate quotas; bypasses are in scope.
- **Path traversal.** zip-slip & equivalents on every container kind (zip, tar.{gz,bz2,xz,zst}, 7z, asar, cab, ar, deb, rpm, NSIS, InstallShield, Inno Setup, AppImage, Docker, OCI, Flatpak, Snap, squashfs, cramfs, ext4). Path-sanitisation lives in `crates/disrobe-binfmt/src/quota.rs::sanitize_entry_path` & sibling functions.
- **HTTP / gRPC server input handling.** `disrobe serve` (HTTP) & the gRPC surface accept `bytes_b64` only - never a filesystem path. Endpoints reject unknown JSON fields via `#[serde(deny_unknown_fields)]`. Any way to make the server read a file via a client-controlled string is high severity.
- **LSP-stdio input handling.** The `disrobe/analyze` LSP method also takes `bytes_b64` only with `deny_unknown_fields`. Same posture as HTTP.
- **Subprocess invocation.** `disrobe install`, `disrobe doctor --auto-install`, & backends that wrap external tools (CFR, Vineflower, jadx, ILSpy, dnSpy, de4dot, Ghidra, Rizin, ...) construct command lines from configuration & sometimes from user input. Command injection or argument smuggling is in scope.
- **`.dr` envelope handling.** `crates/disrobe-ir/src/envelope.rs` decodes a content-addressed binary format. Adversarial envelopes that cause read-past-end, integer overflow, or BLAKE3-mismatch acceptance are in scope.
- **Supply chain.** Tampering with our published binaries (when those land via `release.yml`) including signature-bypass, replay, or cosign-bundle manipulation.

## Out of scope

- **Decompilation output correctness on adversarial input.** disrobe will sometimes produce wrong output on hostile bytecode - the round-trip metric exists to flag this honestly. A decompile result that is not byte-perfect is not a security bug; it is correctness work. Open a normal issue or PR for these.
- **Compute exhaustion via legitimate input.** Decompiling a 67 MiB Hermes bundle is genuinely expensive. We optimise where reasonable, but a slow decompile is not a vulnerability.
- **Issues in third-party tools we wrap.** CFR, Vineflower, jadx, ILSpy, dnSpy, de4dot, Ghidra, Rizin, & friends each have their own security channels. We forward concerns where we can identify the upstream affected.
- **Repository operations outside the disrobe source tree.** GitHub platform issues, runner-image issues, GitHub Actions issues - report to GitHub.

## Hardening posture

- `#![forbid(unsafe_code)]` workspace-wide; the only opt-out is the two pyo3-cextract / pytrace crates that need C-level interop.
- Workspace clippy gate (`-D warnings -W unreachable_pub -W missing_debug_implementations -W unused`) is required for every commit on `main`.
- `cargo deny check` (advisories / bans / licenses / sources) runs on every push & weekly on a cron via `EmbarkStudios/cargo-deny-action@v2`.
- `cargo audit` runs weekly (Monday 06:00 UTC) on a separate schedule.
- All container extractors share the quota machinery in `crates/disrobe-binfmt/src/quota.rs`: per-entry size cap, aggregate size cap, recursion-depth cap, zip-slip path sanitisation.
- `corpus/native/packers/MANIFEST.toml` & sibling registries pin every fixture by BLAKE3; tests verify byte-identity before exercising the parser.
- The HTTP / gRPC / LSP servers never read files from disk based on client input. Only `bytes_b64` is accepted; `#[serde(deny_unknown_fields)]` is enforced; non-loopback HTTP binds emit a `tracing::warn!` banner at startup.
- Branch protection on `main` requires 1 approval + 6 green CI checks + linear history + no force-push + no deletion.
- The author of every commit is the GitHub noreply form (`<id>+<handle>@users.noreply.github.com`); personal email never appears in history.

## Cryptography

- Identity hash: BLAKE3 (the `blake3` crate, `0.x`).
- Stream / file hashing: BLAKE3 incremental.
- Symmetric: AES-CBC / AES-GCM via RustCrypto's `aes` / `aes-gcm` (used only inside specific parsers - Confidential's swift-decrypt, AES-zip, etc. - never on our own envelope format, which is content-addressed not encrypted).
- Asymmetric: none in the disrobe runtime path. The release pipeline signs binaries via [cosign](https://github.com/sigstore/cosign) keyless OIDC & [minisign](https://github.com/jedisct1/minisign).

## Sigstore transparency log

Release artifacts published via the `release.yml` workflow are signed with cosign keyless. Every signature is recorded in the [Rekor public transparency log](https://search.sigstore.dev/). To verify a downloaded binary:

```sh
cosign verify-blob \
  --certificate-identity-regexp '^https://github.com/1-3-7/disrobe/' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  --signature disrobe-v0.9.0-<target>.tar.zst.sig \
  --bundle    disrobe-v0.9.0-<target>.tar.zst.cosign.bundle \
  disrobe-v0.9.0-<target>.tar.zst
```

Or via `slsa-verifier` against the SLSA provenance attached to each release.

## Acknowledgements

When a reported issue ships a fix, we add the reporter (with their preferred handle) to the GitHub Security Advisory page & to the release notes for the version that contains the fix.

## License

This policy is published under the same Apache-2.0 license as the rest of the project. See [LICENSE-APACHE](LICENSE-APACHE) & [NOTICE](NOTICE).
