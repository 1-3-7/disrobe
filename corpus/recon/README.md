# recon planted fixture

`planted/` is a synthetic decompiled-app tree with deliberately planted findings, used
by the `frisk_gauntlet` test to prove the recon engine detects every category.

Committed files carry the non-secret findings:

- `AndroidManifest.xml` - deep-link scheme + host, exported activity/service, content
  provider authority, dangerous permissions.
- `smali/com/planted/recon/Api.smali` - API routes / endpoint paths, an email.
- `assets/config.json` - URL, IPv4, email, `.onion` address.

The secret-per-provider findings (AWS, GitHub, Slack, Stripe, GCP, OpenAI, ...) are NOT
committed as literals: a contiguous real-format secret in a tracked file is rejected by
push protection. The gauntlet test assembles each secret at runtime via `format!`/`concat!`
and writes it into a temp copy of this tree before scanning, so coverage stays complete
while no secret literal lives in version control.

`android-audit/` is the Android code-pattern fixture for `disrobe apk` (the
`DR-APK-*` audit): `src/com/planted/audit/Plants.java` plants one insecure API use per
method across weak cryptography, insecure storage, transport security, WebView settings,
logging, dangerous APIs, privacy and anti-analysis checks, and `Control.java` uses the same
API families safely. `build.sh` compiles both with `javac` against the Apache-licensed
framework jars, dexes with `d8`, links the manifest with `aapt2` and signs with `apksigner`
(tool versions and hashes in `MANIFEST.toml`). The `android_audit` test in
`disrobe-pass-jvm` requires every plant at its method and nothing else, and no finding at
all on the control build.
