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
