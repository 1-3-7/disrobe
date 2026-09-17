# oxyry - manual capture procedure

Last verified: 2026-05-26. Status: **SERVICE-PIVOTED** - the obfuscator is gone.

## probe results 2026-05-26

| probe | result |
|-------|--------|
| `https://oxyry.com` | HTTP 301 -> `https://www.oxyry.com/` |
| `https://www.oxyry.com/` | 200 OK - page is now `氧化效应 OXYRY Studio` (Chinese-language studio portal showcasing an unrelated English-learning video app at babelabc.oxyry.com); no obfuscator UI anywhere on the page |
| `https://www.oxyry.com/obfuscator` | 404 |
| `https://obfuscator.oxyry.com` | empty body |

The Python obfuscator that previously lived at oxyry.com has been retired. The owner
appears to have repurposed the domain for an unrelated studio portfolio.

## procedure (when service returns or a fork ships)

The obfuscation bundle was MIT-licensed per `github.com/oxyry/oxyry-obfuscator` (verify
the repo URL since the org may have moved). If the upstream surfaces, vendor the
implementation locally rather than relying on the (now-defunct) web endpoint.

## current disposition

The synth-fixture test `crates/disrobe-pass-py-deob/tests/oxyry_unminify.rs` ships with
hand-rolled fixtures derived from the previously-documented oxyry output format. The
real-fixture test `oxyry_real.rs` stays `#[ignore = "DEAD-UPSTREAM"]` until a successor
endpoint or a vendored fork appears.
