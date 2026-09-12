# FOPO (fopo.com.ar) - capture procedure

Last verified: 2026-05-26. Status: **SERVICE-DEAD** (origin server unreachable).

## probe results 2026-05-26

| probe | result |
|-------|--------|
| `nslookup fopo.com.ar` | resolves (Cloudflare IPs: 104.21.81.34, 172.67.137.210) |
| `curl https://fopo.com.ar/` | HTTP 520 (Cloudflare: Web Server Returned an Unknown Error) |
| `curl http://www.fopo.com.ar/` | HTTP 301 -> https -> 520 |
| Playwright navigate | `chrome-error://chromewebdata/` (connection failure) |
| `web.archive.org` snapshot 2026-04-03 | exists but renders "URL not archived" |

Conclusion: DNS is alive (CF proxy), but the origin returns 520 on every request. Site appears dead.

## procedure (when site returns)

1. Open https://www.fopo.com.ar.
2. Paste the contents of `corpus/php/megafile/edge_cases.php` (or a pre-PHP-8 subset
   from `corpus/php/megafile/pre80_edge_cases.php` since FOPO predates PHP 8 syntax)
   into the input area.
3. Solve any captcha when challenged.
4. Click "Obfuscate".
5. Copy the resulting `<?php $O00OO0=...; ... eval($O0O000(...));` payload into
   `corpus/php/fopo/real_sample.php`.
6. Compute the sha256, update `corpus/php/MANIFEST.toml`.
7. Add a real fixture test in `crates/disrobe-pass-php/tests/fopo_real.rs` that reads
   the file & asserts the existing FOPO peeler (`peel_eval_chain` with `PeelLayer::Fopo`)
   recovers the inner PHP.

## current disposition

The existing synth test (`crates/disrobe-pass-php/tests/fopo_peel.rs`) covers the FOPO
detection + peel path with hand-built fixtures via `common::build_fopo`. No real
fixture available; service is dead.
