# online_family - manual capture procedure (no CLI, no public API)

Last verified: 2026-05-25. Tools in this family (pyobfuscator.com, pyobfuscate.com) only ship browser UIs & either block direct POSTs or guard the obfuscate endpoint with a CAPTCHA. Automated capture via Playwright was attempted; the form-submit POST returns 403 unless the cf-turnstile token is present in the request body, & the token issuance flow refuses headless browsers.

## procedure (per service)

1. Open https://pyobfuscator.com (or https://pyobfuscate.com).
2. Paste the contents of `.developer/wave2-py-tools/inputs_band/band_3_8.py` into the input editor.
3. Solve the captcha when prompted.
4. Click "Obfuscate".
5. Copy the result text into `real_sample.py` in this directory.
6. Repeat with `band_3_12.py` to populate `real_application.py`.
7. Repeat with each `inputs/<edge>.py` to populate `edge-cases/real_<edge>.py`.
8. After every capture: regenerate this corpus's MANIFEST.toml entry by running `.developer/wave2-py-tools/runner.py --record-manual online_family` (the runner sha256s the just-written files).

## why automation is blocked

- Both services use Cloudflare Turnstile to guard the obfuscate endpoint.
- The token cookie is issued only to interactive sessions & is bound to the IP + User-Agent that solved the challenge.
- Headless browsers (Playwright `chromium --headless=new`, Firefox `--headless`) are scored above the rejection threshold within ~3 seconds.
- Running headed is possible but defeats the point of CI automation.

The real-fixture test for this obfuscator is therefore `#[ignore]` by default. Once a manual capture is recorded & committed, drop the ignore attribute on the matching test in `crates/disrobe-pass-py-deob/tests/online_family_real.rs`.
