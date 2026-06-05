# pyobfuscate.com - manual capture procedure

Last verified: 2026-05-25. https://pyobfuscate.com is a free web obfuscator with a server-side endpoint at `/api/obfuscate`. The endpoint is rate-limited & requires a session token issued via a Cloudflare-Turnstile challenge solved during the initial page load. Headless automation is blocked.

## procedure

1. Open https://pyobfuscate.com .
2. Paste `.developer/wave2-py-tools/inputs_band/band_3_8.py` into the input area.
3. Solve the captcha when challenged.
4. Click "Obfuscate" & copy the output into `real_sample.py`.
5. Repeat for `band_3_12.py` -> `real_application.py`.
6. Repeat for each edge-case input.
7. Update `corpus/python/obfuscators/MANIFEST.toml` with the sha256 of each new file.

## test wiring

`crates/disrobe-pass-py-deob/tests/pyobfuscate_com_real.rs` ships an `#[ignore = "online-service-requires-manual-capture"]` test that locates `real_sample.py` if present & asserts the existing peeler detects it. Drop the ignore attribute after a manual capture lands.
