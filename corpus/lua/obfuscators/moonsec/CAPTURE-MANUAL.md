# MoonSec V1/V2/V3 - capture procedure

Last verified: 2026-05-26. Status: **SERVICE-DEAD** for all known MoonSec endpoints.

## probe results 2026-05-26

| candidate URL | result |
|---------------|--------|
| `moonsec.com` | DNS resolves but HTTP fetch returns empty (Apache, no body) - appears parked/dead |
| `www.moonsec.com` | Live WordPress site `渗透测试培训-网络安全培训-暗月博客` (Chinese cybersec training blog). UNRELATED to the Roblox Lua obfuscator. |
| `moonsec.cn` | 200 OK but minimal content, not a Lua obfuscator |
| `moonsec.io` | DNS no answer |
| `moonsec.xyz` | Parked domain (RapidResultSearch ad page) |
| `api.moonsec.io` | DNS no answer |

The Roblox-era MoonSec V1/V2/V3 obfuscator (active circa 2020-2022) has no surviving endpoint
under any TLD probed. The brand was abandoned years ago.

## procedure (when service returns)

Should a successor ever appear:

1. Open the new endpoint.
2. Paste `corpus/lua/megafile/edge_cases.lua` (or a representative slice).
3. Solve any CAPTCHA / pass any auth gate.
4. Select V1, V2, V3 preset & save each output as `real_v1.lua`, `real_v2.lua`, `real_v3.lua`.
5. Update `corpus/lua/MANIFEST.toml` with sha256 of each.
6. Add real fixture tests in `crates/disrobe-pass-lua/tests/moonsec_v{1,2,3}_real.rs` &
   drop `#[ignore = "DEAD-UPSTREAM"]` once captures land.

## current disposition

The synth-fixture tests `crates/disrobe-pass-lua/tests/moonsec_v{1,2,3}.rs` ship as the
authoritative coverage. They use hand-built fixtures with the documented MoonSec V1/V2/V3
marker strings. Mark these `#[ignore = "DEAD-UPSTREAM"]` for the real-fixture variants.
