# corpus/lua/CAPTURE-MANUAL.md

Manual capture steps for Lua obfuscators that cannot be automated.

| obfuscator | site | status | reason | resume |
|---|---|---|---|---|
| luaobfuscator.com | https://luaobfuscator.com | CAPTCHA-BLOCKED | hCaptcha challenge gates the "New File" / "Upload File" actions; editor stays in "Making sure you ain't a robot..." state under Playwright headless | open in a real browser, solve the captcha, paste `corpus/lua/megafile/edge_cases.lua`, click each obfuscation preset in the right rail (CLEANUP / Dystropic / Malevolence / OBFUSCATE v1 / Basic Good), download each output to `corpus/lua/obfuscators/edge_cases.luaobfuscator_<preset>.lua` |
| wearedevs.net/obfuscator | https://wearedevs.net/obfuscator | EQUIVALENT-PROMETHEUS | the site itself states (and the page footer confirms) that the backend is unmodified `wcrddn/Prometheus` - output is byte-equivalent to our existing `obfuscators/edge_cases.prometheus_minify.lua` & `_weak.lua` | optional: paste the megafile, click Obfuscate, save as `corpus/lua/obfuscators/edge_cases.wearedevs.lua` & verify it matches one of the Prometheus presets |
| MoonSec v1 / v2 / v3 | (moonsec.com) | DEAD-DNS | `curl https://moonsec.com` → DNS resolution failure; project appears dead | none - keep synth fixtures + `#[ignore]` stubs |

## what's already captured

| file | size | source | notes |
|---|---:|---|---|
| `obfuscators/hello.prometheus.lua` | 26762 B | `prometheus-lua/Prometheus@HEAD` preset Medium target Lua51 | smoke fixture from `baseline/hello.lua` |
| `obfuscators/edge_cases.prometheus_minify.lua` | 19996 B | Prometheus preset Minify target Lua51 | megafile-derived; Medium preset crashed on `math.huge` arithmetic in NumbersToExpressions pass |
| `obfuscators/edge_cases.prometheus_weak.lua` | 78543 B | Prometheus preset Weak target Lua51 | megafile-derived |

## dead upstreams (mark `#[ignore = "DEAD-UPSTREAM"]` in tests)

| obfuscator | last known github org | probed urls | http |
|---|---|---|---|
| Ironbrew2 | (various) | `github.com/Ironbrew2/Ironbrew2`, `github.com/IronbrewSec/Ironbrew2-Reupload` | 404, 404 |
| AztupBrew | (various) | `github.com/Aztupbrew/Aztupbrew`, `github.com/AztupHub/Aztup-Brew`, `github.com/AztupBrew/AztupBrew` | 404, 404, 404 |
| PSU (Lua Protector) | (unknown) | `github.com/PSU-Lua/PSU`, `github.com/PSU-Lua/lua-protector`, `github.com/PSU-OS/PSU-Lua-Obfuscator` | 404, 404, 404 |
| Boronide | (unknown) | `github.com/Boronide/lua-obfuscator`, `github.com/0x66cw/Boronide`, `github.com/Boronide-Software/Boronide` | 404, 404, 404 |
| DarkSec | (unknown) | `github.com/darksec-lua/darksec`, `github.com/DarkSec/lua-obfuscator` | 404, 404 |
| WeAreDevs Luau API | api.wearedevs.net | `api.wearedevs.net`, `/obfuscate`, `wearedevs.net/api` | 404, 404, 404 (web obfuscator at wearedevs.net/obfuscator IS up but is Prometheus backend) |
