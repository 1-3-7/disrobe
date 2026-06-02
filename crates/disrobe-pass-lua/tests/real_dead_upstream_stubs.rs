#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

#[test]
#[ignore = "DEAD-UPSTREAM: Ironbrew2 github org gone (404 across all known forks 2026-05-25). detection-only synth fixture lives in tests/ironbrew2.rs; revisit if a fork resurfaces."]
fn real_ironbrew2_dead_upstream() {
    unreachable!("DEAD-UPSTREAM marker only");
}

#[test]
#[ignore = "DEAD-UPSTREAM: AztupBrew github org gone (404 across all known forks 2026-05-25). detection-only synth fixture lives in tests/aztup_brew.rs; revisit if a fork resurfaces."]
fn real_aztup_brew_dead_upstream() {
    unreachable!("DEAD-UPSTREAM marker only");
}

#[test]
#[ignore = "DEAD-UPSTREAM: PSU (Lua Protector) - no live github source found (2026-05-25). detection-only synth fixture lives in tests/psu.rs; revisit if upstream resurfaces."]
fn real_psu_dead_upstream() {
    unreachable!("DEAD-UPSTREAM marker only");
}

#[test]
#[ignore = "DEAD-UPSTREAM: Boronide - no live github source found (2026-05-25). detection-only synth fixture lives in tests/boronide.rs; revisit if upstream resurfaces."]
fn real_boronide_dead_upstream() {
    unreachable!("DEAD-UPSTREAM marker only");
}

#[test]
#[ignore = "DEAD-UPSTREAM: DarkSec - no live github source found (2026-05-25). detection-only synth fixture lives in tests/darksec.rs; revisit if upstream resurfaces."]
fn real_darksec_dead_upstream() {
    unreachable!("DEAD-UPSTREAM marker only");
}

#[test]
#[ignore = "DEAD-UPSTREAM: MoonSec - moonsec.com DNS resolution fails (2026-05-25). v1/v2/v3 detection-only synth fixtures live in tests/moonsec_v{1,2,3}.rs; revisit if site returns."]
fn real_moonsec_dead_upstream() {
    unreachable!("DEAD-UPSTREAM marker only");
}

#[test]
#[ignore = "DEAD-API: api.wearedevs.net returns 404 across all probed endpoints (2026-05-25). web obfuscator at wearedevs.net/obfuscator IS live but uses Prometheus backend - see CAPTURE-MANUAL.md. detection-only synth fixture lives in tests/wearedevs_luau.rs."]
fn real_wearedevs_api_dead() {
    unreachable!("DEAD-API marker only");
}

#[test]
#[ignore = "CAPTCHA-BLOCKED: luaobfuscator.com gates editor behind hCaptcha; no automated capture possible. See CAPTURE-MANUAL.md. detection-only synth fixture lives in tests/luaobfuscator_com.rs."]
fn real_luaobfuscator_com_captcha_blocked() {
    unreachable!("CAPTCHA-BLOCKED marker only");
}
