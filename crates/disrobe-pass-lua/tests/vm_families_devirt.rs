#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

#[path = "support/dvm1_reference.rs"]
#[allow(clippy::redundant_pub_crate, dead_code)]
mod dvm1_reference;

#[path = "support/lua_toolchain.rs"]
#[allow(clippy::redundant_pub_crate, dead_code)]
mod lua_toolchain;

use std::path::PathBuf;

use disrobe_pass_lua::obfuscator::{DeobfOptions, PeelResult};
use dvm1_reference::{PermRecipe, bootstrap_with_payload};
use lua_toolchain::{LuaInterpreter, require_interpreter, run_lua};

const fn recipe(seed: u32, step: u32, base: u32) -> PermRecipe {
    PermRecipe {
        seed,
        step,
        base,
        key_mask: 0xFF,
    }
}

fn assert_reference_container_roundtrip(family: &str, result: &PeelResult) {
    assert!(
        result.fully_recovered,
        "{family}: the {family} marker must route the reference-container payload through a full \
         round-trip back to runnable Lua (this is disrobe's own DVM1 container, not {family}'s \
         real wire format); markers: {:?}",
        result.residual_markers
    );
    let recovered: String = String::from_utf8_lossy(&result.deobfuscated).into_owned();
    assert!(
        recovered.contains("print"),
        "{family}: recovered lua must call print:\n{recovered}"
    );
    assert!(
        recovered.contains('+'),
        "{family}: recovered lua must contain the 40 + 2 addition:\n{recovered}"
    );
    assert!(
        result
            .recovered_strings
            .iter()
            .any(|s: &String| s == "print"),
        "{family}: must surface the 'print' string constant"
    );
}

fn assert_executes_like_original(family: &str, result: &PeelResult) {
    let graded: String =
        format!("the {family} round-trip of this crate's own DVM1 reference container");
    let Some(interp): Option<LuaInterpreter> = require_interpreter(&graded) else {
        return;
    };
    let recovered: String = String::from_utf8_lossy(&result.deobfuscated).into_owned();
    let expected: String = run_lua(&interp, "the known original", "print(40 + 2)");
    assert_eq!(
        expected.trim_end(),
        dvm1_reference::KNOWN_MODULE_STDOUT,
        "the known original must print {}, so a run where it prints {:?} is comparing against \
         nothing meaningful",
        dvm1_reference::KNOWN_MODULE_STDOUT,
        expected.trim_end()
    );
    let actual: String = run_lua(&interp, family, &recovered);
    assert_eq!(
        actual.trim_end(),
        expected.trim_end(),
        "{family}: recovered program output must match the known original\n--- recovered ---\n{recovered}"
    );
}

#[test]
fn boronide_marker_roundtrips_reference_container() {
    use disrobe_pass_lua::boronide;
    let (boot, _payload): (String, Vec<u8>) = bootstrap_with_payload(
        "-- Boronide v0.6\nBORONIDE_VM",
        &recipe(0x1357_2468, 11, 0x40),
    );
    let result: PeelResult =
        boronide::peel(boot.as_bytes(), &DeobfOptions::default()).expect("peel");
    assert_reference_container_roundtrip("boronide", &result);
    assert_executes_like_original("boronide", &result);
}

#[test]
fn psu_marker_roundtrips_reference_container() {
    use disrobe_pass_lua::psu;
    let (boot, _payload): (String, Vec<u8>) =
        bootstrap_with_payload("-- PSU 4.5\nPSU_VM_KEY", &recipe(0x0042_0042, 7, 0x50));
    let result: PeelResult = psu::peel(boot.as_bytes(), &DeobfOptions::default()).expect("peel");
    assert_reference_container_roundtrip("psu", &result);
    assert_executes_like_original("psu", &result);
}

#[test]
fn darksec_marker_roundtrips_reference_container() {
    use disrobe_pass_lua::darksec;
    let (boot, _payload): (String, Vec<u8>) =
        bootstrap_with_payload("-- DarkSec\nDS_VM_BOOT", &recipe(0x7F7F_7F7F, 13, 0x60));
    let result: PeelResult =
        darksec::peel(boot.as_bytes(), &DeobfOptions::default()).expect("peel");
    assert_reference_container_roundtrip("darksec", &result);
    assert_executes_like_original("darksec", &result);
}

#[test]
fn moonsec_v1_marker_roundtrips_reference_container() {
    use disrobe_pass_lua::moonsec_v1;
    let (boot, _payload): (String, Vec<u8>) =
        bootstrap_with_payload("-- MoonSec v1\nmoonsec_v1", &recipe(0x1111_2222, 9, 0x30));
    let result: PeelResult =
        moonsec_v1::peel(boot.as_bytes(), &DeobfOptions::default()).expect("peel");
    assert_reference_container_roundtrip("moonsec_v1", &result);
    assert_executes_like_original("moonsec_v1", &result);
}

#[test]
fn moonsec_v2_marker_roundtrips_reference_container() {
    use disrobe_pass_lua::moonsec_v2;
    let (boot, _payload): (String, Vec<u8>) =
        bootstrap_with_payload("-- MoonSec v2\nMS_V2_KEY", &recipe(0x2222_3333, 7, 0x50));
    let result: PeelResult =
        moonsec_v2::peel(boot.as_bytes(), &DeobfOptions::default()).expect("peel");
    assert_reference_container_roundtrip("moonsec_v2", &result);
    assert_executes_like_original("moonsec_v2", &result);
}

#[test]
fn moonsec_v3_marker_roundtrips_reference_container_with_authorization() {
    use disrobe_pass_lua::moonsec_v3;
    let (boot, _payload): (String, Vec<u8>) =
        bootstrap_with_payload("-- MoonSec v3\nMS_VM_ENTRY", &recipe(0x3333_4444, 13, 0x60));
    let opts: DeobfOptions = DeobfOptions {
        i_have_authorization: true,
        strict: false,
    };
    let result: PeelResult = moonsec_v3::peel(boot.as_bytes(), &opts).expect("peel");
    assert_reference_container_roundtrip("moonsec_v3", &result);
    assert_executes_like_original("moonsec_v3", &result);
}

#[test]
fn moonsec_v3_embedded_payload_blocks_without_authorization() {
    use disrobe_pass_lua::moonsec_v3;
    let (boot, _payload): (String, Vec<u8>) =
        bootstrap_with_payload("-- MoonSec v3\nMS_VM_ENTRY", &recipe(0x3333_4444, 13, 0x60));
    let err: disrobe_pass_lua::Error =
        moonsec_v3::peel(boot.as_bytes(), &DeobfOptions::default()).unwrap_err();
    assert!(matches!(
        err,
        disrobe_pass_lua::Error::AuthorizationRequired("MoonSec V3")
    ));
}

#[test]
fn aztup_brew_marker_roundtrips_reference_container() {
    use disrobe_pass_lua::aztup_brew;
    let (boot, _payload): (String, Vec<u8>) =
        bootstrap_with_payload("-- aztup_brew\nAZB_VM", &recipe(0x4242_4242, 11, 0x40));
    let result: PeelResult =
        aztup_brew::peel(boot.as_bytes(), &DeobfOptions::default()).expect("peel");
    assert_reference_container_roundtrip("aztup_brew", &result);
    assert_executes_like_original("aztup_brew", &result);
}

#[test]
fn prometheus_does_not_claim_disrobe_vm_container() {
    use disrobe_pass_lua::prometheus;
    let (boot, _payload): (String, Vec<u8>) = bootstrap_with_payload(
        "-- Prometheus\nPROMETHEUS_VERSION",
        &recipe(0x5050_6060, 11, 0x40),
    );
    let result: PeelResult =
        prometheus::peel(boot.as_bytes(), &DeobfOptions::default()).expect("peel");
    assert!(
        !result.fully_recovered,
        "prometheus must not claim a test-only vm container as real family recovery"
    );
    assert!(
        result
            .residual_markers
            .iter()
            .any(|marker: &String| marker.contains("constant-array")),
        "prometheus must report the real missing parser surface: {:?}",
        result.residual_markers
    );
}

#[test]
fn hercules_marker_roundtrips_reference_container() {
    use disrobe_pass_lua::hercules;
    let (boot, _payload): (String, Vec<u8>) = bootstrap_with_payload(
        "-- Obfuscated by Hercules\nhercules-obfuscator",
        &recipe(0x6161_7272, 7, 0x50),
    );
    let result: PeelResult =
        hercules::peel(boot.as_bytes(), &DeobfOptions::default()).expect("peel");
    assert_reference_container_roundtrip("hercules", &result);
    assert_executes_like_original("hercules", &result);
}

#[test]
fn luraph_marker_roundtrips_reference_container_else_walls() {
    use disrobe_pass_lua::luraph;
    let (boot, _payload): (String, Vec<u8>) =
        bootstrap_with_payload("-- Luraph\nlura.ph", &recipe(0x7272_8383, 13, 0x60));
    let result: PeelResult = luraph::peel(boot.as_bytes(), &DeobfOptions::default()).expect("peel");
    assert_reference_container_roundtrip("luraph", &result);
    assert_executes_like_original("luraph", &result);
}

#[test]
fn luraph_real_runtime_key_is_honest_wall() {
    use disrobe_pass_lua::luraph;
    let real: &[u8] = b"-- This file was generated by Luraph\nlocal a=LPH_ENCFUNC(...)\nreturn a";
    let result: PeelResult = luraph::peel(real, &DeobfOptions::default()).expect("peel");
    assert!(
        !result.fully_recovered,
        "luraph runtime-key sample must NOT fabricate a recovery"
    );
    assert!(
        result
            .residual_markers
            .iter()
            .any(|m: &String| m.contains("WALL") && m.contains("runtime")),
        "luraph must report the honest info-theoretic runtime-key wall: {:?}",
        result.residual_markers
    );
}

#[test]
fn luaobfuscator_com_unpacks_real_free_tier_constant_pool() {
    use disrobe_pass_lua::luaobfuscator_com;
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path.push("corpus/lua/obfuscators/luaobfuscator_com/sample_default_obf_v1.lua");
    let data: Vec<u8> = std::fs::read(&path)
        .unwrap_or_else(|e| panic!("missing committed fixture {}: {e}", path.display()));
    let result: PeelResult =
        luaobfuscator_com::peel(&data, &DeobfOptions::default()).expect("peel real fixture");
    for want in [
        "sieve_of_eratosthenes",
        "print",
        "math",
        "floor",
        "sqrt",
        "string",
        "pairs",
    ] {
        assert!(
            result.recovered_strings.iter().any(|s: &String| s == want),
            "the real free-tier unpacker must recover the plaintext constant {want:?}; got {:?}",
            result.recovered_strings
        );
    }
}

#[test]
fn families_without_payload_are_honest_passthrough() {
    use disrobe_pass_lua::{boronide, darksec, psu};
    for (name, result) in [
        (
            "boronide",
            boronide::peel(b"-- Boronide v0.5\nBORONIDE_VM", &DeobfOptions::default())
                .expect("peel"),
        ),
        (
            "psu",
            psu::peel(b"-- PSU 4.0\nPSU_VM_KEY", &DeobfOptions::default()).expect("peel"),
        ),
        (
            "darksec",
            darksec::peel(b"-- DarkSec\nDS_VM_BOOT", &DeobfOptions::default()).expect("peel"),
        ),
    ] {
        assert!(
            !result.fully_recovered,
            "{name}: no embedded payload means no honest full recovery"
        );
        assert!(
            !result.residual_markers.is_empty(),
            "{name}: passthrough must explain why"
        );
    }
}
