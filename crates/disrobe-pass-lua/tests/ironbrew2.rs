#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use disrobe_pass_lua::ironbrew2;
use disrobe_pass_lua::obfuscator::{DeobfOptions, LuaObfuscatorKind};

const SAMPLE: &[u8] = b"-- IronBrew2\nIronbrew_Build=1\nIRONBREW_VM";

#[test]
fn detect_ironbrew2() {
    let det = ironbrew2::detect(SAMPLE).expect("detect");
    assert_eq!(det.kind, LuaObfuscatorKind::Ironbrew2);
}

#[test]
fn peel_ironbrew2_blocks_without_authorization() {
    let opts: DeobfOptions = DeobfOptions::default();
    let err: disrobe_pass_lua::Error = ironbrew2::peel(SAMPLE, &opts).unwrap_err();
    assert!(matches!(
        err,
        disrobe_pass_lua::Error::AuthorizationRequired("Ironbrew2")
    ));
}

#[test]
fn peel_ironbrew2_with_authorization() {
    let opts: DeobfOptions = DeobfOptions {
        i_have_authorization: true,
        strict: false,
    };
    let out = ironbrew2::peel(SAMPLE, &opts).expect("peel");
    assert!(
        out.passes_run
            .iter()
            .any(|p: &String| p == "opcode-permutation-undo")
    );
}
