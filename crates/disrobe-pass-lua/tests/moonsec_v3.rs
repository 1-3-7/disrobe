#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use disrobe_pass_lua::moonsec_v3;
use disrobe_pass_lua::obfuscator::{DeobfOptions, LuaObfuscatorKind};

const V3_SAMPLE: &[u8] = b"-- MoonSec v3\nMS_VM_ENTRY()\nMS_VM_TAMPER()";

#[test]
fn detect_moonsec_v3() {
    let det = moonsec_v3::detect(V3_SAMPLE).expect("detect");
    assert_eq!(det.kind, LuaObfuscatorKind::MoonSecV3);
    assert!(det.confidence >= 90);
}

#[test]
fn peel_moonsec_v3_blocks_without_authorization() {
    let opts: DeobfOptions = DeobfOptions::default();
    let err: disrobe_pass_lua::Error = moonsec_v3::peel(V3_SAMPLE, &opts).unwrap_err();
    assert!(matches!(
        err,
        disrobe_pass_lua::Error::AuthorizationRequired("MoonSec V3")
    ));
}

#[test]
fn peel_moonsec_v3_with_authorization() {
    let opts: DeobfOptions = DeobfOptions {
        i_have_authorization: true,
        strict: false,
    };
    let out = moonsec_v3::peel(V3_SAMPLE, &opts).expect("peel");
    assert!(
        out.passes_run
            .iter()
            .any(|p: &String| p == "vm-handler-table-recover")
    );
}
