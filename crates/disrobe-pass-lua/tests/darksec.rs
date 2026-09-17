#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use disrobe_pass_lua::darksec;
use disrobe_pass_lua::obfuscator::{DeobfOptions, LuaObfuscatorKind};

#[test]
fn detect_darksec() {
    let det = darksec::detect(b"-- DarkSec\nDS_VM_BOOT()").expect("detect");
    assert_eq!(det.kind, LuaObfuscatorKind::DarkSec);
}

#[test]
fn peel_darksec() {
    let opts: DeobfOptions = DeobfOptions::default();
    let out = darksec::peel(b"DarkSec_Obf", &opts).expect("peel");
    assert!(!out.fully_recovered);
    assert!(!out.residual_markers.is_empty());
}
