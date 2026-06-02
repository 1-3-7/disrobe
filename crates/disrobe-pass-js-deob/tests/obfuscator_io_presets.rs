#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use disrobe_pass_js_deob::{
    ObfuscatorIoOutput, ObfuscatorIoPreset, obfuscator_io_deobfuscate_preset,
};

const SAMPLE: &str = r"
var _0xa = ['hello', 'world', 'disrobe'];
(function(_0xb, _0xc){
  var _0xd = function(_0xe){
    while(--_0xe){
      _0xb.push(_0xb.shift());
    }
  };
  _0xd(_0xc);
}(_0xa, 0x2));
var _0xf = function(_0x1) { return _0xa[_0x1]; };
console.log(_0xf(0) + ' ' + _0xf(1) + ' ' + _0xf(2));
";

#[test]
fn low_preset_produces_runnable_output() {
    let out: ObfuscatorIoOutput =
        obfuscator_io_deobfuscate_preset(SAMPLE, ObfuscatorIoPreset::Low).expect("ok");
    assert!(out.passes_run >= 1);
    assert!(!out.source.is_empty());
}

#[test]
fn medium_preset_runs_more_controls_than_low() {
    let low: ObfuscatorIoOutput =
        obfuscator_io_deobfuscate_preset(SAMPLE, ObfuscatorIoPreset::Low).expect("ok");
    let medium: ObfuscatorIoOutput =
        obfuscator_io_deobfuscate_preset(SAMPLE, ObfuscatorIoPreset::Medium).expect("ok");
    assert!(medium.controls_applied.len() >= low.controls_applied.len());
}

#[test]
fn high_preset_runs_at_least_as_much_as_medium() {
    let medium: ObfuscatorIoOutput =
        obfuscator_io_deobfuscate_preset(SAMPLE, ObfuscatorIoPreset::Medium).expect("ok");
    let high: ObfuscatorIoOutput =
        obfuscator_io_deobfuscate_preset(SAMPLE, ObfuscatorIoPreset::High).expect("ok");
    assert!(high.controls_applied.len() >= medium.controls_applied.len());
}
