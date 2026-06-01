#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use disrobe_pass_wasm_deob::{JsStringBuiltin, JsStringReport, scan_js_string_builtins};

const WAT_JS_STRING: &str = r#"
    (module
      (type $ft0 (func (param i32) (result (ref extern))))
      (type $ft1 (func (param (ref extern) (ref extern)) (result (ref extern))))
      (type $ft2 (func (param (ref extern)) (result i32)))
      (import "wasm:js-string" "fromCharCode" (func (type $ft0)))
      (import "wasm:js-string" "concat" (func (type $ft1)))
      (import "wasm:js-string" "length" (func (type $ft2))))
"#;

const WAT_TEXT_DECODER: &str = r#"
    (module
      (type $ft (func (param i32 i32) (result (ref extern))))
      (import "wasm:text-decoder" "decodeStringFromUTF8Array" (func (type $ft))))
"#;

fn baked(src: &str) -> Option<Vec<u8>> {
    wat::parse_str(src).ok()
}

#[test]
fn detects_three_js_string_builtins_and_emits_dts() {
    let Some(bytes): Option<Vec<u8>> = baked(WAT_JS_STRING) else {
        return;
    };
    let report: JsStringReport = scan_js_string_builtins(&bytes).expect("scan");
    assert!(report.uses_js_string);
    assert!(
        report
            .by_builtin
            .contains_key(&JsStringBuiltin::FromCharCode)
    );
    assert!(report.by_builtin.contains_key(&JsStringBuiltin::Concat));
    assert!(report.by_builtin.contains_key(&JsStringBuiltin::Length));
    let dts: String = report.render_ts_d_ts();
    assert!(dts.contains("fromCharCode"));
    assert!(dts.contains("concat"));
}

#[test]
fn detects_text_decoder_namespace() {
    let Some(bytes): Option<Vec<u8>> = baked(WAT_TEXT_DECODER) else {
        return;
    };
    let report: JsStringReport = scan_js_string_builtins(&bytes).expect("scan");
    assert!(report.uses_text_decoder);
    assert!(
        report
            .by_builtin
            .contains_key(&JsStringBuiltin::TextDecoderDecode)
    );
}
