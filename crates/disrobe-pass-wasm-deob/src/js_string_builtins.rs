use std::collections::BTreeMap;

use serde::Serialize;
use wasmparser::{Parser, Payload, TypeRef};

use crate::error::{Error, Result};

pub const JS_STRING_NAMESPACE: &str = "wasm:js-string";
pub const TEXT_ENCODER_NAMESPACE: &str = "wasm:text-encoder";
pub const TEXT_DECODER_NAMESPACE: &str = "wasm:text-decoder";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum JsStringBuiltin {
    Cast,
    Test,
    FromCharCode,
    FromCodePoint,
    CharCodeAt,
    CodePointAt,
    Length,
    Concat,
    Substring,
    Equals,
    Compare,
    IntoCharCodeArray,
    FromCharCodeArray,
    TextEncoderEncodeInto,
    TextDecoderDecode,
    Other,
}

impl JsStringBuiltin {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Cast => "cast",
            Self::Test => "test",
            Self::FromCharCode => "fromCharCode",
            Self::FromCodePoint => "fromCodePoint",
            Self::CharCodeAt => "charCodeAt",
            Self::CodePointAt => "codePointAt",
            Self::Length => "length",
            Self::Concat => "concat",
            Self::Substring => "substring",
            Self::Equals => "equals",
            Self::Compare => "compare",
            Self::IntoCharCodeArray => "intoCharCodeArray",
            Self::FromCharCodeArray => "fromCharCodeArray",
            Self::TextEncoderEncodeInto => "encodeStringIntoUTF8Array",
            Self::TextDecoderDecode => "decodeStringFromUTF8Array",
            Self::Other => "other",
        }
    }

    #[must_use]
    pub fn classify(name: &str) -> Self {
        match name {
            "cast" => Self::Cast,
            "test" => Self::Test,
            "fromCharCode" => Self::FromCharCode,
            "fromCodePoint" => Self::FromCodePoint,
            "charCodeAt" => Self::CharCodeAt,
            "codePointAt" => Self::CodePointAt,
            "length" => Self::Length,
            "concat" => Self::Concat,
            "substring" => Self::Substring,
            "equals" => Self::Equals,
            "compare" => Self::Compare,
            "intoCharCodeArray" => Self::IntoCharCodeArray,
            "fromCharCodeArray" => Self::FromCharCodeArray,
            "encodeStringIntoUTF8Array" | "encodeStringToUTF8Array" => Self::TextEncoderEncodeInto,
            "decodeStringFromUTF8Array" => Self::TextDecoderDecode,
            _ => Self::Other,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct JsStringImport {
    pub module: String,
    pub name: String,
    pub function_type_index: u32,
    pub builtin: JsStringBuiltin,
    pub ts_signature: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct JsStringReport {
    pub imports: Vec<JsStringImport>,
    pub by_builtin: BTreeMap<JsStringBuiltin, usize>,
    pub uses_text_encoder: bool,
    pub uses_text_decoder: bool,
    pub uses_js_string: bool,
}

impl JsStringReport {
    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.imports.is_empty()
    }

    #[inline]
    #[must_use]
    pub const fn count(&self) -> usize {
        self.imports.len()
    }

    #[must_use]
    pub fn render_ts_d_ts(&self) -> String {
        let mut out: String = String::with_capacity(self.imports.len() * 64usize);
        out.push_str("declare namespace JSStringBuiltins {\n");
        for imp in &self.imports {
            out.push_str("  export const ");
            out.push_str(&imp.name);
            out.push_str(": ");
            out.push_str(&imp.ts_signature);
            out.push_str(";\n");
        }
        out.push_str("}\n");
        out
    }
}

pub fn scan_js_string_builtins(input: &[u8]) -> Result<JsStringReport> {
    if input.len() < 8 || &input[..4] != b"\0asm" {
        return Err(Error::Parse(
            "DR-WASMDEOB-JSSTR: not a wasm module".to_owned(),
        ));
    }
    let mut report: JsStringReport = JsStringReport::default();
    for payload in Parser::new(0).parse_all(input) {
        let payload: Payload<'_> = payload.map_err(|e| Error::Parse(format!("{e}")))?;
        if let Payload::ImportSection(reader) = payload {
            for group in reader {
                let group: wasmparser::Imports<'_> =
                    group.map_err(|e| Error::Parse(format!("{e}")))?;
                let wasmparser::Imports::Single(_, imp) = group else {
                    continue;
                };
                let module: &str = imp.module;
                let name: &str = imp.name;
                let TypeRef::Func(ftype) = imp.ty else {
                    continue;
                };
                let is_jsstr: bool = module == JS_STRING_NAMESPACE;
                let is_enc: bool = module == TEXT_ENCODER_NAMESPACE;
                let is_dec: bool = module == TEXT_DECODER_NAMESPACE;
                if !(is_jsstr || is_enc || is_dec) {
                    continue;
                }
                if is_jsstr {
                    report.uses_js_string = true;
                }
                if is_enc {
                    report.uses_text_encoder = true;
                }
                if is_dec {
                    report.uses_text_decoder = true;
                }
                let builtin: JsStringBuiltin = JsStringBuiltin::classify(name);
                *report.by_builtin.entry(builtin).or_insert(0usize) += 1usize;
                let ts_signature: String = synthesize_ts_signature(builtin);
                report.imports.push(JsStringImport {
                    module: module.to_owned(),
                    name: name.to_owned(),
                    function_type_index: ftype,
                    builtin,
                    ts_signature,
                });
            }
        }
    }
    Ok(report)
}

fn synthesize_ts_signature(b: JsStringBuiltin) -> String {
    match b {
        JsStringBuiltin::Cast => "(externref) => string".to_owned(),
        JsStringBuiltin::Test => "(externref) => i32".to_owned(),
        JsStringBuiltin::FromCharCode => "(code: i32) => string".to_owned(),
        JsStringBuiltin::FromCodePoint => "(cp: i32) => string".to_owned(),
        JsStringBuiltin::CharCodeAt => "(s: string, i: i32) => i32".to_owned(),
        JsStringBuiltin::CodePointAt => "(s: string, i: i32) => i32".to_owned(),
        JsStringBuiltin::Length => "(s: string) => i32".to_owned(),
        JsStringBuiltin::Concat => "(a: string, b: string) => string".to_owned(),
        JsStringBuiltin::Substring => "(s: string, start: i32, end: i32) => string".to_owned(),
        JsStringBuiltin::Equals => "(a: string, b: string) => i32".to_owned(),
        JsStringBuiltin::Compare => "(a: string, b: string) => i32".to_owned(),
        JsStringBuiltin::IntoCharCodeArray => {
            "(s: string, arr: i16Array, start: i32) => i32".to_owned()
        }
        JsStringBuiltin::FromCharCodeArray => {
            "(arr: i16Array, start: i32, end: i32) => string".to_owned()
        }
        JsStringBuiltin::TextEncoderEncodeInto => {
            "(s: string, arr: i8Array, start: i32) => i32".to_owned()
        }
        JsStringBuiltin::TextDecoderDecode => {
            "(arr: i8Array, start: i32, end: i32) => string".to_owned()
        }
        JsStringBuiltin::Other => {
            "(...args: any[]) => any /* unknown wasm:js-string fn */".to_owned()
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    const WAT_JS_STRING: &str = r#"
        (module
          (type $ft0 (func (param i32) (result (ref extern))))
          (type $ft1 (func (param (ref extern) (ref extern)) (result (ref extern))))
          (import "wasm:js-string" "fromCharCode" (func (type $ft0)))
          (import "wasm:js-string" "concat" (func (type $ft1))))
    "#;

    const WAT_TEXT_DECODER: &str = r#"
        (module
          (type $ft (func (param i32 i32) (result (ref extern))))
          (import "wasm:text-decoder" "decodeStringFromUTF8Array" (func (type $ft))))
    "#;

    fn try_wat(src: &str) -> Option<Vec<u8>> {
        wat::parse_str(src).ok()
    }

    #[test]
    fn detects_js_string_imports() {
        let Some(bytes): Option<Vec<u8>> = try_wat(WAT_JS_STRING) else {
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
        let dts: String = report.render_ts_d_ts();
        assert!(dts.contains("fromCharCode"));
        assert!(dts.contains("concat"));
    }

    #[test]
    fn detects_text_decoder_imports() {
        let Some(bytes): Option<Vec<u8>> = try_wat(WAT_TEXT_DECODER) else {
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

    #[test]
    fn empty_module_is_empty() {
        let bytes: Vec<u8> = wat::parse_str("(module)").expect("wat");
        let report: JsStringReport = scan_js_string_builtins(&bytes).expect("scan");
        assert!(report.is_empty());
    }

    #[test]
    fn rejects_non_wasm_input() {
        let err: Error = scan_js_string_builtins(b"not wasm").unwrap_err();
        assert!(matches!(err, Error::Parse(_)));
    }
}
