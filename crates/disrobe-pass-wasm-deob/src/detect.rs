use serde::Serialize;
use wasmparser::{Parser, Payload};

use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum WasmObfuscator {
    None,
    WasmMixer,
    Wobfuscator,
    WasmNameObfuscator,
    JscramblerWasm,
    TigressEmscripten,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct WasmDetection {
    pub obfuscator: WasmObfuscator,
    pub confidence: f32,
    pub markers: Vec<String>,
    pub has_name_section: bool,
    pub has_dwarf: bool,
    pub function_count: u32,
    pub export_count: u32,
    pub import_count: u32,
}

pub fn detect(bytes: &[u8]) -> Result<WasmDetection> {
    if bytes.len() < 8 || &bytes[..4] != b"\0asm" {
        return Err(Error::Parse(
            "not a wasm module (missing \\0asm magic)".to_owned(),
        ));
    }

    let mut markers: Vec<String> = Vec::new();
    let mut has_name_section: bool = false;
    let mut has_dwarf: bool = false;
    let mut function_count: u32 = 0u32;
    let mut export_count: u32 = 0u32;
    let mut import_count: u32 = 0u32;
    let mut export_names: Vec<String> = Vec::new();

    for payload in Parser::new(0).parse_all(bytes) {
        let payload: Payload<'_> = payload.map_err(|e| Error::Parse(e.to_string()))?;
        match payload {
            Payload::CustomSection(reader) => {
                let name: &str = reader.name();
                if name == "name" {
                    has_name_section = true;
                } else if name.starts_with(".debug_") {
                    has_dwarf = true;
                    markers.push(format!("dwarf:{name}"));
                }
            }
            Payload::FunctionSection(reader) => {
                function_count = reader.count();
            }
            Payload::ExportSection(reader) => {
                export_count = reader.count();
                for e in reader.into_iter().flatten() {
                    export_names.push(e.name.to_owned());
                }
            }
            Payload::ImportSection(reader) => {
                import_count = reader.count();
            }
            _ => {}
        }
    }

    let (obfuscator, confidence): (WasmObfuscator, f32) =
        classify(&export_names, has_name_section, has_dwarf, &mut markers);

    Ok(WasmDetection {
        obfuscator,
        confidence,
        markers,
        has_name_section,
        has_dwarf,
        function_count,
        export_count,
        import_count,
    })
}

fn classify(
    export_names: &[String],
    has_name_section: bool,
    has_dwarf: bool,
    markers: &mut Vec<String>,
) -> (WasmObfuscator, f32) {
    let has_only_short_exports: bool =
        !export_names.is_empty() && export_names.iter().all(|n| n.len() <= 3);
    let has_underscore_exports: bool = export_names.iter().any(|n| n.starts_with("__"));
    let has_emscripten_exports: bool = export_names
        .iter()
        .any(|n| n == "memory" || n.starts_with("_Z"));

    if !has_name_section && !has_dwarf && has_only_short_exports && export_names.len() >= 4 {
        markers.push("stripped+short-exports".to_owned());
        return (WasmObfuscator::WasmNameObfuscator, 0.85);
    }
    if has_emscripten_exports {
        markers.push("emscripten-mangled-exports".to_owned());
        return (WasmObfuscator::TigressEmscripten, 0.55);
    }
    if has_underscore_exports && !has_name_section {
        markers.push("underscore-prefixed-exports".to_owned());
        return (WasmObfuscator::Unknown, 0.35);
    }
    if has_name_section || has_dwarf {
        return (WasmObfuscator::None, 0.0);
    }
    (WasmObfuscator::Unknown, 0.1)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::float_cmp
)]
mod tests {
    use super::*;

    fn min_wasm() -> Vec<u8> {
        vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]
    }

    #[test]
    fn rejects_non_wasm() {
        let err: Error = detect(b"not a wasm").unwrap_err();
        assert!(matches!(err, Error::Parse(_)));
    }

    #[test]
    fn accepts_empty_module() {
        let det: WasmDetection = detect(&min_wasm()).expect("must detect");
        assert_eq!(det.obfuscator, WasmObfuscator::Unknown);
        assert_eq!(det.function_count, 0);
        assert_eq!(det.export_count, 0);
    }

    #[test]
    fn classifies_no_obfuscator_when_name_section_flag_set() {
        let (kind, conf): (WasmObfuscator, f32) = classify(&[], true, false, &mut Vec::new());
        assert_eq!(kind, WasmObfuscator::None);
        assert_eq!(conf, 0.0);
    }
}
