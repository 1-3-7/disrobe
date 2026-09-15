use disrobe_bytes::read_uleb128_at;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WasmTransformSupport {
    DirectHelper,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WasmRecovery {
    Reversed,
    DetectAndClassifyOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WasmPipelineSupport {
    Delivered,
    NotDelivered,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WasmFamilySupport {
    pub transform: WasmTransformSupport,
    pub pipeline: WasmPipelineSupport,
}

impl WasmObfuscator {
    pub const NAMED_FAMILIES: [Self; 5] = [
        Self::JscramblerWasm,
        Self::Wobfuscator,
        Self::TigressEmscripten,
        Self::WasmMixer,
        Self::WasmNameObfuscator,
    ];

    pub const fn support(self) -> Option<WasmFamilySupport> {
        match self {
            Self::None | Self::Unknown => None,
            Self::JscramblerWasm | Self::Wobfuscator | Self::WasmMixer => Some(WasmFamilySupport {
                transform: WasmTransformSupport::DirectHelper,
                pipeline: WasmPipelineSupport::Delivered,
            }),
            Self::TigressEmscripten => Some(WasmFamilySupport {
                transform: WasmTransformSupport::DirectHelper,
                pipeline: WasmPipelineSupport::NotDelivered,
            }),
            Self::WasmNameObfuscator => Some(WasmFamilySupport {
                transform: WasmTransformSupport::Unavailable,
                pipeline: WasmPipelineSupport::NotDelivered,
            }),
        }
    }

    pub const fn recovery(self) -> Option<WasmRecovery> {
        match self.support() {
            Some(WasmFamilySupport {
                transform: WasmTransformSupport::DirectHelper,
                ..
            }) => Some(WasmRecovery::Reversed),
            Some(WasmFamilySupport {
                transform: WasmTransformSupport::Unavailable,
                ..
            }) => Some(WasmRecovery::DetectAndClassifyOnly),
            None => None,
        }
    }

    pub const fn is_named_family(self) -> bool {
        self.support().is_some()
    }
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
    let repaired: Option<Vec<u8>> = magic_repaired_module(bytes);
    if repaired.is_some() {
        crate::debug::dbg_kv("magic-repair", || {
            "scrambled \\0asm magic repaired from a valid section stream".to_owned()
        });
    }
    let module: &[u8] = repaired.as_deref().unwrap_or(bytes);
    if module.len() < 8 || &module[..4] != b"\0asm" {
        return Err(Error::Parse(
            "not a wasm module (missing \\0asm magic)".to_owned(),
        ));
    }
    let bytes: &[u8] = module;

    let mut markers: Vec<String> = Vec::new();
    let mut has_name_section: bool = false;
    let mut has_dwarf: bool = false;
    let mut function_count: u32 = 0u32;
    let mut export_count: u32 = 0u32;
    let mut import_count: u32 = 0u32;
    let mut export_names: Vec<String> = Vec::new();
    let mut import_modules: Vec<String> = Vec::new();
    let mut import_names: Vec<String> = Vec::new();

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
                for imp in reader.into_imports() {
                    let imp: wasmparser::Import<'_> =
                        imp.map_err(|e| Error::Parse(e.to_string()))?;
                    import_modules.push(imp.module.to_owned());
                    import_names.push(imp.name.to_owned());
                }
            }
            _ => {}
        }
    }

    let (obfuscator, confidence): (WasmObfuscator, f32) = classify(
        &export_names,
        &import_modules,
        &import_names,
        has_name_section,
        has_dwarf,
        function_count,
        &mut markers,
    );

    crate::debug::dbg_kv("detect", || {
        format!(
            "obfuscator={obfuscator:?} confidence={confidence:.2} markers={markers:?} funcs={function_count} exports={export_count} imports={import_count} name_section={has_name_section} dwarf={has_dwarf}"
        )
    });

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

const WASM_MAGIC: [u8; 4] = [0x00, 0x61, 0x73, 0x6d];
const WASM_VERSION_1: u32 = 1;
const WASM_MAX_SECTION_ID: u8 = 13;

fn magic_repaired_module(bytes: &[u8]) -> Option<Vec<u8>> {
    if bytes.len() >= 4 && bytes[..4] == WASM_MAGIC {
        return None;
    }
    if !wasm_section_stream_is_valid(bytes) {
        return None;
    }
    let mut repaired: Vec<u8> = bytes.to_vec();
    repaired[..4].copy_from_slice(&WASM_MAGIC);
    Some(repaired)
}

fn wasm_section_stream_is_valid(bytes: &[u8]) -> bool {
    if bytes.len() < 8 {
        return false;
    }
    let version: u32 = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    if version != WASM_VERSION_1 {
        return false;
    }
    let mut cursor: usize = 8;
    let mut sections: u32 = 0;
    while cursor < bytes.len() {
        let Some(&id): Option<&u8> = bytes.get(cursor) else {
            return false;
        };
        if id > WASM_MAX_SECTION_ID {
            return false;
        }
        cursor += 1;
        let Some((payload_len, consumed)): Option<(u64, usize)> =
            read_uleb128_at(bytes, cursor).ok()
        else {
            return false;
        };
        cursor += consumed;
        let Some(end): Option<usize> = cursor.checked_add(payload_len as usize) else {
            return false;
        };
        if end > bytes.len() {
            return false;
        }
        cursor = end;
        sections += 1;
        if sections > 1024 {
            return false;
        }
    }
    cursor == bytes.len() && sections > 0
}

const WASM_MIXER_INFLATION_RATIO: u32 = 20;
const WASM_MIXER_MIN_FUNCTIONS: u32 = 50;

const WOBFUSCATOR_IMPORT_MODULES: &[&str] = &["env", "wasi_snapshot_preview1", "wasi"];
const WOBFUSCATOR_MIN_ENV_IMPORTS: usize = 10;

const JSCRAMBLER_IMPORT_MODULE: &str = "jsc";

fn classify(
    export_names: &[String],
    import_modules: &[String],
    import_names: &[String],
    has_name_section: bool,
    has_dwarf: bool,
    function_count: u32,
    markers: &mut Vec<String>,
) -> (WasmObfuscator, f32) {
    let _ = import_names;

    let has_only_short_exports: bool =
        !export_names.is_empty() && export_names.iter().all(|n: &String| n.len() <= 3);
    let has_underscore_exports: bool = export_names.iter().any(|n: &String| n.starts_with("__"));
    let has_emscripten_exports: bool = export_names
        .iter()
        .any(|n: &String| n == "memory" || n.starts_with("_Z"));

    let has_jscrambler_import: bool = import_modules
        .iter()
        .any(|m: &String| m == JSCRAMBLER_IMPORT_MODULE);

    let env_import_count: usize = import_modules
        .iter()
        .filter(|m: &&String| WOBFUSCATOR_IMPORT_MODULES.contains(&m.as_str()))
        .count();
    let has_wobfuscator_env_imports: bool =
        env_import_count >= WOBFUSCATOR_MIN_ENV_IMPORTS && !has_emscripten_exports;

    let export_count: u32 = export_names.len() as u32;
    let effective_exports: u32 = export_count.max(1);
    let has_mixer_inflation: bool = function_count >= WASM_MIXER_MIN_FUNCTIONS
        && function_count / effective_exports >= WASM_MIXER_INFLATION_RATIO
        && !has_name_section
        && !has_dwarf;

    if has_jscrambler_import {
        markers.push(format!("import-module:{JSCRAMBLER_IMPORT_MODULE}"));
        return (WasmObfuscator::JscramblerWasm, 0.90);
    }
    if has_wobfuscator_env_imports {
        markers.push(format!("env-imports:{env_import_count}"));
        return (WasmObfuscator::Wobfuscator, 0.75);
    }
    if has_mixer_inflation {
        markers.push(format!(
            "function-inflation:{function_count}:{export_count}"
        ));
        return (WasmObfuscator::WasmMixer, 0.75);
    }
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
        let (kind, conf): (WasmObfuscator, f32) =
            classify(&[], &[], &[], true, false, 0, &mut Vec::new());
        assert_eq!(kind, WasmObfuscator::None);
        assert_eq!(conf, 0.0);
    }

    #[test]
    fn classifies_jscrambler_by_import_module() {
        let import_modules: Vec<String> = vec!["jsc".to_owned()];
        let (kind, conf): (WasmObfuscator, f32) =
            classify(&[], &import_modules, &[], false, false, 5, &mut Vec::new());
        assert_eq!(kind, WasmObfuscator::JscramblerWasm);
        assert!(conf > 0.8);
    }

    #[test]
    fn classifies_wobfuscator_by_env_imports() {
        let import_modules: Vec<String> = (0..12).map(|_| "env".to_owned()).collect();
        let (kind, conf): (WasmObfuscator, f32) =
            classify(&[], &import_modules, &[], false, false, 20, &mut Vec::new());
        assert_eq!(kind, WasmObfuscator::Wobfuscator);
        assert!(conf > 0.7);
    }

    #[test]
    fn classifies_wasmmixer_by_function_inflation() {
        let exports: Vec<String> = vec!["a".to_owned(), "b".to_owned()];
        let (kind, conf): (WasmObfuscator, f32) =
            classify(&exports, &[], &[], false, false, 500, &mut Vec::new());
        assert_eq!(kind, WasmObfuscator::WasmMixer);
        assert!(conf > 0.7);
    }

    #[test]
    fn named_family_roster_and_classifier_agree() {
        for family in WasmObfuscator::NAMED_FAMILIES {
            assert!(
                family.is_named_family(),
                "{family:?} is listed in NAMED_FAMILIES but support() classifies it as not a family"
            );
        }
        for stray in [WasmObfuscator::None, WasmObfuscator::Unknown] {
            assert!(
                !stray.is_named_family(),
                "{stray:?} is a detection sentinel, not an obfuscator family"
            );
            assert!(
                !WasmObfuscator::NAMED_FAMILIES.contains(&stray),
                "{stray:?} must never enter the published family roster"
            );
        }
        let mut seen: Vec<WasmObfuscator> =
            Vec::with_capacity(WasmObfuscator::NAMED_FAMILIES.len());
        for family in WasmObfuscator::NAMED_FAMILIES {
            assert!(
                !seen.contains(&family),
                "{family:?} appears twice in NAMED_FAMILIES, which would inflate every count \
                 derived from it"
            );
            seen.push(family);
        }
    }

    #[test]
    fn only_the_name_obfuscator_has_no_direct_helper() {
        let unavailable: Vec<WasmObfuscator> = WasmObfuscator::NAMED_FAMILIES
            .into_iter()
            .filter(|f: &WasmObfuscator| {
                f.support().is_some_and(|support: WasmFamilySupport| {
                    support.transform == WasmTransformSupport::Unavailable
                })
            })
            .collect();
        assert_eq!(
            unavailable,
            vec![WasmObfuscator::WasmNameObfuscator],
            "hex renames destroy the original names, so wasm-name-obfuscator is the one family \
             without a direct helper; any other family joining it lowers the published helper count"
        );
    }

    #[test]
    fn legacy_recovery_projects_transform_support() {
        assert_eq!(
            WasmObfuscator::TigressEmscripten.recovery(),
            Some(WasmRecovery::Reversed)
        );
        assert_eq!(
            WasmObfuscator::WasmNameObfuscator.recovery(),
            Some(WasmRecovery::DetectAndClassifyOnly)
        );
        assert_eq!(WasmObfuscator::Unknown.recovery(), None);
    }
}
