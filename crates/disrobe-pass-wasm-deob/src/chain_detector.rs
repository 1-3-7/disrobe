#![cfg(feature = "chain")]
#![allow(clippy::module_name_repetitions)]

use disrobe_core::Artifact;
use disrobe_core::Rung;
use disrobe_core::chain::{
    DetectContext, DetectVerdict, Detector, FAMILY_INTERPRETER_BYTECODE, OutputKind, Pass,
};
use disrobe_core::error::{CoreError, Result as CoreResult};
use disrobe_core::pass::PassId;
use disrobe_core::provenance::Language;

use serde::Serialize;

use crate::analyze::{ModuleSummary, analyze_module};
use crate::detect::{WasmDetection, WasmObfuscator, detect as detect_wasm};

pub const PASS_ID: PassId = "wasm.deob";

const WASM_MAGIC: &[u8; 4] = b"\0asm";
const TAG_GENERIC: &str = "wasm";
const TAG_WASM_MIXER: &str = "wasm-mixer";
const TAG_WOBFUSCATOR: &str = "wobfuscator";
const TAG_WASM_NAME_OBF: &str = "wasm-name-obfuscator";
const TAG_JSCRAMBLER_WASM: &str = "jscrambler-wasm";
const TAG_TIGRESS_EMSCRIPTEN: &str = "tigress-emscripten";

#[derive(Debug)]
pub struct WasmDetectorImpl;

impl Detector for WasmDetectorImpl {
    #[inline]
    fn id(&self) -> PassId {
        PASS_ID
    }

    fn detect(&self, ctx: &DetectContext<'_>) -> Option<DetectVerdict> {
        let bytes: &[u8] = ctx.bytes;
        if bytes.len() < 8 || &bytes[..4] != WASM_MAGIC {
            return None;
        }
        let detection: WasmDetection = detect_wasm(bytes).ok()?;
        Some(verdict_for(&detection))
    }
}

#[derive(Debug)]
pub struct WasmDeobPass;

impl Pass for WasmDeobPass {
    #[inline]
    fn id(&self) -> PassId {
        PASS_ID
    }

    #[inline]
    fn detector(&self) -> &'static dyn Detector {
        &WasmDetectorImpl
    }

    #[inline]
    fn output_kind(&self, _output: &Artifact) -> OutputKind {
        OutputKind::Source {
            language: Language::Wat,
            formatted: true,
        }
    }

    fn run(&self, artifact: &Artifact) -> CoreResult<Artifact> {
        let bytes: &[u8] = artifact.envelope.as_slice();
        if bytes.len() < 8 || &bytes[..4] != WASM_MAGIC.as_slice() {
            return Err(CoreError::PassFailure(
                "DR-WASM-0902: wasm.deob: input lacks wasm magic header".to_string(),
            ));
        }
        let detection: WasmDetection = detect_wasm(bytes).map_err(|e: crate::error::Error| {
            CoreError::PassFailure(format!("DR-WASM-0903: wasm parse: {e}"))
        })?;
        let summary: ModuleSummary = analyze_module(bytes).map_err(|e: crate::error::Error| {
            CoreError::PassFailure(format!("DR-WASM-0904: wasm analyze: {e}"))
        })?;
        let extract: WasmExtract = WasmExtract { detection, summary };
        let payload: Vec<u8> =
            serde_json::to_vec_pretty(&extract).map_err(|e: serde_json::Error| {
                CoreError::PassFailure(format!("DR-WASM-0905: serialize wasm extract: {e}"))
            })?;
        Ok(Artifact::new(Rung::Disasm, payload, artifact.root_hash))
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct WasmExtract {
    pub detection: WasmDetection,
    pub summary: ModuleSummary,
}

pub static WASM_DEOB_PASS: WasmDeobPass = WasmDeobPass;

fn verdict_for(d: &WasmDetection) -> DetectVerdict {
    let (tag, confidence): (&'static str, f32) = match d.obfuscator {
        WasmObfuscator::WasmMixer => (TAG_WASM_MIXER, d.confidence.max(0.85)),
        WasmObfuscator::Wobfuscator => (TAG_WOBFUSCATOR, d.confidence.max(0.85)),
        WasmObfuscator::WasmNameObfuscator => (TAG_WASM_NAME_OBF, d.confidence.max(0.80)),
        WasmObfuscator::JscramblerWasm => (TAG_JSCRAMBLER_WASM, d.confidence.max(0.85)),
        WasmObfuscator::TigressEmscripten => (TAG_TIGRESS_EMSCRIPTEN, d.confidence.max(0.80)),
        WasmObfuscator::None | WasmObfuscator::Unknown => (TAG_GENERIC, 0.85),
    };
    DetectVerdict::new(
        PASS_ID,
        tag,
        FAMILY_INTERPRETER_BYTECODE,
        confidence,
        25,
        vec!["wasm-magic"],
        format!(
            "wasm module fns={fns} exports={exp} obf={obf:?}",
            fns = d.function_count,
            exp = d.export_count,
            obf = d.obfuscator,
        ),
    )
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use disrobe_core::Rung;

    fn ctx(bytes: &[u8]) -> DetectContext<'_> {
        DetectContext {
            bytes,
            path_hint: None,
            parent_hint: None,
            depth: 0,
        }
    }

    fn minimal_wasm() -> Vec<u8> {
        let mut v: Vec<u8> = Vec::with_capacity(8);
        v.extend_from_slice(b"\0asm");
        v.extend_from_slice(&1u32.to_le_bytes());
        v
    }

    #[test]
    fn detector_id_is_stable() {
        assert_eq!(WasmDetectorImpl.id(), PASS_ID);
    }

    #[test]
    fn detect_wasm_magic() {
        let bytes: Vec<u8> = minimal_wasm();
        let v: DetectVerdict = WasmDetectorImpl.detect(&ctx(&bytes)).expect("must detect");
        assert_eq!(v.specificity, 25);
        assert_eq!(v.family, FAMILY_INTERPRETER_BYTECODE);
    }

    #[test]
    fn detect_misses_non_wasm() {
        let bytes: Vec<u8> = vec![0u8; 16];
        assert!(WasmDetectorImpl.detect(&ctx(&bytes)).is_none());
    }

    #[test]
    fn pass_output_kind_is_wat_source() {
        let a: Artifact = Artifact::new(Rung::Raw, vec![], [0u8; 32]);
        match WASM_DEOB_PASS.output_kind(&a) {
            OutputKind::Source {
                language,
                formatted,
            } => {
                assert_eq!(language, Language::Wat);
                assert!(formatted);
            }
            _ => panic!("expected Source"),
        }
    }

    #[test]
    fn pass_run_extracts_wasm_module_summary() {
        let bytes: Vec<u8> = minimal_wasm();
        let a: Artifact = Artifact::new(Rung::Raw, bytes, [0u8; 32]);
        let out: Artifact = WASM_DEOB_PASS.run(&a).expect("classify must succeed");
        assert_eq!(out.rung, Rung::Disasm);
        let s: &str = std::str::from_utf8(&out.envelope).expect("utf8 json");
        assert!(s.contains("\"summary\""));
        assert!(s.contains("\"detection\""));
    }

    #[test]
    fn pass_run_rejects_non_wasm_bytes() {
        let a: Artifact = Artifact::new(Rung::Raw, vec![0u8; 16], [0u8; 32]);
        let err: CoreError = WASM_DEOB_PASS.run(&a).expect_err("must reject");
        assert!(format!("{err}").contains("DR-WASM-0902"));
    }
}
