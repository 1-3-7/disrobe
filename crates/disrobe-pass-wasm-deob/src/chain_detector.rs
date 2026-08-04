#![cfg(feature = "chain")]
#![allow(clippy::module_name_repetitions)]
use disrobe_core::Artifact;
use disrobe_core::Rung;
use disrobe_core::chain::detection::{ChildArtifact, ChildHandle, TERMINAL_HINT};
use disrobe_core::chain::{
    CatalogEntry, DetectContext, DetectVerdict, Detector, DetectorOutput,
    FAMILY_INTERPRETER_BYTECODE, ObfuscatorCatalog, OutputKind, Pass, SupportQuality,
};
use disrobe_core::error::{CoreError, Result as CoreResult};
use disrobe_core::pass::PassId;
use disrobe_core::provenance::Language;

use wasmparser::{FunctionBody, Parser, Payload};

use crate::analyze::{ModuleSummary, analyze_module};
use crate::cfg::{FunctionCfg, build_function_cfg};
use crate::detect::{WasmDetection, WasmObfuscator, detect as detect_wasm};
use crate::lift_wat::lift_module_to_wat;
use crate::recover::{RecoveredModule, RecoveryReport, recover_module};
use crate::signature::{FunctionSig, ModuleSignatures, extract_signatures};

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
    fn meta(&self) -> disrobe_core::chain::PassMeta {
        META
    }
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
        let recovered: Option<RecoveredModule> = recover_for_detection(bytes, &detection)?;
        if let Some(recovered) = recovered {
            let wat: String = lift_to_wat(&recovered.bytes)?;
            return Ok(Artifact::new(
                Rung::Surface,
                wat.into_bytes(),
                artifact.root_hash,
            ));
        }
        if is_named_obfuscator(detection.obfuscator) {
            return Err(CoreError::PassFailure(format!(
                "DR-WASM-0905: wasm.deob: {obf:?} fingerprinted but no obfuscation transform was statically recoverable (runtime-keyed decrypt, branching control-flow flattening, or interprocedural opaque predicate); the residual wall is the artifact itself",
                obf = detection.obfuscator,
            )));
        }
        let wat: String = lift_to_wat(bytes)?;
        Ok(Artifact::new(
            Rung::Disasm,
            wat.into_bytes(),
            artifact.root_hash,
        ))
    }

    fn extract_children(&self, input: &Artifact) -> CoreResult<Vec<ChildArtifact>> {
        let bytes: &[u8] = input.envelope.as_slice();
        if bytes.len() < 8 || &bytes[..4] != WASM_MAGIC.as_slice() {
            return Ok(Vec::new());
        }
        let detection: WasmDetection = detect_wasm(bytes).map_err(|e: crate::error::Error| {
            CoreError::PassFailure(format!("DR-WASM-0911: wasm child parse: {e}"))
        })?;
        let recovered: Option<RecoveredModule> = recover_for_detection(bytes, &detection)?;
        let analyzed_bytes: &[u8] = recovered
            .as_ref()
            .map_or(bytes, |r: &RecoveredModule| r.bytes.as_slice());
        let report: RecoveryReport = recovered
            .as_ref()
            .map_or_else(RecoveryReport::default, |r: &RecoveredModule| {
                r.report.clone()
            });

        let mut children: Vec<ChildArtifact> = Vec::new();
        if let Ok(json) = serde_json::to_vec_pretty(&detection) {
            children.push(sidecar_child("wasm.detection.json".to_string(), json));
        }
        if let Ok(summary) = analyze_module(analyzed_bytes) {
            let summary: ModuleSummary = summary;
            if let Ok(json) = serde_json::to_vec_pretty(&summary) {
                children.push(sidecar_child("wasm.summary.json".to_string(), json));
            }
        }
        if let Ok(json) = serde_json::to_vec_pretty(&report) {
            children.push(sidecar_child("wasm.recovery.json".to_string(), json));
        }
        if let Ok(cfgs) = collect_cfgs(analyzed_bytes) {
            let cfgs: Vec<CfgSummary> = cfgs;
            if let Ok(json) = serde_json::to_vec_pretty(&cfgs) {
                children.push(sidecar_child("wasm.cfg.json".to_string(), json));
            }
        }
        if let Some(recovered) = recovered {
            children.push(sidecar_child(
                "wasm.recovered.wasm".to_string(),
                recovered.bytes,
            ));
        }
        Ok(children)
    }
}

fn sidecar_child(relative_path: String, bytes: Vec<u8>) -> ChildArtifact {
    ChildArtifact {
        handle: ChildHandle {
            artifact_index: u32::MAX,
            relative_path,
            hint: Some(TERMINAL_HINT.to_string()),
        },
        bytes,
    }
}

#[derive(serde::Serialize)]
struct CfgSummary {
    fn_index: u32,
    blocks: usize,
    entry: u32,
}

fn collect_cfgs(bytes: &[u8]) -> CoreResult<Vec<CfgSummary>> {
    let mut out: Vec<CfgSummary> = Vec::new();
    let mut fn_index: u32 = 0;
    for payload in Parser::new(0).parse_all(bytes) {
        let payload: Payload<'_> = payload.map_err(|e: wasmparser::BinaryReaderError| {
            CoreError::PassFailure(format!("DR-WASM-0908: wasm cfg parse: {e}"))
        })?;
        if let Payload::CodeSectionEntry(body) = payload {
            let cfg: FunctionCfg =
                build_function_cfg(&body).map_err(|e: crate::error::Error| {
                    CoreError::PassFailure(format!("DR-WASM-0909: wasm cfg fn {fn_index}: {e}"))
                })?;
            out.push(CfgSummary {
                fn_index,
                blocks: cfg.blocks.len(),
                entry: cfg.entry.0,
            });
            fn_index = fn_index.saturating_add(1);
        }
    }
    Ok(out)
}

fn recover_if_changed(bytes: &[u8]) -> CoreResult<Option<RecoveredModule>> {
    let recovered: RecoveredModule = recover_module(bytes).map_err(|e: crate::error::Error| {
        CoreError::PassFailure(format!("DR-WASM-0910: wasm recovery: {e}"))
    })?;
    Ok(recovered.report.any_change().then_some(recovered))
}

fn recover_for_detection(
    bytes: &[u8],
    detection: &WasmDetection,
) -> CoreResult<Option<RecoveredModule>> {
    match recover_if_changed(bytes) {
        Ok(recovered) => Ok(recovered),
        Err(_) if !is_named_obfuscator(detection.obfuscator) => Ok(None),
        Err(error) => Err(error),
    }
}

const fn is_named_obfuscator(obf: WasmObfuscator) -> bool {
    obf.is_named_family()
}

fn lift_to_wat(bytes: &[u8]) -> CoreResult<String> {
    let sigs: ModuleSignatures = extract_signatures(bytes).map_err(|e: crate::error::Error| {
        CoreError::PassFailure(format!("DR-WASM-0906: wasm signatures: {e}"))
    })?;
    let defined: &[FunctionSig] = sigs.defined();
    let mut pairs: Vec<(FunctionBody<'_>, FunctionSig)> = Vec::new();
    let mut idx: usize = 0;
    for payload in Parser::new(0).parse_all(bytes) {
        let payload: Payload<'_> = payload.map_err(|e: wasmparser::BinaryReaderError| {
            CoreError::PassFailure(format!("DR-WASM-0907: wasm parse: {e}"))
        })?;
        if let Payload::CodeSectionEntry(body) = payload {
            let sig: FunctionSig = defined_signature(defined, idx)?;
            pairs.push((body, sig));
            idx = idx.checked_add(1).ok_or_else(|| {
                CoreError::PassFailure(
                    "DR-WASM-0912: wasm function body count overflowed usize".to_owned(),
                )
            })?;
        }
    }
    if idx != defined.len() {
        return Err(CoreError::PassFailure(format!(
            "DR-WASM-0913: wasm function section declared {} bodies but code section carried {idx}",
            defined.len(),
        )));
    }
    let offset: u32 = u32::try_from(sigs.imported_function_count()).map_err(|_| {
        CoreError::PassFailure("DR-WASM-0914: wasm imported function count exceeds u32".to_owned())
    })?;
    Ok(lift_module_to_wat(&pairs, offset))
}

fn defined_signature(defined: &[FunctionSig], idx: usize) -> CoreResult<FunctionSig> {
    defined.get(idx).cloned().ok_or_else(|| {
        CoreError::PassFailure(format!(
            "DR-WASM-0911: wasm body {idx} has no function signature"
        ))
    })
}

pub const META: disrobe_core::chain::PassMeta = disrobe_core::chain::PassMeta::new(
    PASS_ID,
    disrobe_core::chain::Ecosystem::Wasm,
    disrobe_core::chain::SupportQuality::Partial,
    disrobe_core::chain::Determinism::Deterministic,
    disrobe_core::chain::SafetyClass::Static,
);

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

#[derive(Debug)]
pub struct WasmObfuscatorEntry {
    pub obfuscator: WasmObfuscator,
    pub id: &'static str,
    pub display_name: &'static str,
    pub aliases: &'static [&'static str],
    pub quality: SupportQuality,
}

impl CatalogEntry for WasmObfuscatorEntry {
    #[inline]
    fn id(&self) -> &'static str {
        self.id
    }
    #[inline]
    fn display_name(&self) -> &'static str {
        self.display_name
    }
    #[inline]
    fn aliases(&self) -> &'static [&'static str] {
        self.aliases
    }
    #[inline]
    fn support_quality(&self) -> SupportQuality {
        self.quality
    }
}

const CATALOG_COUNT: usize = 5;

static CATALOG: [WasmObfuscatorEntry; CATALOG_COUNT] = [
    WasmObfuscatorEntry {
        obfuscator: WasmObfuscator::WasmNameObfuscator,
        id: TAG_WASM_NAME_OBF,
        display_name: "wasm-name-obfuscator",
        aliases: &["wasm-name-mangler"],
        quality: SupportQuality::Partial,
    },
    WasmObfuscatorEntry {
        obfuscator: WasmObfuscator::Wobfuscator,
        id: TAG_WOBFUSCATOR,
        display_name: "Wobfuscator",
        aliases: &[],
        quality: SupportQuality::Partial,
    },
    WasmObfuscatorEntry {
        obfuscator: WasmObfuscator::JscramblerWasm,
        id: TAG_JSCRAMBLER_WASM,
        display_name: "Jscrambler WASM",
        aliases: &["jscrambler"],
        quality: SupportQuality::Partial,
    },
    WasmObfuscatorEntry {
        obfuscator: WasmObfuscator::TigressEmscripten,
        id: TAG_TIGRESS_EMSCRIPTEN,
        display_name: "Tigress -> Emscripten",
        aliases: &["tigress"],
        quality: SupportQuality::Partial,
    },
    WasmObfuscatorEntry {
        obfuscator: WasmObfuscator::WasmMixer,
        id: TAG_WASM_MIXER,
        display_name: "wasm-mixer",
        aliases: &["wasmixer"],
        quality: SupportQuality::Partial,
    },
];

fn catalog_id_for(obf: WasmObfuscator) -> Option<&'static str> {
    CATALOG
        .iter()
        .find(|e: &&WasmObfuscatorEntry| e.obfuscator == obf)
        .map(|e: &WasmObfuscatorEntry| e.id)
}

impl ObfuscatorCatalog for WasmDetectorImpl {
    #[inline]
    fn pass_id(&self) -> PassId {
        PASS_ID
    }

    fn catalog(&self) -> Vec<&'static dyn CatalogEntry> {
        CATALOG
            .iter()
            .map(|e: &'static WasmObfuscatorEntry| e as &'static dyn CatalogEntry)
            .collect()
    }

    fn detect(&self, ctx: &DetectContext<'_>) -> Option<DetectorOutput> {
        let bytes: &[u8] = ctx.bytes;
        if bytes.len() < 8 || &bytes[..4] != WASM_MAGIC {
            return None;
        }
        let detection: WasmDetection = detect_wasm(bytes).ok()?;
        let entry_id: &'static str = catalog_id_for(detection.obfuscator)?;
        Some(DetectorOutput::new(
            entry_id,
            detection.confidence,
            detection.markers,
        ))
    }
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
        let v: DetectVerdict =
            Detector::detect(&WasmDetectorImpl, &ctx(&bytes)).expect("must detect");
        assert_eq!(v.specificity, 25);
        assert_eq!(v.family, FAMILY_INTERPRETER_BYTECODE);
    }

    #[test]
    fn detect_misses_non_wasm() {
        let bytes: Vec<u8> = vec![0u8; 16];
        assert!(Detector::detect(&WasmDetectorImpl, &ctx(&bytes)).is_none());
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
    fn pass_run_lifts_clean_wasm_to_disasm_wat() {
        let bytes: Vec<u8> = minimal_wasm();
        let a: Artifact = Artifact::new(Rung::Raw, bytes, [0u8; 32]);
        let out: Artifact = WASM_DEOB_PASS.run(&a).expect("lift must succeed");
        assert_eq!(out.rung, Rung::Disasm);
        let s: &str = std::str::from_utf8(&out.envelope).expect("utf8 wat");
        assert!(s.contains("(module"));
    }

    #[test]
    fn pass_run_lifts_clean_function_refs_when_recovery_parser_cannot() {
        let path: std::path::PathBuf = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("corpus")
            .join("wasm")
            .join("wat")
            .join("function_refs.wat");
        let Ok(text): std::io::Result<String> = std::fs::read_to_string(path) else {
            eprintln!("SKIP: function_refs.wat fixture missing");
            return;
        };
        let bytes: Vec<u8> = wat::parse_str(&text).expect("assemble function-references wat");
        let a: Artifact = Artifact::new(Rung::Raw, bytes, [0u8; 32]);
        let out: Artifact = WASM_DEOB_PASS
            .run(&a)
            .expect("clean function-refs wasm must lift even when recovery parser cannot");
        assert_eq!(out.rung, Rung::Disasm);
        let s: &str = std::str::from_utf8(&out.envelope).expect("utf8 wat");
        assert!(s.contains("(module"));
    }

    fn corpus_obf(name: &str) -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("corpus")
            .join("wasm")
            .join("obf")
            .join("real")
            .join(name)
    }

    #[test]
    fn pass_run_recovers_real_mba_obfuscated_module_to_surface_wat() {
        let Ok(text): std::io::Result<String> =
            std::fs::read_to_string(corpus_obf("mba_checksum.obf.wat"))
        else {
            eprintln!("SKIP: mba_checksum.obf.wat fixture missing");
            return;
        };
        let bytes: Vec<u8> = wat::parse_str(&text).expect("assemble real obfuscated wat");

        let recovered: crate::recover::RecoveredModule =
            recover_module(&bytes).expect("recover must run on the real obfuscated module");
        assert!(
            recovered.report.any_change(),
            "fixture must drive a real recovery transform, report={:?}",
            recovered.report,
        );
        let obf_wat: String = lift_to_wat(&bytes).expect("lift obfuscated bytes");

        let a: Artifact = Artifact::new(Rung::Raw, bytes, [0u8; 32]);
        let out: Artifact = WASM_DEOB_PASS.run(&a).expect("chain run must recover");
        assert_eq!(
            out.rung,
            Rung::Surface,
            "real recovery must surface, not stop at disasm",
        );
        let recovered_wat: &str = std::str::from_utf8(&out.envelope).expect("utf8 recovered wat");
        assert!(recovered_wat.contains("(module"));
        assert_ne!(
            recovered_wat, obf_wat,
            "chain output must be the recovered module, not the obfuscated input lifted verbatim",
        );
        match WASM_DEOB_PASS.output_kind(&out) {
            OutputKind::Source { language, .. } => assert_eq!(language, Language::Wat),
            other => panic!("expected Source, got {other:?}"),
        }
    }

    #[test]
    fn pass_run_recovers_real_cyclic_cff_loop_to_surface_wat() {
        let Ok(text): std::io::Result<String> =
            std::fs::read_to_string(corpus_obf("cff_loop.obf.wat"))
        else {
            eprintln!("SKIP: cff_loop.obf.wat fixture missing");
            return;
        };
        let bytes: Vec<u8> = wat::parse_str(&text).expect("assemble cyclic cff obfuscated wat");
        let recovered: crate::recover::RecoveredModule =
            recover_module(&bytes).expect("recover must run on cyclic cff");
        assert!(
            recovered.report.flattened_functions_restructured >= 1,
            "cyclic cff fixture must drive a real CFF recovery transform, report={:?}",
            recovered.report,
        );

        let a: Artifact = Artifact::new(Rung::Raw, bytes, [0u8; 32]);
        let out: Artifact = WASM_DEOB_PASS
            .run(&a)
            .expect("cyclic cff chain run must recover");
        assert_eq!(
            out.rung,
            Rung::Surface,
            "cyclic cff recovery must surface instead of hitting the named-obfuscator wall",
        );
        let recovered_wat: &str = std::str::from_utf8(&out.envelope).expect("utf8 recovered wat");
        assert!(
            recovered_wat.contains("(module"),
            "recovered cyclic cff output must be valid WAT text; got {:?}",
            recovered_wat.chars().take(200).collect::<String>(),
        );
    }

    #[test]
    fn pass_run_walls_honestly_when_flagged_family_recovers_nothing() {
        let mut module: walrus::Module = walrus::Module::default();
        for name in ["a", "b", "c", "d"] {
            let mut b: walrus::FunctionBuilder = walrus::FunctionBuilder::new(
                &mut module.types,
                &[walrus::ValType::I32],
                &[walrus::ValType::I32],
            );
            let p: walrus::LocalId = module.locals.add(walrus::ValType::I32);
            b.func_body().local_get(p);
            let fid: walrus::FunctionId = b.finish(vec![p], &mut module.funcs);
            module.exports.add(name, fid);
        }
        let bytes: Vec<u8> = module.emit_wasm();

        let detection: WasmDetection = detect_wasm(&bytes).expect("detect");
        assert_eq!(
            detection.obfuscator,
            WasmObfuscator::WasmNameObfuscator,
            "short-only-export module must fingerprint as a name obfuscator",
        );
        let recovered: crate::recover::RecoveredModule = recover_module(&bytes).expect("recover");
        assert!(
            !recovered.report.any_change(),
            "trivial identity bodies carry no structural obfuscation to recover",
        );

        let a: Artifact = Artifact::new(Rung::Raw, bytes, [0u8; 32]);
        let err: CoreError = WASM_DEOB_PASS
            .run(&a)
            .expect_err("a flagged family that recovers nothing must wall, not pass through");
        assert!(
            format!("{err}").contains("DR-WASM-0905"),
            "wall must carry the residual reason code, got {err}",
        );
    }

    #[test]
    fn pass_run_rejects_non_wasm_bytes() {
        let a: Artifact = Artifact::new(Rung::Raw, vec![0u8; 16], [0u8; 32]);
        let err: CoreError = WASM_DEOB_PASS.run(&a).expect_err("must reject");
        assert!(format!("{err}").contains("DR-WASM-0902"));
    }

    #[test]
    fn defined_signature_rejects_missing_body_signature() {
        let err: CoreError = defined_signature(&[], 0).expect_err("missing signature must fail");
        assert!(format!("{err}").contains("DR-WASM-0911"));
    }

    #[test]
    fn catalog_is_non_empty() {
        let entries: Vec<&'static dyn CatalogEntry> = WasmDetectorImpl.catalog();
        assert_eq!(entries.len(), CATALOG_COUNT);
        for e in &entries {
            assert!(!e.id().is_empty());
            assert!(!e.display_name().is_empty());
        }
    }

    #[test]
    fn catalog_entries_are_exactly_the_named_family_roster() {
        assert_eq!(
            CATALOG_COUNT,
            WasmObfuscator::NAMED_FAMILIES.len(),
            "the chain catalog feeds the published wasm_catalog_entries figure and the family \
             roster in detect.rs feeds the published reverser count; they must describe the same \
             population",
        );
        for family in WasmObfuscator::NAMED_FAMILIES {
            assert!(
                CATALOG
                    .iter()
                    .any(|e: &WasmObfuscatorEntry| e.obfuscator == family),
                "{family:?} is in the family roster but has no catalog entry, so `disrobe catalog` \
                 would under-report it",
            );
        }
        for entry in &CATALOG {
            assert!(
                entry.obfuscator.is_named_family(),
                "catalog entry {} carries {:?}, which the roster does not treat as a family",
                entry.id,
                entry.obfuscator,
            );
            assert!(!entry.id.is_empty());
            assert!(!entry.display_name.is_empty());
        }
    }

    #[test]
    fn catalog_detects_a_real_name_obfuscated_module() {
        let module: &str = r#"
            (module
              (func (export "aa") (result i32) i32.const 1)
              (func (export "bb") (result i32) i32.const 2)
              (func (export "cc") (result i32) i32.const 3)
              (func (export "dd") (result i32) i32.const 4))
        "#;
        let bytes: Vec<u8> = wat::parse_str(module).expect("assemble wat");
        let out: DetectorOutput = ObfuscatorCatalog::detect(&WasmDetectorImpl, &ctx(&bytes))
            .expect("stripped short-export module must be detected as a name obfuscator");
        assert_eq!(out.entry_id, TAG_WASM_NAME_OBF);
        assert!(out.confidence >= 0.80);
    }

    #[test]
    fn catalog_detect_misses_non_wasm() {
        let bytes: Vec<u8> = vec![0u8; 16];
        assert!(ObfuscatorCatalog::detect(&WasmDetectorImpl, &ctx(&bytes)).is_none());
    }

    #[test]
    fn extract_children_emits_summary_recovery_cfg_sidecars_for_clean_module() {
        let module: &str = r#"
            (module
              (func (export "f") (result i32) i32.const 7))
        "#;
        let bytes: Vec<u8> = wat::parse_str(module).expect("assemble wat");
        let a: Artifact = Artifact::new(Rung::Raw, bytes, [0u8; 32]);
        let children: Vec<ChildArtifact> = WASM_DEOB_PASS
            .extract_children(&a)
            .expect("extract_children must run");

        let paths: Vec<&str> = children
            .iter()
            .map(|c: &ChildArtifact| c.handle.relative_path.as_str())
            .collect();
        assert!(
            paths.contains(&"wasm.detection.json"),
            "auto must surface the dedicated WasmDetection sidecar, got {paths:?}",
        );
        assert!(
            paths.contains(&"wasm.summary.json"),
            "auto must surface the dedicated ModuleSummary sidecar, got {paths:?}",
        );
        assert!(
            paths.contains(&"wasm.recovery.json"),
            "auto must surface the dedicated RecoveryReport sidecar, got {paths:?}",
        );
        assert!(
            paths.contains(&"wasm.cfg.json"),
            "auto must surface the per-function cfg sidecar, got {paths:?}",
        );
        for c in &children {
            assert!(c.handle.is_terminal(), "sidecars must be terminal children");
        }
        let summary: &ChildArtifact = children
            .iter()
            .find(|c: &&ChildArtifact| c.handle.relative_path == "wasm.summary.json")
            .expect("summary present");
        let parsed: serde_json::Value =
            serde_json::from_slice(&summary.bytes).expect("summary is valid json");
        assert!(
            parsed.get("func_count").is_some(),
            "summary must carry module structure"
        );
    }

    #[test]
    fn extract_children_detection_sidecar_carries_the_real_classification_markers() {
        let module: &str = r#"
            (module
              (func (export "aa") (result i32) i32.const 1)
              (func (export "bb") (result i32) i32.const 2)
              (func (export "cc") (result i32) i32.const 3)
              (func (export "dd") (result i32) i32.const 4))
        "#;
        let bytes: Vec<u8> = wat::parse_str(module).expect("assemble wat");
        let a: Artifact = Artifact::new(Rung::Raw, bytes, [0u8; 32]);
        let children: Vec<ChildArtifact> = WASM_DEOB_PASS
            .extract_children(&a)
            .expect("extract_children must run");

        let detection: &ChildArtifact = children
            .iter()
            .find(|c: &&ChildArtifact| c.handle.relative_path == "wasm.detection.json")
            .expect("detection sidecar present");
        let parsed: serde_json::Value =
            serde_json::from_slice(&detection.bytes).expect("detection json deserializes");
        assert_eq!(
            parsed.get("obfuscator").and_then(serde_json::Value::as_str),
            Some("WasmNameObfuscator"),
        );
        assert_eq!(
            parsed
                .get("export_count")
                .and_then(serde_json::Value::as_u64),
            Some(4),
        );
        assert_eq!(
            parsed
                .get("import_count")
                .and_then(serde_json::Value::as_u64),
            Some(0),
        );
        assert_eq!(
            parsed
                .get("has_name_section")
                .and_then(serde_json::Value::as_bool),
            Some(false),
        );
        let markers: Vec<&str> = parsed
            .get("markers")
            .and_then(serde_json::Value::as_array)
            .expect("markers array present")
            .iter()
            .filter_map(serde_json::Value::as_str)
            .collect();
        assert!(
            markers.contains(&"stripped+short-exports"),
            "detection sidecar must carry the real per-obfuscator marker the DetectVerdict.markers placeholder drops, got {markers:?}",
        );
    }

    #[test]
    fn extract_children_surfaces_recovered_wasm_for_real_obfuscated_module() {
        let Ok(text): std::io::Result<String> =
            std::fs::read_to_string(corpus_obf("mba_checksum.obf.wat"))
        else {
            eprintln!("SKIP: mba_checksum.obf.wat fixture missing");
            return;
        };
        let bytes: Vec<u8> = wat::parse_str(&text).expect("assemble real obfuscated wat");
        let a: Artifact = Artifact::new(Rung::Raw, bytes, [0u8; 32]);
        let children: Vec<ChildArtifact> = WASM_DEOB_PASS
            .extract_children(&a)
            .expect("extract_children must run");

        let recovered: &ChildArtifact = children
            .iter()
            .find(|c: &&ChildArtifact| c.handle.relative_path == "wasm.recovered.wasm")
            .expect(
                "real recovery must surface the recovered .wasm binary that --emit-wasm writes",
            );
        assert!(
            wasmparser::validate(&recovered.bytes).is_ok(),
            "the surfaced recovered wasm must be a valid module",
        );

        let report: &ChildArtifact = children
            .iter()
            .find(|c: &&ChildArtifact| c.handle.relative_path == "wasm.recovery.json")
            .expect("recovery report present");
        let parsed: serde_json::Value =
            serde_json::from_slice(&report.bytes).expect("recovery json deserializes");
        let folded: u64 = parsed
            .get("mba_expressions_folded")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        let opaque: u64 = parsed
            .get("opaque_predicates_removed")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        assert!(
            folded > 0 || opaque > 0,
            "the chain recovery report must credit the defeated obfuscation, got {parsed:?}",
        );
    }
}
