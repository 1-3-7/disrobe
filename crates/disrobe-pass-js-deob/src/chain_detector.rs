#![cfg(feature = "chain")]
#![allow(clippy::module_name_repetitions)]
use disrobe_core::Artifact;
use disrobe_core::Rung;
use disrobe_core::chain::detection::{ChildArtifact, ChildHandle, TERMINAL_HINT};
use disrobe_core::chain::{
    CatalogEntry, DetectContext, DetectVerdict, Detector, DetectorOutput,
    FAMILY_OBFUSCATOR_WRAPPER, ObfuscatorCatalog, OutputKind, Pass, SupportQuality,
};
use disrobe_core::error::{CoreError, Result as CoreResult};
use disrobe_core::pass::{PassContext, PassId};

use crate::bundle::{BundlerKind, UnbundleResult, auto_unbundle, unbundle as unbundle_source};
use crate::detect::{Detection, JsObfuscator, detect as detect_obfuscator};
use crate::esoteric::{
    AtobIndirectionResult, EsotericClassification, EsotericFamily, EvalIndirectionResult,
    PackerDecode, classify as classify_esoteric, decode_aaencode, decode_jjencode,
    decode_jsfiretruck, decode_jsfuck, peel_atob_indirection, peel_eval_indirection, unpack_packer,
};
use crate::jsconfuser::{DeobOptions, DeobOutput, deobfuscate_all};
use crate::jscrambler::{
    JscramblerOptions, JscramblerOutput, deobfuscate as deobfuscate_jscrambler,
};
use crate::jsobfu::{JsObfuRecovery, recover as recover_jsobfu};
use crate::obfuscator_io::{
    Output as ObfuscatorIoOutput, Preset as ObfPreset, deobfuscate_preset as obfuscator_io_deob,
};
use crate::protectors::{
    ProtectorDetection, ProtectorFamily, ProtectorOptions, ProtectorOutput,
    arxan::{deobfuscate as arxan_deobfuscate, detect as detect_arxan},
    jsdefender::{deobfuscate as jsdefender_deobfuscate, detect as detect_jsdefender},
    pace::{deobfuscate as pace_deobfuscate, detect as detect_pace},
};
use crate::string_array::{StringArrayRecovery, recover as recover_string_array};
use crate::unminify::{AstUnminifyStats, UnminifyStats, try_unminify_ast, unminify};
use crate::v8::{
    BytenodeCacheBody, Disassembly, NodeVersion, RecoveredBytecodeArray, SeaBlob,
    carve_sea_main_code, disassemble, parse_bytenode_full, parse_code_serializer_graph,
    parse_sea_blob,
};

pub const PASS_ID: PassId = "js.deob";

const TAG_JAVASCRIPT_OBF: &str = "js-javascript-obfuscator";
const TAG_JSCONFUSER: &str = "js-jsconfuser";
const TAG_JSCRAMBLER: &str = "js-jscrambler";
const TAG_JSFUCK: &str = "js-jsfuck";
const TAG_JSFIRETRUCK: &str = "js-jsfiretruck";
const TAG_AAENCODE: &str = "js-aaencode";
const TAG_JJENCODE: &str = "js-jjencode";
const TAG_PACKER: &str = "js-dean-edwards-packer";
const TAG_ATOB: &str = "js-atob-indirection";
const TAG_EVAL: &str = "js-eval-indirection";
const TAG_WEBPACK: &str = "js-webpack-bundle";
const TAG_GENERIC: &str = "js-obfuscated";
const TAG_JSDEFENDER: &str = "js-jsdefender";
const TAG_ARXAN: &str = "js-arxan";
const TAG_PACE: &str = "js-pace";
const TAG_NODE_SEA: &str = "js-node-sea";
const TAG_BYTENODE: &str = "js-bytenode-jsc";
const PROTECTOR_SPECIFICITY: u16 = 20;
const SEA_SPECIFICITY: u16 = 40;

#[derive(Debug, Clone, serde::Serialize)]
struct V8DisasmFunction {
    bytecode_file_offset: usize,
    frame_size: i32,
    parameter_count: u16,
    bytecode_length: usize,
    instruction_count: usize,
    disassembly: String,
}

#[derive(Debug, Clone, serde::Serialize)]
struct V8DisasmReport {
    node_version: String,
    function_count: usize,
    functions: Vec<V8DisasmFunction>,
    #[serde(skip_serializing_if = "Option::is_none")]
    note: Option<String>,
}

#[derive(Debug)]
pub struct JsObfDetector;

impl Detector for JsObfDetector {
    #[inline]
    fn id(&self) -> PassId {
        PASS_ID
    }

    fn detect(&self, ctx: &DetectContext<'_>) -> Option<DetectVerdict> {
        let bytes: &[u8] = ctx.bytes;
        if let Some(loc) = crate::v8::sea::detect_node_sea_blob(bytes) {
            return Some(DetectVerdict::new(
                PASS_ID,
                TAG_NODE_SEA,
                FAMILY_OBFUSCATOR_WRAPPER,
                0.95,
                SEA_SPECIFICITY,
                vec!["node-sea-blob"],
                format!(
                    "node SEA blob at offset {off} flags 0x{flags:08x}",
                    off = loc.blob_offset,
                    flags = loc.flags
                ),
            ));
        }
        if crate::v8::bytenode::looks_like_bytenode(bytes) {
            return Some(DetectVerdict::new(
                PASS_ID,
                TAG_BYTENODE,
                FAMILY_OBFUSCATOR_WRAPPER,
                0.90,
                SEA_SPECIFICITY,
                vec!["v8-cached-data-magic"],
                "bytenode .jsc V8 cached-data blob".to_string(),
            ));
        }
        let text: Option<&str> = std::str::from_utf8(bytes).ok();
        let eso: Option<EsotericClassification> = text.map(classify_esoteric);
        if let Some(t) = text {
            if let Some(v) = verdict_from_protector(t) {
                return Some(v);
            }
            if let Some(classification) = eso.as_ref()
                && let Some(v) = verdict_from_strong_esoteric(classification)
            {
                return Some(v);
            }
        }
        let det: Detection = detect_obfuscator(bytes);
        if let Some(v) = verdict_from_obfuscator(bytes, &det) {
            return Some(v);
        }
        eso.as_ref().and_then(verdict_from_weak_esoteric)
    }
}

#[derive(Debug)]
pub struct JsObfPass;

impl Pass for JsObfPass {
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
        &JsObfDetector
    }

    #[inline]
    fn output_kind(&self, _output: &Artifact) -> OutputKind {
        OutputKind::Mixed {
            children: Vec::new(),
        }
    }

    fn extract_children(&self, input: &Artifact) -> CoreResult<Vec<ChildArtifact>> {
        self.extract_children_with_context(input, PassContext::default())
    }

    fn extract_children_with_context(
        &self,
        input: &Artifact,
        context: PassContext<'_>,
    ) -> CoreResult<Vec<ChildArtifact>> {
        let mut children: Vec<ChildArtifact> = Vec::new();
        let detection: Detection = detect_obfuscator(input.envelope.as_slice());
        if let Ok(recovered) = self.run_with_context(input, context)
            && recovered.envelope.as_slice() != input.envelope.as_slice()
            && !recovered.envelope.is_empty()
        {
            let bytes: Vec<u8> = recovered_child_bytes(detection.family, recovered.envelope);
            children.push(child("js-deob.recovered.js".to_string(), bytes));
        }
        children.extend(emit_dedicated_sidecars(input.envelope.as_slice()));
        Ok(children)
    }

    fn run(&self, artifact: &Artifact) -> CoreResult<Artifact> {
        self.run_with_context(artifact, PassContext::default())
    }

    fn run_with_context(
        &self,
        artifact: &Artifact,
        context: PassContext<'_>,
    ) -> CoreResult<Artifact> {
        let bytes: &[u8] = artifact.envelope.as_slice();
        if crate::v8::sea::detect_node_sea_blob(bytes).is_some() {
            return run_node_sea(bytes, artifact);
        }
        if crate::v8::bytenode::looks_like_bytenode(bytes) {
            return run_bytenode(bytes, artifact);
        }
        if let Ok(text) = std::str::from_utf8(bytes) {
            if let Some(out) = run_protector(text, artifact, context.i_have_authorization)? {
                return Ok(out);
            }
            let eso: EsotericClassification = classify_esoteric(text);
            if let Some(source) = run_esoteric(&eso, bytes) {
                return Ok(Artifact::new(
                    Rung::Surface,
                    source.into_bytes(),
                    artifact.root_hash,
                ));
            }
        }
        let det: Detection = detect_obfuscator(bytes);
        match det.family {
            JsObfuscator::ObfuscatorIo => run_javascript_obfuscator(bytes, artifact),
            JsObfuscator::JsConfuser => run_jsconfuser(bytes, artifact),
            JsObfuscator::Jscrambler => run_jscrambler(bytes, artifact),
            JsObfuscator::JsObfu => run_jsobfu(bytes, artifact),
            JsObfuscator::Webpack | JsObfuscator::Vite => run_unbundle(bytes, det.family, artifact),
            JsObfuscator::Minified => run_unminify(bytes, artifact),
            other => Err(CoreError::PassFailure(format!(
                "DR-JS-0901: js.deob: family {other:?} not yet wired through chain runner",
            ))),
        }
    }
}

pub const META: disrobe_core::chain::PassMeta = disrobe_core::chain::PassMeta::new(
    PASS_ID,
    disrobe_core::chain::Ecosystem::JavaScript,
    disrobe_core::chain::SupportQuality::Full,
    disrobe_core::chain::Determinism::Deterministic,
    disrobe_core::chain::SafetyClass::GatedDynamic,
);

pub static JS_OBF_PASS: JsObfPass = JsObfPass;

#[derive(Debug)]
pub struct JsCatalogEntry {
    family: JsObfuscator,
    id: &'static str,
    display_name: &'static str,
    aliases: &'static [&'static str],
    quality: SupportQuality,
}

impl CatalogEntry for JsCatalogEntry {
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

const CATALOG_COUNT: usize = 10;

static CATALOG: [JsCatalogEntry; CATALOG_COUNT] = [
    JsCatalogEntry {
        family: JsObfuscator::ObfuscatorIo,
        id: TAG_JAVASCRIPT_OBF,
        display_name: "obfuscator.io",
        aliases: &["javascript-obfuscator", "obfuscatorio"],
        quality: SupportQuality::Full,
    },
    JsCatalogEntry {
        family: JsObfuscator::JsConfuser,
        id: TAG_JSCONFUSER,
        display_name: "JS-Confuser",
        aliases: &["jsconfuser"],
        quality: SupportQuality::Full,
    },
    JsCatalogEntry {
        family: JsObfuscator::Jscrambler,
        id: TAG_JSCRAMBLER,
        display_name: "Jscrambler",
        aliases: &["jscrambler"],
        quality: SupportQuality::Partial,
    },
    JsCatalogEntry {
        family: JsObfuscator::JsObfu,
        id: "js-jsobfu",
        display_name: "js-obfuscator (jsobfu)",
        aliases: &["jsobfu"],
        quality: SupportQuality::Partial,
    },
    JsCatalogEntry {
        family: JsObfuscator::Webpack,
        id: "js-bundler-webpack",
        display_name: "webpack (bundler)",
        aliases: &["webpack"],
        quality: SupportQuality::Partial,
    },
    JsCatalogEntry {
        family: JsObfuscator::Vite,
        id: "js-bundler-vite",
        display_name: "Vite (bundler)",
        aliases: &["vite"],
        quality: SupportQuality::Partial,
    },
    JsCatalogEntry {
        family: JsObfuscator::Rollup,
        id: "js-bundler-rollup",
        display_name: "Rollup (bundler)",
        aliases: &["rollup"],
        quality: SupportQuality::Partial,
    },
    JsCatalogEntry {
        family: JsObfuscator::Esbuild,
        id: "js-bundler-esbuild",
        display_name: "esbuild (bundler)",
        aliases: &["esbuild"],
        quality: SupportQuality::Partial,
    },
    JsCatalogEntry {
        family: JsObfuscator::Turbopack,
        id: "js-bundler-turbopack",
        display_name: "Turbopack (bundler)",
        aliases: &["turbopack"],
        quality: SupportQuality::Partial,
    },
    JsCatalogEntry {
        family: JsObfuscator::Bun,
        id: "js-bundler-bun",
        display_name: "Bun (bundler)",
        aliases: &["bun"],
        quality: SupportQuality::Partial,
    },
];

fn catalog_id_for(family: JsObfuscator) -> Option<&'static str> {
    CATALOG
        .iter()
        .find(|e: &&JsCatalogEntry| e.family == family)
        .map(|e: &JsCatalogEntry| e.id)
}

impl ObfuscatorCatalog for JsObfDetector {
    #[inline]
    fn pass_id(&self) -> PassId {
        PASS_ID
    }

    fn catalog(&self) -> Vec<&'static dyn CatalogEntry> {
        CATALOG
            .iter()
            .map(|e: &'static JsCatalogEntry| e as &'static dyn CatalogEntry)
            .collect()
    }

    fn detect(&self, ctx: &DetectContext<'_>) -> Option<DetectorOutput> {
        let det: Detection = detect_obfuscator(ctx.bytes);
        if det.confidence < 0.5 {
            return None;
        }
        let entry_id: &'static str = catalog_id_for(det.family)?;
        Some(DetectorOutput::new(entry_id, det.confidence, det.markers))
    }
}

fn verdict_from_strong_esoteric(eso: &EsotericClassification) -> Option<DetectVerdict> {
    match eso.family {
        EsotericFamily::JsFuck => Some(DetectVerdict::new(
            PASS_ID,
            TAG_JSFUCK,
            FAMILY_OBFUSCATOR_WRAPPER,
            0.95,
            30,
            vec!["jsfuck-charset"],
            "jsfuck source".to_string(),
        )),
        EsotericFamily::AaEncode => Some(DetectVerdict::new(
            PASS_ID,
            TAG_AAENCODE,
            FAMILY_OBFUSCATOR_WRAPPER,
            0.95,
            30,
            vec!["aaencode-charset"],
            "aaencode source".to_string(),
        )),
        EsotericFamily::JjEncode => Some(DetectVerdict::new(
            PASS_ID,
            TAG_JJENCODE,
            FAMILY_OBFUSCATOR_WRAPPER,
            0.95,
            30,
            vec!["jjencode-charset"],
            "jjencode source".to_string(),
        )),
        EsotericFamily::JsFireTruck => Some(DetectVerdict::new(
            PASS_ID,
            TAG_JSFIRETRUCK,
            FAMILY_OBFUSCATOR_WRAPPER,
            eso.confidence,
            30,
            vec!["jsfiretruck-charset"],
            "jsfiretruck source".to_string(),
        )),
        EsotericFamily::DeanEdwardsPacker => Some(DetectVerdict::new(
            PASS_ID,
            TAG_PACKER,
            FAMILY_OBFUSCATOR_WRAPPER,
            eso.confidence,
            30,
            vec!["dean-edwards-packer"],
            "dean edwards p,a,c,k,e,r packed source".to_string(),
        )),
        EsotericFamily::AtobIndirection
        | EsotericFamily::EvalIndirection
        | EsotericFamily::Unknown => None,
    }
}

fn verdict_from_weak_esoteric(eso: &EsotericClassification) -> Option<DetectVerdict> {
    match eso.family {
        EsotericFamily::AtobIndirection => Some(DetectVerdict::new(
            PASS_ID,
            TAG_ATOB,
            FAMILY_OBFUSCATOR_WRAPPER,
            eso.confidence,
            18,
            vec!["atob-indirection"],
            "atob base64 indirection".to_string(),
        )),
        EsotericFamily::EvalIndirection => Some(DetectVerdict::new(
            PASS_ID,
            TAG_EVAL,
            FAMILY_OBFUSCATOR_WRAPPER,
            eso.confidence,
            18,
            vec!["eval-indirection"],
            "eval / Function indirection".to_string(),
        )),
        _ => None,
    }
}

fn is_structured_document(bytes: &[u8]) -> bool {
    let leading: Option<u8> = bytes
        .iter()
        .find(|b: &&u8| !b.is_ascii_whitespace())
        .copied();
    if !matches!(leading, Some(b'{' | b'[')) {
        return false;
    }
    serde_json::from_slice::<serde::de::IgnoredAny>(bytes).is_ok()
}

fn verdict_from_obfuscator(bytes: &[u8], det: &Detection) -> Option<DetectVerdict> {
    if det.confidence < 0.5 {
        return None;
    }
    if det.family == JsObfuscator::Minified && is_structured_document(bytes) {
        return None;
    }
    let (format_tag, specificity): (&'static str, u16) = match det.family {
        JsObfuscator::ObfuscatorIo => (TAG_JAVASCRIPT_OBF, 30),
        JsObfuscator::JsConfuser => (TAG_JSCONFUSER, 28),
        JsObfuscator::Jscrambler => (TAG_JSCRAMBLER, 30),
        JsObfuscator::Webpack => (TAG_WEBPACK, 35),
        JsObfuscator::Vite
        | JsObfuscator::Rollup
        | JsObfuscator::Esbuild
        | JsObfuscator::Turbopack
        | JsObfuscator::Bun => (TAG_WEBPACK, 36),
        JsObfuscator::JsObfu | JsObfuscator::Minified | JsObfuscator::Unknown => (TAG_GENERIC, 50),
    };
    Some(DetectVerdict::new(
        PASS_ID,
        format_tag,
        FAMILY_OBFUSCATOR_WRAPPER,
        det.confidence,
        specificity,
        vec!["js-obf-marker"],
        format!("js detector family={family:?}", family = det.family),
    ))
}

fn detect_protector(text: &str) -> Option<ProtectorDetection> {
    detect_pace(text)
        .or_else(|| detect_jsdefender(text))
        .or_else(|| detect_arxan(text))
}

const fn protector_verdict_shape(
    family: ProtectorFamily,
) -> (&'static str, &'static str, &'static str) {
    match family {
        ProtectorFamily::Pace => (TAG_PACE, "js-pace-marker", "pace js"),
        ProtectorFamily::JsDefender => (TAG_JSDEFENDER, "js-jsdefender-marker", "jsdefender"),
        ProtectorFamily::Arxan => (TAG_ARXAN, "js-arxan-marker", "arxan"),
    }
}

fn verdict_from_protector(text: &str) -> Option<DetectVerdict> {
    let detection: ProtectorDetection = detect_protector(text)?;
    let (format_tag, marker, label): (&'static str, &'static str, &'static str) =
        protector_verdict_shape(detection.family);
    Some(DetectVerdict::new(
        PASS_ID,
        format_tag,
        FAMILY_OBFUSCATOR_WRAPPER,
        detection.confidence,
        PROTECTOR_SPECIFICITY,
        vec![marker],
        format!(
            "{label} (stance={stance}) markers={n}",
            stance = detection.stance_doc,
            n = detection.markers.len(),
        ),
    ))
}

fn run_protector(
    text: &str,
    artifact: &Artifact,
    i_have_authorization: bool,
) -> CoreResult<Option<Artifact>> {
    let Some(detection): Option<ProtectorDetection> = detect_protector(text) else {
        return Ok(None);
    };
    let family: ProtectorFamily = detection.family;
    if !i_have_authorization {
        return Err(CoreError::PassFailure(format!(
            "DR-JS-0920: js.deob: {name} detected; its static-marker strip runs only when the \
             operator asserts --i-have-authorization, so the input was left unmodified; see {doc}",
            name = family.display_name(),
            doc = detection.stance_doc,
        )));
    }
    let opts: ProtectorOptions = ProtectorOptions {
        i_have_authorization,
    };
    let out: ProtectorOutput = match family {
        ProtectorFamily::Pace => pace_deobfuscate(text, &opts)
            .map_err(|e| CoreError::PassFailure(format!("DR-JS-0910: pace deob: {e}")))?,
        ProtectorFamily::JsDefender => jsdefender_deobfuscate(text, &opts)
            .map_err(|e| CoreError::PassFailure(format!("DR-JS-0911: jsdefender deob: {e}")))?,
        ProtectorFamily::Arxan => arxan_deobfuscate(text, &opts)
            .map_err(|e| CoreError::PassFailure(format!("DR-JS-0912: arxan deob: {e}")))?,
    };
    debug_assert_eq!(out.family, family);
    Ok(Some(Artifact::new(
        Rung::Surface,
        out.source.into_bytes(),
        artifact.root_hash,
    )))
}

fn run_esoteric(eso: &EsotericClassification, bytes: &[u8]) -> Option<String> {
    let text: &str = std::str::from_utf8(bytes).ok()?;
    match eso.family {
        EsotericFamily::JsFuck => decode_jsfuck(text).recovered,
        EsotericFamily::AaEncode => decode_aaencode(text).recovered,
        EsotericFamily::JjEncode => decode_jjencode(text).recovered,
        EsotericFamily::JsFireTruck => decode_jsfiretruck(text).recovered,
        EsotericFamily::DeanEdwardsPacker => {
            let decode: PackerDecode = unpack_packer(text);
            decode.recovered
        }
        EsotericFamily::AtobIndirection => {
            let peeled: AtobIndirectionResult = peel_atob_indirection(text);
            if peeled.stats.atob_calls_folded + peeled.stats.btoa_calls_folded > 0 {
                Some(peeled.rewritten)
            } else {
                None
            }
        }
        EsotericFamily::EvalIndirection => {
            let peeled: EvalIndirectionResult = peel_eval_indirection(text);
            if peeled.stats.constant_folded > 0 {
                Some(peeled.rewritten)
            } else {
                None
            }
        }
        EsotericFamily::Unknown => None,
    }
}

fn run_javascript_obfuscator(bytes: &[u8], artifact: &Artifact) -> CoreResult<Artifact> {
    let text: &str = std::str::from_utf8(bytes)
        .map_err(|e| CoreError::PassFailure(format!("DR-JS-0902: input not utf-8: {e}")))?;
    let out: ObfuscatorIoOutput = obfuscator_io_deob(text, ObfPreset::High)
        .map_err(|e| CoreError::PassFailure(format!("DR-JS-0903: obfuscator.io deob: {e}")))?;
    let body: Vec<u8> = serde_json::to_vec_pretty(&out)
        .map_err(|e| CoreError::PassFailure(format!("DR-JS-0921: obfuscator.io serialize: {e}")))?;
    Ok(Artifact::new(Rung::Surface, body, artifact.root_hash))
}

fn run_jsconfuser(bytes: &[u8], artifact: &Artifact) -> CoreResult<Artifact> {
    let text: &str = std::str::from_utf8(bytes)
        .map_err(|e| CoreError::PassFailure(format!("DR-JS-0904: input not utf-8: {e}")))?;
    let opts: DeobOptions = DeobOptions::all();
    let out: DeobOutput = deobfuscate_all(text, &opts);
    Ok(Artifact::new(
        Rung::Surface,
        out.source.into_bytes(),
        artifact.root_hash,
    ))
}

fn run_jscrambler(bytes: &[u8], artifact: &Artifact) -> CoreResult<Artifact> {
    let text: &str = std::str::from_utf8(bytes)
        .map_err(|e| CoreError::PassFailure(format!("DR-JS-0905: input not utf-8: {e}")))?;
    let opts: JscramblerOptions = JscramblerOptions::all_obfuscation();
    let out: JscramblerOutput = deobfuscate_jscrambler(text, &opts)
        .map_err(|e| CoreError::PassFailure(format!("DR-JS-0906: jscrambler deob: {e}")))?;
    Ok(Artifact::new(
        Rung::Surface,
        out.source.into_bytes(),
        artifact.root_hash,
    ))
}

fn run_jsobfu(bytes: &[u8], artifact: &Artifact) -> CoreResult<Artifact> {
    let text: &str = std::str::from_utf8(bytes)
        .map_err(|e| CoreError::PassFailure(format!("DR-JS-0918: input not utf-8: {e}")))?;
    let out: JsObfuRecovery = recover_jsobfu(text);
    if out.char_fold.from_char_code_calls_folded == 0
        && out.bracket_rewrite.bracket_to_dot_rewrites == 0
        && out.bracket_rewrite.array_join_folded == 0
    {
        return Err(CoreError::PassFailure(
            "DR-JS-0919: js.deob: jsobfu detected but no String.fromCharCode chain or bracket-access form was statically reducible"
                .to_string(),
        ));
    }
    Ok(Artifact::new(
        Rung::Surface,
        out.source.into_bytes(),
        artifact.root_hash,
    ))
}

fn run_node_sea(bytes: &[u8], artifact: &Artifact) -> CoreResult<Artifact> {
    let blob: SeaBlob = parse_sea_blob(bytes)
        .map_err(|e| CoreError::PassFailure(format!("DR-JS-0913: sea parse: {e}")))?;
    let main_code: Vec<u8> = carve_sea_main_code(bytes, &blob)
        .map_err(|e| CoreError::PassFailure(format!("DR-JS-0915: sea carve main code: {e}")))?;
    Ok(Artifact::new(Rung::Surface, main_code, artifact.root_hash))
}

fn run_bytenode(bytes: &[u8], artifact: &Artifact) -> CoreResult<Artifact> {
    let body: BytenodeCacheBody = parse_bytenode_full(bytes)
        .map_err(|e| CoreError::PassFailure(format!("DR-JS-0914: bytenode parse: {e}")))?;
    let node: NodeVersion = body.header.version_hash.node;
    let report: V8DisasmReport = match parse_code_serializer_graph(&body) {
        Ok(graph) => {
            let functions: Vec<V8DisasmFunction> = graph
                .bytecode_arrays
                .iter()
                .map(|bc: &RecoveredBytecodeArray| {
                    let disasm: Disassembly = disassemble(&bc.bytecode, node);
                    V8DisasmFunction {
                        bytecode_file_offset: bc.bytecode_file_offset,
                        frame_size: bc.frame_size,
                        parameter_count: bc.parameter_count,
                        bytecode_length: bc.bytecode.len(),
                        instruction_count: disasm.instructions.len(),
                        disassembly: disasm.render_text(),
                    }
                })
                .collect();
            V8DisasmReport {
                node_version: format!("{node:?}"),
                function_count: functions.len(),
                functions,
                note: None,
            }
        }
        Err(e) => V8DisasmReport {
            node_version: format!("{node:?}"),
            function_count: 0,
            functions: Vec::new(),
            note: Some(format!("{e}")),
        },
    };
    let body_bytes: Vec<u8> = serde_json::to_vec_pretty(&report).map_err(|e| {
        CoreError::PassFailure(format!("DR-JS-0916: bytenode disasm serialize: {e}"))
    })?;
    Ok(Artifact::new(Rung::Surface, body_bytes, artifact.root_hash))
}

const fn bundler_kind_for(family: JsObfuscator) -> Option<BundlerKind> {
    match family {
        JsObfuscator::Webpack => Some(BundlerKind::Webpack5),
        JsObfuscator::Vite => Some(BundlerKind::Vite),
        JsObfuscator::Rollup => Some(BundlerKind::Rollup),
        JsObfuscator::Esbuild => Some(BundlerKind::Esbuild),
        JsObfuscator::Turbopack => Some(BundlerKind::Turbopack),
        JsObfuscator::Bun => Some(BundlerKind::Bun),
        _ => None,
    }
}

fn unbundle_best(source: &str, family: JsObfuscator) -> Option<UnbundleResult> {
    if let Some(kind) = bundler_kind_for(family)
        && let Ok(result) = unbundle_source(kind, source)
        && !result.modules.is_empty()
    {
        return Some(result);
    }
    match auto_unbundle(source) {
        Ok(result) if !result.modules.is_empty() => Some(result),
        _ => None,
    }
}

fn push_format(out: &mut String, args: std::fmt::Arguments<'_>) {
    let result: std::result::Result<(), std::fmt::Error> = std::fmt::write(out, args);
    if let Err(error) = result {
        unreachable!("string formatting failed: {error}");
    }
}

fn render_modules(result: &UnbundleResult) -> String {
    let mut out: String = String::new();
    for module in &result.modules {
        let chunk: &str = module.chunk_id.as_deref().unwrap_or("main");
        push_format(
            &mut out,
            format_args!(
                "// disrobe-unbundle module {id} (chunk {chunk}, bundler {kind})\n",
                id = module.id,
                kind = result.kind.as_str(),
            ),
        );
        out.push_str(module.source.trim_end());
        out.push_str("\n\n");
    }
    out
}

fn run_unbundle(bytes: &[u8], family: JsObfuscator, artifact: &Artifact) -> CoreResult<Artifact> {
    let source: &str = std::str::from_utf8(bytes)
        .map_err(|e| CoreError::PassFailure(format!("DR-JS-0907: input not utf-8: {e}")))?;
    let Some(result): Option<UnbundleResult> = unbundle_best(source, family) else {
        return Err(CoreError::PassFailure(format!(
            "DR-JS-0908: js.deob: {family:?} bundle detected but no per-module sources were statically recoverable (single-chunk concatenation with no module boundaries, or a runtime-assembled module table)",
        )));
    };
    let rendered: String = render_modules(&result);
    Ok(Artifact::new(
        Rung::Surface,
        rendered.into_bytes(),
        artifact.root_hash,
    ))
}

fn run_unminify(bytes: &[u8], artifact: &Artifact) -> CoreResult<Artifact> {
    let source: &str = std::str::from_utf8(bytes)
        .map_err(|e| CoreError::PassFailure(format!("DR-JS-0909: input not utf-8: {e}")))?;
    let (peeled, _peephole_stats): (String, UnminifyStats) = unminify(source);
    let (beautified, _ast_stats): (String, AstUnminifyStats) = try_unminify_ast(&peeled)
        .map_err(|error: crate::error::Error| CoreError::PassFailure(error.to_string()))?;
    if beautified == source || beautified.matches('\n').count() <= source.matches('\n').count() {
        return Err(CoreError::PassFailure(
            "DR-JS-0917: js.deob: minified input produced no structural transform (already formatted, or no peephole/ast rule applied)"
                .to_string(),
        ));
    }
    Ok(Artifact::new(
        Rung::Surface,
        beautified.into_bytes(),
        artifact.root_hash,
    ))
}

fn child(relative_path: String, bytes: Vec<u8>) -> ChildArtifact {
    ChildArtifact {
        handle: ChildHandle {
            artifact_index: u32::MAX,
            relative_path,
            hint: Some(TERMINAL_HINT.to_string()),
        },
        bytes,
    }
}

fn recovered_child_bytes(family: JsObfuscator, recovered: Vec<u8>) -> Vec<u8> {
    if !matches!(family, JsObfuscator::ObfuscatorIo) {
        return recovered;
    }
    let Ok(value): Result<serde_json::Value, serde_json::Error> =
        serde_json::from_slice(&recovered)
    else {
        return recovered;
    };
    let Some(source): Option<&str> = value.get("source").and_then(serde_json::Value::as_str) else {
        return recovered;
    };
    source.as_bytes().to_vec()
}

fn emit_dedicated_sidecars(bytes: &[u8]) -> Vec<ChildArtifact> {
    let Ok(text): core::result::Result<&str, _> = std::str::from_utf8(bytes) else {
        return Vec::new();
    };
    let mut children: Vec<ChildArtifact> = Vec::new();
    let detection: Detection = detect_obfuscator(bytes);
    if let Ok(json) = serde_json::to_vec_pretty(&detection) {
        children.push(child("js-deob.detection.json".to_string(), json));
    }
    if let Ok(Some(recovery)) = recover_string_array(text) {
        let recovery: StringArrayRecovery = recovery;
        if let Ok(json) = serde_json::to_vec_pretty(&recovery) {
            children.push(child("js-deob.recovery.json".to_string(), json));
        }
    }
    if matches!(detection.family, JsObfuscator::ObfuscatorIo)
        && let Ok(pipeline) = obfuscator_io_deob(text, ObfPreset::High)
        && let Ok(json) = serde_json::to_vec_pretty(&pipeline)
    {
        children.push(child("js-deob.pipeline.json".to_string(), json));
    }
    if matches!(detection.family, JsObfuscator::JsConfuser) {
        let opts: DeobOptions = DeobOptions::all();
        let out: DeobOutput = deobfuscate_all(text, &opts);
        if let Ok(json) = serde_json::to_vec_pretty(&out) {
            children.push(child("js-deob.jsconfuser.json".to_string(), json));
        }
    }
    children
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn detector_id_is_stable() {
        assert_eq!(JsObfDetector.id(), PASS_ID);
    }

    fn detect_bytes(src: &[u8]) -> Option<DetectVerdict> {
        let ctx: DetectContext<'_> = DetectContext {
            bytes: src,
            path_hint: None,
            parent_hint: None,
            depth: 1,
        };
        Detector::detect(&JsObfDetector, &ctx)
    }

    fn minified_body(total: usize) -> Vec<u8> {
        let prefix: &[u8] = b"var pad=\"";
        let suffix: &[u8] = b"\";";
        let fill: usize = total.saturating_sub(prefix.len() + suffix.len());
        let mut out: Vec<u8> = Vec::with_capacity(total);
        out.extend_from_slice(prefix);
        out.extend(std::iter::repeat_n(b'x', fill));
        out.extend_from_slice(suffix);
        out
    }

    fn json_report_body(total: usize) -> Vec<u8> {
        let prefix: &[u8] = b"{\"lang\":\"d\",\"note\":\"";
        let suffix: &[u8] = b"\"}";
        let fill: usize = total.saturating_sub(prefix.len() + suffix.len());
        let mut out: Vec<u8> = Vec::with_capacity(total);
        out.extend_from_slice(prefix);
        out.extend(std::iter::repeat_n(b'x', fill));
        out.extend_from_slice(suffix);
        out
    }

    #[test]
    fn a_structured_pass_report_is_refused_even_at_the_minified_boundary() {
        for size in [199usize, 200, 201, 4096] {
            let body: Vec<u8> = json_report_body(size);
            assert_eq!(body.len(), size);
            assert!(
                serde_json::from_slice::<serde::de::IgnoredAny>(&body).is_ok(),
                "the probe body must be a complete json document at {size} bytes"
            );
            assert!(
                detect_bytes(&body).is_none(),
                "a serialized pass report must never be claimed as javascript at {size} bytes"
            );
        }
    }

    #[test]
    fn genuine_minified_javascript_is_still_claimed_across_the_boundary() {
        for size in [201usize, 400, 4096] {
            let body: Vec<u8> = minified_body(size);
            assert_eq!(body.len(), size);
            let v: DetectVerdict = detect_bytes(&body)
                .unwrap_or_else(|| panic!("minified javascript of {size} bytes must be claimed"));
            assert_eq!(v.format_tag, TAG_GENERIC);
        }
        for size in [199usize, 200] {
            let body: Vec<u8> = minified_body(size);
            assert!(
                detect_bytes(&body).is_none(),
                "the single-line rule starts above 200 bytes, so {size} must stay unclaimed"
            );
        }
    }

    #[test]
    fn a_json_document_that_is_not_a_report_shaped_object_is_unaffected() {
        let almost: &[u8] =
            b"{this is not json but starts with a brace and runs well past two hundred bytes to reach the single line minified rule which needs more than two hundred characters in total so keep typing until the body is long enough}";
        assert!(almost.len() > 200);
        let v: DetectVerdict =
            detect_bytes(almost).expect("a non-json single-line body keeps the minified claim");
        assert_eq!(v.format_tag, TAG_GENERIC);
    }

    #[test]
    fn a_named_obfuscator_claim_survives_a_json_shaped_body() {
        let mut src: Vec<u8> = Vec::new();
        src.extend_from_slice(b"{\"code\":\"var _0x1234 = 1;\", \"fn\": \"function _0xabcd(){}\"}");
        let v: DetectVerdict =
            detect_bytes(&src).expect("a named obfuscator marker must still be claimed");
        assert_eq!(
            v.format_tag, TAG_JAVASCRIPT_OBF,
            "the report guard must only bind the generic minified claim"
        );
    }

    #[test]
    fn detect_javascript_obfuscator_banner() {
        let src: &[u8] = b"// obfuscator.io output\nvar _0xabcd = function(){};";
        let ctx: DetectContext<'_> = DetectContext {
            bytes: src,
            path_hint: None,
            parent_hint: None,
            depth: 0,
        };
        let v: DetectVerdict = Detector::detect(&JsObfDetector, &ctx).expect("must detect");
        assert_eq!(v.format_tag, TAG_JAVASCRIPT_OBF);
    }

    #[test]
    fn detect_jsfuck_charset() {
        let src: &[u8] = b"[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]]";
        let ctx: DetectContext<'_> = DetectContext {
            bytes: src,
            path_hint: None,
            parent_hint: None,
            depth: 0,
        };
        let v: Option<DetectVerdict> = Detector::detect(&JsObfDetector, &ctx);
        if let Some(verdict) = v {
            assert!(
                verdict.format_tag == TAG_JSFUCK || verdict.format_tag.starts_with("js-"),
                "got {tag}",
                tag = verdict.format_tag,
            );
        }
    }

    #[test]
    fn pass_output_kind_is_mixed_for_sidecar_children() {
        let a: Artifact = Artifact::new(Rung::Raw, vec![], [0u8; 32]);
        let k: OutputKind = JS_OBF_PASS.output_kind(&a);
        match k {
            OutputKind::Mixed { children } => assert!(children.is_empty()),
            _ => panic!("expected Mixed"),
        }
    }

    #[test]
    fn extract_children_emits_detection_sidecar() {
        let src: &[u8] = b"// obfuscator.io output\nvar _0xabcd = function(){};";
        let a: Artifact = Artifact::new(Rung::Raw, src.to_vec(), [0u8; 32]);
        let children: Vec<ChildArtifact> =
            JS_OBF_PASS.extract_children(&a).expect("extract_children");
        let detection: &ChildArtifact = children
            .iter()
            .find(|c: &&ChildArtifact| c.handle.relative_path == "js-deob.detection.json")
            .expect("auto must emit the dedicated detection.json sidecar as a chain child");
        assert!(detection.handle.is_terminal());
        let parsed: serde_json::Value =
            serde_json::from_slice(&detection.bytes).expect("detection.json must be valid json");
        assert!(parsed.get("family").is_some(), "detection carries family");
    }

    #[test]
    fn extract_children_emits_recovery_for_real_string_array_sample() {
        let Ok(bytes): std::io::Result<Vec<u8>> =
            std::fs::read(corpus("src/javascript/string-array-basic.js"))
        else {
            eprintln!("SKIP: string-array-basic.js fixture missing");
            return;
        };
        let a: Artifact = Artifact::new(Rung::Raw, bytes.clone(), [0u8; 32]);
        let children: Vec<ChildArtifact> =
            JS_OBF_PASS.extract_children(&a).expect("extract_children");
        let Ok(Some(_)): crate::error::Result<Option<StringArrayRecovery>> =
            recover_string_array(std::str::from_utf8(&bytes).expect("utf8 sample"))
        else {
            eprintln!("SKIP: sample has no recoverable string array");
            return;
        };
        let recovery: &ChildArtifact = children
            .iter()
            .find(|c: &&ChildArtifact| c.handle.relative_path == "js-deob.recovery.json")
            .expect("auto must emit the dedicated recovery.json sidecar for a string-array sample");
        let parsed: serde_json::Value =
            serde_json::from_slice(&recovery.bytes).expect("recovery.json must be valid json");
        assert!(
            parsed.get("array_id").is_some(),
            "recovery sidecar carries StringArrayRecovery fields",
        );
    }

    #[test]
    fn extract_children_emits_obfuscator_io_source_not_pipeline_json() {
        let bytes: Vec<u8> =
            b"// obfuscator.io output\nvar _0xabcd = function(){};\n_0xabcd();\n".to_vec();
        let a: Artifact = Artifact::new(Rung::Raw, bytes, [0u8; 32]);
        let children: Vec<ChildArtifact> =
            JS_OBF_PASS.extract_children(&a).expect("extract_children");
        let recovered: &ChildArtifact = children
            .iter()
            .find(|c: &&ChildArtifact| c.handle.relative_path == "js-deob.recovered.js")
            .expect("source child present");
        let source: &str = std::str::from_utf8(&recovered.bytes).expect("utf8 source");
        assert!(source.contains("var var_1 = function(){};"));
        assert!(!source.trim_start().starts_with('{'));
        let pipeline: &ChildArtifact = children
            .iter()
            .find(|c: &&ChildArtifact| c.handle.relative_path == "js-deob.pipeline.json")
            .expect("pipeline sidecar present");
        let parsed: serde_json::Value =
            serde_json::from_slice(&pipeline.bytes).expect("pipeline json");
        assert!(parsed.get("source").is_some());
    }

    #[test]
    fn extract_children_emits_jsconfuser_recovery_stats_sidecar() {
        let Ok(bytes): std::io::Result<Vec<u8>> =
            std::fs::read(corpus("js/jsconfuser/recovery/obf_statesum.real.js"))
        else {
            eprintln!("SKIP: obf_statesum.real.js fixture missing");
            return;
        };
        assert_eq!(detect_obfuscator(&bytes).family, JsObfuscator::JsConfuser);
        let a: Artifact = Artifact::new(Rung::Raw, bytes, [0u8; 32]);
        let children: Vec<ChildArtifact> =
            JS_OBF_PASS.extract_children(&a).expect("extract_children");
        let stats: &ChildArtifact = children
            .iter()
            .find(|c: &&ChildArtifact| c.handle.relative_path == "js-deob.jsconfuser.json")
            .expect("jsconfuser recovery stats sidecar present");
        let parsed: serde_json::Value =
            serde_json::from_slice(&stats.bytes).expect("jsconfuser recovery json");
        assert!(
            parsed
                .get("cff_generators_devirtualized")
                .and_then(serde_json::Value::as_u64)
                .is_some_and(|n: u64| n > 0),
            "the generator-wrapped state-sum machine's devirtualization count must be carried in the sidecar: {parsed}"
        );
        assert_eq!(
            parsed.get("source").and_then(serde_json::Value::as_str),
            Some("console[\"log\"](\"43:220,13:200,34:214,88:250\");\n"),
            "the sidecar's source field must carry the same linearized plaintext as the primary recovery: {parsed}"
        );
    }

    #[test]
    fn detect_node_sea_blob_yields_sea_tag() {
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice(&crate::v8::sea::SEA_MAGIC.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.push(0u8);
        bytes.extend_from_slice(&0u64.to_le_bytes());
        bytes.extend_from_slice(&0u64.to_le_bytes());
        let ctx: DetectContext<'_> = DetectContext {
            bytes: &bytes,
            path_hint: None,
            parent_hint: None,
            depth: 0,
        };
        let v: DetectVerdict = Detector::detect(&JsObfDetector, &ctx).expect("sea detect");
        assert_eq!(v.format_tag, TAG_NODE_SEA);
    }

    #[test]
    fn detect_misses_clean_source() {
        let src: &[u8] = b"const x = 1;\nfunction foo() { return x + 1; }";
        let ctx: DetectContext<'_> = DetectContext {
            bytes: src,
            path_hint: None,
            parent_hint: None,
            depth: 0,
        };
        assert!(Detector::detect(&JsObfDetector, &ctx).is_none());
    }

    #[test]
    fn catalog_lists_entries_with_full_obfuscators() {
        let entries: Vec<&'static dyn CatalogEntry> = JsObfDetector.catalog();
        assert_eq!(entries.len(), CATALOG_COUNT);
        for e in &entries {
            assert!(!e.id().is_empty());
            assert!(!e.display_name().is_empty());
        }
        let obf_io: &&dyn CatalogEntry = entries
            .iter()
            .find(|e: &&&dyn CatalogEntry| e.id() == TAG_JAVASCRIPT_OBF)
            .expect("obfuscator.io entry present");
        assert_eq!(obf_io.support_quality(), SupportQuality::Full);
        let webpack: &&dyn CatalogEntry = entries
            .iter()
            .find(|e: &&&dyn CatalogEntry| e.id() == "js-bundler-webpack")
            .expect("webpack entry present");
        assert_eq!(webpack.support_quality(), SupportQuality::Partial);
    }

    #[test]
    fn catalog_detect_fires_on_obfuscator_io_banner() {
        let src: &[u8] = b"// obfuscator.io output\nvar _0xabcd = function(){};";
        let ctx: DetectContext<'_> = DetectContext {
            bytes: src,
            path_hint: None,
            parent_hint: None,
            depth: 0,
        };
        let out: DetectorOutput =
            ObfuscatorCatalog::detect(&JsObfDetector, &ctx).expect("catalog detect must fire");
        assert_eq!(out.entry_id, TAG_JAVASCRIPT_OBF);
        assert!(out.confidence >= 0.5);
    }

    #[test]
    fn catalog_detect_misses_clean_source() {
        let src: &[u8] = b"const x = 1;\nfunction foo() { return x + 1; }";
        let ctx: DetectContext<'_> = DetectContext {
            bytes: src,
            path_hint: None,
            parent_hint: None,
            depth: 0,
        };
        assert!(ObfuscatorCatalog::detect(&JsObfDetector, &ctx).is_none());
    }

    fn corpus(rel: &str) -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("corpus")
            .join(rel)
    }

    #[test]
    fn chain_run_splits_real_webpack_bundle_into_modules_not_input() {
        let Ok(bytes): std::io::Result<Vec<u8>> = std::fs::read(corpus("js/webpack5/bundle.js"))
        else {
            eprintln!("SKIP: webpack5/bundle.js fixture missing");
            return;
        };
        let det: Detection = detect_obfuscator(&bytes);
        assert_eq!(
            det.family,
            JsObfuscator::Webpack,
            "webpack bundle must route through the webpack chain arm"
        );
        let a: Artifact = Artifact::new(Rung::Raw, bytes.clone(), [0u8; 32]);
        let out: Artifact = JS_OBF_PASS
            .run(&a)
            .expect("webpack chain run must split the bundle into per-module sources");
        assert_eq!(out.rung, Rung::Surface);
        assert_ne!(
            out.envelope, bytes,
            "chain must emit recovered modules, not the bundled input verbatim"
        );
        let recovered: &str = std::str::from_utf8(&out.envelope).expect("utf8 recovered modules");
        let module_count: usize = recovered.matches("// disrobe-unbundle module").count();
        assert!(
            module_count >= 2,
            "chain output must split into multiple per-module sources; got {module_count} banners in {:?}",
            recovered.chars().take(120).collect::<String>(),
        );
        assert!(
            recovered.contains("./src/index.js") && recovered.contains("./src/math.js"),
            "recovered modules must carry their real source-path ids, not synthetic placeholders",
        );
    }

    #[test]
    fn chain_run_splits_real_webpack4_sample_into_modules_not_input() {
        let Ok(bytes): std::io::Result<Vec<u8>> =
            std::fs::read(corpus("src/javascript/webpack4-sample.js"))
        else {
            eprintln!("SKIP: webpack4-sample.js fixture missing");
            return;
        };
        assert_eq!(detect_obfuscator(&bytes).family, JsObfuscator::Webpack);
        let a: Artifact = Artifact::new(Rung::Raw, bytes.clone(), [0u8; 32]);
        let out: Artifact = JS_OBF_PASS
            .run(&a)
            .expect("webpack4 chain run must split the bundle");
        assert_eq!(out.rung, Rung::Surface);
        assert_ne!(out.envelope, bytes, "must not echo the bundled input");
        let recovered: &str = std::str::from_utf8(&out.envelope).expect("utf8 recovered modules");
        assert!(
            recovered.matches("// disrobe-unbundle module").count() >= 2,
            "webpack4 bundle must split into multiple modules",
        );
    }

    #[test]
    fn chain_run_splits_real_vite_bundle_into_modules_not_input() {
        let Ok(bytes): std::io::Result<Vec<u8>> =
            std::fs::read(corpus("src/javascript/vite-sample.js"))
        else {
            eprintln!("SKIP: vite-sample.js fixture missing");
            return;
        };
        assert_eq!(
            detect_obfuscator(&bytes).family,
            JsObfuscator::Vite,
            "vite sample must route through the vite chain arm"
        );
        let a: Artifact = Artifact::new(Rung::Raw, bytes.clone(), [0u8; 32]);
        let out: Artifact = JS_OBF_PASS
            .run(&a)
            .expect("vite chain run must split the bundle into per-module sources");
        assert_eq!(out.rung, Rung::Surface);
        assert_ne!(
            out.envelope, bytes,
            "chain must emit recovered modules, not the vite bundle verbatim"
        );
        let recovered: &str = std::str::from_utf8(&out.envelope).expect("utf8 recovered modules");
        assert!(
            recovered.matches("// disrobe-unbundle module").count() >= 2,
            "vite bundle must split into multiple per-module sources; got {:?}",
            recovered.chars().take(120).collect::<String>(),
        );
    }

    #[test]
    fn chain_run_beautifies_real_minified_bundle_not_input() {
        let Ok(raw): std::io::Result<Vec<u8>> =
            std::fs::read(corpus("src/javascript/minified-bundle.js"))
        else {
            eprintln!("SKIP: minified-bundle.js fixture missing");
            return;
        };
        let line_end: usize = raw
            .iter()
            .position(|&b: &u8| b == b'\n')
            .unwrap_or(raw.len());
        let body: Vec<u8> = raw[..line_end].to_vec();
        let input: &str = std::str::from_utf8(&body).expect("utf8 minified input");
        assert_eq!(
            input.matches('\n').count(),
            0,
            "the fixture body must be a single minified line to exercise the minified arm",
        );
        let det: Detection = detect_obfuscator(&body);
        assert_eq!(
            det.family,
            JsObfuscator::Minified,
            "single-line minified body must route through the minified chain arm"
        );
        let a: Artifact = Artifact::new(Rung::Raw, body.clone(), [0u8; 32]);
        let out: Artifact = JS_OBF_PASS
            .run(&a)
            .expect("minified chain run must beautify the input");
        assert_eq!(out.rung, Rung::Surface);
        assert_ne!(
            out.envelope, body,
            "chain must emit a beautified transform, not the minified input verbatim"
        );
        let recovered: &str = std::str::from_utf8(&out.envelope).expect("utf8 beautified");
        let out_newlines: usize = recovered.matches('\n').count();
        assert!(
            out_newlines > input.matches('\n').count(),
            "beautified output must gain structure (newlines): in=0 out={out_newlines}",
        );
        assert!(
            recovered.contains("function") && recovered.contains("console.log"),
            "beautified output must preserve the real program text",
        );
    }

    #[test]
    fn chain_run_walls_when_minified_cannot_transform() {
        let mut padded: Vec<u8> = Vec::new();
        padded.extend_from_slice(b"var pad = \"");
        padded.extend_from_slice(&vec![b'x'; 300]);
        padded.extend_from_slice(b"\";");
        let det: Detection = detect_obfuscator(&padded);
        assert_eq!(
            det.family,
            JsObfuscator::Minified,
            "a single-line >200 byte body with no reversible construct must classify as Minified"
        );
        let a: Artifact = Artifact::new(Rung::Raw, padded, [0u8; 32]);
        let err: CoreError = JS_OBF_PASS.run(&a).expect_err(
            "minified input with no recoverable transform must wall, not echo the input as a successful Surface artifact",
        );
        assert!(
            format!("{err}").contains("DR-JS-0917"),
            "wall must carry the no-transform reason code; got {err}",
        );
    }
}
