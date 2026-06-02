#![cfg(feature = "chain")]
#![allow(clippy::module_name_repetitions)]

use disrobe_core::Artifact;
use disrobe_core::Rung;
use disrobe_core::chain::{
    DetectContext, DetectVerdict, Detector, FAMILY_OBFUSCATOR_WRAPPER, OutputKind, Pass,
};
use disrobe_core::error::{CoreError, Result as CoreResult};
use disrobe_core::pass::PassId;
use disrobe_core::provenance::Language;

use serde::Serialize;

use crate::obfuscator::{
    DeobfOptions, LuaObfuscatorKind, ObfuscatorDetection, PeelResult, aztup_brew, boronide,
    darksec, ironbrew2, luaobfuscator_com, moonsec_v1, moonsec_v2, moonsec_v3, prometheus, psu,
    wearedevs,
};
use crate::reader::{DetectedFormat, LuaChunk, detect as detect_format, read_auto};

pub const PASS_ID: PassId = "lua.deob";

const TAG_LUA51: &str = "lua-5.1";
const TAG_LUA52: &str = "lua-5.2";
const TAG_LUA53: &str = "lua-5.3";
const TAG_LUA54: &str = "lua-5.4";
const TAG_LUAJIT: &str = "luajit";
const TAG_LUAU: &str = "luau";
const TAG_GLUA: &str = "glua";
const TAG_OBF_PREFIX: &str = "lua-obf";

#[derive(Debug)]
pub struct LuaDetector;

impl Detector for LuaDetector {
    #[inline]
    fn id(&self) -> PassId {
        PASS_ID
    }

    fn detect(&self, ctx: &DetectContext<'_>) -> Option<DetectVerdict> {
        let bytes: &[u8] = ctx.bytes;
        if let Some(obf) = max_obfuscator(bytes) {
            return Some(verdict_for_obf(&obf));
        }
        let fmt: DetectedFormat = detect_format(bytes);
        verdict_for_format(fmt)
    }
}

#[derive(Debug)]
pub struct LuaPass;

impl Pass for LuaPass {
    #[inline]
    fn id(&self) -> PassId {
        PASS_ID
    }

    #[inline]
    fn detector(&self) -> &'static dyn Detector {
        &LuaDetector
    }

    #[inline]
    fn output_kind(&self, _output: &Artifact) -> OutputKind {
        OutputKind::Source {
            language: Language::Lua,
            formatted: true,
        }
    }

    fn run(&self, artifact: &Artifact) -> CoreResult<Artifact> {
        let bytes: &[u8] = artifact.envelope.as_slice();
        let ctx: DetectContext<'_> = DetectContext {
            bytes,
            path_hint: None,
            parent_hint: None,
            depth: 0,
        };
        if LuaDetector.detect(&ctx).is_none() {
            return Err(CoreError::PassFailure(
                "DR-LUA-0902: lua.deob: input is neither a known lua bytecode nor an obfuscated lua wrapper"
                    .to_string(),
            ));
        }
        let extract: LuaExtract = if let Some(obf) = max_obfuscator(bytes) {
            extract_obfuscated(bytes, &obf)
        } else {
            extract_bytecode(bytes)
        };
        let payload: Vec<u8> =
            serde_json::to_vec_pretty(&extract).map_err(|e: serde_json::Error| {
                CoreError::PassFailure(format!("DR-LUA-0903: serialize lua extract: {e}"))
            })?;
        Ok(Artifact::new(Rung::Surface, payload, artifact.root_hash))
    }
}

pub static LUA_PASS: LuaPass = LuaPass;

#[derive(Debug, Clone, Serialize)]
pub struct LuaExtract {
    pub format: String,
    pub obfuscator_kind: Option<String>,
    pub obfuscator_confidence: Option<u8>,
    pub function_count: Option<usize>,
    pub constant_count: Option<usize>,
    pub peeled_text_preview: Option<String>,
    pub peeled_warnings: Vec<String>,
}

fn format_label(fmt: DetectedFormat) -> String {
    match fmt {
        DetectedFormat::Lua51 => "lua-5.1",
        DetectedFormat::Lua52 => "lua-5.2",
        DetectedFormat::Lua53 => "lua-5.3",
        DetectedFormat::Lua54 => "lua-5.4",
        DetectedFormat::LuaJit => "luajit",
        DetectedFormat::Luau => "luau",
        DetectedFormat::GLua => "glua",
        DetectedFormat::Unknown => "unknown",
    }
    .to_owned()
}

fn kind_label(k: LuaObfuscatorKind) -> String {
    match k {
        LuaObfuscatorKind::Prometheus => "prometheus",
        LuaObfuscatorKind::MoonSecV1 => "moonsec-v1",
        LuaObfuscatorKind::MoonSecV2 => "moonsec-v2",
        LuaObfuscatorKind::MoonSecV3 => "moonsec-v3",
        LuaObfuscatorKind::Ironbrew2 => "ironbrew2",
        LuaObfuscatorKind::AztupBrew => "aztup-brew",
        LuaObfuscatorKind::DarkSec => "darksec",
        LuaObfuscatorKind::Boronide => "boronide",
        LuaObfuscatorKind::Psu => "psu",
        LuaObfuscatorKind::WeAreDevs => "wearedevs",
        LuaObfuscatorKind::LuaObfuscatorCom => "luaobfuscator-com",
    }
    .to_owned()
}

fn extract_bytecode(bytes: &[u8]) -> LuaExtract {
    let fmt: DetectedFormat = detect_format(bytes);
    if let Ok(chunk) = read_auto(bytes) {
        let chunk: LuaChunk = chunk;
        return LuaExtract {
            format: format_label(fmt),
            obfuscator_kind: None,
            obfuscator_confidence: None,
            function_count: Some(count_protos(&chunk)),
            constant_count: Some(count_constants(&chunk)),
            peeled_text_preview: None,
            peeled_warnings: Vec::new(),
        };
    }
    LuaExtract {
        format: format_label(fmt),
        obfuscator_kind: None,
        obfuscator_confidence: None,
        function_count: None,
        constant_count: None,
        peeled_text_preview: None,
        peeled_warnings: vec!["lua bytecode reader returned error".to_owned()],
    }
}

fn extract_obfuscated(bytes: &[u8], det: &ObfuscatorDetection) -> LuaExtract {
    let opts: DeobfOptions = DeobfOptions::default();
    let peel: Option<PeelResult> = match det.kind {
        LuaObfuscatorKind::Prometheus => prometheus::peel(bytes, &opts).ok(),
        LuaObfuscatorKind::MoonSecV1 => moonsec_v1::peel(bytes, &opts).ok(),
        LuaObfuscatorKind::MoonSecV2 => moonsec_v2::peel(bytes, &opts).ok(),
        LuaObfuscatorKind::MoonSecV3 => moonsec_v3::peel(bytes, &opts).ok(),
        LuaObfuscatorKind::Ironbrew2 => ironbrew2::peel(bytes, &opts).ok(),
        LuaObfuscatorKind::AztupBrew => aztup_brew::peel(bytes, &opts).ok(),
        LuaObfuscatorKind::DarkSec => darksec::peel(bytes, &opts).ok(),
        LuaObfuscatorKind::Boronide => boronide::peel(bytes, &opts).ok(),
        LuaObfuscatorKind::Psu => psu::peel(bytes, &opts).ok(),
        LuaObfuscatorKind::WeAreDevs => wearedevs::peel(bytes, &opts).ok(),
        LuaObfuscatorKind::LuaObfuscatorCom => luaobfuscator_com::peel(bytes, &opts).ok(),
    };
    let (preview, warnings): (Option<String>, Vec<String>) = match peel {
        Some(p) => {
            let text: String = String::from_utf8_lossy(&p.deobfuscated).into_owned();
            let preview: String = text.chars().take(2_048).collect();
            let mut warnings: Vec<String> =
                Vec::with_capacity(p.passes_run.len() + p.residual_markers.len());
            for r in p.passes_run {
                warnings.push(format!("pass: {r}"));
            }
            for r in p.residual_markers {
                warnings.push(format!("residual: {r}"));
            }
            (Some(preview), warnings)
        }
        None => (None, vec!["obfuscator peel failed".to_owned()]),
    };
    LuaExtract {
        format: format_label(detect_format(bytes)),
        obfuscator_kind: Some(kind_label(det.kind)),
        obfuscator_confidence: Some(det.confidence),
        function_count: None,
        constant_count: None,
        peeled_text_preview: preview,
        peeled_warnings: warnings,
    }
}

fn count_protos(chunk: &LuaChunk) -> usize {
    fn walk(p: &crate::reader::LuaProto, acc: &mut usize) {
        *acc += 1;
        for sub in &p.protos {
            walk(sub, acc);
        }
    }
    let mut acc: usize = 0usize;
    walk(&chunk.main, &mut acc);
    acc
}

fn count_constants(chunk: &LuaChunk) -> usize {
    fn walk(p: &crate::reader::LuaProto, acc: &mut usize) {
        *acc += p.constants.len();
        for sub in &p.protos {
            walk(sub, acc);
        }
    }
    let mut acc: usize = 0usize;
    walk(&chunk.main, &mut acc);
    acc
}

fn max_obfuscator(bytes: &[u8]) -> Option<ObfuscatorDetection> {
    let candidates: [Option<ObfuscatorDetection>; 11] = [
        prometheus::detect(bytes),
        moonsec_v1::detect(bytes),
        moonsec_v2::detect(bytes),
        moonsec_v3::detect(bytes),
        ironbrew2::detect(bytes),
        aztup_brew::detect(bytes),
        darksec::detect(bytes),
        boronide::detect(bytes),
        psu::detect(bytes),
        wearedevs::detect(bytes),
        luaobfuscator_com::detect(bytes),
    ];
    candidates
        .into_iter()
        .flatten()
        .max_by_key(|d: &ObfuscatorDetection| d.confidence)
}

fn verdict_for_obf(d: &ObfuscatorDetection) -> DetectVerdict {
    let format_tag: &'static str = match d.kind {
        LuaObfuscatorKind::Prometheus => "lua-obf-prometheus",
        LuaObfuscatorKind::MoonSecV1 => "lua-obf-moonsec-v1",
        LuaObfuscatorKind::MoonSecV2 => "lua-obf-moonsec-v2",
        LuaObfuscatorKind::MoonSecV3 => "lua-obf-moonsec-v3",
        LuaObfuscatorKind::Ironbrew2 => "lua-obf-ironbrew2",
        LuaObfuscatorKind::AztupBrew => "lua-obf-aztup-brew",
        LuaObfuscatorKind::DarkSec => "lua-obf-darksec",
        LuaObfuscatorKind::Boronide => "lua-obf-boronide",
        LuaObfuscatorKind::Psu => "lua-obf-psu",
        LuaObfuscatorKind::WeAreDevs => "lua-obf-wearedevs",
        LuaObfuscatorKind::LuaObfuscatorCom => "lua-obf-luaobfuscator-com",
    };
    let confidence: f32 = f32::from(d.confidence) / 100.0_f32;
    DetectVerdict::new(
        PASS_ID,
        format_tag,
        FAMILY_OBFUSCATOR_WRAPPER,
        confidence.clamp(0.5_f32, 1.0_f32),
        30,
        vec![TAG_OBF_PREFIX],
        format!(
            "lua obfuscator={kind:?} variant={variant:?}",
            kind = d.kind,
            variant = d.variant,
        ),
    )
}

fn verdict_for_format(fmt: DetectedFormat) -> Option<DetectVerdict> {
    let (tag, marker, confidence): (&'static str, &'static str, f32) = match fmt {
        DetectedFormat::Lua51 => (TAG_LUA51, "lua-magic-5.1", 0.96),
        DetectedFormat::Lua52 => (TAG_LUA52, "lua-magic-5.2", 0.96),
        DetectedFormat::Lua53 => (TAG_LUA53, "lua-magic-5.3", 0.96),
        DetectedFormat::Lua54 => (TAG_LUA54, "lua-magic-5.4", 0.96),
        DetectedFormat::LuaJit => (TAG_LUAJIT, "luajit-signature", 0.95),
        DetectedFormat::Luau => (TAG_LUAU, "luau-byte0-1..11", 0.78),
        DetectedFormat::GLua => (TAG_GLUA, "glua-marker", 0.80),
        DetectedFormat::Unknown => return None,
    };
    Some(DetectVerdict::new(
        PASS_ID,
        tag,
        FAMILY_OBFUSCATOR_WRAPPER,
        confidence,
        30,
        vec![marker],
        format!("lua format={tag}"),
    ))
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

    #[test]
    fn detector_id_is_stable() {
        assert_eq!(LuaDetector.id(), PASS_ID);
    }

    #[test]
    fn detect_lua_51_magic() {
        let bytes: Vec<u8> = vec![0x1b, b'L', b'u', b'a', 0x51, 0, 0, 0];
        let v: DetectVerdict = LuaDetector.detect(&ctx(&bytes)).expect("must detect");
        assert_eq!(v.format_tag, TAG_LUA51);
        assert_eq!(v.specificity, 30);
    }

    #[test]
    fn detect_misses_random_bytes() {
        let bytes: Vec<u8> = vec![0xff; 32];
        assert!(LuaDetector.detect(&ctx(&bytes)).is_none());
    }

    #[test]
    fn pass_output_kind_is_lua_source() {
        let a: Artifact = Artifact::new(Rung::Raw, vec![], [0u8; 32]);
        match LUA_PASS.output_kind(&a) {
            OutputKind::Source {
                language,
                formatted,
            } => {
                assert_eq!(language, Language::Lua);
                assert!(formatted);
            }
            _ => panic!("expected Source"),
        }
    }

    #[test]
    fn pass_run_extracts_lua51_with_format_label() {
        let bytes: Vec<u8> = vec![0x1b, b'L', b'u', b'a', 0x51, 0, 0, 0];
        let a: Artifact = Artifact::new(Rung::Raw, bytes, [0u8; 32]);
        let out: Artifact = LUA_PASS.run(&a).expect("classify must succeed");
        assert_eq!(out.rung, Rung::Surface);
        let s: &str = std::str::from_utf8(&out.envelope).expect("utf8 json");
        assert!(s.contains("\"lua-5.1\""));
    }

    #[test]
    fn pass_run_rejects_unknown_bytes() {
        let a: Artifact = Artifact::new(Rung::Raw, vec![0xff; 32], [0u8; 32]);
        let err: CoreError = LUA_PASS.run(&a).expect_err("must reject");
        assert!(format!("{err}").contains("DR-LUA-0902"));
    }
}
