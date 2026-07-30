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
use disrobe_core::pass::PassId;

use crate::decompile::{DecompiledChunk, decompile_auto};
use crate::obfuscator::{
    DeobfOptions, LuaObfuscatorKind, ObfuscatorDetection, PeelResult, aztup_brew, boronide,
    darksec, hercules, ironbrew2, luaobfuscator_com, luraph, moonsec_v1, moonsec_v2, moonsec_v3,
    prometheus, psu, slua, wearedevs,
};
use crate::reader::{DetectedFormat, LuaProto, detect as detect_format, read_auto};

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
        OutputKind::Mixed {
            children: Vec::new(),
        }
    }

    fn run(&self, artifact: &Artifact) -> CoreResult<Artifact> {
        let bytes: &[u8] = artifact.envelope.as_slice();
        let recovery: LuaRecovery = recover(bytes)?;
        Ok(Artifact::new(
            Rung::Surface,
            recovery.source,
            artifact.root_hash,
        ))
    }

    fn extract_children(&self, input: &Artifact) -> CoreResult<Vec<ChildArtifact>> {
        let bytes: &[u8] = input.envelope.as_slice();
        let recovery: LuaRecovery = recover(bytes)?;
        let manifest_bytes: Vec<u8> =
            serde_json::to_vec_pretty(&recovery.manifest).map_err(|e: serde_json::Error| {
                CoreError::PassFailure(format!("DR-LUA-0906: lua.deob: serialize manifest: {e}"))
            })?;
        Ok(vec![
            terminal_child("lua-recovered.lua".to_owned(), recovery.source),
            terminal_child("lua.manifest.json".to_owned(), manifest_bytes),
        ])
    }
}

fn terminal_child(relative_path: String, bytes: Vec<u8>) -> ChildArtifact {
    ChildArtifact {
        handle: ChildHandle {
            artifact_index: u32::MAX,
            relative_path,
            hint: Some(TERMINAL_HINT.to_string()),
        },
        bytes,
    }
}

#[derive(Debug)]
struct LuaRecovery {
    source: Vec<u8>,
    manifest: serde_json::Value,
}

fn recover(bytes: &[u8]) -> CoreResult<LuaRecovery> {
    let ctx: DetectContext<'_> = DetectContext {
        bytes,
        path_hint: None,
        parent_hint: None,
        depth: 0,
    };
    if Detector::detect(&LuaDetector, &ctx).is_none() {
        return Err(CoreError::PassFailure(
            "DR-LUA-0902: lua.deob: input is neither a known lua bytecode nor an obfuscated lua wrapper"
                .to_string(),
        ));
    }
    if let Some(obf) = max_obfuscator(bytes) {
        deobfuscated_recovery(bytes, &obf)
    } else {
        decompiled_recovery(bytes)
    }
}

pub static LUA_PASS: LuaPass = LuaPass;

#[derive(Debug)]
enum CatalogKey {
    Obfuscator(LuaObfuscatorKind),
    Dialect(DetectedFormat),
}

#[derive(Debug)]
pub struct LuaCatalogEntry {
    key: CatalogKey,
    id: &'static str,
    display_name: &'static str,
    aliases: &'static [&'static str],
    quality: SupportQuality,
}

impl CatalogEntry for LuaCatalogEntry {
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

const CATALOG_COUNT: usize = 16;

static CATALOG: [LuaCatalogEntry; CATALOG_COUNT] = [
    LuaCatalogEntry {
        key: CatalogKey::Obfuscator(LuaObfuscatorKind::Ironbrew2),
        id: "lua-obf-ironbrew2",
        display_name: "IronBrew2",
        aliases: &["ironbrew", "ironbrew2"],
        quality: SupportQuality::Full,
    },
    LuaCatalogEntry {
        key: CatalogKey::Obfuscator(LuaObfuscatorKind::AztupBrew),
        id: "lua-obf-aztup-brew",
        display_name: "AztupBrew",
        aliases: &["aztupbrew"],
        quality: SupportQuality::Partial,
    },
    LuaCatalogEntry {
        key: CatalogKey::Obfuscator(LuaObfuscatorKind::Prometheus),
        id: "lua-obf-prometheus",
        display_name: "Prometheus",
        aliases: &["prometheus"],
        quality: SupportQuality::Partial,
    },
    LuaCatalogEntry {
        key: CatalogKey::Obfuscator(LuaObfuscatorKind::MoonSecV1),
        id: "lua-obf-moonsec-v1",
        display_name: "MoonSec V1",
        aliases: &["moonsec", "moonsecv1"],
        quality: SupportQuality::Partial,
    },
    LuaCatalogEntry {
        key: CatalogKey::Obfuscator(LuaObfuscatorKind::MoonSecV2),
        id: "lua-obf-moonsec-v2",
        display_name: "MoonSec V2",
        aliases: &["moonsecv2"],
        quality: SupportQuality::Partial,
    },
    LuaCatalogEntry {
        key: CatalogKey::Obfuscator(LuaObfuscatorKind::MoonSecV3),
        id: "lua-obf-moonsec-v3",
        display_name: "MoonSec V3",
        aliases: &["moonsecv3"],
        quality: SupportQuality::Partial,
    },
    LuaCatalogEntry {
        key: CatalogKey::Obfuscator(LuaObfuscatorKind::DarkSec),
        id: "lua-obf-darksec",
        display_name: "DarkSec",
        aliases: &["darksec"],
        quality: SupportQuality::Partial,
    },
    LuaCatalogEntry {
        key: CatalogKey::Obfuscator(LuaObfuscatorKind::Boronide),
        id: "lua-obf-boronide",
        display_name: "Boronide",
        aliases: &["boronide"],
        quality: SupportQuality::Partial,
    },
    LuaCatalogEntry {
        key: CatalogKey::Obfuscator(LuaObfuscatorKind::Psu),
        id: "lua-obf-psu",
        display_name: "PSU",
        aliases: &["psu"],
        quality: SupportQuality::Partial,
    },
    LuaCatalogEntry {
        key: CatalogKey::Obfuscator(LuaObfuscatorKind::WeAreDevs),
        id: "lua-obf-wearedevs",
        display_name: "WeAreDevs LuaU",
        aliases: &["wearedevs"],
        quality: SupportQuality::Partial,
    },
    LuaCatalogEntry {
        key: CatalogKey::Obfuscator(LuaObfuscatorKind::LuaObfuscatorCom),
        id: "lua-obf-luaobfuscator-com",
        display_name: "luaobfuscator.com",
        aliases: &["luaobfuscator"],
        quality: SupportQuality::Partial,
    },
    LuaCatalogEntry {
        key: CatalogKey::Obfuscator(LuaObfuscatorKind::Slua),
        id: "lua-obf-slua",
        display_name: "SLua (Unity Lua 5.3)",
        aliases: &["slua"],
        quality: SupportQuality::Partial,
    },
    LuaCatalogEntry {
        key: CatalogKey::Obfuscator(LuaObfuscatorKind::Hercules),
        id: "lua-obf-hercules",
        display_name: "Hercules",
        aliases: &["hercules"],
        quality: SupportQuality::Partial,
    },
    LuaCatalogEntry {
        key: CatalogKey::Obfuscator(LuaObfuscatorKind::Luraph),
        id: "lua-obf-luraph",
        display_name: "Luraph",
        aliases: &["luraph"],
        quality: SupportQuality::DetectOnly,
    },
    LuaCatalogEntry {
        key: CatalogKey::Dialect(DetectedFormat::Luau),
        id: TAG_LUAU,
        display_name: "Luau bytecode",
        aliases: &["luau"],
        quality: SupportQuality::Full,
    },
    LuaCatalogEntry {
        key: CatalogKey::Dialect(DetectedFormat::GLua),
        id: TAG_GLUA,
        display_name: "Garry's Mod Lua (GLua)",
        aliases: &["glua", "gmod"],
        quality: SupportQuality::Partial,
    },
];

fn catalog_id_for_obf(kind: LuaObfuscatorKind) -> Option<&'static str> {
    CATALOG
        .iter()
        .find(|e: &&LuaCatalogEntry| matches!(e.key, CatalogKey::Obfuscator(k) if k == kind))
        .map(|e: &LuaCatalogEntry| e.id)
}

fn catalog_id_for_dialect(fmt: DetectedFormat) -> Option<&'static str> {
    CATALOG
        .iter()
        .find(|e: &&LuaCatalogEntry| matches!(e.key, CatalogKey::Dialect(f) if f == fmt))
        .map(|e: &LuaCatalogEntry| e.id)
}

impl ObfuscatorCatalog for LuaDetector {
    #[inline]
    fn pass_id(&self) -> PassId {
        PASS_ID
    }

    fn catalog(&self) -> Vec<&'static dyn CatalogEntry> {
        CATALOG
            .iter()
            .map(|e: &'static LuaCatalogEntry| e as &'static dyn CatalogEntry)
            .collect()
    }

    fn detect(&self, ctx: &DetectContext<'_>) -> Option<DetectorOutput> {
        let bytes: &[u8] = ctx.bytes;
        if let Some(obf) = max_obfuscator(bytes) {
            let entry_id: &'static str = catalog_id_for_obf(obf.kind)?;
            let confidence: f32 = (f32::from(obf.confidence) / 100.0_f32).clamp(0.5_f32, 1.0_f32);
            return Some(DetectorOutput::new(entry_id, confidence, obf.markers));
        }
        let fmt: DetectedFormat = detect_format(bytes);
        let entry_id: &'static str = catalog_id_for_dialect(fmt)?;
        let confidence: f32 = match fmt {
            DetectedFormat::Luau => 0.78,
            DetectedFormat::GLua => 0.80,
            _ => return None,
        };
        Some(DetectorOutput::new(
            entry_id,
            confidence,
            vec![format!("lua-dialect-{tag}", tag = entry_id)],
        ))
    }
}

fn deobfuscated_recovery(bytes: &[u8], det: &ObfuscatorDetection) -> CoreResult<LuaRecovery> {
    let opts: DeobfOptions = DeobfOptions {
        i_have_authorization: true,
        strict: false,
    };
    let peel: PeelResult = match det.kind {
        LuaObfuscatorKind::Prometheus => prometheus::peel(bytes, &opts),
        LuaObfuscatorKind::MoonSecV1 => moonsec_v1::peel(bytes, &opts),
        LuaObfuscatorKind::MoonSecV2 => moonsec_v2::peel(bytes, &opts),
        LuaObfuscatorKind::MoonSecV3 => moonsec_v3::peel(bytes, &opts),
        LuaObfuscatorKind::Ironbrew2 => ironbrew2::peel(bytes, &opts),
        LuaObfuscatorKind::AztupBrew => aztup_brew::peel(bytes, &opts),
        LuaObfuscatorKind::DarkSec => darksec::peel(bytes, &opts),
        LuaObfuscatorKind::Boronide => boronide::peel(bytes, &opts),
        LuaObfuscatorKind::Psu => psu::peel(bytes, &opts),
        LuaObfuscatorKind::WeAreDevs => wearedevs::peel(bytes, &opts),
        LuaObfuscatorKind::LuaObfuscatorCom => luaobfuscator_com::peel(bytes, &opts),
        LuaObfuscatorKind::Slua => slua::peel(bytes, &opts),
        LuaObfuscatorKind::Hercules => hercules::peel(bytes, &opts),
        LuaObfuscatorKind::Luraph => luraph::peel(bytes, &opts),
    }
    .map_err(|e: crate::error::Error| {
        CoreError::PassFailure(format!(
            "DR-LUA-0903: lua.deob: {kind:?} peel failed: {e}",
            kind = det.kind,
        ))
    })?;
    if recovered_nothing(&peel, bytes) {
        let wall: String = if peel.residual_markers.is_empty() {
            "no static payload present".to_owned()
        } else {
            peel.residual_markers.join("; ")
        };
        return Err(CoreError::PassFailure(format!(
            "DR-LUA-0905: lua.deob: {kind:?} detected but statically unrecoverable (input passed through unchanged); {wall}",
            kind = det.kind,
        )));
    }
    let manifest: serde_json::Value = serde_json::json!({
        "schema": "disrobe.lua.deobfuscate/v0",
        "mode": "deobfuscate",
        "detected": det.kind.display_name(),
        "confidence": det.confidence,
        "variant": det.variant,
        "passes_run": peel.passes_run,
        "recovered_strings": peel.recovered_strings.len(),
        "fully_recovered": peel.fully_recovered,
        "residual_markers": peel.residual_markers,
    });
    Ok(LuaRecovery {
        source: peel.deobfuscated,
        manifest,
    })
}

fn recovered_nothing(peel: &PeelResult, input: &[u8]) -> bool {
    peel.passes_run.is_empty()
        && peel.recovered_strings.is_empty()
        && !peel.fully_recovered
        && peel.deobfuscated == input
}

fn decompiled_recovery(bytes: &[u8]) -> CoreResult<LuaRecovery> {
    let chunk: DecompiledChunk = decompile_auto(bytes).map_err(|e: crate::error::Error| {
        CoreError::PassFailure(format!("DR-LUA-0904: lua.deob: decompile failed: {e}"))
    })?;
    let format: DetectedFormat = detect_format(bytes);
    let (function_count, constant_count): (Option<usize>, Option<usize>) = match read_auto(bytes) {
        Ok(parsed) => (
            Some(count_protos(&parsed.main)),
            Some(count_constants(&parsed.main)),
        ),
        Err(_) => (None, None),
    };
    let manifest: serde_json::Value = serde_json::json!({
        "schema": "disrobe.lua.decompile/v0",
        "mode": "decompile",
        "format": format!("{format:?}"),
        "fidelity": format!("{:?}", chunk.fidelity),
        "warnings": chunk.warnings,
        "function_count": function_count,
        "constant_count": constant_count,
    });
    Ok(LuaRecovery {
        source: chunk.source.into_bytes(),
        manifest,
    })
}

fn count_protos(proto: &LuaProto) -> usize {
    1 + proto.protos.iter().map(count_protos).sum::<usize>()
}

fn count_constants(proto: &LuaProto) -> usize {
    proto.constants.len() + proto.protos.iter().map(count_constants).sum::<usize>()
}

const OBFUSCATOR_DETECTOR_COUNT: usize = 14;

fn max_obfuscator(bytes: &[u8]) -> Option<ObfuscatorDetection> {
    let candidates: [Option<ObfuscatorDetection>; OBFUSCATOR_DETECTOR_COUNT] = [
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
        slua::detect(bytes),
        hercules::detect(bytes),
        luraph::detect(bytes),
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
        LuaObfuscatorKind::Slua => "lua-obf-slua",
        LuaObfuscatorKind::Hercules => "lua-obf-hercules",
        LuaObfuscatorKind::Luraph => "lua-obf-luraph",
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

    fn published_bar(heading_needle: &str, label: &str) -> serde_json::Value {
        let path: std::path::PathBuf = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("xtask")
            .join("data")
            .join("recovery.json");
        let raw: String = std::fs::read_to_string(&path)
            .unwrap_or_else(|e: std::io::Error| panic!("read {}: {e}", path.display()));
        let doc: serde_json::Value = serde_json::from_str(&raw)
            .unwrap_or_else(|e: serde_json::Error| panic!("parse {}: {e}", path.display()));
        let mut found: Vec<serde_json::Value> = Vec::new();
        for group in doc["groups"].as_array().expect("groups array") {
            let heading_matches: bool = group["heading"]
                .as_str()
                .is_some_and(|h: &str| h.contains(heading_needle));
            if !heading_matches {
                continue;
            }
            for bar in group["bars"].as_array().unwrap_or(&Vec::new()) {
                if bar["label"].as_str() == Some(label) {
                    found.push(bar.clone());
                }
            }
        }
        assert_eq!(
            found.len(),
            1,
            "xtask/data/recovery.json must carry exactly one bar labelled `{label}` under a \
             heading containing `{heading_needle}`, found {}",
            found.len()
        );
        found.remove(0)
    }

    #[test]
    fn published_lua_catalog_count_matches_this_catalog() {
        const BAR: &str = "Lua chain catalog entries";
        let bar: serde_json::Value = published_bar("Obfuscator and bundler family coverage", BAR);
        let published: f64 = bar["value"]
            .as_f64()
            .expect("the Lua chain catalog entries bar must carry a numeric value");
        let entries: usize = LuaDetector.catalog().len();
        assert!(
            (published - entries as f64).abs() < f64::EPSILON,
            "xtask/data/recovery.json publishes {published} Lua chain catalog entries and every \
             document renders that number, but this catalog carries {entries}"
        );
        assert_eq!(
            entries, CATALOG_COUNT,
            "the catalog length and its declared count must not drift"
        );
    }

    #[test]
    fn detector_id_is_stable() {
        assert_eq!(LuaDetector.id(), PASS_ID);
    }

    #[test]
    fn detect_lua_51_magic() {
        let bytes: Vec<u8> = vec![0x1b, b'L', b'u', b'a', 0x51, 0, 0, 0];
        let v: DetectVerdict = Detector::detect(&LuaDetector, &ctx(&bytes)).expect("must detect");
        assert_eq!(v.format_tag, TAG_LUA51);
        assert_eq!(v.specificity, 30);
    }

    #[test]
    fn detect_misses_random_bytes() {
        let bytes: Vec<u8> = vec![0xff; 32];
        assert!(Detector::detect(&LuaDetector, &ctx(&bytes)).is_none());
    }

    #[test]
    fn pass_output_kind_is_mixed_so_runner_emits_sidecars() {
        let a: Artifact = Artifact::new(Rung::Raw, vec![], [0u8; 32]);
        assert!(LUA_PASS.output_kind(&a).is_mixed());
    }

    fn corpus(rel: &str) -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("corpus")
            .join(rel)
    }

    #[test]
    fn pass_run_decompiles_real_bytecode_to_lua_source_not_json() {
        let Ok(bytes): std::io::Result<Vec<u8>> = std::fs::read(corpus("lua/luac/hello.5_3.luac"))
        else {
            eprintln!("SKIP: lua luac fixture missing");
            return;
        };
        let a: Artifact = Artifact::new(Rung::Raw, bytes, [0u8; 32]);
        let out: Artifact = LUA_PASS.run(&a).expect("decompile must succeed");
        assert_eq!(out.rung, Rung::Surface);
        let s: &str = std::str::from_utf8(&out.envelope).expect("utf8 source");
        assert!(
            !s.trim_start().starts_with('{') && !s.contains("\"peeled_text_preview\""),
            "lua chain output must be recovered source, not the extract json; got {:?}",
            s.chars().take(160).collect::<String>(),
        );
        assert!(
            s.contains("function") || s.contains("end") || s.contains("--"),
            "lua chain output has no recognizable lua source; got {:?}",
            s.chars().take(160).collect::<String>(),
        );
        assert!(LUA_PASS.output_kind(&out).is_mixed());
    }

    #[test]
    fn extract_children_emits_recovered_source_and_manifest_sidecar() {
        let Ok(bytes): std::io::Result<Vec<u8>> = std::fs::read(corpus("lua/luac/hello.5_3.luac"))
        else {
            eprintln!("SKIP: lua luac fixture missing");
            return;
        };
        let a: Artifact = Artifact::new(Rung::Raw, bytes, [0u8; 32]);
        let children: Vec<ChildArtifact> = LUA_PASS
            .extract_children(&a)
            .expect("extract_children must succeed");
        let manifest: &ChildArtifact = children
            .iter()
            .find(|c: &&ChildArtifact| c.handle.relative_path == "lua.manifest.json")
            .expect("auto must emit the dedicated lua.manifest.json sidecar as a chain child");
        assert!(manifest.handle.is_terminal());
        let parsed: serde_json::Value =
            serde_json::from_slice(&manifest.bytes).expect("manifest is valid json");
        assert_eq!(parsed["schema"], "disrobe.lua.decompile/v0");
        assert!(parsed.get("fidelity").is_some());
        assert!(
            parsed["function_count"].as_u64().is_some_and(|n| n >= 1),
            "manifest must carry the recovered function count; got {:?}",
            parsed.get("function_count"),
        );
        assert!(
            parsed
                .get("constant_count")
                .is_some_and(serde_json::Value::is_u64),
            "manifest must carry the recovered constant count; got {:?}",
            parsed.get("constant_count"),
        );
        let recovered: &ChildArtifact = children
            .iter()
            .find(|c: &&ChildArtifact| c.handle.relative_path == "lua-recovered.lua")
            .expect("recovered lua source must be a chain child");
        let src: &str = std::str::from_utf8(&recovered.bytes).expect("utf8 lua source");
        assert!(src.contains("function") || src.contains("end") || src.contains("--"));
    }

    #[test]
    fn extract_children_obfuscated_manifest_reports_peel_stats() {
        let Ok(bytes): std::io::Result<Vec<u8>> =
            std::fs::read(corpus("lua/obfuscators/hello.prometheus.lua"))
        else {
            eprintln!("SKIP: hello.prometheus.lua fixture missing");
            return;
        };
        let a: Artifact = Artifact::new(Rung::Raw, bytes, [0u8; 32]);
        let Ok(children): CoreResult<Vec<ChildArtifact>> = LUA_PASS.extract_children(&a) else {
            eprintln!("SKIP: prometheus peel produced no recovery for this sample");
            return;
        };
        let manifest: &ChildArtifact = children
            .iter()
            .find(|c: &&ChildArtifact| c.handle.relative_path == "lua.manifest.json")
            .expect("obfuscated input must emit lua.manifest.json sidecar");
        let parsed: serde_json::Value =
            serde_json::from_slice(&manifest.bytes).expect("manifest is valid json");
        assert_eq!(parsed["schema"], "disrobe.lua.deobfuscate/v0");
        assert_eq!(parsed["detected"], "Prometheus");
        assert!(parsed.get("passes_run").is_some());
        assert!(parsed.get("fully_recovered").is_some());
    }

    #[test]
    fn pass_run_returns_full_deobfuscated_bytes_for_obfuscated_input() {
        let Ok(bytes): std::io::Result<Vec<u8>> =
            std::fs::read(corpus("lua/ironbrew2/obfuscated/hello.min.lua"))
        else {
            eprintln!("SKIP: ironbrew2 fixture missing");
            return;
        };
        let ctx_bytes: DetectContext<'_> = ctx(&bytes);
        if Detector::detect(&LuaDetector, &ctx_bytes).is_none() {
            eprintln!("SKIP: ironbrew2 fixture not detected as obfuscated");
            return;
        }
        let a: Artifact = Artifact::new(Rung::Raw, bytes, [0u8; 32]);
        let Ok(out): CoreResult<Artifact> = LUA_PASS.run(&a) else {
            eprintln!("SKIP: ironbrew2 peel produced no recovered source for this sample");
            return;
        };
        let s: &str = std::str::from_utf8(&out.envelope)
            .unwrap_or_else(|_| panic!("deobfuscated output should be lua text"));
        assert!(
            !s.trim_start().starts_with('{'),
            "obfuscated path must emit the deobfuscated bytes, not json",
        );
        assert!(
            out.envelope.len() > 2_048 || !s.is_empty(),
            "must return the full deobfuscated payload, not a 2KB preview",
        );
    }

    #[test]
    fn pass_run_rejects_unknown_bytes() {
        let a: Artifact = Artifact::new(Rung::Raw, vec![0xff; 32], [0u8; 32]);
        let err: CoreError = LUA_PASS.run(&a).expect_err("must reject");
        assert!(format!("{err}").contains("DR-LUA-0902"));
    }

    #[test]
    fn chain_run_recovers_real_prometheus_string_pool() {
        let Ok(bytes): std::io::Result<Vec<u8>> =
            std::fs::read(corpus("lua/obfuscators/hello.prometheus.lua"))
        else {
            eprintln!("SKIP: hello.prometheus.lua fixture missing");
            return;
        };
        let input_text: String = String::from_utf8_lossy(&bytes).into_owned();
        let a: Artifact = Artifact::new(Rung::Raw, bytes.clone(), [0u8; 32]);
        let out: Artifact = LUA_PASS
            .run(&a)
            .expect("prometheus chain peel must recover the static string pool");
        assert_eq!(out.rung, Rung::Surface);
        assert_ne!(
            out.envelope, bytes,
            "chain must emit recovered source, not the obfuscated input verbatim"
        );
        assert!(
            out.envelope.len() < input_text.len(),
            "recovered string pool must be smaller than the {} byte obfuscated wrapper, got {}",
            input_text.len(),
            out.envelope.len(),
        );
        let recovered: &str = std::str::from_utf8(&out.envelope).expect("utf8 recovered source");
        assert!(
            !recovered.trim_start().starts_with("return(function"),
            "chain output is still the Prometheus VM wrapper, not recovered content: {:?}",
            recovered.chars().take(80).collect::<String>(),
        );
        assert!(
            recovered.contains("PROMETHEUS_STRINGS") && recovered.contains("print"),
            "chain output must contain the decoded constant-array intrinsics; got {:?}",
            recovered.chars().take(160).collect::<String>(),
        );
    }

    #[test]
    fn chain_run_recovers_real_hercules_loader() {
        let Ok(bytes): std::io::Result<Vec<u8>> =
            std::fs::read(corpus("lua/hercules/gauntlet/gauntlet_obfuscated.lua"))
        else {
            eprintln!("SKIP: gauntlet_obfuscated.lua fixture missing");
            return;
        };
        let verdict: DetectVerdict =
            Detector::detect(&LuaDetector, &ctx(&bytes)).expect("hercules must detect");
        assert_eq!(verdict.format_tag, "lua-obf-hercules");
        let a: Artifact = Artifact::new(Rung::Raw, bytes.clone(), [0u8; 32]);
        let out: Artifact = LUA_PASS
            .run(&a)
            .expect("hercules chain peel must recover the static loader layer");
        assert_eq!(out.rung, Rung::Surface);
        assert_ne!(
            out.envelope, bytes,
            "chain must emit the recovered Hercules layer, not the obfuscated input verbatim"
        );
        let recovered: &str = std::str::from_utf8(&out.envelope).expect("utf8 recovered source");
        assert!(
            recovered.contains("HERCULES_EMBEDDED_NEXT_LAYER"),
            "chain output must expose the extracted Hercules inner layer; got {:?}",
            recovered.chars().take(160).collect::<String>(),
        );
    }

    #[test]
    fn chain_run_reports_luraph_runtime_wall() {
        let Ok(bytes): std::io::Result<Vec<u8>> =
            std::fs::read(corpus("lua/luraph/signature_header.lua"))
        else {
            eprintln!("SKIP: signature_header.lua fixture missing");
            return;
        };
        let verdict: DetectVerdict =
            Detector::detect(&LuaDetector, &ctx(&bytes)).expect("luraph must detect");
        assert_eq!(verdict.format_tag, "lua-obf-luraph");
        let a: Artifact = Artifact::new(Rung::Raw, bytes, [0u8; 32]);
        let err: CoreError = LUA_PASS
            .run(&a)
            .expect_err("luraph signature fixture must route to the runtime-key wall");
        let text: String = format!("{err}");
        assert!(
            text.contains("DR-LUA-0905") && text.contains("runtime"),
            "luraph wall must be detected and explain the runtime-key reason; got: {text}"
        );
    }

    #[test]
    fn chain_run_walls_detected_but_unrecoverable_obfuscator() {
        let src: &[u8] =
            b"-- prometheus\n-- Generated by Prometheus\nlocal _0xConst = { \"hello\" }\nprint(_0xConst[1])\n";
        let det: Option<ObfuscatorDetection> = max_obfuscator(src);
        assert!(
            matches!(
                det.as_ref().map(|d: &ObfuscatorDetection| d.kind),
                Some(LuaObfuscatorKind::Prometheus)
            ),
            "fixture must be detected as Prometheus so this exercises the recover-nothing wall"
        );
        let a: Artifact = Artifact::new(Rung::Raw, src.to_vec(), [0u8; 32]);
        let err: CoreError = LUA_PASS.run(&a).expect_err(
            "a detected obfuscator with no statically recoverable payload must wall, not pass the obfuscated bytes through as a successful Surface artifact",
        );
        let text: String = format!("{err}");
        assert!(
            text.contains("DR-LUA-0905") && text.contains("statically unrecoverable"),
            "wall must be honest about why recovery failed; got: {text}"
        );
    }

    #[test]
    fn catalog_lists_entries_ironbrew2_full_moonsec_partial() {
        let entries: Vec<&'static dyn CatalogEntry> = LuaDetector.catalog();
        assert_eq!(entries.len(), CATALOG_COUNT);
        for e in &entries {
            assert!(!e.id().is_empty());
            assert!(!e.display_name().is_empty());
        }
        let ironbrew: &&dyn CatalogEntry = entries
            .iter()
            .find(|e: &&&dyn CatalogEntry| e.id() == "lua-obf-ironbrew2")
            .expect("ironbrew2 entry present");
        assert_eq!(ironbrew.support_quality(), SupportQuality::Full);
        let moonsec: &&dyn CatalogEntry = entries
            .iter()
            .find(|e: &&&dyn CatalogEntry| e.id() == "lua-obf-moonsec-v3")
            .expect("moonsec v3 entry present");
        assert_eq!(moonsec.support_quality(), SupportQuality::Partial);
        let luau: &&dyn CatalogEntry = entries
            .iter()
            .find(|e: &&&dyn CatalogEntry| e.id() == TAG_LUAU)
            .expect("luau entry present");
        assert_eq!(luau.support_quality(), SupportQuality::Full);
    }

    #[test]
    fn catalog_detect_fires_on_ironbrew2_marker() {
        let src: &[u8] = b"-- IronBrew2\nlocal IRONBREW_VM = {}\n";
        let out: DetectorOutput = ObfuscatorCatalog::detect(&LuaDetector, &ctx(src))
            .expect("catalog detect must fire on ironbrew2 marker");
        assert_eq!(out.entry_id, "lua-obf-ironbrew2");
        assert!(out.confidence >= 0.5);
    }

    #[test]
    fn catalog_detect_fires_on_lua_dialect_bytecode() {
        let bytes: Vec<u8> = vec![0x1b, b'L', b'u', b'a', 0x51, 0, 0, 0];
        let verdict: DetectVerdict =
            Detector::detect(&LuaDetector, &ctx(&bytes)).expect("format detected");
        assert_eq!(verdict.format_tag, TAG_LUA51);
        let luau_bytes: Vec<u8> = vec![0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        if matches!(detect_format(&luau_bytes), DetectedFormat::Luau) {
            let out: DetectorOutput = ObfuscatorCatalog::detect(&LuaDetector, &ctx(&luau_bytes))
                .expect("luau dialect catalog detect must fire");
            assert_eq!(out.entry_id, TAG_LUAU);
        }
    }

    #[test]
    fn catalog_detect_misses_random_bytes() {
        let bytes: Vec<u8> = vec![0xff; 32];
        assert!(ObfuscatorCatalog::detect(&LuaDetector, &ctx(&bytes)).is_none());
    }
}
