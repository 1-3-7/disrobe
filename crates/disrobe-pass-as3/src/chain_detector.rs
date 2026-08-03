#![cfg(feature = "chain")]
#![allow(clippy::module_name_repetitions)]
use disrobe_core::Artifact;
use disrobe_core::Rung;
use disrobe_core::chain::{
    CatalogEntry, DetectContext, DetectVerdict, Detector, DetectorOutput,
    FAMILY_INTERPRETER_BYTECODE, ObfuscatorCatalog, OutputKind, Pass, SupportQuality,
};
use disrobe_core::error::{CoreError, Result as CoreResult};
use disrobe_core::pass::PassId;
use disrobe_core::provenance::Language;

use crate::abc::{AbcFile, parse as parse_abc};
use crate::decompile::render_program;
use crate::obf::KnownTool;
use crate::swf::{
    SwfCompression, TagCode, detect as detect_swf, parse as parse_swf, parse_do_abc,
    parse_do_abc_legacy,
};

pub const PASS_ID: PassId = "as3.classify";

const TAG_SWF_FWS: &str = "swf-uncompressed";
const TAG_SWF_CWS: &str = "swf-zlib";
const TAG_SWF_ZWS: &str = "swf-lzma";
const TAG_ABC: &str = "abc-bytecode";

const ABC_VERSION_MINOR: u16 = 16;
const ABC_VERSION_MAJOR: u16 = 46;

#[derive(Debug)]
pub struct As3Detector;

impl Detector for As3Detector {
    #[inline]
    fn id(&self) -> PassId {
        PASS_ID
    }

    fn detect(&self, ctx: &DetectContext<'_>) -> Option<DetectVerdict> {
        let bytes: &[u8] = ctx.bytes;
        if let Some(comp) = detect_swf(bytes) {
            return Some(verdict_swf(comp));
        }
        if looks_like_abc(bytes) {
            return Some(verdict_abc());
        }
        None
    }
}

#[derive(Debug)]
pub struct As3Pass;

impl Pass for As3Pass {
    #[inline]
    fn id(&self) -> PassId {
        PASS_ID
    }

    #[inline]
    fn detector(&self) -> &'static dyn Detector {
        &As3Detector
    }

    #[inline]
    fn output_kind(&self, _output: &Artifact) -> OutputKind {
        OutputKind::Source {
            language: Language::ActionScript3,
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
        let verdict: DetectVerdict = Detector::detect(&As3Detector, &ctx).ok_or_else(|| {
            CoreError::PassFailure(
                "DR-AS3-0902: as3.classify: input is neither SWF nor raw ABC".to_string(),
            )
        })?;
        let extract: As3Extract = match verdict.format_tag {
            TAG_ABC => extract_raw_abc(bytes)?,
            _ => extract_swf(bytes)?,
        };
        if extract.class_skeleton_source.trim().is_empty() {
            return Err(CoreError::PassFailure(format!(
                "DR-AS3-0904: as3.classify: {kind} parsed but no AS3 class source recovered \
                 (no DoABC class definitions present)",
                kind = extract.kind,
            )));
        }
        Ok(Artifact::new(
            Rung::Surface,
            extract.class_skeleton_source.into_bytes(),
            artifact.root_hash,
        ))
    }
}

pub static AS3_PASS: As3Pass = As3Pass;

#[derive(Debug, Clone)]
struct As3Extract {
    kind: &'static str,
    class_skeleton_source: String,
}

fn extract_raw_abc(bytes: &[u8]) -> CoreResult<As3Extract> {
    let abc: AbcFile = parse_abc(bytes).map_err(|e: crate::error::Error| {
        CoreError::PassFailure(format!("DR-AS3-0905: abc parse: {e}"))
    })?;
    let source: String = render_program(&abc).map_err(|e: crate::error::Error| {
        CoreError::PassFailure(format!("DR-AS3-0906: abc render: {e}"))
    })?;
    Ok(As3Extract {
        kind: "abc",
        class_skeleton_source: source,
    })
}

fn extract_swf(bytes: &[u8]) -> CoreResult<As3Extract> {
    let swf: crate::swf::Swf = parse_swf(bytes).map_err(|e: crate::error::Error| {
        CoreError::PassFailure(format!("DR-AS3-0907: swf parse: {e}"))
    })?;
    let mut source: String = String::new();
    for tag in &swf.tags {
        let parsed: crate::error::Result<crate::swf::DoAbc> = match tag.code {
            TagCode::DO_ABC => parse_do_abc(tag),
            TagCode::DO_ABC_DEFINE => parse_do_abc_legacy(tag),
            _ => continue,
        };
        let tag_kind: &'static str = tag.code.name();
        let doabc: crate::swf::DoAbc = parsed.map_err(|error: crate::error::Error| {
            CoreError::PassFailure(format!(
                "DR-AS3-0908: swf {tag_kind} tag parse failed at logical SWF tag offset {}: \
                 {error}",
                tag.offset,
            ))
        })?;
        let abc: AbcFile = parse_abc(&doabc.abc_bytes).map_err(|error: crate::error::Error| {
            CoreError::PassFailure(format!(
                "DR-AS3-0909: swf {tag_kind} ABC parse failed at logical SWF tag offset {}: \
                 {error}",
                tag.offset,
            ))
        })?;
        let rendered: String = render_program(&abc).map_err(|error: crate::error::Error| {
            CoreError::PassFailure(format!(
                "DR-AS3-0910: swf {tag_kind} render failed at logical SWF tag offset {}: {error}",
                tag.offset,
            ))
        })?;
        source.push_str(&rendered);
        source.push('\n');
    }
    Ok(As3Extract {
        kind: "swf",
        class_skeleton_source: source,
    })
}

fn verdict_swf(comp: SwfCompression) -> DetectVerdict {
    let (tag, marker): (&'static str, &'static str) = match comp {
        SwfCompression::None => (TAG_SWF_FWS, "FWS-magic"),
        SwfCompression::Zlib => (TAG_SWF_CWS, "CWS-magic"),
        SwfCompression::Lzma => (TAG_SWF_ZWS, "ZWS-magic"),
    };
    DetectVerdict::new(
        PASS_ID,
        tag,
        FAMILY_INTERPRETER_BYTECODE,
        0.96,
        30,
        vec![marker],
        format!("swf compression={comp:?}"),
    )
}

fn verdict_abc() -> DetectVerdict {
    DetectVerdict::new(
        PASS_ID,
        TAG_ABC,
        FAMILY_INTERPRETER_BYTECODE,
        0.85,
        30,
        vec!["abc-version"],
        "raw abc bytecode (version minor=16 major=46)".to_string(),
    )
}

fn looks_like_abc(bytes: &[u8]) -> bool {
    if bytes.len() < 4 {
        return false;
    }
    let minor: u16 = u16::from_le_bytes([bytes[0], bytes[1]]);
    let major: u16 = u16::from_le_bytes([bytes[2], bytes[3]]);
    minor == ABC_VERSION_MINOR && major == ABC_VERSION_MAJOR
}

#[derive(Debug)]
enum As3CatalogKey {
    Format,
    Tool(KnownTool),
}

#[derive(Debug)]
pub struct As3CatalogEntry {
    key: As3CatalogKey,
    id: &'static str,
    display_name: &'static str,
    aliases: &'static [&'static str],
    quality: SupportQuality,
}

impl CatalogEntry for As3CatalogEntry {
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

const ID_SWF: &str = "as3-swf";
const ID_ABC: &str = "as3-abc";

const CATALOG_COUNT: usize = 7;

static CATALOG: [As3CatalogEntry; CATALOG_COUNT] = [
    As3CatalogEntry {
        key: As3CatalogKey::Format,
        id: ID_SWF,
        display_name: "SWF (Flash, FWS/CWS/ZWS) DoABC",
        aliases: &["swf", "flash", "fws", "cws", "zws"],
        quality: SupportQuality::Full,
    },
    As3CatalogEntry {
        key: As3CatalogKey::Format,
        id: ID_ABC,
        display_name: "Raw ABC bytecode",
        aliases: &["abc", "actionscript3"],
        quality: SupportQuality::Full,
    },
    As3CatalogEntry {
        key: As3CatalogKey::Tool(KnownTool::SecureSwf),
        id: "as3-securesswf",
        display_name: "secureSWF",
        aliases: &["securesswf", "secureswf"],
        quality: SupportQuality::DetectOnly,
    },
    As3CatalogEntry {
        key: As3CatalogKey::Tool(KnownTool::DoSwf),
        id: "as3-doswf",
        display_name: "DoSWF",
        aliases: &["doswf"],
        quality: SupportQuality::DetectOnly,
    },
    As3CatalogEntry {
        key: As3CatalogKey::Tool(KnownTool::Kindi),
        id: "as3-kindi",
        display_name: "Kindi",
        aliases: &["kindi"],
        quality: SupportQuality::DetectOnly,
    },
    As3CatalogEntry {
        key: As3CatalogKey::Tool(KnownTool::Irrfuscator),
        id: "as3-irrfuscator",
        display_name: "Irrfuscator",
        aliases: &["irrfuscator"],
        quality: SupportQuality::DetectOnly,
    },
    As3CatalogEntry {
        key: As3CatalogKey::Tool(KnownTool::Swflock),
        id: "as3-swflock",
        display_name: "swfLock",
        aliases: &["swflock"],
        quality: SupportQuality::DetectOnly,
    },
];

fn tool_entry_id(tool: KnownTool) -> Option<&'static str> {
    CATALOG
        .iter()
        .find(|e: &&As3CatalogEntry| matches!(e.key, As3CatalogKey::Tool(t) if t == tool))
        .map(|e: &As3CatalogEntry| e.id)
}

fn format_entry_id(format_tag: &str) -> Option<&'static str> {
    match format_tag {
        TAG_ABC => Some(ID_ABC),
        TAG_SWF_FWS | TAG_SWF_CWS | TAG_SWF_ZWS => Some(ID_SWF),
        _ => None,
    }
}

impl ObfuscatorCatalog for As3Detector {
    #[inline]
    fn pass_id(&self) -> PassId {
        PASS_ID
    }

    fn catalog(&self) -> Vec<&'static dyn CatalogEntry> {
        CATALOG
            .iter()
            .map(|e: &'static As3CatalogEntry| e as &'static dyn CatalogEntry)
            .collect()
    }

    fn detect(&self, ctx: &DetectContext<'_>) -> Option<DetectorOutput> {
        let verdict: DetectVerdict = Detector::detect(self, ctx)?;
        if verdict.format_tag == TAG_ABC
            && let Ok(abc) = parse_abc(ctx.bytes)
            && let Some(tool) = crate::obf::analyze(&abc).tools.first().copied()
            && let Some(tool_id) = tool_entry_id(tool)
        {
            return Some(DetectorOutput::new(
                tool_id,
                0.85,
                vec![format!("as3-tool-{}", tool.label())],
            ));
        }
        let entry_id: &'static str = format_entry_id(verdict.format_tag)?;
        let markers: Vec<String> = verdict
            .markers
            .iter()
            .map(|m: &&str| (*m).to_owned())
            .collect();
        Some(DetectorOutput::new(entry_id, verdict.confidence, markers))
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

    #[test]
    fn detector_id_is_stable() {
        assert_eq!(As3Detector.id(), PASS_ID);
    }

    #[test]
    fn catalog_lists_formats_and_known_tools() {
        let entries: Vec<&'static dyn CatalogEntry> = ObfuscatorCatalog::catalog(&As3Detector);
        assert_eq!(entries.len(), CATALOG_COUNT);
        let ids: Vec<&'static str> = entries.iter().map(|e| e.id()).collect();
        assert!(ids.contains(&ID_SWF), "got {ids:?}");
        assert!(ids.contains(&ID_ABC), "got {ids:?}");
        assert!(ids.contains(&"as3-securesswf"), "got {ids:?}");
        assert!(ids.contains(&"as3-doswf"), "got {ids:?}");
    }

    #[test]
    fn catalog_detect_maps_swf_format() {
        let out: DetectorOutput =
            ObfuscatorCatalog::detect(&As3Detector, &ctx(b"FWS\x0a\x00\x00\x00\x00"))
                .expect("swf catalog detect");
        assert_eq!(out.entry_id, ID_SWF);
    }

    #[test]
    fn catalog_detect_misses_random_bytes() {
        let bytes: Vec<u8> = vec![0u8; 32];
        assert!(ObfuscatorCatalog::detect(&As3Detector, &ctx(&bytes)).is_none());
    }

    #[test]
    fn detect_fws() {
        let v: DetectVerdict =
            Detector::detect(&As3Detector, &ctx(b"FWS\x0a\x00\x00\x00\x00")).expect("must detect");
        assert_eq!(v.format_tag, TAG_SWF_FWS);
    }

    #[test]
    fn detect_cws() {
        let v: DetectVerdict =
            Detector::detect(&As3Detector, &ctx(b"CWS\x0a\x00\x00\x00\x00")).expect("must detect");
        assert_eq!(v.format_tag, TAG_SWF_CWS);
    }

    #[test]
    fn detect_abc_version_46_16() {
        let mut bytes: Vec<u8> = Vec::with_capacity(8);
        bytes.extend_from_slice(&ABC_VERSION_MINOR.to_le_bytes());
        bytes.extend_from_slice(&ABC_VERSION_MAJOR.to_le_bytes());
        bytes.extend_from_slice(&[0u8; 4]);
        let v: DetectVerdict = Detector::detect(&As3Detector, &ctx(&bytes)).expect("must detect");
        assert_eq!(v.format_tag, TAG_ABC);
    }

    #[test]
    fn detect_misses_random_bytes() {
        let bytes: Vec<u8> = vec![0u8; 32];
        assert!(Detector::detect(&As3Detector, &ctx(&bytes)).is_none());
    }

    #[test]
    fn pass_output_kind_is_as3_source() {
        let a: Artifact = Artifact::new(Rung::Raw, vec![], [0u8; 32]);
        match AS3_PASS.output_kind(&a) {
            OutputKind::Source {
                language,
                formatted,
            } => {
                assert_eq!(language, Language::ActionScript3);
                assert!(formatted);
            }
            _ => panic!("expected Source"),
        }
    }

    #[test]
    fn pass_run_rejects_synthetic_fws_without_real_body() {
        let bytes: Vec<u8> = b"FWS\x0a\x00\x00\x00\x00".to_vec();
        let a: Artifact = Artifact::new(Rung::Raw, bytes, [0u8; 32]);
        let err: CoreError = AS3_PASS
            .run(&a)
            .expect_err("synthetic FWS lacks rect+frame data");
        assert!(format!("{err}").contains("DR-AS3-0907"));
    }

    #[test]
    fn pass_run_rejects_unknown_bytes() {
        let a: Artifact = Artifact::new(Rung::Raw, vec![0u8; 32], [0u8; 32]);
        let err: CoreError = AS3_PASS.run(&a).expect_err("must reject");
        assert!(format!("{err}").contains("DR-AS3-0902"));
    }

    #[test]
    fn pass_run_emits_real_as3_source_not_json() {
        let fixture: std::path::PathBuf = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("disrobe-pass-scriptlang")
            .join("tests")
            .join("fixtures")
            .join("haxe_main.swf");
        let bytes: Vec<u8> = std::fs::read(&fixture).unwrap_or_else(|err: std::io::Error| {
            panic!(
                "the chain's AS3 recovery is measured against real Haxe compiler output at {}, \
                 which could not be read: {err}",
                fixture.display()
            )
        });
        let a: Artifact = Artifact::new(Rung::Raw, bytes, [0u8; 32]);
        let out: Artifact = AS3_PASS.run(&a).expect("swf with DoABC must decompile");
        assert_eq!(out.rung, Rung::Surface);
        let source: &str = std::str::from_utf8(&out.envelope).expect("as3 source is utf-8");
        for declaration in [
            "class Main",
            "function greet",
            "function add",
            "function main",
        ] {
            assert!(
                source.contains(declaration),
                "{declaration} is in the Main.hx the Haxe compiler was given but absent from the \
                 chain's recovery; first 400: {:?}",
                source.chars().take(400).collect::<String>(),
            );
        }
        assert!(
            !source.contains("\"class_skeleton_source\"")
                && !source.contains("\"abc_payload_count\""),
            "as3 chain output still leaks the As3Extract json wrapper",
        );
    }
}
