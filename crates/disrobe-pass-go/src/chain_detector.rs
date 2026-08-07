#![cfg(feature = "chain")]
#![allow(clippy::module_name_repetitions)]
use disrobe_core::Artifact;
use disrobe_core::Rung;
use disrobe_core::chain::detection::TERMINAL_HINT;
use disrobe_core::chain::{
    CatalogEntry, ChildArtifact, ChildHandle, DetectContext, DetectVerdict, Detector,
    DetectorOutput, FAMILY_NATIVE_FORMAT, ObfuscatorCatalog, OutputKind, Pass, SupportQuality,
};
use disrobe_core::error::{CoreError, Result as CoreResult};
use disrobe_core::pass::PassId;

use crate::GoAnalysis;
use crate::binary::GoImage;
use crate::embed_fs::EmbedFile;
use crate::garble::GarbleQuality;
use crate::pclntab::{PclntabVersion, locate_pclntab};
use crate::symbols::GoFunc;

pub const PASS_ID: PassId = "go.classify";

const TAG_GO12: &str = "go-pclntab-1.2";
const TAG_GO116: &str = "go-pclntab-1.16";
const TAG_GO118: &str = "go-pclntab-1.18";
const TAG_GO120: &str = "go-pclntab-1.20+";
const TAG_GO_SYMBOL: &str = "go-runtime-symbol";

const GO_REPORT_BANNER: &str = "// go pclntab symbol recovery";
const MAX_LISTED_FUNCS: usize = 4_096;

const GO_ANALYSIS_SIDECAR: &str = "go-analysis.json";
const EMBED_CARVE_ROOT: &str = "embed";

const FIRSTMODULEDATA_MARKER: &[u8] = b"runtime.firstmoduledata";
const PCLNTAB_SECTION_MARKER: &[u8] = b"runtime.pclntab";
const SCAN_LIMIT: usize = 16 * 1024 * 1024;

#[derive(Debug)]
pub struct GoDetector;

impl Detector for GoDetector {
    #[inline]
    fn id(&self) -> PassId {
        PASS_ID
    }

    fn detect(&self, ctx: &DetectContext<'_>) -> Option<DetectVerdict> {
        let bytes: &[u8] = ctx.bytes;
        if bytes.len() < 64 {
            return None;
        }
        if let Ok(image) = GoImage::parse(bytes)
            && let Ok(located) = locate_pclntab(&image)
        {
            return Some(verdict_for_version(located.header.version));
        }
        let scan: &[u8] = if bytes.len() > SCAN_LIMIT {
            &bytes[..SCAN_LIMIT]
        } else {
            bytes
        };
        if window_contains(scan, FIRSTMODULEDATA_MARKER)
            || window_contains(scan, PCLNTAB_SECTION_MARKER)
        {
            return Some(verdict_runtime_symbol());
        }
        None
    }
}

#[derive(Debug)]
pub struct GoPass;

impl Pass for GoPass {
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
        &GoDetector
    }

    #[inline]
    fn output_kind(&self, _output: &Artifact) -> OutputKind {
        OutputKind::Mixed {
            children: Vec::new(),
        }
    }

    fn run(&self, artifact: &Artifact) -> CoreResult<Artifact> {
        let analysis: GoAnalysis = analyze_artifact(artifact)?;
        let report: String = render_symbol_report(&analysis);
        Ok(Artifact::new(
            Rung::Disasm,
            report.into_bytes(),
            artifact.root_hash,
        ))
    }

    fn extract_children(&self, input: &Artifact) -> CoreResult<Vec<ChildArtifact>> {
        let mut analysis: GoAnalysis = analyze_artifact(input)?;
        let mut children: Vec<ChildArtifact> = Vec::new();
        let mut index: u32 = 0;

        if let Ok(json) = serde_json::to_vec_pretty(&analysis) {
            children.push(terminal_child(index, GO_ANALYSIS_SIDECAR.to_string(), json));
            index += 1;
        }

        let files: Vec<EmbedFile> = std::mem::take(&mut analysis.embed.files);
        for file in files {
            let file: EmbedFile = file;
            if file.is_dir || file.data.is_empty() {
                continue;
            }
            let Some(relpath): Option<String> = safe_embed_relpath(&file.name) else {
                continue;
            };
            children.push(terminal_child(index, relpath, file.data));
            index += 1;
        }

        Ok(children)
    }
}

fn analyze_artifact(artifact: &Artifact) -> CoreResult<GoAnalysis> {
    let bytes: &[u8] = artifact.envelope.as_slice();
    let ctx: DetectContext<'_> = DetectContext {
        bytes,
        path_hint: None,
        parent_hint: None,
        depth: 0,
    };
    if Detector::detect(&GoDetector, &ctx).is_none() {
        return Err(CoreError::PassFailure(
            "DR-GO-0902: go.classify: input has no pclntab/runtime markers".to_string(),
        ));
    }
    crate::analyze(bytes).map_err(|e: crate::error::Error| {
        CoreError::PassFailure(format!("DR-GO-0903: go analyze: {e}"))
    })
}

fn terminal_child(index: u32, relative_path: String, bytes: Vec<u8>) -> ChildArtifact {
    ChildArtifact {
        handle: ChildHandle {
            artifact_index: index,
            relative_path,
            hint: Some(TERMINAL_HINT.to_string()),
        },
        bytes,
    }
}

fn safe_embed_relpath(name: &str) -> Option<String> {
    let mut parts: Vec<&str> = Vec::new();
    for raw in name.split(['/', '\\']) {
        if raw.is_empty() || raw == "." {
            continue;
        }
        if raw == ".." || raw.contains(':') {
            return None;
        }
        parts.push(raw);
    }
    if parts.is_empty() {
        return None;
    }
    Some(format!("{EMBED_CARVE_ROOT}/{}", parts.join("/")))
}

pub const META: disrobe_core::chain::PassMeta = disrobe_core::chain::PassMeta::new(
    PASS_ID,
    disrobe_core::chain::Ecosystem::Go,
    disrobe_core::chain::SupportQuality::Full,
    disrobe_core::chain::Determinism::Deterministic,
    disrobe_core::chain::SafetyClass::Static,
);

pub static GO_PASS: GoPass = GoPass;

fn render_symbol_report(a: &GoAnalysis) -> String {
    let mut out: String =
        String::with_capacity(512 + 64 * a.symbols.funcs.len().min(MAX_LISTED_FUNCS));
    push_line(&mut out, GO_REPORT_BANNER);
    push_line(
        &mut out,
        &format!(
            "// image={} ptr={} pclntab={} build={}",
            a.image_kind,
            a.ptr_size,
            a.pclntab_version,
            a.buildversion.as_deref().unwrap_or("unknown"),
        ),
    );
    push_line(
        &mut out,
        &format!(
            "// functions={} packages={} types={} embed_files={}",
            a.symbols.funcs.len(),
            a.symbols.package_set.len(),
            a.typemeta.types.len(),
            a.embed.files.len(),
        ),
    );

    if !a.symbols.package_set.is_empty() {
        out.push_str("\n// packages\n");
        for pkg in &a.symbols.package_set {
            push_line(&mut out, &format!("package {pkg}"));
        }
    }

    if !a.symbols.funcs.is_empty() {
        out.push_str("\n// functions (entry .. end : name)\n");
        for func in a.symbols.funcs.iter().take(MAX_LISTED_FUNCS) {
            let func: &GoFunc = func;
            push_line(
                &mut out,
                &format!("func {} // {:#x}..{:#x}", func.name, func.entry, func.end),
            );
        }
        if a.symbols.funcs.len() > MAX_LISTED_FUNCS {
            push_line(
                &mut out,
                &format!(
                    "// ... {} more functions elided",
                    a.symbols.funcs.len() - MAX_LISTED_FUNCS,
                ),
            );
        }
    }

    if a.embed.uses_embed_fs || !a.embed.files.is_empty() {
        out.push_str("\n// go:embed files\n");
        for file in &a.embed.files {
            let file: &EmbedFile = file;
            let kind: &str = if file.is_dir { "dir" } else { "file" };
            push_line(
                &mut out,
                &format!("embed {kind} {} ({} bytes)", file.name, file.size),
            );
        }
    }

    out
}

fn push_line(out: &mut String, line: &str) {
    out.push_str(line);
    out.push('\n');
}

fn verdict_for_version(version: PclntabVersion) -> DetectVerdict {
    let tag: &'static str = match version {
        PclntabVersion::Go12 => TAG_GO12,
        PclntabVersion::Go116 => TAG_GO116,
        PclntabVersion::Go118 => TAG_GO118,
        PclntabVersion::Go120 => TAG_GO120,
    };
    DetectVerdict::new(
        PASS_ID,
        tag,
        FAMILY_NATIVE_FORMAT,
        0.92,
        35,
        vec!["pclntab-structural"],
        format!(
            "go pclntab structurally located, version={}",
            version.label()
        ),
    )
}

fn verdict_runtime_symbol() -> DetectVerdict {
    DetectVerdict::new(
        PASS_ID,
        TAG_GO_SYMBOL,
        FAMILY_NATIVE_FORMAT,
        0.78,
        38,
        vec!["runtime.firstmoduledata"],
        "go runtime symbol marker".to_string(),
    )
}

#[inline]
fn window_contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w: &[u8]| w == needle)
}

const GARBLE_ID: &str = "go-garble";

#[derive(Debug)]
pub struct GoCatalogEntry {
    id: &'static str,
    display_name: &'static str,
    aliases: &'static [&'static str],
    quality: SupportQuality,
}

impl CatalogEntry for GoCatalogEntry {
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

const CATALOG_COUNT: usize = 1;

static CATALOG: [GoCatalogEntry; CATALOG_COUNT] = [GoCatalogEntry {
    id: GARBLE_ID,
    display_name: "garble",
    aliases: &["garble", "burrowers-garble"],
    quality: SupportQuality::Full,
}];

impl ObfuscatorCatalog for GoDetector {
    #[inline]
    fn pass_id(&self) -> PassId {
        PASS_ID
    }

    fn catalog(&self) -> Vec<&'static dyn CatalogEntry> {
        CATALOG
            .iter()
            .map(|e: &'static GoCatalogEntry| e as &'static dyn CatalogEntry)
            .collect()
    }

    fn detect(&self, ctx: &DetectContext<'_>) -> Option<DetectorOutput> {
        Detector::detect(&Self, ctx)?;
        let bytes: &[u8] = ctx.bytes;
        let analysis: GoAnalysis = crate::analyze(bytes).ok()?;
        let confidence: f32 = match analysis.garble.quality {
            GarbleQuality::None => return None,
            GarbleQuality::Detected => 0.7,
            GarbleQuality::Partial => 0.85,
            GarbleQuality::Full => 0.95,
        };
        Some(DetectorOutput::new(
            GARBLE_ID,
            confidence,
            vec![format!("garble-quality-{:?}", analysis.garble.quality)],
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

    #[test]
    fn detector_id_is_stable() {
        assert_eq!(GoDetector.id(), PASS_ID);
    }

    #[test]
    fn catalog_lists_garble() {
        let entries: Vec<&'static dyn CatalogEntry> = ObfuscatorCatalog::catalog(&GoDetector);
        assert_eq!(entries.len(), CATALOG_COUNT);
        assert_eq!(entries[0].id(), GARBLE_ID);
        assert_eq!(entries[0].display_name(), "garble");
        assert_eq!(entries[0].support_quality(), SupportQuality::Full);
    }

    #[test]
    fn catalog_detect_misses_non_go_bytes() {
        let bytes: Vec<u8> = vec![0u8; 256];
        assert!(ObfuscatorCatalog::detect(&GoDetector, &ctx(&bytes)).is_none());
    }

    #[test]
    fn catalog_detect_fires_on_real_garble_image() {
        let Some(bytes): Option<Vec<u8>> = garble_fixture() else {
            eprintln!("SKIP: go garble fixture missing");
            return;
        };
        let out: DetectorOutput = ObfuscatorCatalog::detect(&GoDetector, &ctx(&bytes))
            .expect("a real garble image must be catalog-detected");
        assert_eq!(out.entry_id, GARBLE_ID);
        assert!(out.confidence >= 0.7, "confidence={}", out.confidence);
    }

    #[test]
    fn detect_rejects_loose_pclntab_magic_without_structure() {
        use crate::pclntab::MAGIC_GO118;
        let mut bytes: Vec<u8> = vec![0u8; 128];
        bytes[64..68].copy_from_slice(&MAGIC_GO118.to_le_bytes());
        assert!(
            Detector::detect(&GoDetector, &ctx(&bytes)).is_none(),
            "four bare magic bytes with no valid pclntab table layout around them must not \
             classify as go",
        );
    }

    fn workspace_root() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|p: &std::path::Path| p.parent())
            .expect("workspace root")
            .to_path_buf()
    }

    fn find_versioned_native_host(base: &std::path::Path, filename: &str) -> Option<Vec<u8>> {
        let entries: std::fs::ReadDir = std::fs::read_dir(base).ok()?;
        let mut version_dirs: Vec<std::path::PathBuf> = entries
            .filter_map(|e: std::io::Result<std::fs::DirEntry>| e.ok())
            .map(|e: std::fs::DirEntry| e.path())
            .filter(|p: &std::path::PathBuf| p.is_dir())
            .collect();
        version_dirs.sort();
        for version_dir in version_dirs.into_iter().rev() {
            let candidate: std::path::PathBuf = version_dir.join(filename);
            if let Ok(bytes) = std::fs::read(&candidate) {
                return Some(bytes);
            }
        }
        None
    }

    #[test]
    fn detect_rejects_aspack_packed_native_binary_as_go() {
        let path: std::path::PathBuf = workspace_root()
            .join("corpus")
            .join("native")
            .join("packers")
            .join("aspack")
            .join("AccessEnum.original.exe");
        let bytes: Vec<u8> = std::fs::read(&path)
            .unwrap_or_else(|e: std::io::Error| panic!("read {} failed: {e}", path.display()));
        assert!(
            Detector::detect(&GoDetector, &ctx(&bytes)).is_none(),
            "a real aspack-packed native binary must not classify as go via a loose pclntab \
             magic byte match",
        );
    }

    #[test]
    fn detect_rejects_dotnet_hostpolicy_as_go() {
        let base: std::path::PathBuf =
            std::path::PathBuf::from(r"C:\Program Files\dotnet\shared\Microsoft.NETCore.App");
        let Some(bytes): Option<Vec<u8>> = find_versioned_native_host(&base, "hostpolicy.dll")
        else {
            eprintln!(
                "SKIP: no local dotnet runtime install found under {}",
                base.display()
            );
            return;
        };
        assert!(
            Detector::detect(&GoDetector, &ctx(&bytes)).is_none(),
            "microsoft's hostpolicy.dll must not classify as go",
        );
    }

    #[test]
    fn detect_rejects_dotnet_hostfxr_as_go() {
        let base: std::path::PathBuf =
            std::path::PathBuf::from(r"C:\Program Files\dotnet\host\fxr");
        let Some(bytes): Option<Vec<u8>> = find_versioned_native_host(&base, "hostfxr.dll") else {
            eprintln!(
                "SKIP: no local dotnet host fxr install found under {}",
                base.display()
            );
            return;
        };
        assert!(
            Detector::detect(&GoDetector, &ctx(&bytes)).is_none(),
            "microsoft's hostfxr.dll must not classify as go",
        );
    }

    #[test]
    fn detect_fires_on_real_go_binary_after_tightening() {
        let path: std::path::PathBuf = workspace_root()
            .join("corpus")
            .join("native")
            .join("compilers")
            .join("go")
            .join("hello.go.exe");
        let bytes: Vec<u8> = std::fs::read(&path)
            .unwrap_or_else(|e: std::io::Error| panic!("read {} failed: {e}", path.display()));
        let v: DetectVerdict = Detector::detect(&GoDetector, &ctx(&bytes))
            .expect("a real go binary must still classify as go after the pclntab tightening");
        assert!(
            [TAG_GO12, TAG_GO116, TAG_GO118, TAG_GO120].contains(&v.format_tag),
            "unexpected tag {}",
            v.format_tag,
        );
    }

    #[test]
    fn detect_runtime_symbol_marker() {
        let mut bytes: Vec<u8> = vec![0u8; 64];
        bytes.extend_from_slice(FIRSTMODULEDATA_MARKER);
        bytes.extend(std::iter::repeat_n(0u8, 32));
        let v: DetectVerdict = Detector::detect(&GoDetector, &ctx(&bytes)).expect("must detect");
        assert_eq!(v.format_tag, TAG_GO_SYMBOL);
    }

    #[test]
    fn detect_misses_random_bytes() {
        let bytes: Vec<u8> = vec![0u8; 128];
        assert!(Detector::detect(&GoDetector, &ctx(&bytes)).is_none());
    }

    #[test]
    fn pass_output_kind_is_mixed_so_children_are_collected() {
        let a: Artifact = Artifact::new(Rung::Raw, vec![], [0u8; 32]);
        match GO_PASS.output_kind(&a) {
            OutputKind::Mixed { .. } => {}
            other => panic!(
                "go must be Mixed so the chain runner collects embed.FS + analysis children; got {other:?}"
            ),
        }
    }

    #[test]
    fn pass_run_renders_real_symbol_listing_not_json() {
        let fixture: std::path::PathBuf = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("hello_normal.exe");
        let Ok(bytes): std::io::Result<Vec<u8>> = std::fs::read(&fixture) else {
            eprintln!("SKIP: go fixture missing at {}", fixture.display());
            return;
        };
        let a: Artifact = Artifact::new(Rung::Raw, bytes, [0u8; 32]);
        let out: Artifact = GO_PASS.run(&a).expect("go analyze must succeed");
        let s: &str = std::str::from_utf8(&out.envelope).expect("utf8 report");
        assert!(
            !s.trim_start().starts_with('{') && !s.contains("\"image_kind\""),
            "go chain output must be the readable symbol listing, not the analysis json; got {:?}",
            s.chars().take(160).collect::<String>(),
        );
        assert!(
            s.starts_with(GO_REPORT_BANNER),
            "go report must lead with its banner",
        );
        assert!(
            s.contains("func main.main") || s.contains("func runtime."),
            "go report must list real recovered function symbols; got first 400: {:?}",
            s.chars().take(400).collect::<String>(),
        );
        match GO_PASS.output_kind(&out) {
            OutputKind::Mixed { .. } => {}
            other => panic!("expected Mixed output_kind, got {other:?}"),
        }
    }

    #[test]
    fn pass_run_rejects_loose_pclntab_magic_without_structure() {
        use crate::pclntab::MAGIC_GO118;
        let mut bytes: Vec<u8> = vec![0u8; 128];
        bytes[64..68].copy_from_slice(&MAGIC_GO118.to_le_bytes());
        let a: Artifact = Artifact::new(Rung::Raw, bytes, [0u8; 32]);
        let err: CoreError = GO_PASS
            .run(&a)
            .expect_err("must reject bytes carrying only a bare pclntab magic");
        assert!(format!("{err}").contains("DR-GO-0902"));
    }

    #[test]
    fn pass_run_rejects_unknown_bytes() {
        let a: Artifact = Artifact::new(Rung::Raw, vec![0u8; 128], [0u8; 32]);
        let err: CoreError = GO_PASS.run(&a).expect_err("must reject");
        assert!(format!("{err}").contains("DR-GO-0902"));
    }

    fn embed_fixture() -> Option<Vec<u8>> {
        let fixture: std::path::PathBuf = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("hello_embed.exe");
        std::fs::read(&fixture).ok()
    }

    #[test]
    fn extract_children_carves_embed_bytes_and_analysis_sidecar() {
        let Some(bytes): Option<Vec<u8>> = embed_fixture() else {
            eprintln!("SKIP: go embed fixture missing");
            return;
        };
        let a: Artifact = Artifact::new(Rung::Raw, bytes, [0u8; 32]);
        let children: Vec<ChildArtifact> = GO_PASS
            .extract_children(&a)
            .expect("go children extraction");

        let sidecar: &ChildArtifact = children
            .iter()
            .find(|c: &&ChildArtifact| c.handle.relative_path == GO_ANALYSIS_SIDECAR)
            .expect(
                "auto must surface the structured go-analysis.json the dedicated command writes",
            );
        let parsed: serde_json::Value =
            serde_json::from_slice(&sidecar.bytes).expect("analysis sidecar is valid json");
        assert!(
            parsed.get("image_kind").is_some() && parsed.get("garble").is_some(),
            "go-analysis sidecar must carry the full GoAnalysis (image_kind/garble/...)",
        );
        assert_eq!(sidecar.handle.hint.as_deref(), Some(TERMINAL_HINT));

        let note: &ChildArtifact = children
            .iter()
            .find(|c: &&ChildArtifact| c.handle.relative_path == "embed/assets/note.txt")
            .expect("the embed.FS member bytes must be carved as a chain child, not just listed");
        assert_eq!(
            note.bytes, b"disrobe embed fixture payload alpha\n",
            "carved embed member must be byte-exact full content, not a preview",
        );
        assert_eq!(note.handle.hint.as_deref(), Some(TERMINAL_HINT));
    }

    fn carve_in_memory_image(pe_bytes: &[u8]) -> Vec<u8> {
        use object::Object as _;
        use object::ObjectSection as _;
        let file: object::read::File<'_, &[u8]> =
            object::read::File::parse(pe_bytes).expect("parse reference pe");
        let mut min_addr: u64 = u64::MAX;
        let mut max_end: u64 = 0;
        for sec in file.sections() {
            let addr: u64 = sec.address();
            let data: &[u8] = sec.data().unwrap_or(b"");
            if data.is_empty() || addr == 0 {
                continue;
            }
            min_addr = min_addr.min(addr);
            max_end = max_end.max(addr + data.len() as u64);
        }
        let span: usize = usize::try_from(max_end - min_addr).expect("span");
        let mut flat: Vec<u8> = vec![0u8; span];
        for sec in file.sections() {
            let addr: u64 = sec.address();
            let data: &[u8] = sec.data().unwrap_or(b"");
            if data.is_empty() || addr < min_addr {
                continue;
            }
            let off: usize = usize::try_from(addr - min_addr).expect("off");
            let end: usize = off + data.len();
            if end <= flat.len() {
                flat[off..end].copy_from_slice(data);
            }
        }
        flat
    }

    #[test]
    fn extract_children_carves_embed_from_headerless_unpacked_image() {
        let Some(pe): Option<Vec<u8>> = embed_fixture() else {
            eprintln!("SKIP: go embed fixture missing");
            return;
        };
        let flat: Vec<u8> = carve_in_memory_image(&pe);
        assert!(
            object::read::FileKind::parse(flat.as_slice()).is_err(),
            "carved image must be headerless so the chain exercises the flat-image fallback",
        );
        let a: Artifact = Artifact::new(Rung::Raw, flat, [0u8; 32]);
        assert!(
            Detector::detect(&GoDetector, &ctx_from(&a)).is_some(),
            "the go detector must still fire on a headerless upx-unpacked image",
        );
        let children: Vec<ChildArtifact> = GO_PASS
            .extract_children(&a)
            .expect("go children extraction from a headerless image");
        let note: &ChildArtifact = children
            .iter()
            .find(|c: &&ChildArtifact| c.handle.relative_path == "embed/assets/note.txt")
            .expect(
                "after upx unwrap the chain must still carve the embed.FS member from the \
                 sectionless image, not just from the container build",
            );
        assert_eq!(
            note.bytes, b"disrobe embed fixture payload alpha\n",
            "embed member carved from the headerless image must be byte-exact",
        );
    }

    fn ctx_from(a: &Artifact) -> DetectContext<'_> {
        DetectContext {
            bytes: a.envelope.as_slice(),
            path_hint: None,
            parent_hint: None,
            depth: 0,
        }
    }

    fn garble_fixture() -> Option<Vec<u8>> {
        let fixture: std::path::PathBuf = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("hello_garble.exe");
        std::fs::read(&fixture).ok()
    }

    #[test]
    fn chain_surfaces_garble_undo_on_headerless_unpacked_image() {
        let Some(pe): Option<Vec<u8>> = garble_fixture() else {
            eprintln!("SKIP: go garble fixture missing");
            return;
        };
        let flat: Vec<u8> = carve_in_memory_image(&pe);
        assert!(
            object::read::FileKind::parse(flat.as_slice()).is_err(),
            "carved garble image must be headerless so the chain exercises the flat-image path",
        );
        let a: Artifact = Artifact::new(Rung::Raw, flat, [0u8; 32]);
        let children: Vec<ChildArtifact> = GO_PASS
            .extract_children(&a)
            .expect("go children extraction from a headerless garble image");
        let sidecar: &ChildArtifact = children
            .iter()
            .find(|c: &&ChildArtifact| c.handle.relative_path == GO_ANALYSIS_SIDECAR)
            .expect("the chain must surface go-analysis.json for the unpacked garble image");
        let parsed: serde_json::Value =
            serde_json::from_slice(&sidecar.bytes).expect("analysis sidecar is valid json");
        let garble: &serde_json::Value = parsed.get("garble").expect("garble report present");
        assert_eq!(
            garble.get("quality").and_then(serde_json::Value::as_str),
            Some("Full"),
            "the chain's garble-undo on the unpacked image must classify Full, not silently \
             degrade because the unpacked image is sectionless",
        );
        let thunk: u64 = garble
            .get("literal_recovery")
            .and_then(|l: &serde_json::Value| l.get("garble_thunk"))
            .and_then(serde_json::Value::as_u64)
            .expect("garble_thunk count present");
        assert!(
            thunk > 50,
            "the -literals decrypt-thunk emulation must run on the unpacked image and recover a \
             real body of plaintexts, got {thunk}",
        );
    }

    #[test]
    fn extract_children_rejects_unknown_bytes() {
        let a: Artifact = Artifact::new(Rung::Raw, vec![0u8; 128], [0u8; 32]);
        let err: CoreError = GO_PASS
            .extract_children(&a)
            .expect_err("children extraction must reject non-go input");
        assert!(format!("{err}").contains("DR-GO-0902"));
    }

    #[test]
    fn safe_embed_relpath_blocks_traversal() {
        assert!(safe_embed_relpath("../etc/passwd").is_none());
        assert!(safe_embed_relpath("a/../b").is_none());
        assert!(safe_embed_relpath("c:/win").is_none());
        assert_eq!(
            safe_embed_relpath("assets/note.txt").as_deref(),
            Some("embed/assets/note.txt"),
        );
    }
}
