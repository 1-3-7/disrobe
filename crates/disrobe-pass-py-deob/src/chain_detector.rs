#![cfg(feature = "chain")]
#![allow(clippy::module_name_repetitions)]
use disrobe_core::Artifact;
use disrobe_core::Rung;
use disrobe_core::chain::detection::TERMINAL_HINT;
use disrobe_core::chain::{
    CatalogEntry, ChildArtifact, ChildHandle, DetectContext, DetectVerdict, Detector,
    DetectorOutput, FAMILY_OBFUSCATOR_WRAPPER, ObfuscatorCatalog, OutputKind, Pass, SupportQuality,
};
use disrobe_core::error::{CoreError, Result as CoreResult};
use disrobe_core::pass::PassId;

use disrobe_py_marshal::pyversion_from_magic;

use crate::auto_route::{AutoDeobOutcome, RouteKind, auto_deobfuscate, unidentified_guidance};
use crate::detect::{Detection, Family, detect as detect_family};
use crate::marshal::detect_marshal;
use crate::obfuscators::{DetectReport, Obfuscator};
use crate::peel::best_obfuscator_detection;

pub const PASS_ID: PassId = "py.deob";

const TAG_GENERIC: &str = "py-source-obfuscated";
const TAG_MARSHAL: &str = "py-marshal-packer";
const TAG_HYPERION: &str = "py-hyperion";
const TAG_DROPPER: &str = "py-exec-eval-dropper";

const DETECT_THRESHOLD: f32 = 0.5f32;
const OBFUSCATOR_SPECIFICITY: u16 = 40;
const FAMILY_SPECIFICITY: u16 = 30;

const CHILD_SOURCE_PATH: &str = "recovered.deobfuscated.py";
const CHILD_MANIFEST_PATH: &str = "recovered.manifest.json";
const MANIFEST_SCHEMA: &str = "disrobe.py.deob.manifest/v1";

#[derive(Debug, Clone)]
enum PyChainHit {
    Obfuscator {
        obfuscator: Obfuscator,
        confidence: f32,
        markers: Vec<String>,
    },
    Marshal {
        confidence: f32,
    },
    Family {
        family: Family,
        confidence: f32,
        markers: Vec<String>,
    },
}

impl PyChainHit {
    const fn confidence(&self) -> f32 {
        match self {
            Self::Obfuscator { confidence, .. }
            | Self::Marshal { confidence }
            | Self::Family { confidence, .. } => *confidence,
        }
    }

    fn entry_id(&self) -> &'static str {
        match self {
            Self::Obfuscator { obfuscator, .. } => catalog_id_for(*obfuscator),
            Self::Marshal { .. } => TAG_MARSHAL,
            Self::Family { family, .. } => family_tag(*family),
        }
    }

    const fn specificity(&self) -> u16 {
        match self {
            Self::Obfuscator { .. } => OBFUSCATOR_SPECIFICITY,
            Self::Marshal { .. } | Self::Family { .. } => FAMILY_SPECIFICITY,
        }
    }

    fn markers(self) -> Vec<String> {
        match self {
            Self::Obfuscator { markers, .. } | Self::Family { markers, .. } => markers,
            Self::Marshal { .. } => vec!["marshal-packer".to_owned()],
        }
    }

    fn explain(&self) -> String {
        match self {
            Self::Obfuscator { obfuscator, .. } => {
                format!("py-deob obfuscator={obfuscator:?}")
            }
            Self::Marshal { .. } => "py-deob marshal packer".to_owned(),
            Self::Family { family, .. } => format!("py-deob family={family:?}"),
        }
    }
}

fn chain_detect(bytes: &[u8]) -> Option<PyChainHit> {
    if let Some((_, report)) = best_obfuscator_detection(bytes) {
        let report: DetectReport = report;
        return Some(PyChainHit::Obfuscator {
            obfuscator: report.obfuscator,
            confidence: report.confidence,
            markers: report.markers,
        });
    }
    if is_clean_pyc(bytes) {
        return None;
    }
    let marshal_confidence: f32 = detect_marshal(bytes);
    if marshal_confidence >= DETECT_THRESHOLD {
        return Some(PyChainHit::Marshal {
            confidence: marshal_confidence,
        });
    }
    let family: Detection = detect_family(bytes);
    if family.family != Family::Unknown && family.confidence >= DETECT_THRESHOLD {
        return Some(PyChainHit::Family {
            family: family.family,
            confidence: family.confidence,
            markers: family.markers,
        });
    }
    None
}

fn is_clean_pyc(bytes: &[u8]) -> bool {
    if bytes.len() < 4 {
        return false;
    }
    let magic: u32 = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    pyversion_from_magic(magic).is_some()
}

const fn family_tag(family: Family) -> &'static str {
    match family {
        Family::Hyperion => TAG_HYPERION,
        Family::GenericDropper | Family::Pyfuscator => TAG_DROPPER,
        Family::KramerSpecterBerserker
        | Family::BlankObf
        | Family::PyObfuscator
        | Family::Opy
        | Family::Unknown => TAG_GENERIC,
    }
}

#[derive(Debug)]
pub struct PyDeobDetector;

impl Detector for PyDeobDetector {
    #[inline]
    fn id(&self) -> PassId {
        PASS_ID
    }

    fn detect(&self, ctx: &DetectContext<'_>) -> Option<DetectVerdict> {
        let hit: PyChainHit = chain_detect(ctx.bytes)?;
        let confidence: f32 = hit.confidence();
        let format_tag: &'static str = hit.entry_id();
        let specificity: u16 = hit.specificity();
        let explain: String = hit.explain();
        Some(DetectVerdict::new(
            PASS_ID,
            format_tag,
            FAMILY_OBFUSCATOR_WRAPPER,
            confidence,
            specificity,
            vec!["py-source-marker"],
            explain,
        ))
    }
}

#[derive(Debug)]
pub struct PyDeobPass;

impl Pass for PyDeobPass {
    #[inline]
    fn id(&self) -> PassId {
        PASS_ID
    }

    #[inline]
    fn detector(&self) -> &'static dyn Detector {
        &PyDeobDetector
    }

    #[inline]
    fn output_kind(&self, _output: &Artifact) -> OutputKind {
        OutputKind::Mixed {
            children: Vec::new(),
        }
    }

    fn run(&self, artifact: &Artifact) -> CoreResult<Artifact> {
        let bytes: &[u8] = artifact.envelope.as_slice();
        let outcome: AutoDeobOutcome = auto_deobfuscate(bytes, None);
        let source: String = recovered_source(&outcome)?;
        Ok(Artifact::new(
            Rung::Surface,
            source.into_bytes(),
            artifact.root_hash,
        ))
    }

    fn extract_children(&self, input: &Artifact) -> CoreResult<Vec<ChildArtifact>> {
        let bytes: &[u8] = input.envelope.as_slice();
        let outcome: AutoDeobOutcome = auto_deobfuscate(bytes, None);
        let source: String = recovered_source(&outcome)?;
        let mut children: Vec<ChildArtifact> = Vec::with_capacity(2);
        children.push(terminal_child(
            CHILD_SOURCE_PATH.to_owned(),
            source.into_bytes(),
        ));
        let manifest: serde_json::Value = serde_json::json!({
            "schema": MANIFEST_SCHEMA,
            "peel": outcome.peel,
            "cleanup": serde_json::Value::Null,
            "route": outcome.kind,
            "detection": outcome.detection,
            "chain": outcome.chain,
        });
        if let Ok(json) = serde_json::to_vec_pretty(&manifest) {
            children.push(terminal_child(CHILD_MANIFEST_PATH.to_owned(), json));
        }
        reindex(&mut children);
        Ok(children)
    }
}

fn recovered_source(outcome: &AutoDeobOutcome) -> CoreResult<String> {
    match outcome.kind {
        RouteKind::Deobfuscated | RouteKind::CleanPyc => {
            let source: &String = outcome.source.as_ref().ok_or_else(|| {
                CoreError::PassFailure(
                    "DR-PYDEOB-0903: py.deob: route reported recovery but produced no source"
                        .to_string(),
                )
            })?;
            if source.trim().is_empty() {
                return Err(CoreError::PassFailure(
                    "DR-PYDEOB-0904: py.deob: recovered source was empty".to_string(),
                ));
            }
            Ok(source.clone())
        }
        RouteKind::Unidentified => Err(CoreError::PassFailure(
            "DR-PYDEOB-0902: py.deob: no matching obfuscator pass".to_string(),
        )),
    }
}

fn terminal_child(relative_path: String, bytes: Vec<u8>) -> ChildArtifact {
    ChildArtifact {
        handle: ChildHandle {
            artifact_index: 0,
            relative_path,
            hint: Some(TERMINAL_HINT.to_owned()),
        },
        bytes,
    }
}

fn reindex(children: &mut [ChildArtifact]) {
    for (index, child) in children.iter_mut().enumerate() {
        child.handle.artifact_index = u32::try_from(index).unwrap_or(u32::MAX);
    }
}

pub static PY_DEOB_PASS: PyDeobPass = PyDeobPass;

#[derive(Debug)]
pub struct PyObfuscatorEntry {
    pub obfuscator: Obfuscator,
    pub id: &'static str,
    pub display_name: &'static str,
    pub aliases: &'static [&'static str],
    pub quality: SupportQuality,
}

impl CatalogEntry for PyObfuscatorEntry {
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

const fn quality_of(obf: Obfuscator) -> SupportQuality {
    match obf {
        Obfuscator::PythonObfuscatorPypi | Obfuscator::Pyobfus | Obfuscator::Pypacker => {
            SupportQuality::Partial
        }
        _ => SupportQuality::Full,
    }
}

const CATALOG_COUNT: usize = 20;

static CATALOG: [PyObfuscatorEntry; CATALOG_COUNT] = [
    entry(
        Obfuscator::Kramer,
        "kramer",
        "Kramer / Specter",
        &["specter"],
    ),
    entry(
        Obfuscator::Berserker,
        "berserker",
        "Berserker",
        &["hyperion-successor"],
    ),
    entry(Obfuscator::Jawbreaker, "jawbreaker", "Jawbreaker", &[]),
    entry(
        Obfuscator::BlankObf,
        "blankobf",
        "BlankOBF",
        &["blankobfv2"],
    ),
    entry(Obfuscator::PlusObf, "plusobf", "PlusOBF", &[]),
    entry(Obfuscator::Wodx, "wodx", "Wodx", &[]),
    entry(
        Obfuscator::PyobfuscateCom,
        "pyobfuscate-com",
        "pyobfuscate.com",
        &["pyobfuscate-online"],
    ),
    entry(
        Obfuscator::PyobfuscateComXor,
        "pyobfuscate-com-xor",
        "pyobfuscate.com (2026 XOR/lambda)",
        &["pyobfuscate-xor", "pyobfuscate-lambda"],
    ),
    entry(
        Obfuscator::PyObfuscatorMauricelambert,
        "pyobfuscator-mauricelambert",
        "PyObfuscator (mauricelambert)",
        &["pyobfuscator"],
    ),
    entry(
        Obfuscator::PythonObfuscatorPypi,
        "python-obfuscator-pypi",
        "python-obfuscator (PyPI)",
        &["python_obfuscator"],
    ),
    entry(Obfuscator::ObfuXtreme, "obfuxtreme", "ObfuXtreme", &[]),
    entry(Obfuscator::Manglify, "manglify", "Manglify", &[]),
    entry(Obfuscator::Oxyry, "oxyry", "Oxyry", &["oxyry-shrinker"]),
    entry(Obfuscator::Pyminifier, "pyminifier", "pyminifier", &[]),
    entry(
        Obfuscator::OnlineFamily,
        "online-family",
        "online obfuscator family",
        &["pyobfuscate-family"],
    ),
    entry(Obfuscator::XindexObf, "xindex", "Xindex", &[]),
    entry(Obfuscator::Pyobfus, "pyobfus", "pyobfus", &["lambda-chain"]),
    entry(
        Obfuscator::Pypacker,
        "pypacker",
        "Pypacker",
        &["marshal-packer"],
    ),
    entry(
        Obfuscator::Patchwork,
        "patchwork",
        "Patchwork",
        &["patchwork-obfuscator"],
    ),
    entry(
        Obfuscator::PycZipper,
        "pyc-zipper",
        "pyc-zipper",
        &["pyc_zipper", "pyc-packer"],
    ),
];

const fn entry(
    obfuscator: Obfuscator,
    id: &'static str,
    display_name: &'static str,
    aliases: &'static [&'static str],
) -> PyObfuscatorEntry {
    PyObfuscatorEntry {
        obfuscator,
        id,
        display_name,
        aliases,
        quality: quality_of(obfuscator),
    }
}

fn catalog_id_for(obf: Obfuscator) -> &'static str {
    CATALOG
        .iter()
        .find(|e: &&PyObfuscatorEntry| e.obfuscator == obf)
        .map_or(TAG_GENERIC, |e: &PyObfuscatorEntry| e.id)
}

impl ObfuscatorCatalog for PyDeobDetector {
    #[inline]
    fn pass_id(&self) -> PassId {
        PASS_ID
    }

    fn catalog(&self) -> Vec<&'static dyn CatalogEntry> {
        CATALOG
            .iter()
            .map(|e: &'static PyObfuscatorEntry| e as &'static dyn CatalogEntry)
            .collect()
    }

    fn detect(&self, ctx: &DetectContext<'_>) -> Option<DetectorOutput> {
        let hit: PyChainHit = chain_detect(ctx.bytes)?;
        let entry_id: &'static str = hit.entry_id();
        let confidence: f32 = hit.confidence();
        Some(DetectorOutput::new(entry_id, confidence, hit.markers()))
    }

    fn hint_unidentified(&self, ctx: &DetectContext<'_>) -> Option<String> {
        Some(unidentified_guidance(ctx.bytes))
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::obfuscators::iter_passes;

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
        assert_eq!(PyDeobDetector.id(), PASS_ID);
    }

    #[test]
    fn pass_output_kind_is_mixed_so_extract_children_runs() {
        let a: Artifact = Artifact::new(Rung::Raw, vec![], [0u8; 32]);
        assert!(
            PY_DEOB_PASS.output_kind(&a).is_mixed(),
            "the pass must declare Mixed so the chain runner invokes extract_children and the \
             manifest sidecar reaches auto parity with the dedicated `py deob` command"
        );
    }

    #[test]
    fn detect_clean_python_yields_none() {
        let src: &[u8] = b"def foo():\n    return 1\n";
        assert!(Detector::detect(&PyDeobDetector, &ctx(src)).is_none());
        assert!(ObfuscatorCatalog::detect(&PyDeobDetector, &ctx(src)).is_none());
    }

    #[test]
    fn clean_compiled_pyc_is_left_to_the_pyc_decompiler() {
        let mut pyc: Vec<u8> = Vec::with_capacity(32);
        pyc.extend_from_slice(&0x0A0D_0DCBu32.to_le_bytes());
        pyc.extend_from_slice(&[0u8; 12]);
        pyc.extend_from_slice(b"\xe3\x00\x00\x00\x00\x00\x00\x00");
        assert!(
            Detector::detect(&PyDeobDetector, &ctx(&pyc)).is_none(),
            "py.deob must defer a clean compiled pyc to py.decompile, not claim it"
        );
        assert!(ObfuscatorCatalog::detect(&PyDeobDetector, &ctx(&pyc)).is_none());
    }

    #[test]
    fn catalog_is_non_empty_and_covers_registered_passes() {
        let entries: Vec<&'static dyn CatalogEntry> = PyDeobDetector.catalog();
        assert!(!entries.is_empty());
        assert_eq!(entries.len(), iter_passes().len());
        for e in &entries {
            assert!(!e.id().is_empty());
            assert!(!e.display_name().is_empty());
        }
    }

    #[test]
    fn catalog_detects_a_real_berserker_banner_sample() {
        let src: &[u8] = b"# Berserker\n__berserker__ = 'v1'\nimport base64, lzma\n";
        let out: DetectorOutput = ObfuscatorCatalog::detect(&PyDeobDetector, &ctx(src))
            .expect("real berserker banner must be detected");
        assert_eq!(out.entry_id, "berserker");
        assert!(out.confidence >= 0.9);
        assert!(
            entry_ids().contains(&out.entry_id),
            "detected id must be a catalog entry"
        );
    }

    #[test]
    fn hint_unidentified_lists_supported_obfuscators() {
        let hint: String = ObfuscatorCatalog::hint_unidentified(
            &PyDeobDetector,
            &ctx(b"def foo():\n    return 1\n"),
        )
        .expect("hint present");
        assert!(hint.contains("BlankOBF"));
    }

    #[test]
    fn plusobf_baked_sample_detects_and_recovers_through_chain_run() {
        let original: &str = "print('chain plusobf wired')\n";
        let baked: String = crate::obfuscators::plusobf::bake(original);
        let verdict: DetectVerdict = Detector::detect(&PyDeobDetector, &ctx(baked.as_bytes()))
            .expect("plusobf must be detected by the chain detector");
        assert_eq!(verdict.format_tag, "plusobf");
        let a: Artifact = Artifact::new(Rung::Raw, baked.clone().into_bytes(), [0u8; 32]);
        let out: Artifact = PY_DEOB_PASS
            .run(&a)
            .expect("chain run must recover plusobf source");
        let recovered: &str = std::str::from_utf8(&out.envelope).expect("utf8 recovered source");
        assert_ne!(
            recovered.as_bytes(),
            baked.as_bytes(),
            "chain run must not echo the obfuscated input"
        );
        assert!(
            recovered.contains("chain plusobf wired"),
            "recovered source must contain the original payload; got:\n{recovered}"
        );
    }

    #[test]
    fn blankobf_baked_sample_recovers_through_chain_run() {
        let original: &str = "print('chain blankobf wired')\n";
        let baked: String = crate::obfuscators::blankobf::bake(original);
        let verdict: DetectVerdict = Detector::detect(&PyDeobDetector, &ctx(baked.as_bytes()))
            .expect("blankobf must be detected by the chain detector");
        assert_eq!(verdict.format_tag, "blankobf");
        let a: Artifact = Artifact::new(Rung::Raw, baked.into_bytes(), [0u8; 32]);
        let out: Artifact = PY_DEOB_PASS
            .run(&a)
            .expect("chain run must recover blankobf source");
        let recovered: &str = std::str::from_utf8(&out.envelope).expect("utf8 recovered source");
        assert!(
            recovered.contains("chain blankobf wired"),
            "recovered source must contain the original payload; got:\n{recovered}"
        );
    }

    #[test]
    fn extract_children_emits_recovered_source_and_manifest_sidecar() {
        let original: &str = "print('chain plusobf manifest')\n";
        let baked: String = crate::obfuscators::plusobf::bake(original);
        let a: Artifact = Artifact::new(Rung::Raw, baked.into_bytes(), [0u8; 32]);
        let children: Vec<ChildArtifact> = PY_DEOB_PASS
            .extract_children(&a)
            .expect("extract_children must run for a recovered plusobf sample");

        let source_child: &ChildArtifact = children
            .iter()
            .find(|c: &&ChildArtifact| c.handle.relative_path == CHILD_SOURCE_PATH)
            .expect("recovered source child must be emitted");
        let recovered: &str =
            std::str::from_utf8(&source_child.bytes).expect("utf8 recovered source");
        assert!(
            recovered.contains("chain plusobf manifest"),
            "recovered source child must carry the original payload; got:\n{recovered}"
        );
        assert_eq!(source_child.handle.hint.as_deref(), Some(TERMINAL_HINT));

        let manifest_child: &ChildArtifact = children
            .iter()
            .find(|c: &&ChildArtifact| c.handle.relative_path == CHILD_MANIFEST_PATH)
            .expect("manifest sidecar child must be emitted so auto reaches deob parity");
        assert_eq!(manifest_child.handle.hint.as_deref(), Some(TERMINAL_HINT));
        let manifest: serde_json::Value =
            serde_json::from_slice(&manifest_child.bytes).expect("manifest must be valid json");
        assert_eq!(manifest["schema"], MANIFEST_SCHEMA);
        assert!(
            manifest["peel"].is_object(),
            "manifest must carry the full PeelResult provenance; got:\n{manifest}"
        );
        assert!(
            !manifest["peel"]["steps"].is_null(),
            "manifest peel must expose the peel steps; got:\n{manifest}"
        );
        assert_eq!(manifest["route"], "Deobfuscated");

        let indices: Vec<u32> = children
            .iter()
            .map(|c: &ChildArtifact| c.handle.artifact_index)
            .collect();
        assert_eq!(indices, vec![0u32, 1u32], "child indices must be dense");
    }

    #[test]
    fn extract_children_on_garbage_errors_without_fabricating() {
        let a: Artifact = Artifact::new(Rung::Raw, vec![0x00, 0x01, 0x02, 0x99, 0xff], [0u8; 32]);
        let err: CoreError = PY_DEOB_PASS
            .extract_children(&a)
            .expect_err("garbage must not produce fabricated children");
        assert!(format!("{err}").contains("DR-PYDEOB-0902"));
    }

    #[test]
    fn chain_run_on_garbage_errors_without_fabricating() {
        let a: Artifact = Artifact::new(Rung::Raw, vec![0x00, 0x01, 0x02, 0x99, 0xff], [0u8; 32]);
        let err: CoreError = PY_DEOB_PASS
            .run(&a)
            .expect_err("garbage must not be claimed as recovered");
        assert!(format!("{err}").contains("DR-PYDEOB-0902"));
    }

    fn entry_ids() -> Vec<&'static str> {
        PyDeobDetector.catalog().iter().map(|e| e.id()).collect()
    }
}
