#![cfg(feature = "chain")]
#![allow(clippy::module_name_repetitions)]
use std::io::Cursor;

use disrobe_core::Artifact;
use disrobe_core::Rung;
use disrobe_core::chain::detection::{ChildArtifact, ChildHandle};
use disrobe_core::chain::{
    DetectContext, DetectVerdict, Detector, FAMILY_PACKER_ARCHIVE, OutputKind, Pass,
};
use disrobe_core::error::{CoreError, Result as CoreResult};
use disrobe_core::pass::PassId;

use crate::common::manifest::FreezerKind;
use crate::common::zip_tail::{ZipTailInfo, locate};
use crate::detect::{Detection, detect_bytes};

pub const PASS_ID: PassId = "pyfreeze.extract";

const TAG_CXFREEZE: &str = "pyfreeze-cxfreeze";
const TAG_PY2EXE: &str = "pyfreeze-py2exe";
const TAG_PYOXIDIZER: &str = "pyfreeze-pyoxidizer";
const TAG_PEX: &str = "pyfreeze-pex";
const TAG_SHIV: &str = "pyfreeze-shiv";
const TAG_ZIPAPP: &str = "pyfreeze-zipapp";
const TAG_PYC: &str = "pyfreeze-pyc";
const TAG_BRIEFCASE: &str = "pyfreeze-briefcase";
const TAG_BBFREEZE: &str = "pyfreeze-bbfreeze";

const MANIFEST_BANNER: &str = "pyfreeze.extract";
const MAX_ZIP_ENTRIES: usize = 65_536;
const MAX_ENTRY_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Debug)]
pub struct PyfreezeDetector;

impl Detector for PyfreezeDetector {
    #[inline]
    fn id(&self) -> PassId {
        PASS_ID
    }

    fn detect(&self, ctx: &DetectContext<'_>) -> Option<DetectVerdict> {
        let detection: Detection = detect_bytes(ctx.bytes, None);
        verdict_for(&detection)
    }
}

#[derive(Debug)]
pub struct PyfreezePass;

impl Pass for PyfreezePass {
    #[inline]
    fn id(&self) -> PassId {
        PASS_ID
    }

    #[inline]
    fn detector(&self) -> &'static dyn Detector {
        &PyfreezeDetector
    }

    #[inline]
    fn output_kind(&self, _output: &Artifact) -> OutputKind {
        OutputKind::Mixed {
            children: Vec::new(),
        }
    }

    fn run(&self, artifact: &Artifact) -> CoreResult<Artifact> {
        let bytes: &[u8] = artifact.envelope.as_slice();
        let detection: Detection = detect_bytes(bytes, None);
        if verdict_for(&detection).is_none() {
            return Err(CoreError::PassFailure(
                "DR-PYFRZ-0902: pyfreeze.extract: input is not a recognized python freezer container"
                    .to_string(),
            ));
        }
        if matches!(detection.kind, FreezerKind::Unknown) {
            return Err(CoreError::PassFailure(
                "DR-PYFRZ-0903: pyfreeze.extract: freezer kind unknown".to_string(),
            ));
        }
        let members: Vec<ZipMember> = carve_zip_members(bytes);
        let manifest: String = render_manifest(detection.kind, &members);
        Ok(Artifact::new(
            Rung::Disasm,
            manifest.into_bytes(),
            artifact.root_hash,
        ))
    }

    fn extract_children(&self, input: &Artifact) -> CoreResult<Vec<ChildArtifact>> {
        let bytes: &[u8] = input.envelope.as_slice();
        let detection: Detection = detect_bytes(bytes, None);
        if matches!(detection.kind, FreezerKind::Unknown) {
            return Ok(Vec::new());
        }
        if matches!(detection.kind, FreezerKind::Pyc) {
            return Ok(vec![ChildArtifact {
                handle: ChildHandle {
                    artifact_index: 0,
                    relative_path: "module.pyc".to_string(),
                    hint: Some("python-bytecode".to_string()),
                },
                bytes: bytes.to_vec(),
            }]);
        }
        let members: Vec<ZipMember> = carve_zip_members(bytes);
        let children: Vec<ChildArtifact> = members
            .into_iter()
            .enumerate()
            .map(|(index, member): (usize, ZipMember)| ChildArtifact {
                handle: ChildHandle {
                    artifact_index: u32::try_from(index).unwrap_or(u32::MAX),
                    relative_path: member.name,
                    hint: Some("python-freezer-entry".to_string()),
                },
                bytes: member.data,
            })
            .collect();
        Ok(children)
    }
}

pub static PYFREEZE_PASS: PyfreezePass = PyfreezePass;

#[derive(Debug)]
struct ZipMember {
    name: String,
    data: Vec<u8>,
}

fn carve_zip_members(bytes: &[u8]) -> Vec<ZipMember> {
    let info: ZipTailInfo = match locate(bytes) {
        Ok(i) => i,
        Err(_) => return Vec::new(),
    };
    let zip_slice: &[u8] = match bytes.get(info.archive_start_offset..) {
        Some(s) => s,
        None => return Vec::new(),
    };
    let mut archive: zip::ZipArchive<Cursor<&[u8]>> =
        match zip::ZipArchive::new(Cursor::new(zip_slice)) {
            Ok(a) => a,
            Err(_) => return Vec::new(),
        };
    let count: usize = archive.len().min(MAX_ZIP_ENTRIES);
    let mut out: Vec<ZipMember> = Vec::with_capacity(count);
    for i in 0..count {
        let mut file: zip::read::ZipFile<'_> = match archive.by_index(i) {
            Ok(f) => f,
            Err(_) => continue,
        };
        if file.is_dir() || file.size() > MAX_ENTRY_BYTES {
            continue;
        }
        let Some(name): Option<String> = sanitize_member(file.name()) else {
            continue;
        };
        let declared_size: u64 = file.size();
        let Ok(data): std::io::Result<Vec<u8>> = crate::common::read_bounded::read_to_vec_limited(
            &mut file,
            declared_size,
            MAX_ENTRY_BYTES,
        ) else {
            continue;
        };
        if data.is_empty() {
            continue;
        }
        out.push(ZipMember { name, data });
    }
    out
}

fn sanitize_member(name: &str) -> Option<String> {
    let trimmed: String = name.replace('\\', "/");
    if trimmed.split('/').any(|seg: &str| seg == "..") {
        return None;
    }
    let cleaned: String = trimmed
        .split('/')
        .filter(|seg: &&str| !seg.is_empty() && *seg != ".")
        .collect::<Vec<&str>>()
        .join("/");
    if cleaned.is_empty() {
        return None;
    }
    Some(cleaned)
}

fn render_manifest(kind: FreezerKind, members: &[ZipMember]) -> String {
    let mut out: String = String::with_capacity(64 + 48 * members.len());
    let header: String = format!(
        "{MANIFEST_BANNER} kind={kind:?} members={n}\n",
        n = members.len()
    );
    out.push_str(&header);
    if members.is_empty() {
        out.push_str(
            "no in-memory trailing-zip members carved; payload is stored in a resource or sibling tree\n",
        );
        return out;
    }
    for member in members {
        let line: String = format!(
            "{name} ({size} bytes)\n",
            name = member.name,
            size = member.data.len()
        );
        out.push_str(&line);
    }
    out
}

fn verdict_for(d: &Detection) -> Option<DetectVerdict> {
    if d.confidence < 0.5 {
        return None;
    }
    let (tag, marker): (&'static str, &'static str) = match d.kind {
        FreezerKind::CxFreeze => (TAG_CXFREEZE, "cxfreeze-layout"),
        FreezerKind::Py2exe => (TAG_PY2EXE, "PYTHONSCRIPT-resource"),
        FreezerKind::PyOxidizer => (TAG_PYOXIDIZER, "pyoxidizer-symbol"),
        FreezerKind::Pex => (TAG_PEX, "PEX-INFO-marker"),
        FreezerKind::Shiv => (TAG_SHIV, "_bootstrap-marker"),
        FreezerKind::Zipapp => (TAG_ZIPAPP, "__main__-marker"),
        FreezerKind::Pyc => (TAG_PYC, "pyc-magic"),
        FreezerKind::Briefcase => (TAG_BRIEFCASE, "briefcase-layout"),
        FreezerKind::Bbfreeze => (TAG_BBFREEZE, "bbfreeze-layout"),
        FreezerKind::Unknown => return None,
    };
    let explain: String = if d.reasons.is_empty() {
        format!("pyfreeze kind={tag}")
    } else {
        d.reasons.join("; ")
    };
    Some(DetectVerdict::new(
        PASS_ID,
        tag,
        FAMILY_PACKER_ARCHIVE,
        d.confidence,
        22,
        vec![marker],
        explain,
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
        assert_eq!(PyfreezeDetector.id(), PASS_ID);
    }

    #[test]
    fn detect_misses_random_bytes() {
        let bytes: Vec<u8> = vec![0u8; 32];
        assert!(PyfreezeDetector.detect(&ctx(&bytes)).is_none());
    }

    #[test]
    fn detect_verdict_explain_carries_the_resolved_python_version() {
        let magic: u32 = disrobe_py_marshal::magic_for(disrobe_py_marshal::PyVersion::PY315)
            .expect("known magic");
        let mut bytes: Vec<u8> = magic.to_le_bytes().to_vec();
        bytes.resize(16, 0);
        let verdict: DetectVerdict = PyfreezeDetector
            .detect(&ctx(&bytes))
            .expect("pyc magic must detect");
        assert_eq!(verdict.format_tag, TAG_PYC);
        assert!(
            verdict.explain.contains("3.15"),
            "the durably-serialized DetectorPickDoc.explain must carry the resolved Python version, not a generic template; got {:?}",
            verdict.explain,
        );
    }

    #[test]
    fn pyoxidizer_verdict_preserves_serialized_marker() {
        let bytes: &[u8] = b"PyOxidizer\0pyembed\0python312.dll";
        let verdict: DetectVerdict = PyfreezeDetector
            .detect(&ctx(bytes))
            .expect("PyOxidizer markers must detect");
        assert_eq!(verdict.format_tag, TAG_PYOXIDIZER);
        assert_eq!(verdict.markers, vec!["pyoxidizer-symbol"]);
    }

    #[test]
    fn pass_output_kind_is_mixed() {
        let a: Artifact = Artifact::new(Rung::Raw, vec![], [0u8; 32]);
        match PYFREEZE_PASS.output_kind(&a) {
            OutputKind::Mixed { children } => assert!(children.is_empty()),
            _ => panic!("expected Mixed"),
        }
    }

    #[test]
    fn pass_run_rejects_random_bytes() {
        let a: Artifact = Artifact::new(Rung::Raw, vec![0u8; 16], [0u8; 32]);
        let err: CoreError = PYFREEZE_PASS.run(&a).expect_err("must reject");
        let msg: String = format!("{err}");
        assert!(msg.contains("DR-PYFRZ-0902") || msg.contains("DR-PYFRZ-0903"));
    }

    fn freezer_fixture(rel: &str) -> Option<Vec<u8>> {
        let path: std::path::PathBuf = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("corpus")
            .join("python")
            .join("freezers")
            .join(rel);
        let bytes: Option<Vec<u8>> = std::fs::read(&path).ok();
        if bytes.is_none() {
            eprintln!("SKIP: freezer fixture missing at {}", path.display());
        }
        bytes
    }

    #[test]
    fn pass_run_emits_manifest_not_input_unchanged() {
        let Some(bytes): Option<Vec<u8>> = freezer_fixture("shiv/hello.pyz") else {
            return;
        };
        let original: Vec<u8> = bytes.clone();
        let a: Artifact = Artifact::new(Rung::Raw, bytes, [0u8; 32]);
        let out: Artifact = PYFREEZE_PASS.run(&a).expect("shiv run must succeed");
        assert_ne!(
            out.envelope, original,
            "run must transform the container, not return the input unchanged",
        );
        let manifest: &str = std::str::from_utf8(&out.envelope).expect("utf8 manifest");
        assert!(
            manifest.starts_with(MANIFEST_BANNER),
            "run must emit the readable manifest; got {:?}",
            manifest.chars().take(160).collect::<String>(),
        );
        assert!(
            manifest.contains("members=") && manifest.contains("bytes)"),
            "shiv manifest must list the carved zip members; got first 300: {:?}",
            manifest.chars().take(300).collect::<String>(),
        );
    }

    #[test]
    fn extract_children_carves_real_shiv_members() {
        let Some(bytes): Option<Vec<u8>> = freezer_fixture("shiv/hello.pyz") else {
            return;
        };
        let a: Artifact = Artifact::new(Rung::Raw, bytes, [0u8; 32]);
        let children: Vec<ChildArtifact> = PYFREEZE_PASS
            .extract_children(&a)
            .expect("shiv children extraction must succeed");
        assert!(
            !children.is_empty(),
            "shiv must surface its embedded zip members as real children",
        );
        let any_bootstrap: bool = children
            .iter()
            .any(|c: &ChildArtifact| c.handle.relative_path.starts_with("_bootstrap/"));
        assert!(
            any_bootstrap,
            "shiv extraction must include the _bootstrap members; got {:?}",
            children
                .iter()
                .map(|c: &ChildArtifact| c.handle.relative_path.as_str())
                .take(8)
                .collect::<Vec<&str>>(),
        );
        let all_nonempty: bool = children.iter().all(|c: &ChildArtifact| !c.bytes.is_empty());
        assert!(
            all_nonempty,
            "every carved member must carry real recovered bytes"
        );
    }
}
