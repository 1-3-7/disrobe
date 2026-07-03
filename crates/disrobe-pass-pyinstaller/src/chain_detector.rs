#![cfg(feature = "chain")]
#![allow(clippy::module_name_repetitions)]
use disrobe_core::Artifact;
use disrobe_core::Rung;
use disrobe_core::chain::detection::TERMINAL_HINT;
use disrobe_core::chain::{
    ChildArtifact, ChildHandle, DetectContext, DetectVerdict, Detector, FAMILY_PACKER_ARCHIVE,
    OutputKind, Pass,
};
use disrobe_core::error::{CoreError, Result as CoreResult};
use disrobe_core::pass::PassId;

use crate::cookie::{Cookie, CookieVariant, find_cookie};
use crate::extract::{ExtractOutput, ExtractedEntry, extract_archive};
use crate::native_surface::{NativeArtifact, NativeSurfaceStats, surface_native_entry};
use crate::toc::{EntryType, classify_native_image};

pub const PASS_ID: PassId = "pyinstaller.extract";

const TAG_PRE21: &str = "pyinstaller-carchive-pre2.1";
const TAG_V21_PLUS: &str = "pyinstaller-carchive-2.1+";

#[derive(Debug)]
pub struct PyInstallerDetector;

impl Detector for PyInstallerDetector {
    #[inline]
    fn id(&self) -> PassId {
        PASS_ID
    }

    fn detect(&self, ctx: &DetectContext<'_>) -> Option<DetectVerdict> {
        let cookie: Cookie = find_cookie(ctx.bytes).ok()?;
        if cookie.python_major == 0 {
            return None;
        }
        Some(verdict_for(&cookie))
    }
}

#[derive(Debug)]
pub struct PyInstallerPass;

impl Pass for PyInstallerPass {
    #[inline]
    fn id(&self) -> PassId {
        PASS_ID
    }

    #[inline]
    fn detector(&self) -> &'static dyn Detector {
        &PyInstallerDetector
    }

    #[inline]
    fn output_kind(&self, _output: &Artifact) -> OutputKind {
        OutputKind::Mixed {
            children: Vec::new(),
        }
    }

    fn run(&self, artifact: &Artifact) -> CoreResult<Artifact> {
        let bytes: &[u8] = artifact.envelope.as_slice();
        let extracted: ExtractOutput =
            extract_archive(bytes).map_err(|e: crate::error::Error| {
                CoreError::PassFailure(format!("DR-PYINS-0902: pyinstaller extract: {e}"))
            })?;
        if extracted.entries.is_empty() {
            return Err(CoreError::PassFailure(
                "DR-PYINS-0903: pyinstaller.extract: archive has no entries".to_string(),
            ));
        }
        let manifest: String = render_manifest(&extracted);
        Ok(Artifact::new(
            Rung::Disasm,
            manifest.into_bytes(),
            artifact.root_hash,
        ))
    }

    fn extract_children(&self, input: &Artifact) -> CoreResult<Vec<ChildArtifact>> {
        let bytes: &[u8] = input.envelope.as_slice();
        let extracted: ExtractOutput =
            extract_archive(bytes).map_err(|e: crate::error::Error| {
                CoreError::PassFailure(format!("DR-PYINS-0904: pyinstaller extract children: {e}"))
            })?;
        let mut children: Vec<ChildArtifact> = Vec::with_capacity(extracted.entries.len());
        let mut native_stats: NativeSurfaceStats = NativeSurfaceStats::default();
        for entry in &extracted.entries {
            if child_can_chain(entry) {
                let index: u32 = child_index(children.len());
                children.push(ChildArtifact {
                    handle: ChildHandle {
                        artifact_index: index,
                        relative_path: entry.toc.name.clone(),
                        hint: Some("interpreter-bytecode".to_string()),
                    },
                    bytes: entry.data.clone(),
                });
            } else if native_can_surface(entry) {
                let (artifacts, stats): (Vec<NativeArtifact>, NativeSurfaceStats) =
                    surface_native_entry(&entry.toc.name, &entry.data);
                native_stats.accumulate(stats);
                for artifact in artifacts {
                    let index: u32 = child_index(children.len());
                    children.push(ChildArtifact {
                        handle: ChildHandle {
                            artifact_index: index,
                            relative_path: artifact.relative_path,
                            hint: Some(TERMINAL_HINT.to_string()),
                        },
                        bytes: artifact.bytes,
                    });
                }
            }
        }
        if native_stats.modules_disassembled > 0
            && let Ok(json) = serde_json::to_vec_pretty(&native_recovery_manifest(&native_stats))
        {
            let index: u32 = child_index(children.len());
            children.push(ChildArtifact {
                handle: ChildHandle {
                    artifact_index: index,
                    relative_path: "native/recovery-manifest.json".to_string(),
                    hint: Some(TERMINAL_HINT.to_string()),
                },
                bytes: json,
            });
        }
        Ok(children)
    }
}

fn native_recovery_manifest(stats: &NativeSurfaceStats) -> serde_json::Value {
    serde_json::json!({
        "schema": "disrobe.pyinstaller.native-recovery/v1",
        "outputs": {
            "native/*.asm": {
                "what": "x86 disassembly of each bundled compiled extension .text",
                "modules": stats.modules_disassembled,
                "instructions": stats.instructions,
                "functions": stats.functions,
            },
            "native/*.capabilities.json": { "what": "behavioral capability inventory of each bundled extension" },
            "native/*.recon.json": { "what": "secrets/endpoints/IOC findings carved from each bundled extension" }
        }
    })
}

const fn child_can_chain(entry: &ExtractedEntry) -> bool {
    entry.toc.entry_type.is_pyc_carrier() && !entry.data.is_empty()
}

const MAX_NATIVE_SURFACE_BYTES: usize = 96 * 1024 * 1024;

fn native_can_surface(entry: &ExtractedEntry) -> bool {
    entry.toc.entry_type == EntryType::Binary
        && !entry.data.is_empty()
        && entry.data.len() <= MAX_NATIVE_SURFACE_BYTES
        && is_native_image(&entry.data)
}

fn is_native_image(bytes: &[u8]) -> bool {
    classify_native_image(bytes).is_some()
}

pub static PYINSTALLER_PASS: PyInstallerPass = PyInstallerPass;

fn child_index(index: usize) -> u32 {
    u32::try_from(index).map_or(u32::MAX, |value: u32| value)
}

fn render_manifest(out: &ExtractOutput) -> String {
    let mut s: String = String::with_capacity(manifest_capacity(out.entries.len()));
    s.push_str("pyinstaller.extract\n");
    s.push_str("cookie py=");
    s.push_str(&out.cookie.python_major.to_string());
    s.push('.');
    s.push_str(&out.cookie.python_minor.to_string());
    s.push_str(" entries=");
    s.push_str(&out.entries.len().to_string());
    s.push('\n');
    for entry in &out.entries {
        let kind: String = format!("{:?}", entry.toc.entry_type);
        s.push_str(&entry.toc.name);
        s.push_str(" type=");
        s.push_str(&kind);
        s.push_str(" bytes=");
        s.push_str(&entry.data.len().to_string());
        s.push('\n');
    }
    s
}

const fn manifest_capacity(entries: usize) -> usize {
    64usize.saturating_add(entries.saturating_mul(64usize))
}

fn verdict_for(c: &Cookie) -> DetectVerdict {
    let tag: &'static str = match c.variant {
        CookieVariant::Pre21 => TAG_PRE21,
        CookieVariant::V21Plus => TAG_V21_PLUS,
    };
    DetectVerdict::new(
        PASS_ID,
        tag,
        FAMILY_PACKER_ARCHIVE,
        0.97,
        15,
        vec!["MEI-cookie"],
        format!(
            "pyinstaller cookie py={maj}.{min} variant={tag}",
            maj = c.python_major,
            min = c.python_minor,
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

    #[test]
    fn detector_id_is_stable() {
        assert_eq!(PyInstallerDetector.id(), PASS_ID);
    }

    #[test]
    fn detect_misses_random_bytes() {
        let bytes: Vec<u8> = vec![0u8; 256];
        assert!(PyInstallerDetector.detect(&ctx(&bytes)).is_none());
    }

    #[test]
    fn pass_output_kind_is_mixed() {
        let a: Artifact = Artifact::new(Rung::Raw, vec![], [0u8; 32]);
        match PYINSTALLER_PASS.output_kind(&a) {
            OutputKind::Mixed { children } => assert!(children.is_empty()),
            _ => panic!("expected Mixed"),
        }
    }

    #[test]
    fn manifest_capacity_saturates() {
        assert_eq!(manifest_capacity(0usize), 64usize);
        assert_eq!(manifest_capacity(usize::MAX), usize::MAX);
    }

    #[test]
    fn child_index_saturates() {
        assert_eq!(child_index(7usize), 7u32);
        assert_eq!(child_index(usize::MAX), u32::MAX);
    }

    #[test]
    fn pass_run_rejects_non_pyinstaller_bytes() {
        let a: Artifact = Artifact::new(Rung::Raw, vec![0u8; 64], [0u8; 32]);
        let err: CoreError = PYINSTALLER_PASS.run(&a).expect_err("must reject");
        assert!(format!("{err}").contains("DR-PYINS-0902"));
    }

    fn gauntlet_fixture() -> Option<Vec<u8>> {
        let path: std::path::PathBuf = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("corpus")
            .join("python")
            .join("freezers")
            .join("pyinstaller")
            .join("gauntlet")
            .join("hello.exe");
        std::fs::read(&path).ok()
    }

    static GAUNTLET_CHILDREN: std::sync::OnceLock<Option<Vec<ChildArtifact>>> =
        std::sync::OnceLock::new();

    fn gauntlet_children() -> Option<&'static [ChildArtifact]> {
        GAUNTLET_CHILDREN
            .get_or_init(|| {
                let Some(bytes): Option<Vec<u8>> = gauntlet_fixture() else {
                    eprintln!("SKIP: pyinstaller gauntlet fixture missing");
                    return None;
                };
                let a: Artifact = Artifact::new(Rung::Raw, bytes, [0u8; 32]);
                Some(
                    PYINSTALLER_PASS
                        .extract_children(&a)
                        .expect("pyinstaller children extraction must succeed"),
                )
            })
            .as_deref()
    }

    #[test]
    fn extract_children_fans_out_unpacked_pyz_modules_as_bytecode() {
        let Some(children): Option<&[ChildArtifact]> = gauntlet_children() else {
            return;
        };
        let pyz_children: Vec<&ChildArtifact> = children
            .iter()
            .filter(|c: &&ChildArtifact| c.handle.relative_path.starts_with("PYZ.pyz_extracted/"))
            .collect();
        assert!(
            pyz_children.len() >= 20,
            "the unpacked PYZ modules must be fanned out as chain children so auto routes them to py-decompile; got {}",
            pyz_children.len(),
        );
        for child in children
            .iter()
            .filter(|c: &&ChildArtifact| !c.handle.relative_path.starts_with("native/"))
        {
            assert_eq!(
                child.handle.hint.as_deref(),
                Some("interpreter-bytecode"),
                "every pyc child must be hinted as interpreter-bytecode so py.decompile claims it",
            );
        }
        let future_child: &ChildArtifact = pyz_children
            .iter()
            .copied()
            .find(|c: &&ChildArtifact| c.handle.relative_path == "PYZ.pyz_extracted/__future__.pyc")
            .expect("the unpacked __future__ module must be a chain child");
        assert!(
            future_child.bytes.len() > 16 && future_child.bytes[..4] == [0xCB, 0x0D, 0x0D, 0x0A],
            "the fanned-out PYZ module must carry a reconstructed 3.12 pyc header",
        );
    }

    #[test]
    fn extract_children_surfaces_native_disasm_for_bundled_extension() {
        let Some(children): Option<&[ChildArtifact]> = gauntlet_children() else {
            return;
        };

        let asm_children: Vec<&ChildArtifact> = children
            .iter()
            .filter(|c: &&ChildArtifact| {
                c.handle.relative_path.starts_with("native/")
                    && std::path::Path::new(&c.handle.relative_path)
                        .extension()
                        .is_some_and(|ext: &std::ffi::OsStr| ext.eq_ignore_ascii_case("asm"))
            })
            .collect();
        assert!(
            !asm_children.is_empty(),
            "the bundled compiled extension modules (.pyd/.dll) must be routed through native disasm so auto surfaces native code",
        );

        let has_real_x86: bool = asm_children.iter().any(|c: &&ChildArtifact| {
            let asm: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&c.bytes);
            ["mov", "push", "call", "ret", "lea", "jmp", "pop", "test"]
                .iter()
                .any(|m: &&str| asm.contains(*m))
        });
        assert!(
            has_real_x86,
            "the surfaced native disasm must contain real x86 mnemonics, not a placeholder",
        );

        let manifest: &ChildArtifact = children
            .iter()
            .find(|c: &&ChildArtifact| c.handle.relative_path == "native/recovery-manifest.json")
            .expect("a native recovery manifest must summarize the surfaced disasm");
        let parsed: serde_json::Value =
            serde_json::from_slice(&manifest.bytes).expect("manifest must be valid json");
        let instructions: u64 = parsed["outputs"]["native/*.asm"]["instructions"]
            .as_u64()
            .expect("instruction count must be present");
        assert!(
            instructions > 50,
            "expected real disassembly across bundled extensions, got {instructions} instructions",
        );

        for child in &asm_children {
            assert_eq!(
                child.handle.hint.as_deref(),
                Some(TERMINAL_HINT),
                "native disasm children are terminal artifacts, not re-chained inputs",
            );
        }
    }
}
