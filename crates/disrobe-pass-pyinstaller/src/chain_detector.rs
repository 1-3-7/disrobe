#![cfg(feature = "chain")]
#![allow(clippy::module_name_repetitions)]

use disrobe_core::Artifact;
use disrobe_core::Rung;
use disrobe_core::chain::{
    DetectContext, DetectVerdict, Detector, FAMILY_PACKER_ARCHIVE, OutputKind, Pass,
};
use disrobe_core::error::{CoreError, Result as CoreResult};
use disrobe_core::pass::PassId;

use crate::cookie::{Cookie, CookieVariant, find_cookie};
use crate::extract::{ExtractOutput, extract_archive};

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
}

pub static PYINSTALLER_PASS: PyInstallerPass = PyInstallerPass;

fn render_manifest(out: &ExtractOutput) -> String {
    use std::fmt::Write as _;
    let mut s: String = String::with_capacity(64 + 64 * out.entries.len());
    s.push_str("pyinstaller.extract\n");
    let _ = writeln!(
        s,
        "cookie py={maj}.{min} entries={n}",
        maj = out.cookie.python_major,
        min = out.cookie.python_minor,
        n = out.entries.len(),
    );
    for entry in &out.entries {
        let _ = writeln!(
            s,
            "{name} type={kind:?} bytes={sz}",
            name = entry.toc.name,
            kind = entry.toc.entry_type,
            sz = entry.data.len(),
        );
    }
    s
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
        0.96,
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
    fn pass_run_rejects_non_pyinstaller_bytes() {
        let a: Artifact = Artifact::new(Rung::Raw, vec![0u8; 64], [0u8; 32]);
        let err: CoreError = PYINSTALLER_PASS.run(&a).expect_err("must reject");
        assert!(format!("{err}").contains("DR-PYINS-0902"));
    }
}
