#![cfg(feature = "chain")]
#![allow(clippy::module_name_repetitions)]

use disrobe_core::Artifact;
use disrobe_core::Rung;
use disrobe_core::chain::{
    DetectContext, DetectVerdict, Detector, FAMILY_SOURCE, OutputKind, Pass,
};
use disrobe_core::error::{CoreError, Result as CoreResult};
use disrobe_core::pass::PassId;
use disrobe_core::provenance::Language;

use serde::Serialize;

use crate::detect::{Detection, Dialect, Family, detect as detect_shell};
use crate::format_wire::format_identity;

pub const PASS_ID: PassId = "shell.deob";

const TAG_POWERSHELL: &str = "shell-powershell";
const TAG_BASH: &str = "shell-bash";
const TAG_DASH: &str = "shell-dash";
const TAG_KSH: &str = "shell-ksh";
const TAG_ZSH: &str = "shell-zsh";
const TAG_BATCH: &str = "shell-batch";
const TAG_VBA: &str = "shell-vba";
const TAG_VBS: &str = "shell-vbs";
const TAG_WSH: &str = "shell-wsh";

#[derive(Debug)]
pub struct ShellDetector;

impl Detector for ShellDetector {
    #[inline]
    fn id(&self) -> PassId {
        PASS_ID
    }

    fn detect(&self, ctx: &DetectContext<'_>) -> Option<DetectVerdict> {
        let detection: Detection = detect_shell(ctx.bytes);
        verdict_for(&detection)
    }
}

#[derive(Debug)]
pub struct ShellPass;

impl Pass for ShellPass {
    #[inline]
    fn id(&self) -> PassId {
        PASS_ID
    }

    #[inline]
    fn detector(&self) -> &'static dyn Detector {
        &ShellDetector
    }

    #[inline]
    fn output_kind(&self, _output: &Artifact) -> OutputKind {
        OutputKind::Source {
            language: Language::Bash,
            formatted: true,
        }
    }

    fn run(&self, artifact: &Artifact) -> CoreResult<Artifact> {
        let bytes: &[u8] = artifact.envelope.as_slice();
        let detection: Detection = detect_shell(bytes);
        if verdict_for(&detection).is_none() {
            return Err(CoreError::PassFailure(
                "DR-SHELL-0902: shell.deob: input dialect unknown or below confidence threshold"
                    .to_string(),
            ));
        }
        let source_text: String = std::str::from_utf8(bytes).map_or_else(
            |_| format!("/* non-utf8 shell payload of {} bytes */", bytes.len()),
            |s: &str| format_identity(s),
        );
        let extract: ShellExtract = ShellExtract {
            dialect: detection.dialect,
            family: detection.family,
            confidence: detection.confidence,
            source: source_text,
        };
        let payload: Vec<u8> =
            serde_json::to_vec_pretty(&extract).map_err(|e: serde_json::Error| {
                CoreError::PassFailure(format!("DR-SHELL-0903: serialize shell extract: {e}"))
            })?;
        Ok(Artifact::new(Rung::Surface, payload, artifact.root_hash))
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ShellExtract {
    pub dialect: Dialect,
    pub family: Family,
    pub confidence: f32,
    pub source: String,
}

pub static SHELL_PASS: ShellPass = ShellPass;

fn verdict_for(d: &Detection) -> Option<DetectVerdict> {
    if d.confidence < 0.5 {
        return None;
    }
    let (tag, marker): (&'static str, &'static str) = match d.dialect {
        Dialect::PowerShell => (TAG_POWERSHELL, "powershell-dialect"),
        Dialect::Bash => (TAG_BASH, "bash-dialect"),
        Dialect::Dash => (TAG_DASH, "dash-dialect"),
        Dialect::Ksh => (TAG_KSH, "ksh-dialect"),
        Dialect::Zsh => (TAG_ZSH, "zsh-dialect"),
        Dialect::Batch => (TAG_BATCH, "batch-dialect"),
        Dialect::Vba => (TAG_VBA, "vba-dialect"),
        Dialect::Vbs => (TAG_VBS, "vbs-dialect"),
        Dialect::Wsh => (TAG_WSH, "wsh-dialect"),
        Dialect::Unknown => return None,
    };
    Some(DetectVerdict::new(
        PASS_ID,
        tag,
        FAMILY_SOURCE,
        d.confidence,
        35,
        vec![marker],
        format!(
            "shell dialect={dialect:?} family={family:?}",
            dialect = d.dialect,
            family = d.family,
        ),
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
        assert_eq!(ShellDetector.id(), PASS_ID);
    }

    #[test]
    fn detect_bash_shebang() {
        let bytes: &[u8] = b"#!/bin/bash\necho hello\n";
        let v: DetectVerdict = ShellDetector.detect(&ctx(bytes)).expect("must detect");
        assert_eq!(v.format_tag, TAG_BASH);
    }

    #[test]
    fn detect_misses_empty() {
        assert!(ShellDetector.detect(&ctx(b"")).is_none());
    }

    #[test]
    fn pass_output_kind_is_shell_source() {
        let a: Artifact = Artifact::new(Rung::Raw, vec![], [0u8; 32]);
        match SHELL_PASS.output_kind(&a) {
            OutputKind::Source {
                language,
                formatted,
            } => {
                assert_eq!(language, Language::Bash);
                assert!(formatted);
            }
            _ => panic!("expected Source"),
        }
    }

    #[test]
    fn pass_run_extracts_bash_source_with_metadata() {
        let bytes: Vec<u8> = b"#!/bin/bash\necho hello\n".to_vec();
        let a: Artifact = Artifact::new(Rung::Raw, bytes, [0u8; 32]);
        let out: Artifact = SHELL_PASS.run(&a).expect("classify must succeed");
        assert_eq!(out.rung, Rung::Surface);
        let s: &str = std::str::from_utf8(&out.envelope).expect("utf8 json");
        assert!(s.contains("\"Bash\""));
        assert!(s.contains("echo hello"));
    }

    #[test]
    fn pass_run_rejects_unknown_bytes() {
        let a: Artifact = Artifact::new(Rung::Raw, vec![0u8; 16], [0u8; 32]);
        let err: CoreError = SHELL_PASS.run(&a).expect_err("must reject");
        assert!(format!("{err}").contains("DR-SHELL-0902"));
    }
}
