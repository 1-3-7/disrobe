#![cfg(feature = "chain")]
#![allow(clippy::module_name_repetitions)]

use disrobe_core::Artifact;
use disrobe_core::Rung;
use disrobe_core::chain::{
    DetectContext, DetectVerdict, Detector, FAMILY_PACKER_ARCHIVE, OutputKind, Pass,
};
use disrobe_core::error::{CoreError, Result as CoreResult};
use disrobe_core::pass::PassId;

use crate::packers::{
    Detection as PackerDetection, Packer, detect as detect_packers, unpack_with_upx_cli,
};

pub const PASS_ID: PassId = "native.packer-unpack";

const FORMAT_PE_UNPACKED: &str = "pe";

#[derive(Debug)]
pub struct PackerDetector;

impl Detector for PackerDetector {
    #[inline]
    fn id(&self) -> PassId {
        PASS_ID
    }

    fn detect(&self, ctx: &DetectContext<'_>) -> Option<DetectVerdict> {
        let dets: Vec<PackerDetection> = detect_packers(ctx.bytes);
        let pick: PackerDetection = highest_priority(dets)?;
        Some(verdict_for(&pick))
    }
}

#[derive(Debug)]
pub struct PackerPass;

impl Pass for PackerPass {
    #[inline]
    fn id(&self) -> PassId {
        PASS_ID
    }

    #[inline]
    fn detector(&self) -> &'static dyn Detector {
        &PackerDetector
    }

    #[inline]
    fn output_kind(&self, _output: &Artifact) -> OutputKind {
        OutputKind::Bytes {
            format_tag: FORMAT_PE_UNPACKED,
            family: FAMILY_PACKER_ARCHIVE,
        }
    }

    fn run(&self, artifact: &Artifact) -> CoreResult<Artifact> {
        let dets: Vec<PackerDetection> = detect_packers(&artifact.envelope);
        let Some(pick): Option<PackerDetection> = highest_priority(dets) else {
            return Err(CoreError::PassFailure(
                "DR-NAT-0901: native.packer-unpack: no packer signature in artifact".to_string(),
            ));
        };
        match pick.packer {
            Packer::Upx => run_upx(artifact),
            other => Err(CoreError::PassFailure(format!(
                "DR-NAT-0902: native.packer-unpack: {label} detect-only (no Rust unpacker yet)",
                label = other.label(),
            ))),
        }
    }
}

pub static PACKER_PASS: PackerPass = PackerPass;

fn run_upx(artifact: &Artifact) -> CoreResult<Artifact> {
    let mut input_tmp: std::path::PathBuf = std::env::temp_dir();
    input_tmp.push(format!("disrobe-upx-in-{:x}.bin", artifact.root_hash[0]));
    let mut output_tmp: std::path::PathBuf = std::env::temp_dir();
    output_tmp.push(format!("disrobe-upx-out-{:x}.bin", artifact.root_hash[0]));
    std::fs::write(&input_tmp, &artifact.envelope)
        .map_err(|e| CoreError::PassFailure(format!("DR-NAT-0903: write tmp: {e}")))?;
    let _ = std::fs::remove_file(&output_tmp);
    unpack_with_upx_cli(input_tmp.as_path(), output_tmp.as_path())
        .map_err(|e| CoreError::PassFailure(format!("DR-NAT-0904: upx -d failed: {e}")))?;
    let unpacked: Vec<u8> = std::fs::read(&output_tmp)
        .map_err(|e| CoreError::PassFailure(format!("DR-NAT-0905: read upx out: {e}")))?;
    let _ = std::fs::remove_file(&input_tmp);
    let _ = std::fs::remove_file(&output_tmp);
    if unpacked.is_empty() {
        return Err(CoreError::PassFailure(
            "DR-NAT-0906: upx produced empty output".to_string(),
        ));
    }
    Ok(Artifact::new(Rung::Raw, unpacked, artifact.root_hash))
}

fn highest_priority(mut dets: Vec<PackerDetection>) -> Option<PackerDetection> {
    if dets.is_empty() {
        return None;
    }
    dets.sort_by_key(|d: &PackerDetection| priority_rank(d.packer));
    Some(dets.remove(0))
}

const fn priority_rank(p: Packer) -> u8 {
    match p {
        Packer::Upx => 0,
        Packer::Mpress => 1,
        Packer::Petite => 2,
        Packer::AsPack => 3,
        Packer::AsProtect => 4,
        _ => 9,
    }
}

fn verdict_for(d: &PackerDetection) -> DetectVerdict {
    let format_tag: &'static str = match d.packer {
        Packer::Upx => "upx",
        Packer::Mpress => "mpress",
        Packer::Petite => "petite",
        Packer::AsPack => "aspack",
        Packer::AsProtect => "asprotect",
        Packer::Fsg => "fsg",
        Packer::Mew => "mew",
        Packer::PeCompact => "pecompact",
        Packer::PolyCryptor => "polycryptor",
        Packer::Themida => "themida",
        Packer::VmProtect => "vmprotect",
        _ => "native-packer",
    };
    let confidence: f32 = match d.confidence {
        crate::packers::Confidence::High => 0.96,
        crate::packers::Confidence::Medium => 0.80,
        crate::packers::Confidence::Low => 0.60,
    };
    let specificity: u16 = 20;
    DetectVerdict::new(
        PASS_ID,
        format_tag,
        FAMILY_PACKER_ARCHIVE,
        confidence,
        specificity,
        vec!["packer-section-magic"],
        format!(
            "packer={label} note={note}",
            label = d.packer.label(),
            note = d.note
        ),
    )
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn detector_id_is_stable() {
        assert_eq!(PackerDetector.id(), PASS_ID);
    }

    #[test]
    fn detect_upx_marker() {
        let mut buf: Vec<u8> = vec![0u8; 256];
        buf[100..104].copy_from_slice(b"UPX!");
        let ctx: DetectContext<'_> = DetectContext {
            bytes: &buf,
            path_hint: None,
            parent_hint: None,
            depth: 0,
        };
        let v: DetectVerdict = PackerDetector.detect(&ctx).expect("upx detected");
        assert_eq!(v.format_tag, "upx");
        assert!(v.confidence > 0.9);
    }

    #[test]
    fn detect_mpress_marker() {
        let mut buf: Vec<u8> = vec![0u8; 256];
        buf[40..48].copy_from_slice(b".MPRESS1");
        let ctx: DetectContext<'_> = DetectContext {
            bytes: &buf,
            path_hint: None,
            parent_hint: None,
            depth: 0,
        };
        let v: DetectVerdict = PackerDetector.detect(&ctx).expect("mpress detected");
        assert_eq!(v.format_tag, "mpress");
    }

    #[test]
    fn detect_misses_clean_bytes() {
        let buf: Vec<u8> = vec![0x55u8; 1024];
        let ctx: DetectContext<'_> = DetectContext {
            bytes: &buf,
            path_hint: None,
            parent_hint: None,
            depth: 0,
        };
        assert!(PackerDetector.detect(&ctx).is_none());
    }

    #[test]
    fn pass_output_kind_is_bytes_pe() {
        let a: Artifact = Artifact::new(Rung::Raw, vec![], [0u8; 32]);
        let k: OutputKind = PACKER_PASS.output_kind(&a);
        match k {
            OutputKind::Bytes { format_tag, family } => {
                assert_eq!(format_tag, FORMAT_PE_UNPACKED);
                assert_eq!(family, FAMILY_PACKER_ARCHIVE);
            }
            _ => panic!("expected Bytes"),
        }
    }

    #[test]
    fn upx_priority_above_mpress() {
        assert!(priority_rank(Packer::Upx) < priority_rank(Packer::Mpress));
    }

    #[test]
    fn run_rejects_no_packer() {
        let a: Artifact = Artifact::new(Rung::Raw, vec![0u8; 64], [0u8; 32]);
        let r: CoreResult<Artifact> = PACKER_PASS.run(&a);
        assert!(r.is_err());
    }
}
