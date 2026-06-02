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
    Detection as PackerDetection, FsgUnpackOutput, MewUnpackOutput, MpressUnpackOutput,
    NspackEmulatedReport, Packer, PetitePhase2EmulatedOutput, UnpackerStatus, UpxUnpackOutput,
    detect as detect_packers, unpack_fsg, unpack_mew, unpack_mpress, unpack_nspack_emulated,
    unpack_petite_phase2_emulated, unpack_upx,
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
        dispatch_unpack(pick.packer, artifact)
    }
}

pub static PACKER_PASS: PackerPass = PackerPass;

/// Route a detected packer to its real unpacker, keyed by the single source of
/// truth [`Packer::unpacker_status`]. Every packer marked
/// [`UnpackerStatus::Implemented`] has a wired pure-Rust unpacker reachable from
/// here (so `disrobe auto` / `disrobe native` actually unpacks); the remaining
/// statuses surface an honest, actionable error rather than a fake success.
fn dispatch_unpack(packer: Packer, artifact: &Artifact) -> CoreResult<Artifact> {
    match packer.unpacker_status() {
        UnpackerStatus::Implemented => run_rust_unpacker(packer, artifact),
        UnpackerStatus::StubEvalPending => Err(CoreError::PassFailure(format!(
            "DR-NAT-0902: native.packer-unpack: {label} detected; Rust unpacker stub-eval pending \
             (detection is production-grade, byte recovery not yet wired)",
            label = packer.label(),
        ))),
        UnpackerStatus::DetectOnly => Err(CoreError::PassFailure(format!(
            "DR-NAT-0907: native.packer-unpack: {label} is detect-only (crypter/loader family \
             without a deterministic unpack path)",
            label = packer.label(),
        ))),
        UnpackerStatus::GreyZoneDetectOnly => Err(CoreError::PassFailure(format!(
            "DR-NAT-0908: native.packer-unpack: {label} is a grey-zone protector; detection-only \
             per docs/legal stance (no unpack)",
            label = packer.label(),
        ))),
        UnpackerStatus::GreyZoneDetectAndCarve => Err(CoreError::PassFailure(format!(
            "DR-NAT-0909: native.packer-unpack: {label} is a grey-zone protector; \
             detect-and-carve only, original code is virtualized and not recoverable by unpacking",
            label = packer.label(),
        ))),
    }
}

/// Invoke the concrete pure-Rust unpacker for an [`UnpackerStatus::Implemented`]
/// packer and wrap the recovered bytes in a fresh [`Rung::Raw`] artifact.
fn run_rust_unpacker(packer: Packer, artifact: &Artifact) -> CoreResult<Artifact> {
    let packed: &[u8] = &artifact.envelope;
    let recovered: Vec<u8> = match packer {
        Packer::Upx => {
            let out: UpxUnpackOutput =
                unpack_upx(packed).map_err(|e| pass_err("DR-NAT-0917", packer, &e))?;
            out.recovered_image
        }
        Packer::Petite => {
            let out: PetitePhase2EmulatedOutput = unpack_petite_phase2_emulated(packed)
                .map_err(|e| pass_err("DR-NAT-0910", packer, &e))?;
            out.recovered_image
        }
        Packer::Nspack => {
            let report: NspackEmulatedReport =
                unpack_nspack_emulated(packed).map_err(|e| pass_err("DR-NAT-0911", packer, &e))?;
            report.decompressed_image
        }
        Packer::Mew => {
            let out: MewUnpackOutput =
                unpack_mew(packed).map_err(|e| pass_err("DR-NAT-0912", packer, &e))?;
            out.raw_image
        }
        Packer::Fsg => {
            let out: FsgUnpackOutput =
                unpack_fsg(packed).map_err(|e| pass_err("DR-NAT-0913", packer, &e))?;
            out.raw_image
        }
        Packer::Mpress => {
            let out: MpressUnpackOutput =
                unpack_mpress(packed).map_err(|e| pass_err("DR-NAT-0916", packer, &e))?;
            out.decompressed_image
        }
        other => {
            return Err(CoreError::PassFailure(format!(
                "DR-NAT-0914: native.packer-unpack: {label} reports Implemented status but no \
                 dispatch arm is wired - fix run_rust_unpacker",
                label = other.label(),
            )));
        }
    };
    if recovered.is_empty() {
        return Err(CoreError::PassFailure(format!(
            "DR-NAT-0915: native.packer-unpack: {label} unpacker produced no bytes",
            label = packer.label(),
        )));
    }
    Ok(Artifact::new(Rung::Raw, recovered, artifact.root_hash))
}

fn pass_err(code: &str, packer: Packer, err: &crate::error::Error) -> CoreError {
    CoreError::PassFailure(format!(
        "{code}: native.packer-unpack: {label} unpack failed: {err}",
        label = packer.label(),
    ))
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
        Packer::EnigmaProtector => "enigma",
        Packer::Obsidium => "obsidium",
        Packer::WinLicense => "winlicense",
        Packer::YodasCrypter => "yodas-crypter",
        Packer::YodasProtector => "yodas-protector",
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

    fn err_text(buf: Vec<u8>) -> String {
        let a: Artifact = Artifact::new(Rung::Raw, buf, [0u8; 32]);
        match PACKER_PASS.run(&a) {
            Ok(_) => panic!("synthetic non-PE input must not unpack"),
            Err(e) => format!("{e}"),
        }
    }

    #[test]
    fn implemented_packers_dispatch_to_real_unpacker_not_stub() {
        for (sig, code) in [
            (&b"petite\x00\x00"[..], "DR-NAT-0910"),
            (&b"nsp1"[..], "DR-NAT-0911"),
            (&b"MEW"[..], "DR-NAT-0912"),
            (&b"FSG!"[..], "DR-NAT-0913"),
            (&b".MPRESS1"[..], "DR-NAT-0916"),
        ] {
            let mut buf: Vec<u8> = vec![0u8; 512];
            buf[64..64 + sig.len()].copy_from_slice(sig);
            let msg: String = err_text(buf);
            assert!(
                msg.contains(code),
                "signature {sig:?} must reach its real unpacker (expected {code}); got: {msg}",
            );
            assert!(
                !msg.contains("no Rust unpacker yet"),
                "Implemented packer must NOT report the old detect-only stub message; got: {msg}",
            );
        }
    }

    #[test]
    fn grey_zone_protectors_return_honest_carve_error() {
        let mut buf: Vec<u8> = vec![0u8; 256];
        buf[10..15].copy_from_slice(b".vmp0");
        let msg: String = err_text(buf);
        assert!(
            msg.contains("DR-NAT-0909") && msg.contains("grey-zone"),
            "VMProtect must surface the honest grey-zone detect-and-carve error; got: {msg}",
        );
        assert!(!msg.contains("no Rust unpacker yet"), "got: {msg}");
    }

    #[test]
    fn detect_only_family_returns_honest_error() {
        let mut buf: Vec<u8> = vec![0u8; 256];
        buf[10..21].copy_from_slice(b"PolyCryptor");
        let msg: String = err_text(buf);
        assert!(
            msg.contains("DR-NAT-0907") && msg.contains("detect-only"),
            "PolyCryptor must surface the honest detect-only error; got: {msg}",
        );
    }

    #[test]
    fn every_implemented_packer_has_a_dispatch_arm() {
        let implemented: [Packer; 6] = [
            Packer::Upx,
            Packer::Petite,
            Packer::Nspack,
            Packer::Mew,
            Packer::Fsg,
            Packer::Mpress,
        ];
        for p in implemented {
            assert_eq!(
                p.unpacker_status(),
                UnpackerStatus::Implemented,
                "{} must be Implemented for CLI dispatch",
                p.label()
            );
            let a: Artifact = Artifact::new(Rung::Raw, vec![0u8; 256], [0u8; 32]);
            let msg: String = match dispatch_unpack(p, &a) {
                Ok(_) => continue,
                Err(e) => format!("{e}"),
            };
            assert!(
                !msg.contains("DR-NAT-0914"),
                "{} must have a real dispatch arm, not the missing-arm guard; got: {msg}",
                p.label()
            );
        }
    }
}
