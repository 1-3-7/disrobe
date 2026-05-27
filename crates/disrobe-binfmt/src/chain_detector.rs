#![cfg(feature = "chain")]
#![allow(clippy::module_name_repetitions)]

use disrobe_core::Artifact;
use disrobe_core::Rung;
use disrobe_core::chain::{
    DetectContext, DetectVerdict, Detector, FAMILY_CONTAINER, OutputKind, Pass,
};
use disrobe_core::error::{CoreError, Result as CoreResult};
use disrobe_core::pass::PassId;

pub const PASS_ID: PassId = "binfmt.container";

const TAG_ZIP: &str = "zip";
const TAG_TAR: &str = "tar";
const TAG_AR: &str = "ar";
const TAG_GZIP: &str = "gzip";
const TAG_XZ: &str = "xz";
const TAG_ZSTD: &str = "zstd";
const TAG_BZIP2: &str = "bzip2";
const TAG_SEVENZIP: &str = "7z";
const TAG_CAB: &str = "cab";
const TAG_RAR: &str = "rar";
const TAG_ISO: &str = "iso";

#[derive(Debug)]
pub struct ContainerDetector;

impl Detector for ContainerDetector {
    #[inline]
    fn id(&self) -> PassId {
        PASS_ID
    }

    fn detect(&self, ctx: &DetectContext<'_>) -> Option<DetectVerdict> {
        let bytes: &[u8] = ctx.bytes;
        if bytes.len() < 4 {
            return None;
        }
        let tag: Option<&'static str> = sniff_container_tag(bytes);
        tag.map(|t: &'static str| {
            DetectVerdict::new(
                PASS_ID,
                t,
                FAMILY_CONTAINER,
                0.90,
                50,
                vec!["container-magic"],
                format!("container format: {t}"),
            )
        })
    }
}

#[derive(Debug)]
pub struct ContainerPass;

impl Pass for ContainerPass {
    #[inline]
    fn id(&self) -> PassId {
        PASS_ID
    }

    #[inline]
    fn detector(&self) -> &'static dyn Detector {
        &ContainerDetector
    }

    #[inline]
    fn output_kind(&self, _output: &Artifact) -> OutputKind {
        OutputKind::Bytes {
            format_tag: "container",
            family: FAMILY_CONTAINER,
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
        if ContainerDetector.detect(&ctx).is_none() {
            return Err(CoreError::PassFailure(
                "DR-BINFMT-0901: binfmt.container: input is not a recognised container".to_string(),
            ));
        }
        Ok(Artifact::new(Rung::Raw, bytes.to_vec(), artifact.root_hash))
    }
}

pub static CONTAINER_PASS: ContainerPass = ContainerPass;

fn sniff_container_tag(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(b"PK\x03\x04")
        || bytes.starts_with(b"PK\x05\x06")
        || bytes.starts_with(b"PK\x07\x08")
    {
        return Some(TAG_ZIP);
    }
    if bytes.len() >= 262 && &bytes[257..262] == b"ustar" {
        return Some(TAG_TAR);
    }
    if bytes.starts_with(b"!<arch>\n") {
        return Some(TAG_AR);
    }
    if bytes.starts_with(&[0x1f, 0x8b]) {
        return Some(TAG_GZIP);
    }
    if bytes.starts_with(&[0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00]) {
        return Some(TAG_XZ);
    }
    if bytes.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        return Some(TAG_ZSTD);
    }
    if bytes.starts_with(&[0x42, 0x5a, 0x68]) {
        return Some(TAG_BZIP2);
    }
    if bytes.starts_with(&[0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]) {
        return Some(TAG_SEVENZIP);
    }
    if bytes.starts_with(b"MSCF") {
        return Some(TAG_CAB);
    }
    if bytes.starts_with(b"Rar!\x1a\x07") {
        return Some(TAG_RAR);
    }
    if bytes.len() >= 0x8006 && &bytes[0x8001..0x8006] == b"CD001" {
        return Some(TAG_ISO);
    }
    None
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

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
        assert_eq!(ContainerDetector.id(), PASS_ID);
    }

    #[test]
    fn detects_zip() {
        let v: DetectVerdict = ContainerDetector
            .detect(&ctx(b"PK\x03\x04rest"))
            .expect("zip magic");
        assert_eq!(v.format_tag, TAG_ZIP);
    }

    #[test]
    fn detects_gzip() {
        let v: DetectVerdict = ContainerDetector
            .detect(&ctx(&[0x1f, 0x8b, 0x08, 0x00]))
            .expect("gzip magic");
        assert_eq!(v.format_tag, TAG_GZIP);
    }

    #[test]
    fn rejects_random_bytes() {
        assert!(ContainerDetector.detect(&ctx(&[0u8; 32])).is_none());
    }

    #[test]
    fn rejects_short_input() {
        assert!(ContainerDetector.detect(&ctx(b"PK")).is_none());
    }
}
