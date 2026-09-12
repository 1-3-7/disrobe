use serde::{Deserialize, Serialize};

use super::upx_decoder::{UpxUnpackOutput, unpack_upx};
use crate::error::Result;

const GOPCLNTAB_MAGICS: [[u8; 4]; 4] = [
    [0xFB, 0xFF, 0xFF, 0xFF],
    [0xFA, 0xFF, 0xFF, 0xFF],
    [0xF0, 0xFF, 0xFF, 0xFF],
    [0xF1, 0xFF, 0xFF, 0xFF],
];

const GO_BUILD_ID_TAG: &[u8] = b"Go build ID: ";
const GO_VERSION_TAG: &[u8] = b"go1.";
const GO_RUNTIME_MORESTACK: &[u8] = b"runtime.morestack";
const GO_BUILDINF_MAGIC: &[u8] = b"\xff Go buildinf:";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(clippy::struct_field_names)]
pub struct GoRuntimeEvidence {
    pub gopclntab_at: Option<u64>,
    pub build_id_at: Option<u64>,
    pub version_at: Option<u64>,
    pub morestack_at: Option<u64>,
    pub buildinf_at: Option<u64>,
}

impl GoRuntimeEvidence {
    #[must_use]
    pub const fn marker_count(&self) -> u32 {
        self.gopclntab_at.is_some() as u32
            + self.build_id_at.is_some() as u32
            + self.version_at.is_some() as u32
            + self.morestack_at.is_some() as u32
            + self.buildinf_at.is_some() as u32
    }

    #[must_use]
    pub const fn is_go(&self) -> bool {
        self.marker_count() >= 2
    }
}

#[must_use]
pub fn scan_go_runtime(image: &[u8]) -> GoRuntimeEvidence {
    GoRuntimeEvidence {
        gopclntab_at: find_gopclntab(image),
        build_id_at: find_bytes(image, GO_BUILD_ID_TAG),
        version_at: find_go_version(image),
        morestack_at: find_bytes(image, GO_RUNTIME_MORESTACK),
        buildinf_at: find_bytes(image, GO_BUILDINF_MAGIC),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpxGoChainOutput {
    pub unpacked_image: Vec<u8>,
    pub adler_verified: bool,
    pub go_evidence: GoRuntimeEvidence,
    pub is_go_binary: bool,
}

pub fn unpack_upx_go_chain(packed: &[u8]) -> Result<UpxGoChainOutput> {
    let upx: UpxUnpackOutput = unpack_upx(packed)?;
    let go_evidence: GoRuntimeEvidence = scan_go_runtime(&upx.recovered_image);
    let is_go_binary: bool = go_evidence.is_go();
    Ok(UpxGoChainOutput {
        unpacked_image: upx.recovered_image,
        adler_verified: upx.adler_verified,
        go_evidence,
        is_go_binary,
    })
}

#[must_use]
pub fn detect_upx_packed_go(packed: &[u8]) -> bool {
    unpack_upx_go_chain(packed).is_ok_and(|out: UpxGoChainOutput| out.is_go_binary)
}

fn find_gopclntab(image: &[u8]) -> Option<u64> {
    if image.len() < 8 {
        return None;
    }
    for window_start in 0..=image.len() - 8 {
        let head: [u8; 4] = [
            image[window_start],
            image[window_start + 1],
            image[window_start + 2],
            image[window_start + 3],
        ];
        if !GOPCLNTAB_MAGICS.contains(&head) {
            continue;
        }
        let pc_quantum: u8 = image[window_start + 6];
        let ptr_size: u8 = image[window_start + 7];
        if image[window_start + 4] == 0
            && image[window_start + 5] == 0
            && (pc_quantum == 1 || pc_quantum == 2 || pc_quantum == 4)
            && (ptr_size == 4 || ptr_size == 8)
        {
            return Some(window_start as u64);
        }
    }
    None
}

fn find_go_version(image: &[u8]) -> Option<u64> {
    let mut cursor: usize = 0;
    while let Some(rel) = find_bytes(&image[cursor..], GO_VERSION_TAG) {
        let abs: usize = cursor + rel as usize;
        let digit_pos: usize = abs + GO_VERSION_TAG.len();
        if image.get(digit_pos).is_some_and(u8::is_ascii_digit) {
            return Some(abs as u64);
        }
        cursor = abs + 1;
        if cursor >= image.len() {
            break;
        }
    }
    None
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<u64> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|w: &[u8]| w == needle)
        .map(|p: usize| p as u64)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn gopclntab_go118_magic_detected() {
        let mut buf: Vec<u8> = vec![0u8; 64];
        buf[16..20].copy_from_slice(&[0xF0, 0xFF, 0xFF, 0xFF]);
        buf[22] = 1;
        buf[23] = 8;
        assert_eq!(find_gopclntab(&buf), Some(16));
    }

    #[test]
    fn gopclntab_go116_magic_detected() {
        let mut buf: Vec<u8> = vec![0u8; 64];
        buf[0..4].copy_from_slice(&[0xFA, 0xFF, 0xFF, 0xFF]);
        buf[6] = 1;
        buf[7] = 8;
        assert_eq!(find_gopclntab(&buf), Some(0));
    }

    #[test]
    fn gopclntab_rejects_bad_quantum_and_ptrsize() {
        let mut buf: Vec<u8> = vec![0u8; 64];
        buf[0..4].copy_from_slice(&[0xFB, 0xFF, 0xFF, 0xFF]);
        buf[6] = 3;
        buf[7] = 5;
        assert_eq!(find_gopclntab(&buf), None);
    }

    #[test]
    fn go_version_requires_trailing_digit() {
        let with_digit: &[u8] = b"....go1.21.4....";
        assert!(find_go_version(with_digit).is_some());
        let no_digit: &[u8] = b"....go1.X....";
        assert!(find_go_version(no_digit).is_none());
    }

    #[test]
    fn evidence_requires_two_markers_to_be_go() {
        let single: GoRuntimeEvidence = GoRuntimeEvidence {
            gopclntab_at: Some(0),
            build_id_at: None,
            version_at: None,
            morestack_at: None,
            buildinf_at: None,
        };
        assert!(!single.is_go());
        let double: GoRuntimeEvidence = GoRuntimeEvidence {
            gopclntab_at: Some(0),
            build_id_at: None,
            version_at: Some(8),
            morestack_at: None,
            buildinf_at: None,
        };
        assert!(double.is_go());
        assert_eq!(double.marker_count(), 2);
    }

    #[test]
    fn scan_finds_multiple_markers_in_synthetic_go_image() {
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&[0xF1, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x01, 0x08]);
        buf.extend_from_slice(b" padding ");
        buf.extend_from_slice(b"go1.22.0 ");
        buf.extend_from_slice(b"Go build ID: \"abc\" ");
        buf.extend_from_slice(b"runtime.morestack_noctxt");
        let ev: GoRuntimeEvidence = scan_go_runtime(&buf);
        assert!(ev.gopclntab_at.is_some());
        assert!(ev.version_at.is_some());
        assert!(ev.build_id_at.is_some());
        assert!(ev.morestack_at.is_some());
        assert!(ev.is_go(), "four runtime markers must classify as Go");
    }

    #[test]
    fn non_go_buffer_is_not_classified_go() {
        let buf: Vec<u8> = vec![0x42u8; 4096];
        let ev: GoRuntimeEvidence = scan_go_runtime(&buf);
        assert_eq!(ev.marker_count(), 0);
        assert!(!ev.is_go());
    }
}
