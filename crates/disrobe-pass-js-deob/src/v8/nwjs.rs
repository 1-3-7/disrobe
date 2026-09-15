use serde::{Deserialize, Serialize};

const ZIP_EOCD_SIGNATURE: u32 = 0x0605_4b50;
const ZIP_EOCD_FIXED_LEN: usize = 22;
const ZIP_MAX_COMMENT: usize = 0xFFFF;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NwjsLocation {
    pub eocd_offset: u64,
    pub central_dir_offset: u64,
    pub central_dir_size: u64,
}

#[must_use]
pub fn detect_nwjs_zip_suffix(bytes: &[u8]) -> Option<NwjsLocation> {
    if bytes.len() < ZIP_EOCD_FIXED_LEN {
        return None;
    }
    let scan_budget: usize = ZIP_EOCD_FIXED_LEN + ZIP_MAX_COMMENT + 4;
    let start: usize = bytes.len().saturating_sub(scan_budget);
    for off in (start..=bytes.len() - ZIP_EOCD_FIXED_LEN).rev() {
        let sig: u32 =
            u32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]]);
        if sig == ZIP_EOCD_SIGNATURE {
            let cd_size: u32 = u32::from_le_bytes([
                bytes[off + 12],
                bytes[off + 13],
                bytes[off + 14],
                bytes[off + 15],
            ]);
            let cd_offset: u32 = u32::from_le_bytes([
                bytes[off + 16],
                bytes[off + 17],
                bytes[off + 18],
                bytes[off + 19],
            ]);
            return Some(NwjsLocation {
                eocd_offset: off as u64,
                central_dir_offset: u64::from(cd_offset),
                central_dir_size: u64::from(cd_size),
            });
        }
    }
    None
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn synth_binary_with_zip_suffix() -> Vec<u8> {
        let mut out: Vec<u8> = vec![0u8; 4096];
        let off: usize = out.len() - ZIP_EOCD_FIXED_LEN;
        out[off..off + 4].copy_from_slice(&ZIP_EOCD_SIGNATURE.to_le_bytes());
        out[off + 12..off + 16].copy_from_slice(&100u32.to_le_bytes());
        out[off + 16..off + 20].copy_from_slice(&500u32.to_le_bytes());
        out
    }

    #[test]
    fn detects_zip_eocd_appended_to_binary() {
        let bytes: Vec<u8> = synth_binary_with_zip_suffix();
        let loc: NwjsLocation = detect_nwjs_zip_suffix(&bytes).expect("nwjs");
        assert_eq!(loc.eocd_offset, (bytes.len() - ZIP_EOCD_FIXED_LEN) as u64);
        assert_eq!(loc.central_dir_size, 100);
        assert_eq!(loc.central_dir_offset, 500);
    }

    #[test]
    fn returns_none_on_no_eocd() {
        assert!(detect_nwjs_zip_suffix(&[0u8; 1024]).is_none());
    }
}
