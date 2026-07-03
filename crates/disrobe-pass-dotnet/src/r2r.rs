use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::pe::{ClrHeader, DataDirectory, PeImage};

pub const R2R_MAGIC: u32 = 0x0052_5452;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct R2rHeader {
    pub magic: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub flags: u32,
    pub number_of_sections: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct R2rReport {
    pub present: bool,
    pub header: Option<R2rHeader>,
    pub crossgen2_native_aot: bool,
    pub composite_image: bool,
}

#[must_use]
pub fn detect(image: &[u8], pe: &PeImage, clr: &ClrHeader) -> R2rReport {
    if clr.managed_native_header.rva == 0 || clr.managed_native_header.size == 0 {
        return R2rReport {
            present: false,
            header: None,
            crossgen2_native_aot: false,
            composite_image: false,
        };
    }
    let parsed: Option<R2rHeader> = parse_header(image, pe, clr).ok();
    let composite: bool = parsed
        .as_ref()
        .is_some_and(|h: &R2rHeader| (h.flags & 0x0000_0001) != 0);
    let aot: bool = parsed
        .as_ref()
        .is_some_and(|h: &R2rHeader| (h.flags & 0x0000_0080) != 0);
    R2rReport {
        present: parsed.is_some(),
        header: parsed,
        crossgen2_native_aot: aot,
        composite_image: composite,
    }
}

pub fn parse_header(image: &[u8], pe: &PeImage, clr: &ClrHeader) -> Result<R2rHeader> {
    let dir: DataDirectory = clr.managed_native_header;
    if dir.size < 16 {
        return Err(Error::Truncated {
            offset: dir.rva as usize,
            needed: 16,
            had: dir.size as usize,
        });
    }
    let slice: &[u8] = pe.slice_at_rva(image, dir.rva, dir.size as usize)?;
    let magic: u32 = u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]);
    if magic != R2R_MAGIC {
        return Err(Error::BadR2rMagic(magic));
    }
    let major_version: u16 = u16::from_le_bytes([slice[4], slice[5]]);
    let minor_version: u16 = u16::from_le_bytes([slice[6], slice[7]]);
    if !(1..=16).contains(&major_version) {
        return Err(Error::UnsupportedR2rVersion(u32::from(major_version)));
    }
    let flags: u32 = u32::from_le_bytes([slice[8], slice[9], slice[10], slice[11]]);
    let number_of_sections: u32 = u32::from_le_bytes([slice[12], slice[13], slice[14], slice[15]]);
    Ok(R2rHeader {
        magic,
        major_version,
        minor_version,
        flags,
        number_of_sections,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn r2r_magic_matches_rtr_ascii() {
        assert_eq!(R2R_MAGIC.to_le_bytes(), [b'R', b'T', b'R', 0]);
    }
}
