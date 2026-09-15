use crate::error::{Error, Result};

const EOCD_SIGNATURE: u32 = 0x0605_4b50;
const ZIP64_EOCD_SIGNATURE: u32 = 0x0606_4b50;
const MAX_COMMENT: usize = 0xFFFF;
const EOCD_FIXED_LEN: usize = 22;
const SEARCH_BUDGET: usize = MAX_COMMENT + EOCD_FIXED_LEN + 4;

#[derive(Debug, Clone, Copy)]
pub struct ZipTailInfo {
    pub eocd_offset: usize,
    pub central_dir_offset: usize,
    pub central_dir_size: usize,
    pub archive_start_offset: usize,
}

fn archive_start_offset(
    eocd_offset: usize,
    central_dir_size: usize,
    central_dir_offset: usize,
) -> Result<usize> {
    let before_directory: usize = eocd_offset
        .checked_sub(central_dir_size)
        .ok_or(Error::ZipTailNotFound)?;
    before_directory
        .checked_sub(central_dir_offset)
        .ok_or(Error::ZipTailNotFound)
}

fn zip64_field_usize(bytes: &[u8], offset: usize) -> Result<usize> {
    let end: usize = offset.checked_add(8).ok_or(Error::ZipTailNotFound)?;
    let raw: [u8; 8] = bytes
        .get(offset..end)
        .and_then(|s: &[u8]| <[u8; 8]>::try_from(s).ok())
        .ok_or(Error::ZipTailNotFound)?;
    usize::try_from(u64::from_le_bytes(raw)).map_err(|_| Error::ZipTailNotFound)
}

pub fn locate(bytes: &[u8]) -> Result<ZipTailInfo> {
    let len: usize = bytes.len();
    if len < EOCD_FIXED_LEN {
        return Err(Error::ZipTailNotFound);
    }
    let start: usize = len.saturating_sub(SEARCH_BUDGET);
    for off in (start..=len - EOCD_FIXED_LEN).rev() {
        let sig: u32 =
            u32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]]);
        if sig == EOCD_SIGNATURE {
            let cd_size: usize = u32::from_le_bytes([
                bytes[off + 12],
                bytes[off + 13],
                bytes[off + 14],
                bytes[off + 15],
            ]) as usize;
            let cd_offset: usize = u32::from_le_bytes([
                bytes[off + 16],
                bytes[off + 17],
                bytes[off + 18],
                bytes[off + 19],
            ]) as usize;
            let archive_start: usize = archive_start_offset(off, cd_size, cd_offset)?;
            return Ok(ZipTailInfo {
                eocd_offset: off,
                central_dir_offset: cd_offset,
                central_dir_size: cd_size,
                archive_start_offset: archive_start,
            });
        }
        if sig == ZIP64_EOCD_SIGNATURE {
            let cd_size_offset: usize = off.checked_add(40).ok_or(Error::ZipTailNotFound)?;
            let cd_offset_offset: usize = off.checked_add(48).ok_or(Error::ZipTailNotFound)?;
            let cd_size: usize = zip64_field_usize(bytes, cd_size_offset)?;
            let cd_offset: usize = zip64_field_usize(bytes, cd_offset_offset)?;
            let archive_start: usize = archive_start_offset(off, cd_size, cd_offset)?;
            return Ok(ZipTailInfo {
                eocd_offset: off,
                central_dir_offset: cd_offset,
                central_dir_size: cd_size,
                archive_start_offset: archive_start,
            });
        }
    }
    Err(Error::ZipTailNotFound)
}

#[must_use]
pub fn is_likely_trailing_zip(bytes: &[u8]) -> bool {
    locate(bytes).is_ok()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn no_zip_returns_error() {
        let buf: Vec<u8> = vec![0u8; 1024];
        let err: Error = locate(&buf).expect_err("must fail");
        assert!(matches!(err, Error::ZipTailNotFound));
    }

    #[test]
    fn synthetic_eocd_locates() {
        let mut buf: Vec<u8> = vec![0u8; 1024];
        let off: usize = buf.len() - EOCD_FIXED_LEN;
        buf[off..off + 4].copy_from_slice(&EOCD_SIGNATURE.to_le_bytes());
        let info: ZipTailInfo = locate(&buf).expect("must locate");
        assert_eq!(info.eocd_offset, off);
    }

    #[test]
    fn eocd_rejects_central_directory_before_archive_start() {
        let mut buf: Vec<u8> = vec![0u8; 128];
        let off: usize = buf.len() - EOCD_FIXED_LEN;
        buf[off..off + 4].copy_from_slice(&EOCD_SIGNATURE.to_le_bytes());
        buf[off + 12..off + 16].copy_from_slice(&80_u32.to_le_bytes());
        buf[off + 16..off + 20].copy_from_slice(&80_u32.to_le_bytes());
        let err: Error = locate(&buf).expect_err("central directory cannot start before archive");
        assert!(matches!(err, Error::ZipTailNotFound));
    }

    #[test]
    fn zip64_eocd_rejects_central_directory_before_archive_start() {
        let mut buf: Vec<u8> = vec![0u8; 128];
        let off: usize = buf.len() - 56;
        buf[off..off + 4].copy_from_slice(&ZIP64_EOCD_SIGNATURE.to_le_bytes());
        buf[off + 40..off + 48].copy_from_slice(&80_u64.to_le_bytes());
        buf[off + 48..off + 56].copy_from_slice(&80_u64.to_le_bytes());
        let err: Error = locate(&buf).expect_err("central directory cannot start before archive");
        assert!(matches!(err, Error::ZipTailNotFound));
    }

    #[test]
    fn synthetic_zip64_eocd_parses_central_dir_fields() {
        let mut buf: Vec<u8> = vec![0u8; 1024];
        let off: usize = buf.len() - 56;
        buf[off..off + 4].copy_from_slice(&ZIP64_EOCD_SIGNATURE.to_le_bytes());
        let cd_size: u64 = 100;
        let cd_offset: u64 = 200;
        buf[off + 40..off + 48].copy_from_slice(&cd_size.to_le_bytes());
        buf[off + 48..off + 56].copy_from_slice(&cd_offset.to_le_bytes());
        let info: ZipTailInfo = locate(&buf).expect("must locate zip64");
        assert_eq!(info.eocd_offset, off);
        assert_eq!(info.central_dir_size, 100);
        assert_eq!(info.central_dir_offset, 200);
        assert_eq!(info.archive_start_offset, off - 100 - 200);
    }

    #[test]
    fn truncated_zip64_eocd_fails_fast() {
        let mut buf: Vec<u8> = vec![0u8; 30];
        let off: usize = 4;
        buf[off..off + 4].copy_from_slice(&ZIP64_EOCD_SIGNATURE.to_le_bytes());
        assert!(matches!(locate(&buf), Err(Error::ZipTailNotFound)));
    }
}
