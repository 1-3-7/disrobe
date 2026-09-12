use crate::common::zip_tail::{is_likely_trailing_zip, locate};
use crate::error::{Error, Result};

pub fn extract_overlay_zip(bytes: &[u8]) -> Result<Vec<u8>> {
    if !is_likely_trailing_zip(bytes) {
        return Err(Error::ZipTailNotFound);
    }
    let info: crate::common::zip_tail::ZipTailInfo = locate(bytes)?;
    let start: usize = info.archive_start_offset;
    let end: usize = info.eocd_offset + 22;
    if start >= end || end > bytes.len() {
        return Err(Error::ZipTailNotFound);
    }
    Ok(bytes[start..end].to_vec())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn returns_error_when_no_overlay() {
        let buf: Vec<u8> = vec![0u8; 256];
        let err: Error = extract_overlay_zip(&buf).unwrap_err();
        assert!(matches!(err, Error::ZipTailNotFound));
    }
}
