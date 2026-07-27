use std::path::{Path, PathBuf};

use crate::error::{CextractError, Result};

pub(crate) const PYC_HEADER_LEN: usize = 16;
pub(crate) const MAX_MARSHAL_BODY_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone)]
pub(crate) struct WrittenPyc {
    pub path: PathBuf,
    pub blake3_hex: String,
    pub size: usize,
}

#[inline]
const fn pyc_header(magic_number: [u8; 4]) -> [u8; PYC_HEADER_LEN] {
    let mut buf: [u8; PYC_HEADER_LEN] = [0u8; PYC_HEADER_LEN];
    buf[0] = magic_number[0];
    buf[1] = magic_number[1];
    buf[2] = magic_number[2];
    buf[3] = magic_number[3];
    buf
}

#[inline]
pub(crate) fn blake3_hex(bytes: &[u8]) -> String {
    let hash: blake3::Hash = blake3::hash(bytes);
    hash.to_hex().to_string()
}

pub(crate) fn write_pyc(
    out_dir: &Path,
    stem: &str,
    index: usize,
    marshal_body: &[u8],
    magic_number: [u8; 4],
) -> Result<WrittenPyc> {
    let header: [u8; PYC_HEADER_LEN] = pyc_header(magic_number);
    let total_len: usize = checked_pyc_len(marshal_body.len())?;
    let mut buf: Vec<u8> = Vec::with_capacity(total_len);
    buf.extend_from_slice(&header);
    buf.extend_from_slice(marshal_body);

    let blake_hex: String = blake3_hex(&buf);
    let short: &str = blake_hex
        .get(..16)
        .map_or(blake_hex.as_str(), |value: &str| value);
    let filename: String = format!("{stem}_ce_{index}_{short}.pyc");
    let path: PathBuf = out_dir.join(&filename);

    std::fs::write(&path, &buf).map_err(|source: std::io::Error| CextractError::PycWrite {
        path: path.display().to_string(),
        source,
    })?;

    Ok(WrittenPyc {
        path,
        blake3_hex: blake_hex,
        size: buf.len(),
    })
}

pub(crate) fn checked_pyc_len(body_len: usize) -> Result<usize> {
    if body_len > MAX_MARSHAL_BODY_BYTES {
        return Err(CextractError::PycTooLarge {
            body_len,
            limit: MAX_MARSHAL_BODY_BYTES,
        });
    }
    PYC_HEADER_LEN
        .checked_add(body_len)
        .ok_or(CextractError::PycTooLarge {
            body_len,
            limit: MAX_MARSHAL_BODY_BYTES,
        })
}

pub(crate) fn ensure_writable(out_dir: &Path) -> Result<()> {
    std::fs::create_dir_all(out_dir).map_err(|source: std::io::Error| {
        CextractError::OutDirCreate {
            path: out_dir.display().to_string(),
            source,
        }
    })?;
    let probe: PathBuf = out_dir.join(".disrobe_cextract_probe");
    std::fs::write(&probe, b"").map_err(|source: std::io::Error| {
        CextractError::OutDirNotWritable {
            path: out_dir.display().to_string(),
            source,
        }
    })?;
    let _: std::io::Result<()> = std::fs::remove_file(&probe);
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::{
        MAX_MARSHAL_BODY_BYTES, PYC_HEADER_LEN, WrittenPyc, blake3_hex, checked_pyc_len,
        ensure_writable, pyc_header, write_pyc,
    };
    use disrobe_core::scratch::ScratchDir;
    use std::path::PathBuf;

    fn temp_dir() -> (ScratchDir, PathBuf) {
        let scratch: ScratchDir =
            ScratchDir::create("disrobe_cextract_test").expect("create scratch directory");
        let base: PathBuf = scratch.path().to_path_buf();
        (scratch, base)
    }

    #[test]
    fn pyc_header_layout_is_16_bytes_with_magic_in_first_4() {
        let magic: [u8; 4] = [0x55, 0x0d, 0x0d, 0x0a];
        let h: [u8; PYC_HEADER_LEN] = pyc_header(magic);
        assert_eq!(h.len(), 16);
        assert_eq!(&h[..4], &magic);
        for &b in &h[4..] {
            assert_eq!(b, 0u8);
        }
    }

    #[test]
    fn write_pyc_writes_header_plus_body_and_filename_carries_hash_prefix() {
        let (_scratch, dir): (ScratchDir, PathBuf) = temp_dir();
        let body: [u8; 3] = [0x63, 0x00, 0x00];
        let magic: [u8; 4] = [0xa7, 0x0d, 0x0d, 0x0a];
        let w: WrittenPyc = write_pyc(&dir, "hello", 0, &body, magic).unwrap();
        assert_eq!(w.size, PYC_HEADER_LEN + body.len());
        let stored: Vec<u8> = std::fs::read(&w.path).unwrap();
        assert_eq!(&stored[..4], &magic);
        assert_eq!(&stored[PYC_HEADER_LEN..], &body);
        let filename: String = w
            .path
            .file_name()
            .and_then(|s| s.to_str())
            .map_or_else(String::new, str::to_owned);
        assert!(filename.starts_with("hello_ce_0_"));
        assert!(filename.to_lowercase().ends_with(".pyc"));
        let prefix_present: bool = w.blake3_hex.get(..16).is_some_and(|p| filename.contains(p));
        assert!(prefix_present);
    }

    #[test]
    fn ensure_writable_round_trip_creates_dir_and_passes() {
        let (_scratch, dir): (ScratchDir, PathBuf) = temp_dir();
        ensure_writable(&dir).unwrap();
    }

    #[test]
    fn blake3_hex_is_64_chars_lowercase() {
        let h: String = blake3_hex(b"abc");
        assert_eq!(h.len(), 64);
        assert!(h.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')));
    }

    #[test]
    fn write_pyc_distinct_bodies_have_distinct_filenames() {
        let (_scratch, dir): (ScratchDir, PathBuf) = temp_dir();
        let magic: [u8; 4] = [0xa7, 0x0d, 0x0d, 0x0a];
        let w1: WrittenPyc = write_pyc(&dir, "x", 0, b"alpha", magic).unwrap();
        let w2: WrittenPyc = write_pyc(&dir, "x", 0, b"beta", magic).unwrap();
        assert_ne!(w1.path, w2.path);
    }

    #[test]
    fn checked_pyc_len_rejects_oversized_body_without_allocating() {
        assert!(checked_pyc_len(MAX_MARSHAL_BODY_BYTES + 1).is_err());
        assert_eq!(
            checked_pyc_len(8).unwrap(),
            PYC_HEADER_LEN.checked_add(8).unwrap()
        );
    }
}
