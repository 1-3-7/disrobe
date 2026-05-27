use std::io::Read;
use std::path::Path;

use aes::Aes128;
use ctr::Ctr128BE;
use ctr::cipher::{KeyIvInit, StreamCipher};
use disrobe_py_marshal::{PyVersion, magic_for};
use flate2::read::ZlibDecoder;

use crate::cookie::{Cookie, find_cookie};
use crate::error::{Error, Result};
use crate::toc::{EntryType, TocEntry, walk_toc};

#[derive(Debug, Clone)]
pub struct ExtractedEntry {
    pub toc: TocEntry,
    pub data: Vec<u8>,
    pub written_path: Option<String>,
    pub decrypted: bool,
}

#[derive(Debug)]
pub struct ExtractOutput {
    pub cookie: Cookie,
    pub entries: Vec<ExtractedEntry>,
    pub encryption_key: Option<[u8; 16]>,
    pub bare_pyc_paths: Vec<String>,
}

pub fn extract_from_path(path: &Path) -> Result<ExtractOutput> {
    let bytes: Vec<u8> = std::fs::read(path)?;
    extract_archive(&bytes)
}

pub fn extract_archive(image: &[u8]) -> Result<ExtractOutput> {
    let cookie: Cookie = find_cookie(image)?;
    let toc: Vec<TocEntry> = walk_toc(image, &cookie)?;
    let overlay_pos: usize = compute_overlay_pos(image, &cookie);

    let key: Option<[u8; 16]> = locate_encryption_key(image, &toc, overlay_pos);
    let mut entries: Vec<ExtractedEntry> = Vec::with_capacity(toc.len());
    let mut bare_pyc_paths: Vec<String> = Vec::new();

    let py_version: PyVersion = PyVersion::new(cookie.python_major, cookie.python_minor);

    for entry in toc {
        if entry.entry_type.should_skip() {
            continue;
        }
        let start: usize = overlay_pos + entry.entry_position as usize;
        let end: usize = start + entry.compressed_size as usize;
        if end > image.len() {
            return Err(Error::TocWalk(
                start,
                format!("entry '{}' data exceeds file size", entry.name),
            ));
        }
        let raw: &[u8] = &image[start..end];
        let (decrypted_view, decrypted): (DecryptedBuf<'_>, bool) = decrypt_view(raw, key.as_ref());

        let inflated: Vec<u8> = if entry.compressed_flag == 1 {
            inflate(decrypted_view.as_slice()).map_err(|e| Error::Inflate {
                name: entry.name.clone(),
                source: e,
            })?
        } else {
            decrypted_view.into_owned()
        };

        let final_bytes: Vec<u8> = if entry.entry_type.is_pyc_carrier() {
            prepend_pyc_header(&inflated, py_version)
        } else {
            inflated
        };

        if entry.entry_type.is_pyc_carrier() {
            bare_pyc_paths.push(format!("{}.pyc", entry.name));
        }

        entries.push(ExtractedEntry {
            toc: entry,
            data: final_bytes,
            written_path: None,
            decrypted,
        });
    }

    Ok(ExtractOutput {
        cookie,
        entries,
        encryption_key: key,
        bare_pyc_paths,
    })
}

const fn compute_overlay_pos(image: &[u8], cookie: &Cookie) -> usize {
    let cookie_size: usize = cookie.variant.header_len();
    let cookie_end: usize = cookie.magic_offset + cookie_size;
    let tail_bytes: usize = image.len().saturating_sub(cookie_end);
    let overlay_size: usize = cookie.length_of_package as usize + tail_bytes;
    image.len().saturating_sub(overlay_size)
}

enum DecryptedBuf<'a> {
    Borrowed(&'a [u8]),
    Owned(Vec<u8>),
}

impl DecryptedBuf<'_> {
    const fn as_slice(&self) -> &[u8] {
        match self {
            Self::Borrowed(b) => b,
            Self::Owned(v) => v.as_slice(),
        }
    }

    fn into_owned(self) -> Vec<u8> {
        match self {
            Self::Borrowed(b) => b.to_vec(),
            Self::Owned(v) => v,
        }
    }
}

fn decrypt_view<'a>(raw: &'a [u8], key: Option<&[u8; 16]>) -> (DecryptedBuf<'a>, bool) {
    let Some(k) = key else {
        return (DecryptedBuf::Borrowed(raw), false);
    };
    try_decrypt_ctr(raw, k).map_or((DecryptedBuf::Borrowed(raw), false), |plain| {
        (DecryptedBuf::Owned(plain), true)
    })
}

fn locate_encryption_key(image: &[u8], toc: &[TocEntry], overlay_pos: usize) -> Option<[u8; 16]> {
    let key_entry: &TocEntry = toc
        .iter()
        .find(|e| e.name == "pyimod00_crypto_key" && e.entry_type == EntryType::Module)?;
    let start: usize = overlay_pos + key_entry.entry_position as usize;
    let end: usize = start + key_entry.compressed_size as usize;
    if end > image.len() {
        return None;
    }
    let raw: &[u8] = &image[start..end];
    let inflated: Vec<u8> = if key_entry.compressed_flag == 1 {
        inflate(raw).ok()?
    } else {
        raw.to_vec()
    };
    find_16byte_string_literal(&inflated)
}

fn find_16byte_string_literal(blob: &[u8]) -> Option<[u8; 16]> {
    for window in blob.windows(18) {
        if matches!(window[0], b'\'' | b'"') && window[17] == window[0] {
            let tail: &[u8] = &window[1..17];
            if tail.iter().all(u8::is_ascii_alphanumeric) {
                let mut out: [u8; 16] = [0u8; 16];
                out.copy_from_slice(tail);
                return Some(out);
            }
        }
    }
    None
}

fn try_decrypt_ctr(raw: &[u8], key: &[u8; 16]) -> Option<Vec<u8>> {
    if raw.len() < 16 {
        return None;
    }
    let iv: [u8; 16] = raw[..16].try_into().ok()?;
    let mut buf: Vec<u8> = raw[16..].to_vec();
    let mut cipher: Ctr128BE<Aes128> = Ctr128BE::<Aes128>::new(key.into(), &iv.into());
    cipher.apply_keystream(&mut buf);
    if buf.len() >= 2 && buf[0] == 0x78 && matches!(buf[1], 0x01 | 0x5e | 0x9c | 0xda) {
        Some(buf)
    } else {
        None
    }
}

fn inflate(input: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut decoder: ZlibDecoder<&[u8]> = ZlibDecoder::new(input);
    let mut out: Vec<u8> = Vec::new();
    decoder.read_to_end(&mut out)?;
    Ok(out)
}

fn prepend_pyc_header(body: &[u8], py_version: PyVersion) -> Vec<u8> {
    let magic: u16 = magic_for(py_version).unwrap_or(3531);
    let trailing_u32_count: usize = if py_version.has_pep552_header() {
        3
    } else if py_version.has_source_size() {
        2
    } else {
        1
    };
    let mut header: Vec<u8> = Vec::with_capacity(4 + trailing_u32_count * 4 + body.len());
    header.extend_from_slice(&magic.to_le_bytes());
    header.extend_from_slice(b"\r\n");
    for _ in 0..trailing_u32_count {
        header.extend_from_slice(&0u32.to_le_bytes());
    }
    header.extend_from_slice(body);
    header
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn missing_cookie_fails() {
        let data: Vec<u8> = vec![0u8; 4096];
        let err: Option<Error> = extract_archive(&data).err();
        assert!(matches!(err, Some(Error::CookieNotFound)));
    }

    #[test]
    fn pyc_header_py312_layout() {
        let body: Vec<u8> = vec![0x00, 0x01, 0x02, 0x03];
        let header: Vec<u8> = prepend_pyc_header(&body, PyVersion::PY312);
        assert_eq!(header.len(), 16 + body.len());
        assert_eq!(&header[2..4], b"\r\n");
        assert_eq!(&header[12..16], &[0x00; 4]);
        assert_eq!(&header[16..], body.as_slice());
    }

    #[test]
    fn pyc_header_py34_short_layout() {
        let body: Vec<u8> = vec![0xAA; 8];
        let header: Vec<u8> = prepend_pyc_header(&body, PyVersion::PY34);
        assert_eq!(header.len(), 12 + body.len());
        assert_eq!(&header[12..], body.as_slice());
    }

    #[test]
    fn pyc_header_py27_legacy_layout() {
        let body: Vec<u8> = vec![0xCC; 8];
        let header: Vec<u8> = prepend_pyc_header(&body, PyVersion::PY27);
        assert_eq!(header.len(), 8 + body.len());
        assert_eq!(&header[8..], body.as_slice());
    }

    #[test]
    fn find_key_picks_quoted_literal() {
        let mut blob: Vec<u8> = b"some-junk'ABCDEFGHIJKLMNOP'tail".to_vec();
        blob.extend_from_slice(b"extra-noise");
        let key: [u8; 16] = find_16byte_string_literal(&blob).expect("key not found");
        assert_eq!(&key, b"ABCDEFGHIJKLMNOP");
    }

    #[test]
    fn find_key_double_quote_balanced_literal() {
        let blob: Vec<u8> = br#"prefix"0123456789abcdef"suffix"#.to_vec();
        let key: [u8; 16] = find_16byte_string_literal(&blob).expect("key not found");
        assert_eq!(&key, b"0123456789abcdef");
    }

    #[test]
    fn find_key_returns_none_when_no_literal_present() {
        let blob: Vec<u8> = (b'a'..=b'p').collect();
        assert!(
            find_16byte_string_literal(&blob).is_none(),
            "no quoted literal: must not fabricate a key from raw bytes"
        );
    }

    #[test]
    fn find_key_returns_none_on_mismatched_quotes() {
        let blob: Vec<u8> = b"prefix'ABCDEFGHIJKLMNOP\"tail".to_vec();
        assert!(find_16byte_string_literal(&blob).is_none());
    }

    #[test]
    fn find_key_returns_none_on_unbalanced_short_blob() {
        let blob: Vec<u8> = b"shortblob".to_vec();
        assert!(find_16byte_string_literal(&blob).is_none());
    }

    #[test]
    fn try_decrypt_ctr_rejects_short_input() {
        let key: [u8; 16] = [0u8; 16];
        assert!(try_decrypt_ctr(b"short", &key).is_none());
    }
}
