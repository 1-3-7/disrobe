use crate::error::{Error, Result};
use crate::py2exe::scriptinfo::PY2EXE_MAGIC_TAG;

pub fn extract_pythonscript_resource(bytes: &[u8]) -> Result<Vec<u8>> {
    if !looks_like_pe(bytes) {
        return Err(Error::PeParse(
            "input is not a PE (missing MZ magic)".to_owned(),
        ));
    }
    let magic_bytes: [u8; 4] = PY2EXE_MAGIC_TAG.to_le_bytes();
    let Some(start): Option<usize> = locate_magic(bytes, &magic_bytes) else {
        return Err(Error::Py2exeScriptResourceMissing);
    };
    let slice: &[u8] = &bytes[start..];
    let end: usize = bounded_payload_end(slice);
    Ok(slice[..end].to_vec())
}

fn locate_magic(bytes: &[u8], magic: &[u8]) -> Option<usize> {
    bytes.windows(magic.len()).position(|w| w == magic)
}

fn bounded_payload_end(slice: &[u8]) -> usize {
    let total: usize = slice.len();
    let cap: usize = total.min(8 * 1024 * 1024);
    if cap == total { total } else { cap }
}

#[must_use]
pub fn sniff_python_version(bytes: &[u8]) -> Option<(u8, u8)> {
    let needle: &[u8] = b"python";
    let mut idx: usize = 0;
    while let Some(pos) = bytes[idx..]
        .windows(needle.len())
        .position(|w: &[u8]| w.eq_ignore_ascii_case(needle))
    {
        let start: usize = idx + pos + needle.len();
        if let Some(version) = parse_python_dll_version(&bytes[start..]) {
            return Some(version);
        }
        idx = idx + pos + 1;
        if idx + needle.len() > bytes.len() {
            break;
        }
    }
    None
}

fn parse_python_dll_version(tail: &[u8]) -> Option<(u8, u8)> {
    let digits: Vec<u8> = tail
        .iter()
        .take(3)
        .copied()
        .take_while(u8::is_ascii_digit)
        .collect();
    let suffix: &[u8] = &tail[digits.len()..tail.len().min(digits.len() + 4)];
    if !suffix.eq_ignore_ascii_case(b".dll") {
        return None;
    }
    match digits.as_slice() {
        [major, minor] => Some((major - b'0', minor - b'0')),
        [major, minor, patch] => {
            let major_val: u8 = major - b'0';
            if major_val >= 3 {
                Some((major_val, (minor - b'0') * 10 + (patch - b'0')))
            } else {
                None
            }
        }
        _ => None,
    }
}

#[must_use]
pub fn looks_like_pe(bytes: &[u8]) -> bool {
    if bytes.len() < 0x40 {
        return false;
    }
    if &bytes[..2] != b"MZ" {
        return false;
    }
    let Some(pe_offset): Option<usize> = usize::try_from(u32::from_le_bytes([
        bytes[0x3C],
        bytes[0x3D],
        bytes[0x3E],
        bytes[0x3F],
    ]))
    .ok() else {
        return false;
    };
    let Some(pe_end): Option<usize> = pe_offset.checked_add(4) else {
        return false;
    };
    bytes.get(pe_offset..pe_end) == Some(&b"PE\0\0"[..])
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_pe() {
        let err: Error = extract_pythonscript_resource(b"not a pe").unwrap_err();
        assert!(matches!(err, Error::PeParse(_)));
    }

    #[test]
    fn detects_minimal_pe() {
        let mut buf: Vec<u8> = vec![0u8; 0x80];
        buf[0..2].copy_from_slice(b"MZ");
        buf[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        buf[0x40..0x44].copy_from_slice(b"PE\0\0");
        assert!(looks_like_pe(&buf));
    }

    #[test]
    fn sniffs_python3_dll_version() {
        let buf: Vec<u8> = b"\x00\x00MZjunk python314.dll trailer".to_vec();
        assert_eq!(sniff_python_version(&buf), Some((3, 14)));
    }

    #[test]
    fn sniffs_python2_dll_version() {
        let buf: Vec<u8> = b"prefix PYTHON27.DLL suffix".to_vec();
        assert_eq!(sniff_python_version(&buf), Some((2, 7)));
    }

    #[test]
    fn ignores_non_dll_python_strings() {
        let buf: Vec<u8> = b"pythonpath=/usr/lib/python3".to_vec();
        assert_eq!(sniff_python_version(&buf), None);
    }

    #[test]
    fn finds_magic_in_synthetic_pe() {
        let mut buf: Vec<u8> = vec![0u8; 0x80];
        buf[0..2].copy_from_slice(b"MZ");
        buf[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        buf[0x40..0x44].copy_from_slice(b"PE\0\0");
        buf.extend_from_slice(&PY2EXE_MAGIC_TAG.to_le_bytes());
        buf.extend_from_slice(&2u32.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&1u32.to_le_bytes());
        buf.extend_from_slice(b"app.zip\0");
        buf.extend_from_slice(&[0xE3, 0x00, 0x00, 0x00]);
        let resource: Vec<u8> = extract_pythonscript_resource(&buf).expect("must extract");
        assert!(resource.starts_with(&PY2EXE_MAGIC_TAG.to_le_bytes()));
    }
}
