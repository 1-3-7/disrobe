#[derive(Debug, Clone, Copy)]
pub struct PycFingerprint {
    pub magic: u32,
    pub python_major: u8,
    pub python_minor: u8,
    pub header_len: usize,
}

#[must_use]
pub fn fingerprint(bytes: &[u8]) -> Option<PycFingerprint> {
    if bytes.len() < 4 {
        return None;
    }
    let magic: u32 = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let (py_major, py_minor): (u8, u8) = python_version_for_magic(magic)?;
    let header_len: usize = pyc_header_len(py_major, py_minor);
    Some(PycFingerprint {
        magic,
        python_major: py_major,
        python_minor: py_minor,
        header_len,
    })
}

#[must_use]
pub const fn python_version_for_magic(magic: u32) -> Option<(u8, u8)> {
    let lower: u32 = magic & 0xFFFF;
    let suffix: u32 = (magic >> 16) & 0xFFFF;
    if suffix != 0x0A0D {
        return None;
    }
    match lower as u16 {
        62211 => Some((2, 7)),
        3379 => Some((3, 6)),
        3394 => Some((3, 7)),
        3413 => Some((3, 8)),
        3425 => Some((3, 9)),
        3439 => Some((3, 10)),
        3494 | 3495 => Some((3, 11)),
        3531 => Some((3, 12)),
        3571 => Some((3, 13)),
        3627 => Some((3, 14)),
        _ => None,
    }
}

#[must_use]
pub const fn pyc_header_len(major: u8, minor: u8) -> usize {
    match (major, minor) {
        (2, _) | (3, 0..=2) => 8,
        (3, 3..=6) => 12,
        _ => 16,
    }
}

#[allow(dead_code)]
pub(crate) fn body_offset(bytes: &[u8]) -> usize {
    let Some(fp): Option<PycFingerprint> = fingerprint(bytes) else {
        return 0;
    };
    fp.header_len
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn detects_311_magic() {
        let mut hdr: Vec<u8> = vec![0u8; 16];
        hdr[0..2].copy_from_slice(&3494u16.to_le_bytes());
        hdr[2..4].copy_from_slice(&0x0A0Du16.to_le_bytes());
        let fp: PycFingerprint = fingerprint(&hdr).expect("must fingerprint");
        assert_eq!((fp.python_major, fp.python_minor), (3, 11));
        assert_eq!(fp.header_len, 16);
    }

    #[test]
    fn detects_27_magic() {
        let mut hdr: Vec<u8> = vec![0u8; 8];
        hdr[0..2].copy_from_slice(&62211u16.to_le_bytes());
        hdr[2..4].copy_from_slice(&0x0A0Du16.to_le_bytes());
        let fp: PycFingerprint = fingerprint(&hdr).expect("must fingerprint");
        assert_eq!((fp.python_major, fp.python_minor), (2, 7));
        assert_eq!(fp.header_len, 8);
    }

    #[test]
    fn rejects_random_bytes() {
        assert!(fingerprint(b"PK\x03\x04zip-archive").is_none());
    }
}
