use disrobe_py_marshal::{PyVersion, pyversion_from_magic};

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
    let version: PyVersion = pyversion_from_magic(magic)?;
    let header_len: usize = version.pyc_header_len();
    Some(PycFingerprint {
        magic,
        python_major: version.major,
        python_minor: version.minor,
        header_len,
    })
}

#[must_use]
pub const fn python_version_for_magic(magic: u32) -> Option<(u8, u8)> {
    match pyversion_from_magic(magic) {
        Some(version) => Some((version.major, version.minor)),
        None => None,
    }
}

#[must_use]
pub const fn pyc_header_len(major: u8, minor: u8) -> usize {
    PyVersion::new(major, minor).pyc_header_len()
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
        let magic: u32 = disrobe_py_marshal::magic_for(disrobe_py_marshal::PyVersion::PY311)
            .expect("known magic");
        hdr[0..4].copy_from_slice(&magic.to_le_bytes());
        let fp: PycFingerprint = fingerprint(&hdr).expect("must fingerprint");
        assert_eq!((fp.python_major, fp.python_minor), (3, 11));
        assert_eq!(fp.header_len, 16);
    }

    #[test]
    fn detects_315_magic_from_shared_table() {
        let mut hdr: Vec<u8> = vec![0u8; 16];
        let magic: u32 = disrobe_py_marshal::magic_for(disrobe_py_marshal::PyVersion::PY315)
            .expect("known magic");
        hdr[0..4].copy_from_slice(&magic.to_le_bytes());
        let fp: PycFingerprint = fingerprint(&hdr).expect("must fingerprint");
        assert_eq!((fp.python_major, fp.python_minor), (3, 15));
        assert_eq!(fp.header_len, 16);
    }

    #[test]
    fn detects_27_magic() {
        let mut hdr: Vec<u8> = vec![0u8; 8];
        let magic: u32 = disrobe_py_marshal::magic_for(disrobe_py_marshal::PyVersion::PY27)
            .expect("known magic");
        hdr[0..4].copy_from_slice(&magic.to_le_bytes());
        let fp: PycFingerprint = fingerprint(&hdr).expect("must fingerprint");
        assert_eq!((fp.python_major, fp.python_minor), (2, 7));
        assert_eq!(fp.header_len, 8);
    }

    #[test]
    fn rejects_random_bytes() {
        assert!(fingerprint(b"PK\x03\x04zip-archive").is_none());
    }
}
