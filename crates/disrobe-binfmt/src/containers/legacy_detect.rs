pub const PARTCLONE_MAGIC: &[u8; 15] = b"partclone-image";
const PARTCLONE_VERSION_OFFSET: usize = 30;

pub const STUFFIT_CLASSIC: &[u8; 4] = b"SIT!";
pub const STUFFIT_5: &[u8; 4] = b"rLau";
pub const STUFFIT_X: &[u8; 7] = b"StuffIt";

const QNX6_SUPERBLOCK_MAGIC: u32 = 0x6819_1122;
const QNX_IFS_STARTUP: &[u8; 4] = &[0xeb, 0x7e, 0xff, 0x00];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PartcloneImage {
    pub version: [u8; 4],
}

#[must_use]
pub fn detect_partclone(bytes: &[u8]) -> Option<PartcloneImage> {
    if !bytes.starts_with(PARTCLONE_MAGIC) {
        return None;
    }
    let version: [u8; 4] = bytes
        .get(PARTCLONE_VERSION_OFFSET..PARTCLONE_VERSION_OFFSET + 4)?
        .try_into()
        .ok()?;
    if version == *b"0001" || version == *b"0002" {
        Some(PartcloneImage { version })
    } else {
        None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StuffItKind {
    Classic,
    Version5,
    SitX,
}

#[must_use]
pub fn detect_stuffit(bytes: &[u8]) -> Option<StuffItKind> {
    if bytes.starts_with(STUFFIT_CLASSIC) {
        return Some(StuffItKind::Classic);
    }
    if bytes.starts_with(STUFFIT_5) {
        return Some(StuffItKind::Version5);
    }
    if bytes.starts_with(STUFFIT_X) {
        return Some(StuffItKind::SitX);
    }
    None
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QnxKind {
    Qnx6Fs,
    IfsStartup,
}

#[must_use]
pub fn detect_qnx(bytes: &[u8]) -> Option<QnxKind> {
    if bytes.starts_with(QNX_IFS_STARTUP) {
        return Some(QnxKind::IfsStartup);
    }
    if bytes.len() >= 8 {
        let magic_le: u32 = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let magic_le0: u32 = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if magic_le == QNX6_SUPERBLOCK_MAGIC || magic_le0 == QNX6_SUPERBLOCK_MAGIC {
            return Some(QnxKind::Qnx6Fs);
        }
    }
    None
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn detect_partclone_v2() {
        let mut bytes: Vec<u8> = PARTCLONE_MAGIC.to_vec();
        bytes.resize(PARTCLONE_VERSION_OFFSET, 0);
        bytes.extend_from_slice(b"0002");
        bytes.extend([0u8; 64]);
        assert_eq!(detect_partclone(&bytes).map(|p| p.version), Some(*b"0002"));
        assert!(detect_partclone(b"not partclone at all").is_none());
    }

    #[test]
    fn detect_stuffit_variants() {
        assert_eq!(detect_stuffit(b"SIT!rest"), Some(StuffItKind::Classic));
        assert_eq!(detect_stuffit(b"rLau...."), Some(StuffItKind::Version5));
        assert_eq!(detect_stuffit(b"StuffIt (c)"), Some(StuffItKind::SitX));
        assert!(detect_stuffit(b"PK\x03\x04").is_none());
    }

    #[test]
    fn detect_qnx_startup_and_fs() {
        assert_eq!(
            detect_qnx(&[0xeb, 0x7e, 0xff, 0x00, 0, 0]),
            Some(QnxKind::IfsStartup)
        );
        let mut fs: Vec<u8> = vec![0u8; 16];
        fs[0..4].copy_from_slice(&QNX6_SUPERBLOCK_MAGIC.to_le_bytes());
        assert_eq!(detect_qnx(&fs), Some(QnxKind::Qnx6Fs));
    }
}
