use crate::containers::squashfs::{
    SQUASHFS_MAGIC_LE, SquashfsSuperblock, parse_squashfs_superblock,
};
use crate::error::Result;

pub fn detect_snap(bytes: &[u8]) -> Option<SquashfsSuperblock> {
    if bytes.len() < 100 {
        return None;
    }
    let magic: [u8; 4] = SQUASHFS_MAGIC_LE.to_le_bytes();
    if bytes[0..4] != magic {
        return None;
    }
    let parsed: Result<SquashfsSuperblock> = parse_squashfs_superblock(bytes, 0);
    parsed.ok()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::containers::squashfs::SUPERBLOCK_MIN_BYTES;

    fn synth_snap() -> Vec<u8> {
        let mut out: Vec<u8> = vec![0u8; 128];
        out[0..4].copy_from_slice(&SQUASHFS_MAGIC_LE.to_le_bytes());
        out[20..22].copy_from_slice(&4u16.to_le_bytes());
        out[28..30].copy_from_slice(&4u16.to_le_bytes());
        let _ = SUPERBLOCK_MIN_BYTES;
        out
    }

    #[test]
    fn detects_snap_squashfs_at_offset_zero() {
        let bytes: Vec<u8> = synth_snap();
        let sb: SquashfsSuperblock = detect_snap(&bytes).expect("snap detection");
        assert_eq!(sb.version_major, 4);
    }

    #[test]
    fn rejects_short() {
        assert!(detect_snap(&[0u8; 8]).is_none());
    }

    #[test]
    fn rejects_non_squashfs() {
        let bytes: Vec<u8> = vec![0u8; 100];
        assert!(detect_snap(&bytes).is_none());
    }
}
