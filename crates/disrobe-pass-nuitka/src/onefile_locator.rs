//! Validated locator for a Nuitka `--onefile` payload inside an image.

/// A validated onefile payload location.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocatedOnefile {
    /// Offset of the `K` of the `KA` magic within the image.
    pub offset: usize,
    /// Whether the indicator byte selected zstd compression (`Y`).
    pub compressed: bool,
}

const ZSTD_FRAME_MAGIC: [u8; 4] = [0x28, 0xB5, 0x2F, 0xFD];

/// Scan `image` for the first validated `KA[XY]` onefile payload, returning its location.
#[must_use]
pub fn locate_onefile_payload(image: &[u8]) -> Option<LocatedOnefile> {
    let mut cursor: usize = 0usize;
    while cursor + 3 <= image.len() {
        let rel: usize = find_two_byte(&image[cursor..], b'K', b'A')?;
        let abs: usize = cursor + rel;
        if abs + 3 > image.len() {
            return None;
        }
        let indicator: u8 = image[abs + 2];
        let body: &[u8] = &image[abs + 3..];
        match indicator {
            b'Y' if starts_zstd_frame(body) => {
                return Some(LocatedOnefile {
                    offset: abs,
                    compressed: true,
                });
            }
            b'X' if starts_plausible_entry(body) => {
                return Some(LocatedOnefile {
                    offset: abs,
                    compressed: false,
                });
            }
            _ => {}
        }
        cursor = abs + 1;
    }
    None
}

#[inline]
fn find_two_byte(haystack: &[u8], a: u8, b: u8) -> Option<usize> {
    let mut i: usize = 0usize;
    while i + 1 < haystack.len() {
        let rel: usize = haystack[i..].iter().position(|&x| x == a)?;
        let at: usize = i + rel;
        if at + 1 < haystack.len() && haystack[at + 1] == b {
            return Some(at);
        }
        i = at + 1;
    }
    None
}

#[inline]
fn starts_zstd_frame(body: &[u8]) -> bool {
    if body.len() < 4 {
        return false;
    }
    let head: [u8; 4] = [body[0], body[1], body[2], body[3]];
    head == ZSTD_FRAME_MAGIC
        || (head[0] & 0xF0 == 0x50 && head[1] == 0x2A && head[2] == 0x4D && head[3] == 0x18)
}

/// Whether a stored (`KAX`) payload begins with a plausible filename or empty terminator.
#[inline]
fn starts_plausible_entry(body: &[u8]) -> bool {
    if body.len() >= 2 && body[0] == 0 && body[1] == 0 {
        return true;
    }
    if !body.is_empty() && body[0] == 0 {
        return true;
    }
    let utf16_ok: bool = body.len() >= 4
        && is_path_ascii(body[0])
        && body[1] == 0
        && (is_path_ascii(body[2]) || (body[2] == 0 && body[3] == 0));
    let utf8_ok: bool = !body.is_empty()
        && is_path_ascii(body[0])
        && body.iter().take(MAX_NAME_PROBE).any(|&byte| byte == 0);
    utf16_ok || utf8_ok
}

const MAX_NAME_PROBE: usize = 4096;

#[inline]
const fn is_path_ascii(byte: u8) -> bool {
    matches!(byte, 0x20..=0x7E) && !matches!(byte, b'?' | b'*' | b'<' | b'>' | b'|' | b'"')
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn locates_validated_kay() {
        let mut bytes: Vec<u8> = vec![0u8; 64];
        bytes.extend_from_slice(b"KAY");
        bytes.extend_from_slice(&ZSTD_FRAME_MAGIC);
        bytes.extend_from_slice(&[0u8; 16]);
        let loc: LocatedOnefile = locate_onefile_payload(&bytes).expect("validated KAY");
        assert_eq!(loc.offset, 64);
        assert!(loc.compressed);
    }

    #[test]
    fn rejects_kay_without_zstd_frame() {
        let mut bytes: Vec<u8> = vec![0u8; 64];
        bytes.extend_from_slice(b"KAY");
        bytes.extend_from_slice(&[0xABu8; 16]);
        assert_eq!(locate_onefile_payload(&bytes), None);
    }

    #[test]
    fn locates_validated_kax_with_utf16_name() {
        let mut bytes: Vec<u8> = b"KAX".to_vec();
        for unit in "hello.exe".encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        bytes.extend_from_slice(&[0u8, 0u8]);
        bytes.extend_from_slice(&8u64.to_le_bytes());
        bytes.extend_from_slice(b"MZ\x90\x00data");
        bytes.extend_from_slice(&[0u8, 0u8]);
        let loc: LocatedOnefile = locate_onefile_payload(&bytes).expect("validated KAX");
        assert_eq!(loc.offset, 0);
        assert!(!loc.compressed);
    }

    #[test]
    fn skips_coincidental_ka_garbage_then_finds_real() {
        let mut bytes: Vec<u8> = vec![0u8; 16];
        bytes.extend_from_slice(b"KAZ");
        bytes.extend_from_slice(&[0xFFu8; 8]);
        let real_at: usize = bytes.len();
        bytes.extend_from_slice(b"KAY");
        bytes.extend_from_slice(&ZSTD_FRAME_MAGIC);
        bytes.extend_from_slice(&[0u8; 8]);
        let loc: LocatedOnefile = locate_onefile_payload(&bytes).expect("real KAY after garbage");
        assert_eq!(loc.offset, real_at);
    }

    #[test]
    fn empty_archive_kax_is_valid() {
        let bytes: Vec<u8> = b"KAX\0\0".to_vec();
        let loc: LocatedOnefile = locate_onefile_payload(&bytes).expect("empty KAX");
        assert!(!loc.compressed);
    }

    #[test]
    fn no_payload_returns_none() {
        let bytes: Vec<u8> = (0..2048u32).map(|i| (i & 0x7F) as u8).collect();
        let _ = locate_onefile_payload(&bytes);
    }
}
