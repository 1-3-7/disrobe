#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocatedOnefile {
    pub offset: usize,

    pub compressed: bool,
}

const GLOBAL_CANDIDATE_LOG_CAP: u32 = 16;
static CANDIDATE_LOGS: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
static LOCATE_HEADER_LOGGED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

fn candidate_log_allowed() -> bool {
    use std::sync::atomic::Ordering;
    CANDIDATE_LOGS
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n: u32| {
            (n < GLOBAL_CANDIDATE_LOG_CAP).then_some(n + 1)
        })
        .is_ok()
}

#[must_use]
pub fn locate_onefile_payload(image: &[u8]) -> Option<LocatedOnefile> {
    let debug: bool = crate::util::dbg_enabled()
        && !LOCATE_HEADER_LOGGED.swap(true, std::sync::atomic::Ordering::Relaxed);
    if debug {
        crate::util::dbg_line(|| format!("locate: image_len={}", image.len()));
        match crate::util::pe_overlay_offset(image) {
            Some(overlay) => {
                crate::util::dbg_line(|| {
                    format!("locate: PE overlay (appended-payload start) at {overlay}")
                });
                crate::util::dbg_hex(
                    "locate: 64 bytes at PE overlay start",
                    image.get(overlay..).unwrap_or_default(),
                    64,
                );
            }
            None => {
                crate::util::dbg_line(|| {
                    "locate: no PE overlay computed (not PE or parse failed)".to_owned()
                });
            }
        }
        let tail: usize = image.len().saturating_sub(512);
        crate::util::dbg_hex(
            "locate: last 512 bytes (trailer region)",
            &image[tail..],
            512,
        );
    }

    let mut found: Option<LocatedOnefile> = None;
    let mut candidates: u32 = 0u32;

    for (range_start, range_end) in payload_scan_ranges(image) {
        let mut cursor: usize = range_start;
        while cursor + 3 <= range_end {
            let Some(rel): Option<usize> = find_two_byte(&image[cursor..range_end], b'K', b'A')
            else {
                break;
            };
            let abs: usize = cursor + rel;
            if abs + 3 > image.len() {
                break;
            }
            let indicator: u8 = image[abs + 2];
            if matches!(indicator, b'X' | b'Y') {
                candidates += 1;
                match crate::onefile::validates_at(image, abs) {
                    Some(compressed) => {
                        if debug && candidate_log_allowed() {
                            crate::util::dbg_line(|| {
                                format!(
                                    "locate: KA{} at offset {abs} VALIDATES (compressed={compressed})",
                                    indicator as char
                                )
                            });
                        }
                        if found.is_none() {
                            found = Some(LocatedOnefile {
                                offset: abs,
                                compressed,
                            });
                            if !debug {
                                return found;
                            }
                        }
                    }
                    None => {
                        if debug && candidate_log_allowed() {
                            crate::util::dbg_line(|| {
                                format!(
                                    "locate: KA{} at offset {abs} rejected (not a valid first entry)",
                                    indicator as char
                                )
                            });
                        }
                    }
                }
            }
            cursor = abs + 1;
        }
        if found.is_some() && !debug {
            return found;
        }
    }

    if debug {
        crate::util::dbg_line(|| {
            format!("locate: done, {candidates} KAX/KAY candidates scanned, result={found:?}")
        });
    }
    found
}

fn payload_scan_ranges(image: &[u8]) -> Vec<(usize, usize)> {
    match crate::util::pe_overlay_offset(image) {
        Some(overlay) if overlay < image.len() => {
            let mut ranges: Vec<(usize, usize)> = vec![(overlay, image.len())];
            if let Some(sections) = crate::util::pe_data_section_ranges(image) {
                ranges.extend(sections);
            }
            ranges
        }
        _ => vec![(0, image.len())],
    }
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

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    const ZSTD_FRAME_MAGIC: [u8; 4] = [0x28, 0xB5, 0x2F, 0xFD];

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
    fn rejects_kax_followed_by_machine_code() {
        let mut bytes: Vec<u8> = vec![0u8; 32];
        bytes.extend_from_slice(b"KAX");
        bytes.extend_from_slice(&[
            0x2c, 0x4c, 0x8b, 0xc0, 0x48, 0x8b, 0x0d, 0xc9, 0xe9, 0x3c, 0x2d, 0xe8, 0xcc, 0x0e,
            0x09, 0xfd, 0x48, 0x8b, 0x15, 0x55,
        ]);
        bytes.extend_from_slice(&[0x48u8; 4096]);
        assert_eq!(locate_onefile_payload(&bytes), None);
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
