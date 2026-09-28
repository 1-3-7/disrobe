use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContainerKind {
    Pickle,
    Zip,
    Zip64,
    Tar,
    Gzip,
    Bzip2,
    Xz,
    Zstd,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolyglotReport {
    pub is_pickle: bool,
    pub kinds: Vec<ContainerKind>,
    pub is_polyglot: bool,
    pub notes: Vec<String>,
}

#[must_use]
pub fn looks_like_pickle(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }
    if bytes[0] == 0x80 && bytes.len() >= 2 && bytes[1] <= 5 {
        return true;
    }
    matches!(
        bytes[0],
        b'(' | b']' | b'}' | b'c' | b'\x88' | b'\x89' | b'N' | b'I' | b'K' | b'M' | b'J' | b'X'
    ) && has_trailing_stop(bytes)
}

fn has_trailing_stop(bytes: &[u8]) -> bool {
    let tail: &[u8] = &bytes[bytes.len().saturating_sub(64)..];
    tail.contains(&b'.')
}

#[must_use]
pub fn analyze(bytes: &[u8]) -> PolyglotReport {
    let mut kinds: Vec<ContainerKind> = Vec::new();
    let mut notes: Vec<String> = Vec::new();
    let eocd: Option<ZipEnd> = find_zip_end(bytes);
    let pickle_after_zip: bool = eocd
        .as_ref()
        .and_then(|end: &ZipEnd| bytes.get(end.archive_end..))
        .is_some_and(decodes_as_pickle);
    let pickle_in_comment: bool = eocd
        .as_ref()
        .and_then(|end: &ZipEnd| bytes.get(end.comment.clone()))
        .is_some_and(decodes_as_pickle);
    let is_pickle: bool = looks_like_pickle(bytes) || pickle_after_zip || pickle_in_comment;
    if is_pickle {
        kinds.push(ContainerKind::Pickle);
    }

    let zip_at_start: bool = bytes.starts_with(b"PK\x03\x04") || bytes.starts_with(b"PK\x05\x06");
    if zip_at_start || eocd.is_some() {
        kinds.push(ContainerKind::Zip);
        if has_zip64_eocd(bytes) {
            kinds.push(ContainerKind::Zip64);
            notes.push("ZIP64 end-of-central-directory locator present".to_string());
        }
        if zip_at_start {
            notes.push(
                "ZIP local-file header at offset 0 - weaponized model archives stack pickle + zip"
                    .to_string(),
            );
        } else if let Some(end) = &eocd {
            notes.push(format!(
                "ZIP end-of-central-directory at offset {} after leading non-zip bytes - a zip reader opens this file",
                end.record
            ));
        }
        if pickle_after_zip {
            notes.push("a pickle stream follows the end of the zip archive".to_string());
        }
        if pickle_in_comment {
            notes.push("the zip archive comment holds a pickle stream".to_string());
        }
    }
    if is_tar(bytes) {
        kinds.push(ContainerKind::Tar);
        notes.push("POSIX tar ustar magic at offset 257".to_string());
    }
    if bytes.starts_with(&[0x1f, 0x8b]) {
        kinds.push(ContainerKind::Gzip);
    }
    if bytes.starts_with(b"BZh") {
        kinds.push(ContainerKind::Bzip2);
    }
    if bytes.starts_with(&[0xfd, b'7', b'z', b'X', b'Z', 0x00]) {
        kinds.push(ContainerKind::Xz);
    }
    if bytes.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        kinds.push(ContainerKind::Zstd);
    }

    let is_polyglot: bool = is_pickle
        && kinds
            .iter()
            .any(|k: &ContainerKind| !matches!(k, ContainerKind::Pickle));

    crate::debug::dbg_section("pickle polyglot detection");
    crate::debug::dbg_kv("polyglot", || {
        format!("is_pickle={is_pickle} is_polyglot={is_polyglot} containers={kinds:?}")
    });
    if crate::debug::dbg_enabled() {
        for note in &notes {
            crate::debug::dbg_line(|| format!("polyglot note: {note}"));
        }
    }

    PolyglotReport {
        is_pickle,
        kinds,
        is_polyglot,
        notes,
    }
}

fn decodes_as_pickle(bytes: &[u8]) -> bool {
    looks_like_pickle(bytes)
        && crate::disasm::disassemble(bytes)
            .is_ok_and(|dis: crate::disasm::Disassembly| dis.stop_offset.is_some())
}

const EOCD_LEN: usize = 22;
const MAX_ZIP_COMMENT: usize = 0xFFFF;

#[derive(Debug, Clone, PartialEq, Eq)]
struct ZipEnd {
    record: usize,
    comment: std::ops::Range<usize>,
    archive_end: usize,
}

fn find_zip_end(bytes: &[u8]) -> Option<ZipEnd> {
    let search_from: usize = bytes
        .len()
        .saturating_sub(EOCD_LEN + MAX_ZIP_COMMENT + 4096);
    let window: &[u8] = bytes.get(search_from..)?;
    let relative: usize = window.windows(4).rposition(|w: &[u8]| w == b"PK\x05\x06")?;
    let record: usize = search_from + relative;
    let length_bytes: [u8; 2] = bytes.get(record + 20..record + EOCD_LEN)?.try_into().ok()?;
    let comment_start: usize = record + EOCD_LEN;
    let archive_end: usize =
        comment_start.checked_add(usize::from(u16::from_le_bytes(length_bytes)))?;
    if archive_end > bytes.len() {
        return None;
    }
    Some(ZipEnd {
        record,
        comment: comment_start..archive_end,
        archive_end,
    })
}

fn has_zip64_eocd(bytes: &[u8]) -> bool {
    bytes
        .windows(4)
        .rev()
        .take(4096)
        .any(|w: &[u8]| w == [b'P', b'K', 0x06, 0x07])
}

fn is_tar(bytes: &[u8]) -> bool {
    bytes.len() >= 265 && &bytes[257..262] == b"ustar"
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn detects_proto2_pickle() {
        assert!(looks_like_pickle(b"\x80\x02N."));
    }

    #[test]
    fn zip_is_detected() {
        let r: PolyglotReport = analyze(b"PK\x03\x04rest");
        assert!(r.kinds.contains(&ContainerKind::Zip));
    }

    fn empty_zip(comment: &[u8]) -> Vec<u8> {
        let mut v: Vec<u8> = b"PK\x05\x06".to_vec();
        v.extend_from_slice(&[0u8; 16]);
        let len: u16 = u16::try_from(comment.len()).expect("short comment");
        v.extend_from_slice(&len.to_le_bytes());
        v.extend_from_slice(comment);
        v
    }

    #[test]
    fn a_zip_appended_to_a_pickle_is_a_polyglot() {
        let mut bytes: Vec<u8> = b"\x80\x02N.".to_vec();
        bytes.extend(empty_zip(b""));
        let r: PolyglotReport = analyze(&bytes);
        assert!(r.is_pickle);
        assert!(r.kinds.contains(&ContainerKind::Zip));
        assert!(r.is_polyglot);
    }

    #[test]
    fn a_pickle_appended_to_a_zip_is_a_polyglot() {
        let mut bytes: Vec<u8> = empty_zip(b"");
        bytes.extend_from_slice(b"\x80\x02N.");
        let r: PolyglotReport = analyze(&bytes);
        assert!(r.is_pickle);
        assert!(r.kinds.contains(&ContainerKind::Zip));
        assert!(r.is_polyglot);
    }

    #[test]
    fn a_pickle_in_the_zip_comment_is_a_polyglot() {
        let r: PolyglotReport = analyze(&empty_zip(b"\x80\x02N."));
        assert!(r.is_polyglot);
    }

    #[test]
    fn text_after_a_zip_is_not_a_pickle() {
        let mut bytes: Vec<u8> = empty_zip(b"");
        bytes.extend_from_slice(b"Notes: see the README.");
        let r: PolyglotReport = analyze(&bytes);
        assert!(!r.is_pickle);
        assert!(!r.is_polyglot);
    }

    #[test]
    fn a_plain_zip_is_not_a_polyglot() {
        let r: PolyglotReport = analyze(&empty_zip(b"release notes"));
        assert!(r.kinds.contains(&ContainerKind::Zip));
        assert!(!r.is_pickle);
        assert!(!r.is_polyglot);
    }
}
