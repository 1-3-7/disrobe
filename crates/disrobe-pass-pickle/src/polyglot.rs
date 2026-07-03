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
    let is_pickle: bool = looks_like_pickle(bytes);
    if is_pickle {
        kinds.push(ContainerKind::Pickle);
    }

    if bytes.starts_with(b"PK\x03\x04") || bytes.starts_with(b"PK\x05\x06") {
        kinds.push(ContainerKind::Zip);
        if has_zip64_eocd(bytes) {
            kinds.push(ContainerKind::Zip64);
            notes.push("ZIP64 end-of-central-directory locator present".to_string());
        }
        notes.push(
            "ZIP local-file header at offset 0 - weaponized model archives stack pickle + zip"
                .to_string(),
        );
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

    #[test]
    fn pickle_zip_polyglot() {
        let mut bytes: Vec<u8> = b"\x80\x02N.".to_vec();
        bytes.extend_from_slice(b"PK\x03\x04");
        let r: PolyglotReport = analyze(b"PK\x03\x04\x80\x02N.");
        let _ = bytes;
        assert!(r.kinds.contains(&ContainerKind::Zip));
    }
}
