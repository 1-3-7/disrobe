use crate::cookie::Cookie;
use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryType {
    Script,
    Module,
    Package,
    Pyz,
    PyzZipfile,
    Binary,
    Data,
    Dependency,
    RuntimeOption,
    Splash,
    Symlink,
    Unknown(u8),
}

impl EntryType {
    pub const fn from_byte(b: u8) -> Self {
        match b {
            b's' => Self::Script,
            b'm' => Self::Module,
            b'M' => Self::Package,
            b'z' => Self::Pyz,
            b'Z' => Self::PyzZipfile,
            b'b' => Self::Binary,
            b'x' => Self::Data,
            b'd' => Self::Dependency,
            b'o' => Self::RuntimeOption,
            b'l' => Self::Splash,
            b'n' => Self::Symlink,
            other => Self::Unknown(other),
        }
    }

    pub const fn is_pyc_carrier(self) -> bool {
        matches!(self, Self::Script | Self::Module | Self::Package)
    }

    pub const fn is_pyz(self) -> bool {
        matches!(self, Self::Pyz | Self::PyzZipfile)
    }

    pub const fn should_skip(self) -> bool {
        matches!(self, Self::Dependency | Self::RuntimeOption)
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Script => "script",
            Self::Module => "module",
            Self::Package => "package",
            Self::Pyz => "pyz",
            Self::PyzZipfile => "pyz-zipfile",
            Self::Binary => "binary",
            Self::Data => "data",
            Self::Dependency => "dependency",
            Self::RuntimeOption => "runtime-option",
            Self::Splash => "splash",
            Self::Symlink => "symlink",
            Self::Unknown(_) => "unknown",
        }
    }
}

#[derive(Debug, Clone)]
pub struct TocEntry {
    pub entry_size: u32,
    pub entry_position: u32,
    pub compressed_size: u32,
    pub uncompressed_size: u32,
    pub compressed_flag: u8,
    pub entry_type: EntryType,
    pub name: String,
}

pub fn walk_toc(image: &[u8], cookie: &Cookie) -> Result<Vec<TocEntry>> {
    let file_size: usize = image.len();
    let cookie_size: usize = cookie.variant.header_len();
    let cookie_end: usize = cookie.magic_offset + cookie_size;
    let tail_bytes: usize = file_size.saturating_sub(cookie_end);
    let overlay_size: usize = cookie.length_of_package as usize + tail_bytes;
    let overlay_pos: usize = file_size.saturating_sub(overlay_size);
    let toc_pos: usize = overlay_pos + cookie.toc_offset as usize;
    let toc_len: usize = cookie.toc_length as usize;

    if toc_pos + toc_len > file_size {
        return Err(Error::TocWalk(
            toc_pos,
            format!(
                "toc end {} exceeds file size {}",
                toc_pos + toc_len,
                file_size
            ),
        ));
    }

    let toc_region: &[u8] = &image[toc_pos..toc_pos + toc_len];
    let mut entries: Vec<TocEntry> = Vec::new();
    let mut cursor: usize = 0usize;
    while cursor < toc_region.len() {
        if cursor + 4 > toc_region.len() {
            break;
        }
        let entry_size: u32 = u32::from_be_bytes([
            toc_region[cursor],
            toc_region[cursor + 1],
            toc_region[cursor + 2],
            toc_region[cursor + 3],
        ]);
        if entry_size < 18 || (cursor + entry_size as usize) > toc_region.len() {
            return Err(Error::TocWalk(
                toc_pos + cursor,
                format!("invalid entry size {entry_size} at toc offset {cursor}"),
            ));
        }
        let entry_position: u32 = read_u32_be(toc_region, cursor + 4)?;
        let compressed_size: u32 = read_u32_be(toc_region, cursor + 8)?;
        let uncompressed_size: u32 = read_u32_be(toc_region, cursor + 12)?;
        let compressed_flag: u8 = toc_region[cursor + 16];
        let type_byte: u8 = toc_region[cursor + 17];
        let name_len: usize = entry_size as usize - 18;
        let name_bytes: &[u8] = &toc_region[cursor + 18..cursor + 18 + name_len];
        let name: String = sanitize_name(name_bytes)?;
        entries.push(TocEntry {
            entry_size,
            entry_position,
            compressed_size,
            uncompressed_size,
            compressed_flag,
            entry_type: EntryType::from_byte(type_byte),
            name,
        });
        cursor += entry_size as usize;
    }
    Ok(entries)
}

fn read_u32_be(buf: &[u8], at: usize) -> Result<u32> {
    let slice: &[u8] = buf
        .get(at..at + 4)
        .ok_or_else(|| Error::TocWalk(at, format!("buffer too short at offset {at}")))?;
    Ok(u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn sanitize_name(name_bytes: &[u8]) -> Result<String> {
    let null_end: usize = name_bytes
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(name_bytes.len());
    let raw: String = String::from_utf8_lossy(&name_bytes[..null_end]).into_owned();
    if raw.contains("..") || raw.starts_with('/') || raw.starts_with('\\') {
        return Err(Error::PathTraversal(raw));
    }
    Ok(raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn type_byte_table() {
        assert_eq!(EntryType::from_byte(b's'), EntryType::Script);
        assert_eq!(EntryType::from_byte(b'm'), EntryType::Module);
        assert_eq!(EntryType::from_byte(b'M'), EntryType::Package);
        assert_eq!(EntryType::from_byte(b'z'), EntryType::Pyz);
        assert_eq!(EntryType::from_byte(b'b'), EntryType::Binary);
        assert_eq!(EntryType::from_byte(b'x'), EntryType::Data);
        assert_eq!(EntryType::from_byte(b'd'), EntryType::Dependency);
        assert_eq!(EntryType::from_byte(b'o'), EntryType::RuntimeOption);
        assert_eq!(EntryType::from_byte(b'l'), EntryType::Splash);
        assert_eq!(EntryType::from_byte(b'n'), EntryType::Symlink);
        assert!(matches!(EntryType::from_byte(b'?'), EntryType::Unknown(_)));
    }

    #[test]
    fn pyc_carrier_predicates() {
        assert!(EntryType::Script.is_pyc_carrier());
        assert!(EntryType::Module.is_pyc_carrier());
        assert!(EntryType::Package.is_pyc_carrier());
        assert!(!EntryType::Binary.is_pyc_carrier());
        assert!(EntryType::Pyz.is_pyz());
        assert!(EntryType::Dependency.should_skip());
    }

    #[test]
    fn sanitize_rejects_traversal() {
        let err: Option<Error> = sanitize_name(b"../etc/passwd\0").err();
        assert!(matches!(err, Some(Error::PathTraversal(_))));
    }

    #[test]
    fn label_table_is_ascii_and_nonempty() {
        for label in [
            EntryType::Script.label(),
            EntryType::Module.label(),
            EntryType::Package.label(),
            EntryType::Pyz.label(),
            EntryType::PyzZipfile.label(),
            EntryType::Binary.label(),
            EntryType::Data.label(),
            EntryType::Dependency.label(),
            EntryType::RuntimeOption.label(),
            EntryType::Splash.label(),
            EntryType::Symlink.label(),
            EntryType::Unknown(0).label(),
        ] {
            assert!(label.is_ascii(), "label '{label}' is not ascii");
            assert!(!label.is_empty());
        }
    }
}
