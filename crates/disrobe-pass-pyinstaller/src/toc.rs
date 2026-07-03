use crate::cookie::Cookie;
use crate::debug::{dbg_enabled, dbg_kv, dbg_line, dbg_section};
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
    PyzModule,
    PyzPackage,
    BaseLibraryModule,
    BaseLibraryPackage,
    Unknown(u8),
}

impl EntryType {
    #[must_use]
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

    #[must_use]
    pub const fn is_pyc_carrier(self) -> bool {
        matches!(
            self,
            Self::Script
                | Self::Module
                | Self::Package
                | Self::PyzModule
                | Self::PyzPackage
                | Self::BaseLibraryModule
                | Self::BaseLibraryPackage
        )
    }

    #[must_use]
    pub const fn carries_full_filename(self) -> bool {
        matches!(
            self,
            Self::PyzModule | Self::PyzPackage | Self::BaseLibraryModule | Self::BaseLibraryPackage
        )
    }

    #[must_use]
    pub const fn is_pyz(self) -> bool {
        matches!(self, Self::Pyz | Self::PyzZipfile)
    }

    #[must_use]
    pub const fn should_skip(self) -> bool {
        matches!(self, Self::Dependency | Self::RuntimeOption)
    }

    #[must_use]
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
            Self::PyzModule => "pyz-module",
            Self::PyzPackage => "pyz-package",
            Self::BaseLibraryModule => "base-library-module",
            Self::BaseLibraryPackage => "base-library-package",
            Self::Unknown(_) => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NativeImageKind {
    WindowsPe,
    LinuxElf,
    MachO,
}

impl NativeImageKind {
    pub(crate) const fn onefile_layout_hint(self) -> &'static str {
        match self {
            Self::WindowsPe => "windows-onefile-exe",
            Self::LinuxElf => "linux-onefile-elf",
            Self::MachO => "macos-onefile-macho",
        }
    }
}

pub(crate) fn classify_native_image(head: &[u8]) -> Option<NativeImageKind> {
    match head.get(0..4)? {
        [b'M', b'Z', _, _] => Some(NativeImageKind::WindowsPe),
        [0x7F, b'E', b'L', b'F'] => Some(NativeImageKind::LinuxElf),
        [0xFE, 0xED, 0xFA, 0xCE | 0xCF] | [0xCE | 0xCF, 0xFA, 0xED, 0xFE] => {
            Some(NativeImageKind::MachO)
        }
        _ => None,
    }
}

pub(crate) fn overlay_position(image_len: usize, cookie: &Cookie) -> Result<usize> {
    let cookie_size: usize = cookie.variant.header_len();
    let cookie_end: usize = cookie
        .magic_offset
        .checked_add(cookie_size)
        .ok_or_else(|| {
            Error::TocWalk(
                cookie.magic_offset,
                "cookie end offset overflows usize".to_owned(),
            )
        })?;
    if cookie_end > image_len {
        return Err(Error::TocWalk(
            cookie.magic_offset,
            format!("cookie end {cookie_end} exceeds file size {image_len}"),
        ));
    }
    let tail_bytes: usize = image_len - cookie_end;
    let package_len: usize = usize::try_from(cookie.length_of_package).map_err(|_| {
        Error::TocWalk(
            cookie.magic_offset,
            format!(
                "package length {} does not fit usize",
                cookie.length_of_package
            ),
        )
    })?;
    let overlay_size: usize = package_len.checked_add(tail_bytes).ok_or_else(|| {
        Error::TocWalk(
            cookie.magic_offset,
            format!("package length {package_len} plus tail {tail_bytes} overflows usize"),
        )
    })?;
    if overlay_size > image_len {
        return Err(Error::TocWalk(
            cookie.magic_offset,
            format!(
                "package length {package_len} plus tail {tail_bytes} exceeds file size {image_len}"
            ),
        ));
    }
    Ok(image_len - overlay_size)
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
    let overlay_pos: usize = overlay_position(file_size, cookie)?;
    let toc_offset: usize = usize::try_from(cookie.toc_offset).map_err(|_| {
        Error::TocWalk(
            overlay_pos,
            format!("toc offset {} does not fit usize", cookie.toc_offset),
        )
    })?;
    let toc_len: usize = usize::try_from(cookie.toc_length).map_err(|_| {
        Error::TocWalk(
            overlay_pos,
            format!("toc length {} does not fit usize", cookie.toc_length),
        )
    })?;
    let toc_pos: usize = overlay_pos.checked_add(toc_offset).ok_or_else(|| {
        Error::TocWalk(
            overlay_pos,
            format!("toc offset {toc_offset} overflows usize"),
        )
    })?;
    let toc_end: usize = toc_pos
        .checked_add(toc_len)
        .ok_or_else(|| Error::TocWalk(toc_pos, format!("toc length {toc_len} overflows usize")))?;

    dbg_section("toc.walk");
    dbg_kv("overlay_pos", || format!("{overlay_pos:#x}"));
    dbg_kv("toc_pos", || format!("{toc_pos:#x}"));
    dbg_kv("toc_len", || toc_len.to_string());

    if toc_end > file_size {
        dbg_line(|| format!("toc end {toc_end} exceeds file size {file_size}"));
        return Err(Error::TocWalk(
            toc_pos,
            format!("toc end {toc_end} exceeds file size {file_size}"),
        ));
    }

    let toc_region: &[u8] = &image[toc_pos..toc_end];
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
        let entry_size_usize: usize = usize::try_from(entry_size).map_err(|_| {
            Error::TocWalk(
                toc_pos + cursor,
                format!("entry size {entry_size} does not fit usize"),
            )
        })?;
        let entry_end: usize = cursor.checked_add(entry_size_usize).ok_or_else(|| {
            Error::TocWalk(
                toc_pos + cursor,
                format!("entry size {entry_size} overflows usize"),
            )
        })?;
        if entry_size < 18 || entry_end > toc_region.len() {
            dbg_line(|| format!("invalid entry size {entry_size} at toc offset {cursor}"));
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
        let name_len: usize = entry_size_usize - 18;
        let name_bytes: &[u8] = &toc_region[cursor + 18..cursor + 18 + name_len];
        let name: String = sanitize_name(name_bytes)?;
        let entry_type: EntryType = EntryType::from_byte(type_byte);
        if dbg_enabled() {
            let label: &'static str = entry_type.label();
            dbg_line(|| {
                format!(
                    "entry '{name}' type={label} pos={entry_position:#x} csize={compressed_size} usize={uncompressed_size} flag={compressed_flag}"
                )
            });
        }
        entries.push(TocEntry {
            entry_size,
            entry_position,
            compressed_size,
            uncompressed_size,
            compressed_flag,
            entry_type,
            name,
        });
        cursor = entry_end;
    }
    dbg_kv("entry_count", || entries.len().to_string());
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
        .map_or(name_bytes.len(), |position: usize| position);
    let raw: String = String::from_utf8_lossy(&name_bytes[..null_end]).into_owned();
    if raw.contains("..")
        || raw.starts_with('/')
        || raw.starts_with('\\')
        || raw.contains(['\\', ':'])
    {
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
    fn sanitize_rejects_windows_absolute_and_backslash_names() {
        for raw in [
            b"C:\\temp\\evil.pyc\0".as_slice(),
            b"pkg\\mod.pyc\0".as_slice(),
        ] {
            let err: Option<Error> = sanitize_name(raw).err();
            assert!(matches!(err, Some(Error::PathTraversal(_))));
        }
    }

    #[test]
    fn toc_rejects_package_length_larger_than_image() {
        let mut image: Vec<u8> = vec![0u8; 64];
        image[..4].copy_from_slice(&18u32.to_be_bytes());
        let cookie: Cookie = Cookie {
            variant: crate::cookie::CookieVariant::Pre21,
            magic_offset: 40,
            length_of_package: 128,
            toc_offset: 0,
            toc_length: 18,
            pyver: 311,
            python_libname: None,
            python_major: 3,
            python_minor: 11,
        };
        assert!(matches!(
            walk_toc(&image, &cookie),
            Err(Error::TocWalk(_, _))
        ));
    }

    #[test]
    fn native_image_classifier_covers_every_magic_form() {
        assert_eq!(
            classify_native_image(b"MZ\x90\x00"),
            Some(NativeImageKind::WindowsPe)
        );
        assert_eq!(
            classify_native_image(b"\x7fELF"),
            Some(NativeImageKind::LinuxElf)
        );
        for magic in [
            [0xFE_u8, 0xED, 0xFA, 0xCE],
            [0xFE, 0xED, 0xFA, 0xCF],
            [0xCE, 0xFA, 0xED, 0xFE],
            [0xCF, 0xFA, 0xED, 0xFE],
        ] {
            assert_eq!(
                classify_native_image(&magic),
                Some(NativeImageKind::MachO),
                "mach-o magic {magic:?} must classify",
            );
        }
        assert_eq!(classify_native_image(b"PK\x03\x04"), None);
        assert_eq!(classify_native_image(b"MZ"), None);
        assert_eq!(classify_native_image(&[]), None);
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
            EntryType::PyzModule.label(),
            EntryType::PyzPackage.label(),
            EntryType::BaseLibraryModule.label(),
            EntryType::BaseLibraryPackage.label(),
            EntryType::Unknown(0).label(),
        ] {
            assert!(label.is_ascii(), "label '{label}' is not ascii");
            assert!(!label.is_empty());
        }
    }
}
