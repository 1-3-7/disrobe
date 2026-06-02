use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::error::{Error, Result};
use crate::util::find_subslice;

const BUILD_INFO_MARKER: &[u8] = b"__nuitka_build_info";
const NUITKA_PREFIX_MARKER: &[u8] = b"Nuitka-";
const MAX_FIELD_LEN: usize = 256;
const MAX_RECORD_LEN: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum BuildInfoFlag {
    Standalone,
    Onefile,
    Modular,
    Lto,
    Pgo,
    NoConsole,
    NoFollow,
    DebugBuild,
    ReleaseBuild,
    MingwLink,
    MsvcLink,
    ClangLink,
    GccLink,
    MacosBundle,
    WindowsConsole,
    WindowsGui,
    NoDeprecations,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct BuildInfo {
    pub raw_marker_offset: Option<usize>,
    pub raw_version: Option<String>,
    pub python_version: Option<String>,
    pub os_token: Option<String>,
    pub arch_token: Option<String>,
    pub compiler_token: Option<String>,
    pub flags: Vec<BuildInfoFlag>,
    pub fields: BTreeMap<String, String>,
}

pub fn scan_build_info(image: &[u8]) -> Result<BuildInfo> {
    let mut info: BuildInfo = BuildInfo::default();

    if let Some(marker_off) = find_subslice(image, BUILD_INFO_MARKER) {
        info.raw_marker_offset = Some(marker_off);
        let record_start: usize = marker_off + BUILD_INFO_MARKER.len();
        let record_end: usize = (record_start + MAX_RECORD_LEN).min(image.len());
        decode_record(&image[record_start..record_end], &mut info);
    }

    if info.raw_version.is_none()
        && let Some(version) = scan_nuitka_prefix_version(image)
    {
        info.raw_version = Some(version);
    }

    scan_compiler_and_os(image, &mut info);
    classify_flags_from_strings(image, &mut info);

    if info.raw_marker_offset.is_none()
        && info.raw_version.is_none()
        && info.flags.is_empty()
        && info.fields.is_empty()
    {
        return Err(Error::BuildInfoMissing);
    }
    Ok(info)
}

fn decode_record(record: &[u8], info: &mut BuildInfo) {
    let mut cursor: usize = 0usize;
    let mut field_index: usize = 0usize;
    while cursor < record.len() && field_index < 32 {
        let Some(field_end): Option<usize> = next_nul_or_unprintable(&record[cursor..]) else {
            break;
        };
        if field_end == 0 {
            cursor += 1;
            field_index += 1;
            continue;
        }
        let raw_field: &[u8] = &record[cursor..cursor + field_end];
        if raw_field.len() > MAX_FIELD_LEN {
            cursor += field_end + 1;
            field_index += 1;
            continue;
        }
        let Ok(s): core::result::Result<&str, core::str::Utf8Error> =
            core::str::from_utf8(raw_field)
        else {
            cursor += field_end + 1;
            field_index += 1;
            continue;
        };
        ingest_record_field(s, field_index, info);
        cursor += field_end + 1;
        field_index += 1;
    }
}

fn ingest_record_field(raw: &str, position: usize, info: &mut BuildInfo) {
    let key: &'static str = match position {
        0 => "version",
        1 => "python_version",
        2 => "os",
        3 => "arch",
        4 => "compiler",
        _ => return,
    };
    info.fields.insert(key.to_owned(), raw.to_owned());
    match position {
        0 if info.raw_version.is_none() => info.raw_version = Some(raw.to_owned()),
        1 if info.python_version.is_none() => info.python_version = Some(raw.to_owned()),
        2 if info.os_token.is_none() => info.os_token = Some(raw.to_owned()),
        3 if info.arch_token.is_none() => info.arch_token = Some(raw.to_owned()),
        4 if info.compiler_token.is_none() => info.compiler_token = Some(raw.to_owned()),
        _ => {}
    }
}

fn next_nul_or_unprintable(slice: &[u8]) -> Option<usize> {
    if slice.is_empty() {
        return None;
    }
    for (idx, &byte) in slice.iter().enumerate() {
        if byte == 0 {
            return Some(idx);
        }
        if !(byte.is_ascii_graphic()
            || byte == b' '
            || byte == b'.'
            || byte == b'-'
            || byte == b'_'
            || byte == b'/'
            || byte == b'+'
            || byte == b'('
            || byte == b')')
        {
            return Some(idx);
        }
    }
    Some(slice.len())
}

fn scan_nuitka_prefix_version(image: &[u8]) -> Option<String> {
    let idx: usize = find_subslice(image, NUITKA_PREFIX_MARKER)?;
    let start: usize = idx + NUITKA_PREFIX_MARKER.len();
    let end: usize = (start + 32).min(image.len());
    let slice: &[u8] = &image[start..end];
    let printable: Vec<u8> = slice
        .iter()
        .take_while(|&&b| b.is_ascii_digit() || b == b'.' || b == b'r' || b == b'c' || b == b'-')
        .copied()
        .collect();
    if printable.is_empty() {
        None
    } else {
        Some(String::from_utf8_lossy(&printable).into_owned())
    }
}

fn scan_compiler_and_os(image: &[u8], info: &mut BuildInfo) {
    if info.compiler_token.is_none() {
        for tok in [
            b"GCC".as_slice(),
            b"Clang".as_slice(),
            b"MSVC".as_slice(),
            b"mingw".as_slice(),
        ] {
            if find_subslice(image, tok).is_some()
                && let Ok(s) = core::str::from_utf8(tok)
            {
                info.compiler_token = Some(s.to_owned());
                break;
            }
        }
    }
    if info.os_token.is_none() {
        for tok in [
            b"Linux".as_slice(),
            b"Darwin".as_slice(),
            b"Windows".as_slice(),
            b"FreeBSD".as_slice(),
        ] {
            if find_subslice(image, tok).is_some()
                && let Ok(s) = core::str::from_utf8(tok)
            {
                info.os_token = Some(s.to_owned());
                break;
            }
        }
    }
}

fn classify_flags_from_strings(image: &[u8], info: &mut BuildInfo) {
    let mapping: &[(&[u8], BuildInfoFlag)] = &[
        (b"--standalone", BuildInfoFlag::Standalone),
        (b"--onefile", BuildInfoFlag::Onefile),
        (b"--module", BuildInfoFlag::Modular),
        (b"--lto", BuildInfoFlag::Lto),
        (b"--pgo", BuildInfoFlag::Pgo),
        (b"--disable-console", BuildInfoFlag::NoConsole),
        (b"--nofollow-imports", BuildInfoFlag::NoFollow),
        (b"NUITKA_DEBUG", BuildInfoFlag::DebugBuild),
        (b"NUITKA_RELEASE", BuildInfoFlag::ReleaseBuild),
        (b"-lmingw32", BuildInfoFlag::MingwLink),
        (b"link.exe", BuildInfoFlag::MsvcLink),
        (b"clang++", BuildInfoFlag::ClangLink),
        (b"g++", BuildInfoFlag::GccLink),
        (b".app/Contents", BuildInfoFlag::MacosBundle),
        (b"CONSOLE_APPLICATION", BuildInfoFlag::WindowsConsole),
        (b"WINDOWS_APPLICATION", BuildInfoFlag::WindowsGui),
        (b"NUITKA_NO_DEPRECATION", BuildInfoFlag::NoDeprecations),
    ];

    let mut seen: BTreeSet<BuildInfoFlag> = BTreeSet::new();
    for (needle, flag) in mapping {
        if find_subslice(image, needle).is_some() {
            seen.insert(*flag);
        }
    }
    info.flags.extend(seen);
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn synth_record(fields: &[&str]) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        out.extend_from_slice(BUILD_INFO_MARKER);
        for f in fields {
            out.extend_from_slice(f.as_bytes());
            out.push(0);
        }
        out.push(0);
        out
    }

    #[test]
    fn empty_image_errors_with_missing() {
        let Err(err): Result<BuildInfo> = scan_build_info(&[]) else {
            panic!("empty must error");
        };
        assert!(matches!(err, Error::BuildInfoMissing));
    }

    #[test]
    fn marker_with_record_extracts_fields() {
        let bytes: Vec<u8> = synth_record(&["2.5.1", "3.12.4", "Linux", "x86_64", "GCC"]);
        let info: BuildInfo = scan_build_info(&bytes).expect("synthetic record");
        assert_eq!(info.raw_version.as_deref(), Some("2.5.1"));
        assert_eq!(info.python_version.as_deref(), Some("3.12.4"));
        assert_eq!(info.os_token.as_deref(), Some("Linux"));
        assert_eq!(info.arch_token.as_deref(), Some("x86_64"));
        assert_eq!(info.compiler_token.as_deref(), Some("GCC"));
        assert_eq!(info.fields.get("os"), Some(&"Linux".to_owned()));
    }

    #[test]
    fn nuitka_prefix_version_when_no_marker() {
        let mut bytes: Vec<u8> = vec![0u8; 1024];
        bytes[400..407].copy_from_slice(b"Nuitka-");
        bytes[407..412].copy_from_slice(b"2.6.0");
        let info: BuildInfo = scan_build_info(&bytes).expect("prefix version path");
        assert_eq!(info.raw_version.as_deref(), Some("2.6.0"));
        assert!(info.raw_marker_offset.is_none());
    }

    #[test]
    fn flag_classification_dedups_and_orders() {
        let mut bytes: Vec<u8> = synth_record(&["2.5.1"]);
        bytes.extend_from_slice(b"\0--standalone\0--onefile\0--standalone\0--lto\0");
        let info: BuildInfo = scan_build_info(&bytes).expect("with flags");
        assert!(info.flags.contains(&BuildInfoFlag::Standalone));
        assert!(info.flags.contains(&BuildInfoFlag::Onefile));
        assert!(info.flags.contains(&BuildInfoFlag::Lto));
        let std_count: usize = info
            .flags
            .iter()
            .filter(|&&f| f == BuildInfoFlag::Standalone)
            .count();
        assert_eq!(std_count, 1);
    }

    #[test]
    fn windows_console_application_marker_detected() {
        let mut bytes: Vec<u8> = synth_record(&["2.5.0"]);
        bytes.extend_from_slice(b"\0CONSOLE_APPLICATION\0link.exe\0");
        let info: BuildInfo = scan_build_info(&bytes).expect("windows markers");
        assert!(info.flags.contains(&BuildInfoFlag::WindowsConsole));
        assert!(info.flags.contains(&BuildInfoFlag::MsvcLink));
    }

    #[test]
    fn truncated_record_does_not_panic() {
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice(BUILD_INFO_MARKER);
        bytes.extend_from_slice(b"2.5.0");
        let info: BuildInfo = scan_build_info(&bytes).expect("trailing without nul");
        assert_eq!(info.raw_version.as_deref(), Some("2.5.0"));
    }

    #[test]
    fn malformed_unicode_field_is_skipped_not_fatal() {
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice(BUILD_INFO_MARKER);
        bytes.extend_from_slice(&[0xFF, 0xFE, 0xFD, 0]);
        bytes.extend_from_slice(b"3.12\0");
        let info: BuildInfo = scan_build_info(&bytes).expect("malformed first field, valid second");
        assert!(info.raw_version.is_none() || info.python_version.is_some());
    }

    #[test]
    fn macos_bundle_marker_detected() {
        let mut bytes: Vec<u8> = synth_record(&["2.5.1", "3.11.0", "Darwin"]);
        bytes.extend_from_slice(b"\0App.app/Contents/MacOS/binary\0");
        let info: BuildInfo = scan_build_info(&bytes).expect("macos");
        assert!(info.flags.contains(&BuildInfoFlag::MacosBundle));
        assert_eq!(info.os_token.as_deref(), Some("Darwin"));
    }
}
