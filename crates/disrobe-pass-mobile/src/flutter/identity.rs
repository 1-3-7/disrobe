use std::collections::{BTreeMap, BTreeSet};
use std::io::Cursor;

use object::read::macho::{FatArch as _, MachOFatFile32, MachOFatFile64};
use object::{FileKind, Object as _, ObjectSection as _, ObjectSymbol as _};
use serde::Serialize;
use sha2::{Digest as _, Sha256};

use super::{
    DART_ISOLATE_DATA_SYMBOL, DART_SNAPSHOT_FEATURES_MAX, DART_SNAPSHOT_HEADER_FIXED_LEN,
    DART_VM_DATA_SYMBOL, DartSnapshotHeader, DartSnapshotKind, parse_dart_snapshot,
};
use crate::error::{Error, Result};

const DART_SNAPSHOT_TABLE: &str = include_str!("dart_snapshot_hashes.tsv");
const FLUTTER_ENGINE_TABLE: &str = include_str!("flutter_engine_revisions.tsv");
const SNAPSHOT_MAGIC: [u8; 4] = [0xf5, 0xf5, 0xdc, 0xdc];
const HEADER_READ_MAX: usize = DART_SNAPSHOT_HEADER_FIXED_LEN + DART_SNAPSHOT_FEATURES_MAX + 1;
const SCANNED_HEADERS_MAX: usize = 8;
const STRING_LEN_MIN: usize = 4;
const STRING_LEN_MAX: usize = 256;
const HASH_STRINGS_MAX: usize = 32;
const REVISION_STRINGS_MAX: usize = 32;
const VERSION_STRINGS_MAX: usize = 8;
const LIBRARIES_MAX: usize = 64;
const FAT_ARCHES_MAX: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum FlutterContainer {
    Apk,
    Aab,
    Ipa,
    Archive,
    Library,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum FlutterLibraryRole {
    App,
    Engine,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SnapshotStampSource {
    Symbol,
    Scan,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct DartSdkRelease {
    pub dart_version: String,
    pub dart_revision: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct FlutterRelease {
    pub flutter_version: String,
    pub engine_revision: String,
    pub dart_revision: String,
    pub dart_version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FlutterSnapshotStamp {
    pub source: SnapshotStampSource,
    pub symbol: Option<String>,
    pub offset: u64,
    pub kind: DartSnapshotKind,
    pub snapshot_hash: String,
    pub features: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct DartVersionString {
    pub version: String,
    pub channel: String,
    pub built: String,
    pub target: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FlutterLibrary {
    pub path: String,
    pub role: FlutterLibraryRole,
    pub abi: Option<String>,
    pub format: Option<String>,
    pub architecture: Option<String>,
    pub size: u64,
    pub sha256: String,
    pub build_id: Option<String>,
    pub snapshots: Vec<FlutterSnapshotStamp>,
    pub dart_versions: Vec<DartVersionString>,
    pub hash_strings: Vec<String>,
    pub revision_strings: Vec<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FlutterIdentityReport {
    pub container: FlutterContainer,
    pub size: u64,
    pub sha256: String,
    pub flutter_detected: bool,
    pub snapshot_hash: Option<String>,
    pub snapshot_hash_candidates: Vec<String>,
    pub dart_sdk_releases: Vec<DartSdkRelease>,
    pub dart_version: Option<String>,
    pub engine_revision: Option<String>,
    pub flutter_releases: Vec<FlutterRelease>,
    pub flutter_releases_with_dart: Vec<String>,
    pub libraries: Vec<FlutterLibrary>,
    pub findings: Vec<String>,
}

#[must_use]
pub fn dart_sdk_releases(snapshot_hash: &str) -> Vec<DartSdkRelease> {
    dart_sdk_releases_in(DART_SNAPSHOT_TABLE, snapshot_hash)
}

#[must_use]
pub fn dart_sdk_releases_in(table: &str, snapshot_hash: &str) -> Vec<DartSdkRelease> {
    table_rows(table)
        .filter(|row: &Vec<&str>| row.first() == Some(&snapshot_hash))
        .filter_map(|row: Vec<&str>| match row.as_slice() {
            [_, version, revision] => Some(DartSdkRelease {
                dart_version: (*version).to_owned(),
                dart_revision: (*revision).to_owned(),
            }),
            _ => None,
        })
        .collect()
}

#[must_use]
pub fn flutter_releases() -> Vec<FlutterRelease> {
    table_rows(FLUTTER_ENGINE_TABLE)
        .filter_map(|row: Vec<&str>| match row.as_slice() {
            [engine, flutter, dart_revision, dart_version] => Some(FlutterRelease {
                flutter_version: (*flutter).to_owned(),
                engine_revision: (*engine).to_owned(),
                dart_revision: (*dart_revision).to_owned(),
                dart_version: (!dart_version.is_empty()).then(|| (*dart_version).to_owned()),
            }),
            _ => None,
        })
        .collect()
}

fn table_rows(table: &str) -> impl Iterator<Item = Vec<&str>> {
    table
        .lines()
        .filter(|line: &&str| !line.is_empty() && !line.starts_with('#'))
        .map(|line: &str| line.split('\t').collect())
}

pub fn flutter_identity(bytes: &[u8]) -> Result<FlutterIdentityReport> {
    let (container, mut libraries): (FlutterContainer, Vec<FlutterLibrary>) =
        if bytes.starts_with(b"PK\x03\x04") || bytes.starts_with(b"PK\x05\x06") {
            archive_libraries(bytes)?
        } else {
            (FlutterContainer::Library, standalone_libraries(bytes)?)
        };
    libraries.sort_by(|a: &FlutterLibrary, b: &FlutterLibrary| {
        (&a.path, &a.abi, a.role).cmp(&(&b.path, &b.abi, b.role))
    });
    Ok(summarize(container, bytes, libraries))
}

fn archive_libraries(bytes: &[u8]) -> Result<(FlutterContainer, Vec<FlutterLibrary>)> {
    let mut archive: zip::ZipArchive<Cursor<&[u8]>> =
        zip::ZipArchive::new(Cursor::new(bytes)).map_err(Error::from)?;
    let count: usize = crate::checked_zip_entry_count(archive.len())?;
    let mut names: Vec<(usize, String)> = Vec::new();
    let mut android: bool = false;
    let mut bundle: bool = false;
    let mut ios: bool = false;
    for index in 0..count {
        let entry: zip::read::ZipFile<'_> = archive.by_index_raw(index).map_err(Error::from)?;
        let name: &str = entry.name();
        android |= name == "AndroidManifest.xml";
        bundle |= name == "base/manifest/AndroidManifest.xml";
        ios |= name.starts_with("Payload/");
        if entry.is_file() && library_role(name).is_some() {
            names.push((index, name.to_owned()));
        }
    }
    if names.len() > LIBRARIES_MAX {
        return Err(Error::FlutterIdentityTooManyLibraries {
            found: names.len(),
            limit: LIBRARIES_MAX,
        });
    }
    let container: FlutterContainer = if bundle {
        FlutterContainer::Aab
    } else if android {
        FlutterContainer::Apk
    } else if ios {
        FlutterContainer::Ipa
    } else {
        FlutterContainer::Archive
    };
    let mut libraries: Vec<FlutterLibrary> = Vec::new();
    for (index, name) in names {
        let Some(role): Option<FlutterLibraryRole> = library_role(&name) else {
            continue;
        };
        let entry: zip::read::ZipFile<'_> = archive.by_index(index).map_err(Error::from)?;
        let data: Vec<u8> = crate::read_zip_file_bounded(entry, &name)?;
        libraries.extend(read_library(&name, path_abi(&name), role, &data));
    }
    Ok((container, libraries))
}

fn standalone_libraries(bytes: &[u8]) -> Result<Vec<FlutterLibrary>> {
    let kind: FileKind = FileKind::parse(bytes)
        .map_err(|error: object::Error| Error::FlutterIdentityInput(error.to_string()))?;
    if !matches!(
        kind,
        FileKind::Elf32
            | FileKind::Elf64
            | FileKind::MachO32
            | FileKind::MachO64
            | FileKind::MachOFat32
            | FileKind::MachOFat64
            | FileKind::Pe32
            | FileKind::Pe64
    ) {
        return Err(Error::FlutterIdentityInput(format!(
            "{kind:?} is not a shared library format a Flutter build ships"
        )));
    }
    let app: Vec<FlutterLibrary> = read_library("", None, FlutterLibraryRole::App, bytes);
    if app
        .iter()
        .any(|library: &FlutterLibrary| !library.snapshots.is_empty())
    {
        return Ok(app);
    }
    let engine: Vec<FlutterLibrary> = read_library("", None, FlutterLibraryRole::Engine, bytes);
    if engine.iter().any(|library: &FlutterLibrary| {
        !library.dart_versions.is_empty() || !library.hash_strings.is_empty()
    }) {
        return Ok(engine);
    }
    Ok(Vec::new())
}

fn library_role(path: &str) -> Option<FlutterLibraryRole> {
    let base: &str = path.rsplit('/').next().unwrap_or(path);
    let app: bool = matches!(base, "libapp.so" | "app.so")
        || path.ends_with("App.framework/App")
        || path.ends_with("App.framework/Versions/A/App");
    let engine: bool = matches!(
        base,
        "libflutter.so" | "flutter_windows.dll" | "libflutter_linux_gtk.so"
    ) || path.ends_with("Flutter.framework/Flutter")
        || path.ends_with("FlutterMacOS.framework/FlutterMacOS")
        || path.ends_with("FlutterMacOS.framework/Versions/A/FlutterMacOS");
    match (app, engine) {
        (true, false) => Some(FlutterLibraryRole::App),
        (false, true) => Some(FlutterLibraryRole::Engine),
        _ => None,
    }
}

fn path_abi(path: &str) -> Option<String> {
    let rest: &str = path
        .strip_prefix("base/lib/")
        .or_else(|| path.strip_prefix("lib/"))?;
    let (abi, file): (&str, &str) = rest.split_once('/')?;
    (!abi.is_empty() && !file.contains('/')).then(|| abi.to_owned())
}

fn read_library(
    path: &str,
    abi: Option<String>,
    role: FlutterLibraryRole,
    data: &[u8],
) -> Vec<FlutterLibrary> {
    let slices: Vec<(Option<String>, &[u8])> = match fat_slices(data) {
        Ok(Some(slices)) => slices
            .into_iter()
            .map(|(arch, slice): (String, &[u8])| (Some(arch), slice))
            .collect(),
        Ok(None) => vec![(abi, data)],
        Err(message) => {
            let mut library: FlutterLibrary = empty_library(path, abi, role, data);
            library.error = Some(message);
            return vec![library];
        }
    };
    slices
        .into_iter()
        .map(|(slice_abi, slice): (Option<String>, &[u8])| {
            let mut library: FlutterLibrary = empty_library(path, slice_abi, role, slice);
            fill_library(&mut library, slice);
            library
        })
        .collect()
}

type FatSlice<'data> = (
    object::Architecture,
    core::result::Result<&'data [u8], object::Error>,
);
type NamedSlices<'data> = core::result::Result<Option<Vec<(String, &'data [u8])>>, String>;

fn fat_slices(data: &[u8]) -> NamedSlices<'_> {
    let arches: Vec<FatSlice<'_>> = match FileKind::parse(data) {
        Ok(FileKind::MachOFat32) => MachOFatFile32::parse(data)
            .map_err(|error: object::Error| error.to_string())?
            .arches()
            .iter()
            .map(|arch| (arch.architecture(), arch.data(data)))
            .collect(),
        Ok(FileKind::MachOFat64) => MachOFatFile64::parse(data)
            .map_err(|error: object::Error| error.to_string())?
            .arches()
            .iter()
            .map(|arch| (arch.architecture(), arch.data(data)))
            .collect(),
        _ => return Ok(None),
    };
    if arches.len() > FAT_ARCHES_MAX {
        return Err(format!(
            "universal Mach-O declares {} slices, over the {FAT_ARCHES_MAX} slice cap",
            arches.len()
        ));
    }
    let mut slices: Vec<(String, &[u8])> = Vec::with_capacity(arches.len());
    for (architecture, slice) in arches {
        let bytes: &[u8] = slice.map_err(|error: object::Error| error.to_string())?;
        slices.push((architecture_name(architecture), bytes));
    }
    Ok(Some(slices))
}

fn empty_library(
    path: &str,
    abi: Option<String>,
    role: FlutterLibraryRole,
    data: &[u8],
) -> FlutterLibrary {
    FlutterLibrary {
        path: path.to_owned(),
        role,
        abi,
        format: None,
        architecture: None,
        size: u64::try_from(data.len()).unwrap_or(u64::MAX),
        sha256: sha256_hex(data),
        build_id: None,
        snapshots: Vec::new(),
        dart_versions: Vec::new(),
        hash_strings: Vec::new(),
        revision_strings: Vec::new(),
        error: None,
    }
}

fn fill_library(library: &mut FlutterLibrary, data: &[u8]) {
    match object::File::parse(data) {
        Ok(file) => {
            library.format = Some(format!("{:?}", file.format()).to_ascii_lowercase());
            let architecture: String = architecture_name(file.architecture());
            if library.abi.is_none() {
                library.abi = Some(architecture.clone());
            }
            library.architecture = Some(architecture);
            library.build_id = build_id(&file);
            if library.role == FlutterLibraryRole::App {
                library.snapshots = symbol_stamps(&file, data);
            }
        }
        Err(error) => library.error = Some(format!("not an object file: {error}")),
    }
    match library.role {
        FlutterLibraryRole::App => {
            if library.snapshots.is_empty() {
                library.snapshots = scanned_stamps(data);
            }
        }
        FlutterLibraryRole::Engine => scan_engine_strings(library, data),
    }
}

fn architecture_name(architecture: object::Architecture) -> String {
    match architecture {
        object::Architecture::Aarch64 => "arm64".to_owned(),
        object::Architecture::Arm => "arm".to_owned(),
        object::Architecture::X86_64 => "x86_64".to_owned(),
        object::Architecture::I386 => "x86".to_owned(),
        other => format!("{other:?}").to_ascii_lowercase(),
    }
}

fn build_id(file: &object::File<'_>) -> Option<String> {
    if let Ok(Some(id)) = file.build_id() {
        return Some(hex_lower(id));
    }
    if let Ok(Some(uuid)) = file.mach_uuid() {
        return Some(hex_lower(&uuid));
    }
    None
}

fn symbol_stamps(file: &object::File<'_>, data: &[u8]) -> Vec<FlutterSnapshotStamp> {
    let mut found: BTreeMap<&'static str, FlutterSnapshotStamp> = BTreeMap::new();
    for symbol in file.dynamic_symbols().chain(file.symbols()) {
        let Ok(name): core::result::Result<&str, object::Error> = symbol.name() else {
            continue;
        };
        let Some(wanted): Option<&'static str> = [DART_VM_DATA_SYMBOL, DART_ISOLATE_DATA_SYMBOL]
            .into_iter()
            .find(|wanted: &&str| name == *wanted || name.strip_prefix('_') == Some(*wanted))
        else {
            continue;
        };
        if found.contains_key(wanted) {
            continue;
        }
        let Some(index): Option<object::SectionIndex> = symbol.section_index() else {
            continue;
        };
        let Ok(section) = file.section_by_index(index) else {
            continue;
        };
        let Some((section_offset, section_size)): Option<(u64, u64)> = section.file_range() else {
            continue;
        };
        let Some(relative): Option<u64> = symbol.address().checked_sub(section.address()) else {
            continue;
        };
        if relative >= section_size {
            continue;
        }
        let Some(offset): Option<u64> = section_offset.checked_add(relative) else {
            continue;
        };
        let Some(section_end): Option<u64> = section_offset.checked_add(section_size) else {
            continue;
        };
        if let Some(stamp) = stamp_at(data, offset, section_end, SnapshotStampSource::Symbol) {
            found.insert(
                wanted,
                FlutterSnapshotStamp {
                    symbol: Some(wanted.to_owned()),
                    ..stamp
                },
            );
        }
    }
    found.into_values().collect()
}

fn scanned_stamps(data: &[u8]) -> Vec<FlutterSnapshotStamp> {
    let end: u64 = u64::try_from(data.len()).unwrap_or(u64::MAX);
    let mut stamps: Vec<FlutterSnapshotStamp> = Vec::new();
    let mut start: usize = 0;
    while stamps.len() < SCANNED_HEADERS_MAX {
        let Some(found): Option<usize> = data.get(start..).and_then(|rest: &[u8]| {
            rest.windows(4)
                .position(|window: &[u8]| window == SNAPSHOT_MAGIC)
        }) else {
            break;
        };
        let at: usize = start + found;
        if let Ok(offset) = u64::try_from(at)
            && let Some(stamp) = stamp_at(data, offset, end, SnapshotStampSource::Scan)
            && !matches!(stamp.kind, DartSnapshotKind::Unknown(_))
        {
            stamps.push(stamp);
        }
        start = at + 1;
    }
    stamps
}

fn stamp_at(
    data: &[u8],
    offset: u64,
    limit: u64,
    source: SnapshotStampSource,
) -> Option<FlutterSnapshotStamp> {
    let start: usize = usize::try_from(offset).ok()?;
    let limit: usize = usize::try_from(limit).ok()?.min(data.len());
    let end: usize = start.checked_add(HEADER_READ_MAX)?.min(limit);
    let window: &[u8] = data.get(start..end)?;
    let header: DartSnapshotHeader = parse_dart_snapshot(window).ok()?;
    if !header
        .version_hash
        .bytes()
        .all(|byte: u8| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || !header
            .features
            .bytes()
            .all(|byte: u8| byte.is_ascii_graphic() || byte == b' ')
    {
        return None;
    }
    Some(FlutterSnapshotStamp {
        source,
        symbol: None,
        offset,
        kind: header.kind,
        snapshot_hash: header.version_hash,
        features: header
            .features
            .split(' ')
            .filter(|feature: &&str| !feature.is_empty())
            .map(str::to_owned)
            .collect(),
    })
}

fn scan_engine_strings(library: &mut FlutterLibrary, data: &[u8]) {
    let mut versions: BTreeSet<DartVersionString> = BTreeSet::new();
    let mut hashes: BTreeSet<String> = BTreeSet::new();
    let mut revisions: BTreeSet<String> = BTreeSet::new();
    for run in data.split(|byte: &u8| *byte == 0) {
        if run.len() < STRING_LEN_MIN
            || run.len() > STRING_LEN_MAX
            || !run.iter().all(|byte: &u8| (0x20..=0x7e).contains(byte))
        {
            continue;
        }
        let Ok(text): core::result::Result<&str, core::str::Utf8Error> = core::str::from_utf8(run)
        else {
            continue;
        };
        if is_lower_hex(text, 32) {
            if hashes.len() < HASH_STRINGS_MAX {
                hashes.insert(text.to_owned());
            }
        } else if is_lower_hex(text, 40) {
            if revisions.len() < REVISION_STRINGS_MAX {
                revisions.insert(text.to_owned());
            }
        } else if versions.len() < VERSION_STRINGS_MAX
            && let Some(version) = parse_dart_version_string(text)
        {
            versions.insert(version);
        }
    }
    library.dart_versions = versions.into_iter().collect();
    library.hash_strings = hashes.into_iter().collect();
    library.revision_strings = revisions.into_iter().collect();
}

fn is_lower_hex(text: &str, len: usize) -> bool {
    text.len() == len
        && text
            .bytes()
            .all(|byte: u8| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[must_use]
pub fn parse_dart_version_string(text: &str) -> Option<DartVersionString> {
    let (version, rest): (&str, &str) = text.split_once(" (")?;
    let (channel, rest): (&str, &str) = rest.split_once(") (")?;
    let (built, rest): (&str, &str) = rest.split_once(") on \"")?;
    let target: &str = rest.strip_suffix('"')?;
    let version_ok: bool = version.starts_with(|c: char| c.is_ascii_digit())
        && version.contains('.')
        && version
            .chars()
            .all(|c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+'));
    let channel_ok: bool =
        !channel.is_empty() && channel.chars().all(|c: char| c.is_ascii_lowercase());
    let target_ok: bool = target.contains('_')
        && target
            .chars()
            .all(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
    let built_ok: bool = !built.is_empty() && !built.contains(['(', ')', '"']);
    (version_ok && channel_ok && target_ok && built_ok).then(|| DartVersionString {
        version: version.to_owned(),
        channel: channel.to_owned(),
        built: built.to_owned(),
        target: target.to_owned(),
    })
}

fn summarize(
    container: FlutterContainer,
    bytes: &[u8],
    libraries: Vec<FlutterLibrary>,
) -> FlutterIdentityReport {
    let mut findings: Vec<String> = Vec::new();
    let app_hashes: BTreeSet<&str> = libraries
        .iter()
        .flat_map(|library: &FlutterLibrary| &library.snapshots)
        .map(|stamp: &FlutterSnapshotStamp| stamp.snapshot_hash.as_str())
        .collect();
    let engine_hashes: BTreeSet<&str> = libraries
        .iter()
        .flat_map(|library: &FlutterLibrary| &library.hash_strings)
        .map(String::as_str)
        .filter(|hash: &&str| app_hashes.contains(hash) || !dart_sdk_releases(hash).is_empty())
        .collect();
    let candidates: BTreeSet<&str> = app_hashes.union(&engine_hashes).copied().collect();
    let snapshot_hash: Option<String> = match candidates.len() {
        1 => candidates.first().map(|hash: &&str| (*hash).to_owned()),
        0 => None,
        _ => {
            findings.push(format!(
                "the libraries disagree on the Dart snapshot hash ({}); no single SDK is claimed",
                candidates.iter().copied().collect::<Vec<&str>>().join(", ")
            ));
            None
        }
    };
    let releases: Vec<DartSdkRelease> = snapshot_hash
        .as_deref()
        .map(dart_sdk_releases)
        .unwrap_or_default();
    if let Some(hash) = &snapshot_hash
        && releases.is_empty()
    {
        findings.push(format!(
            "snapshot hash {hash} is not the hash of a stable Dart SDK release from 2.0.0 in the bundled table (a beta, dev or locally patched SDK, or a release newer than the table)"
        ));
    }
    let versions: BTreeSet<&str> = libraries
        .iter()
        .flat_map(|library: &FlutterLibrary| &library.dart_versions)
        .map(|version: &DartVersionString| version.version.as_str())
        .collect();
    let dart_version: Option<String> = match versions.len() {
        1 => versions.first().map(|version: &&str| (*version).to_owned()),
        0 => None,
        _ => {
            findings.push(format!(
                "the engines name more than one Dart version ({})",
                versions.iter().copied().collect::<Vec<&str>>().join(", ")
            ));
            None
        }
    };
    if let Some(version) = &dart_version
        && !releases.is_empty()
        && !releases
            .iter()
            .any(|release: &DartSdkRelease| &release.dart_version == version)
    {
        findings.push(format!(
            "the engine names Dart {version}, but the snapshot hash belongs to {}",
            releases
                .iter()
                .map(|release: &DartSdkRelease| release.dart_version.as_str())
                .collect::<Vec<&str>>()
                .join(", ")
        ));
    }
    let known: Vec<FlutterRelease> = flutter_releases();
    let revisions: BTreeSet<&str> = libraries
        .iter()
        .flat_map(|library: &FlutterLibrary| &library.revision_strings)
        .map(String::as_str)
        .collect();
    let engine_revisions: BTreeSet<&str> = revisions
        .iter()
        .copied()
        .filter(|revision: &&str| {
            known
                .iter()
                .any(|release: &FlutterRelease| release.engine_revision == *revision)
        })
        .collect();
    let engine_revision: Option<String> = match engine_revisions.len() {
        1 => engine_revisions
            .first()
            .map(|revision: &&str| (*revision).to_owned()),
        0 => {
            if !revisions.is_empty() {
                findings.push(format!(
                    "the engine carries {} revision string(s), none of them the engine of a Flutter release tag in the bundled table",
                    revisions.len()
                ));
            }
            None
        }
        _ => {
            findings.push(format!(
                "the engines carry more than one Flutter release engine revision ({})",
                engine_revisions
                    .iter()
                    .copied()
                    .collect::<Vec<&str>>()
                    .join(", ")
            ));
            None
        }
    };
    let flutter_releases_exact: Vec<FlutterRelease> = engine_revision
        .as_deref()
        .map(|revision: &str| {
            known
                .iter()
                .filter(|release: &&FlutterRelease| release.engine_revision == revision)
                .cloned()
                .collect()
        })
        .unwrap_or_default();
    let dart_versions: BTreeSet<&str> = releases
        .iter()
        .map(|release: &DartSdkRelease| release.dart_version.as_str())
        .collect();
    let flutter_releases_with_dart: Vec<String> = known
        .iter()
        .filter(|release: &&FlutterRelease| {
            release
                .dart_version
                .as_deref()
                .is_some_and(|version: &str| dart_versions.contains(version))
        })
        .map(|release: &FlutterRelease| release.flutter_version.clone())
        .collect();
    pair_findings(&libraries, &mut findings);
    for library in &libraries {
        if let Some(error) = &library.error {
            findings.push(format!("{}: {error}", display_path(library)));
        }
        if library.role == FlutterLibraryRole::App && library.snapshots.is_empty() {
            findings.push(format!(
                "{}: no Dart snapshot header was found",
                display_path(library)
            ));
        }
    }
    FlutterIdentityReport {
        container,
        size: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        sha256: sha256_hex(bytes),
        flutter_detected: !libraries.is_empty(),
        snapshot_hash,
        snapshot_hash_candidates: candidates.into_iter().map(str::to_owned).collect(),
        dart_sdk_releases: releases,
        dart_version,
        engine_revision,
        flutter_releases: flutter_releases_exact,
        flutter_releases_with_dart,
        libraries,
        findings,
    }
}

fn pair_findings(libraries: &[FlutterLibrary], findings: &mut Vec<String>) {
    let mut roles: BTreeMap<&str, BTreeSet<FlutterLibraryRole>> = BTreeMap::new();
    for library in libraries {
        if library.path.is_empty() {
            continue;
        }
        let abi: &str = library.abi.as_deref().unwrap_or("unknown");
        roles.entry(abi).or_default().insert(library.role);
    }
    for (abi, present) in roles {
        if !present.contains(&FlutterLibraryRole::App) {
            findings.push(format!("{abi}: a Flutter engine without an app snapshot"));
        }
        if !present.contains(&FlutterLibraryRole::Engine) {
            findings.push(format!("{abi}: an app snapshot without a Flutter engine"));
        }
    }
}

fn display_path(library: &FlutterLibrary) -> String {
    match (&library.path, &library.abi) {
        (path, _) if !path.is_empty() => path.clone(),
        (_, Some(abi)) => format!("input ({abi})"),
        (_, None) => "input".to_owned(),
    }
}

fn sha256_hex(data: &[u8]) -> String {
    hex_lower(&Sha256::digest(data))
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut text: String = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(char::from(HEX[usize::from(byte >> 4)]));
        text.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_dart_vm_version_string() {
        let parsed: Option<DartVersionString> = parse_dart_version_string(
            "3.12.2 (stable) (Tue Jun 9 01:11:39 2026 -0700) on \"android_arm64\"",
        );
        assert_eq!(
            parsed,
            Some(DartVersionString {
                version: "3.12.2".to_owned(),
                channel: "stable".to_owned(),
                built: "Tue Jun 9 01:11:39 2026 -0700".to_owned(),
                target: "android_arm64".to_owned(),
            })
        );
        assert_eq!(parse_dart_version_string("3.12.2 (stable)"), None);
        assert_eq!(
            parse_dart_version_string("x (stable) (Tue) on \"android_arm64\""),
            None
        );
    }

    #[test]
    fn every_table_row_is_well_formed() {
        let dart_rows: Vec<Vec<&str>> = table_rows(DART_SNAPSHOT_TABLE).collect();
        assert!(dart_rows.len() >= 149);
        for row in &dart_rows {
            assert!(
                matches!(row.as_slice(), [hash, _, revision] if is_lower_hex(hash, 32) && is_lower_hex(revision, 40)),
                "{row:?}"
            );
        }
        let flutter_rows: Vec<FlutterRelease> = flutter_releases();
        assert!(flutter_rows.len() >= 353);
        assert!(flutter_rows.iter().all(|release: &FlutterRelease| {
            is_lower_hex(&release.engine_revision, 40) && is_lower_hex(&release.dart_revision, 40)
        }));
    }

    #[test]
    fn abi_comes_from_the_android_library_directory() {
        assert_eq!(
            path_abi("lib/arm64-v8a/libapp.so").as_deref(),
            Some("arm64-v8a")
        );
        assert_eq!(
            path_abi("base/lib/x86_64/libflutter.so").as_deref(),
            Some("x86_64")
        );
        assert_eq!(path_abi("assets/lib/x/y/libapp.so"), None);
        assert_eq!(
            library_role("Payload/Runner.app/Frameworks/App.framework/App"),
            Some(FlutterLibraryRole::App)
        );
        assert_eq!(
            library_role("Payload/Runner.app/Frameworks/Flutter.framework/Flutter"),
            Some(FlutterLibraryRole::Engine)
        );
        assert_eq!(library_role("lib/arm64-v8a/libmain.so"), None);
    }
}
