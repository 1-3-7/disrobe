use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{PackageType, VersionScheme, build_package_url, compare_versions};

const MAX_STATUS_BYTES: u64 = 256 * 1024 * 1024;
const MAX_OS_RELEASE_BYTES: u64 = 64 * 1024;
const MAX_OSV_BYTES: u64 = 16 * 1024 * 1024;
const MAX_LINE_BYTES: usize = 64 * 1024;
const MAX_FIELD_BYTES: usize = 64 * 1024;
const MAX_PACKAGE_FIELD_BYTES: usize = 4 * 1024;
const MAX_STANZA_BYTES: usize = 1024 * 1024;
const MAX_PACKAGES: usize = 100_000;
const MAX_AFFECTED: usize = 4_096;
const MAX_RANGES: usize = 128;
const MAX_EVENTS: usize = 512;
const MAX_EXPLICIT_VERSIONS: usize = 8_192;
const MAX_EVALUATION_WORK: usize = 2_000_000;
const MAX_FINDINGS: usize = 10_000;
const MAX_ISSUES: usize = 10_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InstalledDebianPackage {
    pub name: String,
    pub version: String,
    pub architecture: String,
    pub purl: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OfflineVulnerabilityFinding {
    pub vulnerability_id: String,
    pub package: InstalledDebianPackage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OfflineMatchIssueKind {
    UnsupportedRange,
    InvalidConstraint,
    WorkLimitReached,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OfflineMatchIssue {
    pub vulnerability_id: String,
    pub package_name: String,
    pub kind: OfflineMatchIssueKind,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OfflineMatchReport {
    pub database_schema_version: String,
    pub database_modified: String,
    pub ecosystem: String,
    pub packages_scanned: usize,
    pub findings: Vec<OfflineVulnerabilityFinding>,
    pub issues: Vec<OfflineMatchIssue>,
    pub complete: bool,
}

#[derive(Debug, Error)]
pub enum OfflineMatchError {
    #[error("root filesystem path is not a directory: {path}")]
    RootNotDirectory { path: PathBuf },
    #[error("cannot resolve {path}: {source}")]
    Resolve {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("root filesystem file escapes the selected directory: {path}")]
    RootEscape { path: PathBuf },
    #[error("required root filesystem file is not regular: {path}")]
    NotRegularFile { path: PathBuf },
    #[error("{path} is {actual} bytes, exceeding the {limit}-byte limit")]
    FileTooLarge {
        path: PathBuf,
        actual: u64,
        limit: u64,
    },
    #[error("cannot read {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("allocation of {requested} bytes failed while reading {path}")]
    AllocationFailed { path: PathBuf, requested: usize },
    #[error("{path} contains an invalid UTF-8 line at byte {offset}")]
    InvalidUtf8 { path: PathBuf, offset: u64 },
    #[error("{path} line at byte {offset} exceeds the {limit}-byte limit")]
    LineTooLong {
        path: PathBuf,
        offset: u64,
        limit: usize,
    },
    #[error("{path} stanza at byte {offset} exceeds the {limit}-byte limit")]
    StanzaTooLarge {
        path: PathBuf,
        offset: u64,
        limit: usize,
    },
    #[error("malformed dpkg status at byte {offset}: {detail}")]
    MalformedStatus { offset: u64, detail: &'static str },
    #[error("duplicate dpkg field {field} at byte {offset}")]
    DuplicateField { field: &'static str, offset: u64 },
    #[error("dpkg status contains more than {limit} installed packages")]
    TooManyPackages { limit: usize },
    #[error("os-release is missing required field {field}")]
    MissingOsReleaseField { field: &'static str },
    #[error("unsupported distribution {id}")]
    UnsupportedDistribution { id: String },
    #[error("invalid os-release value for {field}")]
    InvalidOsReleaseValue { field: &'static str },
    #[error("cannot parse OSV JSON {path}: {source}")]
    InvalidOsvJson {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("unsupported OSV schema version {version}")]
    UnsupportedOsvSchema { version: String },
    #[error("OSV field {field} is invalid")]
    InvalidOsvField { field: &'static str },
    #[error("OSV document exceeds the {limit} {kind} limit")]
    OsvCountLimit { kind: &'static str, limit: usize },
    #[error("package URL construction failed: {0}")]
    PackageUrl(#[from] crate::PackageUrlError),
}

#[derive(Debug, Default)]
struct DpkgStanza {
    package: Option<String>,
    status: Option<String>,
    architecture: Option<String>,
    version: Option<String>,
    current: Option<DpkgField>,
    bytes: usize,
    offset: u64,
}

#[derive(Debug, Clone, Copy)]
enum DpkgField {
    Package,
    Status,
    Architecture,
    Version,
    Ignored,
}

#[derive(Debug, Deserialize)]
struct OsvDocument {
    schema_version: String,
    id: String,
    modified: String,
    affected: Vec<OsvAffected>,
}

#[derive(Debug, Deserialize)]
struct OsvAffected {
    package: OsvPackage,
    #[serde(default)]
    ranges: Vec<OsvRange>,
    #[serde(default)]
    versions: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct OsvPackage {
    ecosystem: String,
    name: String,
}

#[derive(Debug, Deserialize)]
struct OsvRange {
    #[serde(rename = "type")]
    range_type: String,
    events: Vec<OsvEvent>,
}

#[derive(Debug, Deserialize)]
struct OsvEvent {
    introduced: Option<String>,
    fixed: Option<String>,
    last_affected: Option<String>,
    limit: Option<String>,
}

pub fn match_debian_rootfs(
    rootfs: &Path,
    database: &Path,
) -> Result<OfflineMatchReport, OfflineMatchError> {
    let canonical_root: PathBuf = canonical_root(rootfs)?;
    let distro: DebianDistribution = read_distribution(&canonical_root)?;
    let mut packages: Vec<InstalledDebianPackage> = read_dpkg_packages(&canonical_root)?;
    packages.sort_by(
        |left: &InstalledDebianPackage, right: &InstalledDebianPackage| {
            (&left.name, &left.architecture, &left.version).cmp(&(
                &right.name,
                &right.architecture,
                &right.version,
            ))
        },
    );
    let document: OsvDocument = read_osv_document(database)?;
    validate_osv_document(&document)?;
    let ecosystem: String = format!("Debian:{}", distro.major_version);
    let mut findings: Vec<OfflineVulnerabilityFinding> = Vec::new();
    let mut issues: Vec<OfflineMatchIssue> = Vec::new();
    let mut evaluation_work: usize = 0;
    let mut complete: bool = true;

    'affected: for affected in document
        .affected
        .iter()
        .filter(|affected: &&OsvAffected| affected.package.ecosystem == ecosystem)
    {
        for package in packages_named(&packages, &affected.package.name) {
            match evaluate_package(package, affected, &mut evaluation_work) {
                Ok(true) if findings.len() < MAX_FINDINGS => {
                    findings.push(OfflineVulnerabilityFinding {
                        vulnerability_id: document.id.clone(),
                        package: package.clone(),
                    });
                }
                Ok(true) => {
                    issues.push(OfflineMatchIssue {
                        vulnerability_id: document.id.clone(),
                        package_name: package.name.clone(),
                        kind: OfflineMatchIssueKind::WorkLimitReached,
                        detail: format!("finding limit {MAX_FINDINGS} reached"),
                    });
                    complete = false;
                    break 'affected;
                }
                Ok(false) => {}
                Err(EvaluationError::WorkLimit) => {
                    issues.push(OfflineMatchIssue {
                        vulnerability_id: document.id.clone(),
                        package_name: package.name.clone(),
                        kind: OfflineMatchIssueKind::WorkLimitReached,
                        detail: format!("evaluation work limit {MAX_EVALUATION_WORK} reached"),
                    });
                    complete = false;
                    break 'affected;
                }
                Err(EvaluationError::UnsupportedRange(range_type)) => {
                    if issues.len() >= MAX_ISSUES {
                        complete = false;
                        break 'affected;
                    }
                    issues.push(OfflineMatchIssue {
                        vulnerability_id: document.id.clone(),
                        package_name: package.name.clone(),
                        kind: OfflineMatchIssueKind::UnsupportedRange,
                        detail: range_type,
                    });
                    complete = false;
                }
                Err(EvaluationError::InvalidConstraint(detail)) => {
                    if issues.len() >= MAX_ISSUES {
                        complete = false;
                        break 'affected;
                    }
                    issues.push(OfflineMatchIssue {
                        vulnerability_id: document.id.clone(),
                        package_name: package.name.clone(),
                        kind: OfflineMatchIssueKind::InvalidConstraint,
                        detail,
                    });
                    complete = false;
                }
            }
        }
    }
    findings.sort_by(
        |left: &OfflineVulnerabilityFinding, right: &OfflineVulnerabilityFinding| {
            (
                &left.vulnerability_id,
                &left.package.name,
                &left.package.architecture,
                &left.package.version,
            )
                .cmp(&(
                    &right.vulnerability_id,
                    &right.package.name,
                    &right.package.architecture,
                    &right.package.version,
                ))
        },
    );
    issues.sort_by(|left: &OfflineMatchIssue, right: &OfflineMatchIssue| {
        (
            &left.vulnerability_id,
            &left.package_name,
            left.kind as u8,
            &left.detail,
        )
            .cmp(&(
                &right.vulnerability_id,
                &right.package_name,
                right.kind as u8,
                &right.detail,
            ))
    });
    Ok(OfflineMatchReport {
        database_schema_version: document.schema_version,
        database_modified: document.modified,
        ecosystem,
        packages_scanned: packages.len(),
        findings,
        issues,
        complete,
    })
}

fn evaluate_package(
    package: &InstalledDebianPackage,
    affected: &OsvAffected,
    evaluation_work: &mut usize,
) -> Result<bool, EvaluationError> {
    charge_evaluation(evaluation_work)?;
    package_is_affected(package, affected, evaluation_work)
}

fn packages_named<'a>(
    packages: &'a [InstalledDebianPackage],
    name: &str,
) -> &'a [InstalledDebianPackage] {
    let start: usize =
        packages.partition_point(|package: &InstalledDebianPackage| package.name.as_str() < name);
    let end: usize = packages[start..]
        .partition_point(|package: &InstalledDebianPackage| package.name.as_str() == name)
        + start;
    &packages[start..end]
}

#[derive(Debug)]
struct DebianDistribution {
    major_version: String,
}

fn canonical_root(rootfs: &Path) -> Result<PathBuf, OfflineMatchError> {
    let canonical: PathBuf =
        rootfs
            .canonicalize()
            .map_err(|source: std::io::Error| OfflineMatchError::Resolve {
                path: rootfs.to_path_buf(),
                source,
            })?;
    if !canonical.is_dir() {
        return Err(OfflineMatchError::RootNotDirectory {
            path: rootfs.to_path_buf(),
        });
    }
    Ok(canonical)
}

fn contained_file(
    root: &Path,
    relative: &Path,
    limit: u64,
) -> Result<(File, PathBuf), OfflineMatchError> {
    let requested: PathBuf = root.join(relative);
    let canonical: PathBuf =
        requested
            .canonicalize()
            .map_err(|source: std::io::Error| OfflineMatchError::Resolve {
                path: requested.clone(),
                source,
            })?;
    if !canonical.starts_with(root) {
        return Err(OfflineMatchError::RootEscape { path: requested });
    }
    let file: File =
        File::open(&canonical).map_err(|source: std::io::Error| OfflineMatchError::Read {
            path: canonical.clone(),
            source,
        })?;
    let metadata: std::fs::Metadata =
        file.metadata()
            .map_err(|source: std::io::Error| OfflineMatchError::Read {
                path: canonical.clone(),
                source,
            })?;
    if !metadata.is_file() {
        return Err(OfflineMatchError::NotRegularFile { path: canonical });
    }
    if metadata.len() > limit {
        return Err(OfflineMatchError::FileTooLarge {
            path: canonical,
            actual: metadata.len(),
            limit,
        });
    }
    Ok((file, canonical))
}

fn read_distribution(root: &Path) -> Result<DebianDistribution, OfflineMatchError> {
    let (file, path): (File, PathBuf) =
        contained_file(root, Path::new("etc/os-release"), MAX_OS_RELEASE_BYTES)?;
    let mut bytes: Vec<u8> = Vec::new();
    bytes
        .try_reserve_exact(MAX_OS_RELEASE_BYTES as usize)
        .map_err(|_| OfflineMatchError::AllocationFailed {
            path: path.clone(),
            requested: MAX_OS_RELEASE_BYTES as usize,
        })?;
    file.take(MAX_OS_RELEASE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|source: std::io::Error| OfflineMatchError::Read {
            path: path.clone(),
            source,
        })?;
    if bytes.len() as u64 > MAX_OS_RELEASE_BYTES {
        return Err(OfflineMatchError::FileTooLarge {
            path,
            actual: bytes.len() as u64,
            limit: MAX_OS_RELEASE_BYTES,
        });
    }
    let text: &str = std::str::from_utf8(&bytes).map_err(|error: std::str::Utf8Error| {
        OfflineMatchError::InvalidUtf8 {
            path,
            offset: error.valid_up_to() as u64,
        }
    })?;
    let mut id: Option<String> = None;
    let mut version: Option<String> = None;
    for line in text.lines() {
        let Some((key, raw_value)): Option<(&str, &str)> = line.split_once('=') else {
            continue;
        };
        let (target, field): (&mut Option<String>, &'static str) = match key {
            "ID" => (&mut id, "ID"),
            "VERSION_ID" => (&mut version, "VERSION_ID"),
            _ => continue,
        };
        if target.is_some() {
            return Err(OfflineMatchError::InvalidOsReleaseValue { field });
        }
        *target = Some(parse_os_release_value(raw_value, field)?);
    }
    let id: String = id.ok_or(OfflineMatchError::MissingOsReleaseField { field: "ID" })?;
    if id != "debian" {
        return Err(OfflineMatchError::UnsupportedDistribution { id });
    }
    let version: String = version.ok_or(OfflineMatchError::MissingOsReleaseField {
        field: "VERSION_ID",
    })?;
    let major_version: &str = version.split('.').next().map_or("", |major: &str| major);
    if major_version.is_empty()
        || major_version.len() > 8
        || !major_version.bytes().all(|byte: u8| byte.is_ascii_digit())
    {
        return Err(OfflineMatchError::InvalidOsReleaseValue {
            field: "VERSION_ID",
        });
    }
    Ok(DebianDistribution {
        major_version: major_version.to_owned(),
    })
}

fn parse_os_release_value(raw: &str, field: &'static str) -> Result<String, OfflineMatchError> {
    if raw.len() > MAX_FIELD_BYTES || raw.contains(['\0', '\n', '\r']) {
        return Err(OfflineMatchError::InvalidOsReleaseValue { field });
    }
    let matching_quotes: bool = raw.len() >= 2
        && matches!(
            (raw.as_bytes().first(), raw.as_bytes().last()),
            (Some(b'"'), Some(b'"')) | (Some(b'\''), Some(b'\''))
        );
    let value: &str = if matching_quotes {
        &raw[1..raw.len() - 1]
    } else if raw.starts_with(['"', '\'']) || raw.ends_with(['"', '\'']) {
        return Err(OfflineMatchError::InvalidOsReleaseValue { field });
    } else {
        raw
    };
    if value.contains(['"', '\'', '\\', '$', '`']) {
        return Err(OfflineMatchError::InvalidOsReleaseValue { field });
    }
    Ok(value.to_owned())
}

fn read_dpkg_packages(root: &Path) -> Result<Vec<InstalledDebianPackage>, OfflineMatchError> {
    let (file, path): (File, PathBuf) =
        contained_file(root, Path::new("var/lib/dpkg/status"), MAX_STATUS_BYTES)?;
    let mut reader: BufReader<File> = BufReader::new(file);
    let mut line: Vec<u8> = Vec::new();
    let mut offset: u64 = 0;
    let mut stanza: DpkgStanza = DpkgStanza::default();
    let mut packages: Vec<InstalledDebianPackage> = Vec::new();
    while read_bounded_line(&mut reader, &mut line, &path, offset)? {
        let line_start: u64 = offset;
        offset = offset.saturating_add(line.len() as u64);
        if offset > MAX_STATUS_BYTES {
            return Err(OfflineMatchError::FileTooLarge {
                path,
                actual: offset,
                limit: MAX_STATUS_BYTES,
            });
        }
        let without_lf: &[u8] = line.strip_suffix(b"\n").map_or(&line, |value: &[u8]| value);
        let raw: &[u8] = without_lf
            .strip_suffix(b"\r")
            .map_or(without_lf, |value: &[u8]| value);
        if raw.is_empty() {
            finish_stanza(&mut stanza, &mut packages)?;
            continue;
        }
        stanza.bytes = stanza.bytes.checked_add(raw.len()).ok_or_else(|| {
            OfflineMatchError::StanzaTooLarge {
                path: path.clone(),
                offset: stanza.offset,
                limit: MAX_STANZA_BYTES,
            }
        })?;
        if stanza.bytes > MAX_STANZA_BYTES {
            return Err(OfflineMatchError::StanzaTooLarge {
                path: path.clone(),
                offset: stanza.offset,
                limit: MAX_STANZA_BYTES,
            });
        }
        if stanza.bytes == raw.len() {
            stanza.offset = line_start;
        }
        let text: &str = std::str::from_utf8(raw).map_err(|_| OfflineMatchError::InvalidUtf8 {
            path: path.clone(),
            offset: line_start,
        })?;
        parse_status_line(&mut stanza, text, line_start)?;
    }
    finish_stanza(&mut stanza, &mut packages)?;
    Ok(packages)
}

fn read_bounded_line<R: BufRead>(
    reader: &mut R,
    line: &mut Vec<u8>,
    path: &Path,
    offset: u64,
) -> Result<bool, OfflineMatchError> {
    line.clear();
    loop {
        let (take, finished): (usize, bool) = {
            let available: &[u8] =
                reader
                    .fill_buf()
                    .map_err(|source: std::io::Error| OfflineMatchError::Read {
                        path: path.to_path_buf(),
                        source,
                    })?;
            if available.is_empty() {
                return Ok(!line.is_empty());
            }
            let take: usize = available
                .iter()
                .position(|byte: &u8| *byte == b'\n')
                .map_or(available.len(), |index: usize| index + 1);
            let next_len: usize =
                line.len()
                    .checked_add(take)
                    .ok_or_else(|| OfflineMatchError::LineTooLong {
                        path: path.to_path_buf(),
                        offset,
                        limit: MAX_LINE_BYTES,
                    })?;
            if next_len > MAX_LINE_BYTES {
                return Err(OfflineMatchError::LineTooLong {
                    path: path.to_path_buf(),
                    offset,
                    limit: MAX_LINE_BYTES,
                });
            }
            line.try_reserve(take)
                .map_err(|_| OfflineMatchError::AllocationFailed {
                    path: path.to_path_buf(),
                    requested: next_len,
                })?;
            line.extend_from_slice(&available[..take]);
            (take, available.get(take.wrapping_sub(1)) == Some(&b'\n'))
        };
        reader.consume(take);
        if finished {
            return Ok(true);
        }
    }
}

fn parse_status_line(
    stanza: &mut DpkgStanza,
    line: &str,
    offset: u64,
) -> Result<(), OfflineMatchError> {
    if line.starts_with([' ', '\t']) {
        let current: DpkgField = stanza.current.ok_or(OfflineMatchError::MalformedStatus {
            offset,
            detail: "continuation line has no field",
        })?;
        let continuation: &str = line.trim_start_matches([' ', '\t']);
        let target: Option<&mut String> = match current {
            DpkgField::Package => stanza.package.as_mut(),
            DpkgField::Status => stanza.status.as_mut(),
            DpkgField::Architecture => stanza.architecture.as_mut(),
            DpkgField::Version => stanza.version.as_mut(),
            DpkgField::Ignored => None,
        };
        if let Some(value) = target {
            let requested: usize = value
                .len()
                .checked_add(1)
                .and_then(|length: usize| length.checked_add(continuation.len()))
                .ok_or(OfflineMatchError::MalformedStatus {
                    offset,
                    detail: "field value is too large",
                })?;
            if requested > MAX_FIELD_BYTES {
                return Err(OfflineMatchError::MalformedStatus {
                    offset,
                    detail: "field value is too large",
                });
            }
            value.try_reserve(1 + continuation.len()).map_err(|_| {
                OfflineMatchError::AllocationFailed {
                    path: PathBuf::from("var/lib/dpkg/status"),
                    requested,
                }
            })?;
            value.push('\n');
            value.push_str(continuation);
        }
        return Ok(());
    }
    let (name, raw_value): (&str, &str) =
        line.split_once(':')
            .ok_or(OfflineMatchError::MalformedStatus {
                offset,
                detail: "field line has no colon",
            })?;
    if name.is_empty() || raw_value.is_empty() || !raw_value.starts_with(' ') {
        return Err(OfflineMatchError::MalformedStatus {
            offset,
            detail: "field syntax is invalid",
        });
    }
    let value: &str = &raw_value[1..];
    if value.len() > MAX_FIELD_BYTES {
        return Err(OfflineMatchError::MalformedStatus {
            offset,
            detail: "field value is too large",
        });
    }
    stanza.current = Some(match name {
        "Package" => {
            assign_field(&mut stanza.package, value, "Package", offset)?;
            DpkgField::Package
        }
        "Status" => {
            assign_field(&mut stanza.status, value, "Status", offset)?;
            DpkgField::Status
        }
        "Architecture" => {
            assign_field(&mut stanza.architecture, value, "Architecture", offset)?;
            DpkgField::Architecture
        }
        "Version" => {
            assign_field(&mut stanza.version, value, "Version", offset)?;
            DpkgField::Version
        }
        _ => DpkgField::Ignored,
    });
    Ok(())
}

fn assign_field(
    target: &mut Option<String>,
    value: &str,
    field: &'static str,
    offset: u64,
) -> Result<(), OfflineMatchError> {
    if target.is_some() {
        return Err(OfflineMatchError::DuplicateField { field, offset });
    }
    *target = Some(value.to_owned());
    Ok(())
}

fn finish_stanza(
    stanza: &mut DpkgStanza,
    packages: &mut Vec<InstalledDebianPackage>,
) -> Result<(), OfflineMatchError> {
    if stanza.bytes == 0 {
        return Ok(());
    }
    if stanza.status.as_deref() == Some("install ok installed") {
        let name: String = take_required(&mut stanza.package, stanza.offset, "Package")?;
        let version: String = take_required(&mut stanza.version, stanza.offset, "Version")?;
        let architecture: String =
            take_required(&mut stanza.architecture, stanza.offset, "Architecture")?;
        validate_dpkg_token(&name, stanza.offset, "Package")?;
        validate_dpkg_token(&version, stanza.offset, "Version")?;
        validate_dpkg_token(&architecture, stanza.offset, "Architecture")?;
        if packages.len() >= MAX_PACKAGES {
            return Err(OfflineMatchError::TooManyPackages {
                limit: MAX_PACKAGES,
            });
        }
        let qualifiers: BTreeMap<String, String> =
            BTreeMap::from([("arch".to_owned(), architecture.clone())]);
        let purl: String = build_package_url(
            PackageType::Debian,
            Some("debian"),
            &name,
            Some(&version),
            &qualifiers,
            None,
        )?;
        packages.push(InstalledDebianPackage {
            name,
            version,
            architecture,
            purl,
        });
    }
    *stanza = DpkgStanza::default();
    Ok(())
}

fn take_required(
    value: &mut Option<String>,
    offset: u64,
    field: &'static str,
) -> Result<String, OfflineMatchError> {
    value.take().ok_or(OfflineMatchError::MalformedStatus {
        offset,
        detail: match field {
            "Package" => "installed stanza has no Package field",
            "Version" => "installed stanza has no Version field",
            _ => "installed stanza has no Architecture field",
        },
    })
}

fn validate_dpkg_token(
    value: &str,
    offset: u64,
    field: &'static str,
) -> Result<(), OfflineMatchError> {
    if value.is_empty() || value.bytes().any(|byte: u8| byte.is_ascii_whitespace()) {
        return Err(OfflineMatchError::MalformedStatus {
            offset,
            detail: match field {
                "Package" => "Package contains whitespace or is empty",
                "Version" => "Version contains whitespace or is empty",
                _ => "Architecture contains whitespace or is empty",
            },
        });
    }
    Ok(())
}

fn read_osv_document(path: &Path) -> Result<OsvDocument, OfflineMatchError> {
    let file: File =
        File::open(path).map_err(|source: std::io::Error| OfflineMatchError::Read {
            path: path.to_path_buf(),
            source,
        })?;
    let metadata: std::fs::Metadata =
        file.metadata()
            .map_err(|source: std::io::Error| OfflineMatchError::Read {
                path: path.to_path_buf(),
                source,
            })?;
    if !metadata.is_file() {
        return Err(OfflineMatchError::NotRegularFile {
            path: path.to_path_buf(),
        });
    }
    if metadata.len() > MAX_OSV_BYTES {
        return Err(OfflineMatchError::FileTooLarge {
            path: path.to_path_buf(),
            actual: metadata.len(),
            limit: MAX_OSV_BYTES,
        });
    }
    let requested: usize =
        usize::try_from(metadata.len()).map_or(MAX_OSV_BYTES as usize, |value: usize| value);
    let mut bytes: Vec<u8> = Vec::new();
    bytes
        .try_reserve_exact(requested)
        .map_err(|_| OfflineMatchError::AllocationFailed {
            path: path.to_path_buf(),
            requested,
        })?;
    file.take(MAX_OSV_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|source: std::io::Error| OfflineMatchError::Read {
            path: path.to_path_buf(),
            source,
        })?;
    if bytes.len() as u64 > MAX_OSV_BYTES {
        return Err(OfflineMatchError::FileTooLarge {
            path: path.to_path_buf(),
            actual: bytes.len() as u64,
            limit: MAX_OSV_BYTES,
        });
    }
    serde_json::from_slice(&bytes).map_err(|source: serde_json::Error| {
        OfflineMatchError::InvalidOsvJson {
            path: path.to_path_buf(),
            source,
        }
    })
}

fn validate_osv_document(document: &OsvDocument) -> Result<(), OfflineMatchError> {
    if !document.schema_version.starts_with("1.")
        || document.schema_version.len() > 32
        || !document
            .schema_version
            .bytes()
            .all(|byte: u8| byte.is_ascii_digit() || byte == b'.')
    {
        return Err(OfflineMatchError::UnsupportedOsvSchema {
            version: document.schema_version.clone(),
        });
    }
    if document.id.is_empty() || document.id.len() > 1024 {
        return Err(OfflineMatchError::InvalidOsvField { field: "id" });
    }
    if document.modified.is_empty()
        || document.modified.len() > 128
        || !document.modified.is_ascii()
    {
        return Err(OfflineMatchError::InvalidOsvField { field: "modified" });
    }
    if document.affected.len() > MAX_AFFECTED {
        return Err(OfflineMatchError::OsvCountLimit {
            kind: "affected entries",
            limit: MAX_AFFECTED,
        });
    }
    for affected in &document.affected {
        if affected.package.name.is_empty()
            || affected.package.name.len() > MAX_PACKAGE_FIELD_BYTES
            || affected.package.ecosystem.is_empty()
            || affected.package.ecosystem.len() > MAX_PACKAGE_FIELD_BYTES
        {
            return Err(OfflineMatchError::InvalidOsvField { field: "package" });
        }
        if affected.ranges.len() > MAX_RANGES {
            return Err(OfflineMatchError::OsvCountLimit {
                kind: "ranges per affected entry",
                limit: MAX_RANGES,
            });
        }
        if affected.versions.len() > MAX_EXPLICIT_VERSIONS {
            return Err(OfflineMatchError::OsvCountLimit {
                kind: "versions per affected entry",
                limit: MAX_EXPLICIT_VERSIONS,
            });
        }
        for range in &affected.ranges {
            if range.range_type.is_empty() || range.range_type.len() > 64 {
                return Err(OfflineMatchError::InvalidOsvField {
                    field: "range.type",
                });
            }
            if range.events.len() > MAX_EVENTS {
                return Err(OfflineMatchError::OsvCountLimit {
                    kind: "events per range",
                    limit: MAX_EVENTS,
                });
            }
        }
    }
    Ok(())
}

#[derive(Debug, Clone)]
enum EvaluationError {
    UnsupportedRange(String),
    InvalidConstraint(String),
    WorkLimit,
}

fn package_is_affected(
    package: &InstalledDebianPackage,
    affected: &OsvAffected,
    evaluation_work: &mut usize,
) -> Result<bool, EvaluationError> {
    let mut uncertainty: Option<EvaluationError> = None;
    for version in &affected.versions {
        charge_evaluation(evaluation_work)?;
        match compare(package, version, evaluation_work) {
            Ok(Ordering::Equal) => return Ok(true),
            Ok(_) => {}
            Err(EvaluationError::WorkLimit) => return Err(EvaluationError::WorkLimit),
            Err(error) => merge_uncertainty(&mut uncertainty, error),
        }
    }
    for range in &affected.ranges {
        charge_evaluation(evaluation_work)?;
        if range.range_type != "ECOSYSTEM" {
            merge_uncertainty(
                &mut uncertainty,
                EvaluationError::UnsupportedRange(range.range_type.clone()),
            );
            continue;
        }
        match ecosystem_range_is_affected(package, range, evaluation_work) {
            Ok(true) => return Ok(true),
            Ok(false) => {}
            Err(EvaluationError::WorkLimit) => return Err(EvaluationError::WorkLimit),
            Err(error) => merge_uncertainty(&mut uncertainty, error),
        }
    }
    uncertainty.map_or(Ok(false), Err)
}

fn ecosystem_range_is_affected(
    package: &InstalledDebianPackage,
    range: &OsvRange,
    evaluation_work: &mut usize,
) -> Result<bool, EvaluationError> {
    let mut active: bool = false;
    for event in &range.events {
        charge_evaluation(evaluation_work)?;
        let present: usize = [
            event.introduced.is_some(),
            event.fixed.is_some(),
            event.last_affected.is_some(),
            event.limit.is_some(),
        ]
        .into_iter()
        .filter(|value: &bool| *value)
        .count();
        if present != 1 {
            return Err(EvaluationError::InvalidConstraint(
                "OSV event must contain exactly one boundary".to_owned(),
            ));
        }
        if let Some(introduced) = &event.introduced {
            if introduced == "0" || compare(package, introduced, evaluation_work)?.is_ge() {
                active = true;
            }
        } else if let Some(fixed) = &event.fixed {
            if compare(package, fixed, evaluation_work)?.is_ge() {
                active = false;
            }
        } else if let Some(last_affected) = &event.last_affected {
            if compare(package, last_affected, evaluation_work)?.is_gt() {
                active = false;
            }
        } else if let Some(limit) = &event.limit
            && compare(package, limit, evaluation_work)?.is_ge()
        {
            active = false;
        }
    }
    Ok(active)
}

fn merge_uncertainty(current: &mut Option<EvaluationError>, candidate: EvaluationError) {
    let replace: bool = current.as_ref().is_none_or(|existing: &EvaluationError| {
        evaluation_error_key(&candidate) < evaluation_error_key(existing)
    });
    if replace {
        *current = Some(candidate);
    }
}

fn evaluation_error_key(error: &EvaluationError) -> (u8, &str) {
    match error {
        EvaluationError::InvalidConstraint(detail) => (0, detail),
        EvaluationError::UnsupportedRange(range_type) => (1, range_type),
        EvaluationError::WorkLimit => (2, ""),
    }
}

fn compare(
    package: &InstalledDebianPackage,
    boundary: &str,
    evaluation_work: &mut usize,
) -> Result<Ordering, EvaluationError> {
    charge_evaluation(evaluation_work)?;
    compare_versions(VersionScheme::Debian, &package.version, boundary)
        .map_err(|error| EvaluationError::InvalidConstraint(error.to_string()))
}

const fn charge_evaluation(evaluation_work: &mut usize) -> Result<(), EvaluationError> {
    if *evaluation_work >= MAX_EVALUATION_WORK {
        return Err(EvaluationError::WorkLimit);
    }
    *evaluation_work += 1;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_affected_entries_consume_evaluation_work() {
        let package: InstalledDebianPackage = InstalledDebianPackage {
            name: "zlib1g".to_owned(),
            version: "1.0-1".to_owned(),
            architecture: "amd64".to_owned(),
            purl: "pkg:deb/debian/zlib1g@1.0-1?arch=amd64".to_owned(),
        };
        let affected: OsvAffected = OsvAffected {
            package: OsvPackage {
                ecosystem: "Debian:12".to_owned(),
                name: "zlib1g".to_owned(),
            },
            ranges: Vec::new(),
            versions: Vec::new(),
        };
        let mut evaluation_work: usize = MAX_EVALUATION_WORK;

        assert!(matches!(
            evaluate_package(&package, &affected, &mut evaluation_work),
            Err(EvaluationError::WorkLimit)
        ));
    }
}
