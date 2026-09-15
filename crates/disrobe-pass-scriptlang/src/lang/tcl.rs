use std::io::{Cursor, Read};

use serde::Serialize;

use crate::debug::dbg_line;
use crate::error::{Error, Result};
use crate::lang::metakit::{self, MetakitMember};

const STARKIT_SHEBANG: &[u8] = b"#!/bin/sh";
const STARKIT_HEADER_MARKER: &[u8] = b"package require starkit";
const METAKIT_MAGIC: &[u8] = b"JL\x1a\x00";
const METAKIT_SCHEMA: &[u8] = b"dirs[name:S,parent:I,files[name:S,size:I,date:I,contents:B]]";
const ZIP_EOCD: &[u8] = b"PK\x05\x06";
const ZIP_LOCAL: &[u8] = b"PK\x03\x04";
const MAX_ENTRY_BYTES: u64 = 64 * 1024 * 1024;
const MAX_TOTAL_ENTRY_BYTES: u64 = 256 * 1024 * 1024;
const MAX_ENTRIES: usize = 65_536usize;
const ENTRY_PREALLOC_CAP: u64 = 1024 * 1024;
const MAX_METAKIT_NAME_LEN: usize = 255usize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum StarkitFormat {
    ZipVfs,
    Metakit,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StarkitEntry {
    pub path: String,
    pub size: usize,
    #[serde(skip)]
    pub contents: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TclObfuscationKind {
    IndirectCall,
    DynamicProc,
    Subst,
}

impl TclObfuscationKind {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::IndirectCall => "indirect-call",
            Self::DynamicProc => "dynamic-proc",
            Self::Subst => "subst-codegen",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TclObfuscationHit {
    pub kind: TclObfuscationKind,
    pub file: String,
    pub marker: &'static str,
    pub occurrences: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TclObfuscation {
    pub obfuscated: bool,
    pub indirect_call_hits: usize,
    pub dynamic_proc_hits: usize,
    pub subst_hits: usize,
    pub hits: Vec<TclObfuscationHit>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TclExtractionCompleteness {
    pub declared_entries: usize,
    pub recovered_with_contents: usize,
    pub tcl_source_files: usize,
}

impl TclExtractionCompleteness {
    #[must_use]
    pub fn ratio(&self) -> f64 {
        if self.declared_entries == 0 {
            return 1.0;
        }
        self.recovered_with_contents as f64 / self.declared_entries as f64
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StarkitContainer {
    pub format: StarkitFormat,
    pub has_starkit_header: bool,
    pub entries: Vec<StarkitEntry>,
    pub tcl_source_files: Vec<String>,
    pub obfuscation: TclObfuscation,
    pub completeness: TclExtractionCompleteness,
}

#[must_use]
pub fn is_starkit(bytes: &[u8]) -> bool {
    detect_format(bytes).is_some()
}

#[must_use]
pub fn detect_format(bytes: &[u8]) -> Option<StarkitFormat> {
    if window_contains(bytes, METAKIT_MAGIC) && window_contains(bytes, METAKIT_SCHEMA) {
        return Some(StarkitFormat::Metakit);
    }
    if window_contains(bytes, ZIP_EOCD)
        && window_contains(bytes, ZIP_LOCAL)
        && window_contains(bytes, STARKIT_HEADER_MARKER)
        && find_zip_start(bytes).is_some()
    {
        return Some(StarkitFormat::ZipVfs);
    }
    None
}

#[must_use]
pub fn has_starkit_header(bytes: &[u8]) -> bool {
    let prefix: &[u8] = &bytes[..bytes.len().min(512)];
    window_contains(prefix, STARKIT_SHEBANG) && window_contains(bytes, STARKIT_HEADER_MARKER)
}

pub fn extract(bytes: &[u8]) -> Result<StarkitContainer> {
    let format: StarkitFormat = detect_format(bytes).ok_or(Error::NotStarkit)?;
    let has_header: bool = has_starkit_header(bytes);
    match format {
        StarkitFormat::ZipVfs => extract_zip(bytes, has_header),
        StarkitFormat::Metakit => extract_metakit(bytes, has_header),
    }
}

fn extract_zip(bytes: &[u8], has_header: bool) -> Result<StarkitContainer> {
    extract_zip_with_limits(bytes, has_header, MAX_ENTRY_BYTES, MAX_TOTAL_ENTRY_BYTES)
}

fn extract_zip_with_limits(
    bytes: &[u8],
    has_header: bool,
    max_entry_bytes: u64,
    max_total_entry_bytes: u64,
) -> Result<StarkitContainer> {
    let start: usize = find_zip_start(bytes).ok_or(Error::NotStarkit)?;
    let archive_bytes: &[u8] = &bytes[start..];
    let cursor: Cursor<&[u8]> = Cursor::new(archive_bytes);
    let mut zip: zip::ZipArchive<Cursor<&[u8]>> = zip::ZipArchive::new(cursor)?;
    let mut entries: Vec<StarkitEntry> = Vec::with_capacity(zip.len().min(MAX_ENTRIES));
    let mut total_uncompressed: u64 = 0;
    for i in 0..zip.len().min(MAX_ENTRIES) {
        let file: zip::read::ZipFile<'_> = zip.by_index(i)?;
        let name: String = file.name().to_owned();
        if file.is_dir() {
            continue;
        }
        let safe: String = sanitize_path(&name)?;
        let declared: u64 = file.size();
        let remaining_total: u64 = max_total_entry_bytes
            .checked_sub(total_uncompressed)
            .ok_or_else(|| {
                Error::StarkitZip(format!(
                    "entry '{name}' aggregate size {total_uncompressed} exceeds quota"
                ))
            })?;
        let entry_limit: u64 = max_entry_bytes.min(remaining_total);
        let contents: Vec<u8> = read_zip_entry_to_limit(file, &name, declared, entry_limit)?;
        let content_len: u64 = u64::try_from(contents.len()).map_err(|_| {
            Error::StarkitZip(format!(
                "entry '{name}' read size exceeds aggregate quota {max_total_entry_bytes}"
            ))
        })?;
        total_uncompressed = total_uncompressed
            .checked_add(content_len)
            .ok_or_else(|| Error::StarkitZip(format!("entry '{name}' aggregate size overflow")))?;
        if total_uncompressed > max_total_entry_bytes {
            return Err(Error::StarkitZip(format!(
                "entry '{name}' aggregate size {total_uncompressed} exceeds quota {max_total_entry_bytes}"
            )));
        }
        entries.push(StarkitEntry {
            path: safe,
            size: contents.len(),
            contents,
        });
    }
    entries.sort_by(|a: &StarkitEntry, b: &StarkitEntry| a.path.cmp(&b.path));
    let tcl_source_files: Vec<String> = collect_tcl(&entries);
    let obfuscation: TclObfuscation = analyze_obfuscation(&entries);
    let completeness: TclExtractionCompleteness = measure_completeness(&entries, &tcl_source_files);
    Ok(StarkitContainer {
        format: StarkitFormat::ZipVfs,
        has_starkit_header: has_header,
        entries,
        tcl_source_files,
        obfuscation,
        completeness,
    })
}

fn extract_metakit(bytes: &[u8], has_header: bool) -> Result<StarkitContainer> {
    if !window_contains(bytes, METAKIT_SCHEMA) {
        return Err(Error::StarkitNoSchema);
    }
    let entries: Vec<StarkitEntry> = match decode_metakit(bytes) {
        Ok(decoded) => decoded,
        Err(error) => {
            dbg_line(|| format!("metakit payload declined, listing filenames only: {error}"));
            scan_metakit_files(bytes)
        }
    };
    let tcl_source_files: Vec<String> = collect_tcl(&entries);
    let obfuscation: TclObfuscation = analyze_obfuscation(&entries);
    let completeness: TclExtractionCompleteness = measure_completeness(&entries, &tcl_source_files);
    Ok(StarkitContainer {
        format: StarkitFormat::Metakit,
        has_starkit_header: has_header,
        entries,
        tcl_source_files,
        obfuscation,
        completeness,
    })
}

fn decode_metakit(bytes: &[u8]) -> Result<Vec<StarkitEntry>> {
    decode_metakit_with_limits(bytes, MAX_ENTRY_BYTES, MAX_TOTAL_ENTRY_BYTES)
}

fn decode_metakit_with_limits(
    bytes: &[u8],
    max_entry_bytes: u64,
    max_total_entry_bytes: u64,
) -> Result<Vec<StarkitEntry>> {
    let members: Vec<MetakitMember<'_>> = metakit::read_starkit_members(bytes)?;
    let mut entries: Vec<StarkitEntry> = Vec::with_capacity(members.len().min(MAX_ENTRIES));
    let mut total_uncompressed: u64 = 0u64;
    for member in members {
        let path: String = sanitize_path(&member.path)?;
        let contents: Vec<u8> = match member_bytes(&member, max_entry_bytes) {
            Ok(recovered) => recovered,
            Err(error) => {
                dbg_line(|| format!("metakit member '{path}' payload declined: {error}"));
                Vec::new()
            }
        };
        let recovered: u64 = contents.len() as u64;
        total_uncompressed = total_uncompressed
            .checked_add(recovered)
            .ok_or_else(|| Error::StarkitZip(format!("entry '{path}' aggregate size overflow")))?;
        if total_uncompressed > max_total_entry_bytes {
            return Err(Error::StarkitZip(format!(
                "entry '{path}' aggregate size {total_uncompressed} exceeds quota {max_total_entry_bytes}"
            )));
        }
        entries.push(StarkitEntry {
            path,
            size: contents.len(),
            contents,
        });
    }
    entries.sort_by(|a: &StarkitEntry, b: &StarkitEntry| a.path.cmp(&b.path));
    Ok(entries)
}

fn member_bytes(member: &MetakitMember<'_>, max_entry_bytes: u64) -> Result<Vec<u8>> {
    let declared: u64 = member.declared_size as u64;
    if declared > max_entry_bytes {
        return Err(Error::StarkitMetakit {
            reason: format!("declared size {declared} exceeds quota {max_entry_bytes}"),
        });
    }
    if member.stored.len() == member.declared_size {
        return Ok(member.stored.to_vec());
    }
    let mut contents: Vec<u8> = Vec::with_capacity(entry_prealloc(declared, max_entry_bytes));
    let mut reader: std::io::Take<flate2::read::ZlibDecoder<&[u8]>> =
        flate2::read::ZlibDecoder::new(member.stored).take(declared.saturating_add(1u64));
    let read: usize = reader.read_to_end(&mut contents)?;
    if read != member.declared_size {
        return Err(Error::StarkitMetakit {
            reason: format!(
                "the {} stored bytes inflate to {read}, not the declared {}",
                member.stored.len(),
                member.declared_size
            ),
        });
    }
    Ok(contents)
}

#[inline]
fn entry_prealloc(declared: u64, limit: u64) -> usize {
    let bound: u64 = declared.min(limit).min(ENTRY_PREALLOC_CAP);
    usize::try_from(bound).map_or(usize::MAX, |value: usize| value)
}

fn read_zip_entry_to_limit<R: Read>(
    reader: R,
    name: &str,
    declared: u64,
    limit: u64,
) -> Result<Vec<u8>> {
    if declared > limit {
        return Err(Error::StarkitZip(format!(
            "entry '{name}' size {declared} exceeds quota"
        )));
    }
    let read_limit: u64 = limit
        .checked_add(1)
        .ok_or_else(|| Error::StarkitZip(format!("entry '{name}' quota overflow")))?;
    let mut limited: std::io::Take<R> = reader.take(read_limit);
    let mut contents: Vec<u8> = Vec::with_capacity(entry_prealloc(declared, limit));
    let read: usize = std::io::Read::read_to_end(&mut limited, &mut contents)?;
    let read_u64: u64 = u64::try_from(read).map_err(|_| {
        Error::StarkitZip(format!("entry '{name}' read size exceeds quota {limit}"))
    })?;
    if read_u64 > limit {
        return Err(Error::StarkitZip(format!(
            "entry '{name}' read size {read_u64} exceeds quota {limit}"
        )));
    }
    Ok(contents)
}

fn scan_metakit_files(bytes: &[u8]) -> Vec<StarkitEntry> {
    let mut names: Vec<String> = Vec::new();
    let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let limit: usize = bytes.len().saturating_sub(4);
    let mut i: usize = 0usize;
    while i < limit && names.len() < MAX_ENTRIES {
        if let Some((maybe_name, next)) = read_metakit_token(bytes, i) {
            if let Some(name) = maybe_name
                && is_plausible_filename(&name)
                && seen.insert(name.clone())
            {
                names.push(name);
            }
            i = next;
        } else {
            i += 1;
        }
    }
    names
        .into_iter()
        .map(|path: String| StarkitEntry {
            size: 0usize,
            path,
            contents: Vec::new(),
        })
        .collect()
}

fn is_filename_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-' | b'+')
}

fn read_metakit_token(bytes: &[u8], at: usize) -> Option<(Option<String>, usize)> {
    let b: u8 = *bytes.get(at)?;
    if !is_filename_byte(b) {
        return None;
    }
    let mut end: usize = at;
    while end < bytes.len() && is_filename_byte(bytes[end]) {
        end += 1;
    }
    if end - at > MAX_METAKIT_NAME_LEN {
        return Some((None, end));
    }
    let slice: &[u8] = &bytes[at..end];
    let text: &str = std::str::from_utf8(slice).ok()?;
    Some((Some(text.to_owned()), end))
}

fn is_plausible_filename(name: &str) -> bool {
    let known: [&str; 8] = [".tcl", ".tm", ".msg", ".dat", ".txt", ".rc", ".sh", ".gif"];
    name.len() >= 4
        && name.len() <= MAX_METAKIT_NAME_LEN
        && name.contains('.')
        && !name.starts_with('.')
        && !name.ends_with('.')
        && known.iter().any(|ext: &&str| name.ends_with(ext))
        && name.bytes().all(is_filename_byte)
}

const INDIRECT_CALL_MARKERS: &[&str] = &[
    "eval ",
    "interp eval",
    "namespace eval",
    "namespace inscope",
    "uplevel ",
    "apply ",
    "tailcall ",
    "coroutine ",
];

const DYNAMIC_PROC_MARKERS: &[&str] = &["proc [", "proc $", "proc {*}", "rename ", "interp alias"];

const SUBST_MARKERS: &[&str] = &[
    "subst ",
    "subst -",
    "string map",
    "regsub ",
    "binary scan",
    "binary format",
    "encoding convertfrom",
    "base64::decode",
];

const OBFUSCATION_THRESHOLD: usize = 3usize;

fn analyze_obfuscation(entries: &[StarkitEntry]) -> TclObfuscation {
    let mut hits: Vec<TclObfuscationHit> = Vec::new();
    let mut indirect_call_hits: usize = 0usize;
    let mut dynamic_proc_hits: usize = 0usize;
    let mut subst_hits: usize = 0usize;

    for entry in entries {
        if !(entry.path.ends_with(".tcl") || entry.path.ends_with(".tm")) {
            continue;
        }
        let Ok(text): core::result::Result<&str, _> = std::str::from_utf8(&entry.contents) else {
            continue;
        };
        scan_markers(
            text,
            &entry.path,
            INDIRECT_CALL_MARKERS,
            TclObfuscationKind::IndirectCall,
            &mut indirect_call_hits,
            &mut hits,
        );
        scan_markers(
            text,
            &entry.path,
            DYNAMIC_PROC_MARKERS,
            TclObfuscationKind::DynamicProc,
            &mut dynamic_proc_hits,
            &mut hits,
        );
        scan_markers(
            text,
            &entry.path,
            SUBST_MARKERS,
            TclObfuscationKind::Subst,
            &mut subst_hits,
            &mut hits,
        );
    }

    let total: usize = indirect_call_hits + dynamic_proc_hits + subst_hits;
    let distinct_kinds: usize = usize::from(indirect_call_hits > 0)
        + usize::from(dynamic_proc_hits > 0)
        + usize::from(subst_hits > 0);
    let obfuscated: bool = total >= OBFUSCATION_THRESHOLD && distinct_kinds >= 2;

    TclObfuscation {
        obfuscated,
        indirect_call_hits,
        dynamic_proc_hits,
        subst_hits,
        hits,
    }
}

fn scan_markers(
    text: &str,
    file: &str,
    markers: &[&'static str],
    kind: TclObfuscationKind,
    counter: &mut usize,
    hits: &mut Vec<TclObfuscationHit>,
) {
    for marker in markers {
        let occurrences: usize = text.matches(marker).count();
        if occurrences > 0 {
            *counter += occurrences;
            hits.push(TclObfuscationHit {
                kind,
                file: file.to_owned(),
                marker,
                occurrences,
            });
        }
    }
}

fn measure_completeness(
    entries: &[StarkitEntry],
    tcl_source_files: &[String],
) -> TclExtractionCompleteness {
    let declared_entries: usize = entries.len();
    let recovered_with_contents: usize = entries
        .iter()
        .filter(|e: &&StarkitEntry| !e.contents.is_empty())
        .count();
    TclExtractionCompleteness {
        declared_entries,
        recovered_with_contents,
        tcl_source_files: tcl_source_files.len(),
    }
}

fn collect_tcl(entries: &[StarkitEntry]) -> Vec<String> {
    let mut out: Vec<String> = entries
        .iter()
        .filter(|e: &&StarkitEntry| e.path.ends_with(".tcl") || e.path.ends_with(".tm"))
        .map(|e: &StarkitEntry| e.path.clone())
        .collect();
    out.sort();
    out.dedup();
    out
}

fn find_zip_start(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(ZIP_LOCAL.len())
        .position(|w: &[u8]| w == ZIP_LOCAL)
}

fn sanitize_path(name: &str) -> Result<String> {
    let normalized: String = name.replace('\\', "/");
    if normalized.starts_with('/')
        || normalized.contains("../")
        || normalized.split('/').any(|seg: &str| seg == "..")
        || normalized.split('/').any(|seg: &str| seg.contains(':'))
    {
        return Err(Error::StarkitUnsafePath(name.to_owned()));
    }
    Ok(normalized)
}

#[inline]
fn window_contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w: &[u8]| w == needle)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::io::Write;

    use super::*;

    fn build_zip_starkit(header: bool, files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        if header {
            out.extend_from_slice(STARKIT_SHEBANG);
            out.extend_from_slice(b"\n# \\\nexec tclkit \"$0\" ${1+\"$@\"}\n");
            out.extend_from_slice(STARKIT_HEADER_MARKER);
            out.extend_from_slice(b"\nstarkit::header mk4 -readonly\n");
        }
        let mut buf: Vec<u8> = Vec::new();
        {
            let cursor: Cursor<&mut Vec<u8>> = Cursor::new(&mut buf);
            let mut zip: zip::ZipWriter<Cursor<&mut Vec<u8>>> = zip::ZipWriter::new(cursor);
            let opts: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            for (path, data) in files {
                zip.start_file(*path, opts).expect("start");
                zip.write_all(data).expect("write");
            }
            zip.finish().expect("finish");
        }
        out.extend_from_slice(&buf);
        out
    }

    #[test]
    fn detects_zip_starkit() {
        let kit: Vec<u8> = build_zip_starkit(true, &[("main.tcl", b"puts hi\n")]);
        assert_eq!(detect_format(&kit), Some(StarkitFormat::ZipVfs));
        assert!(has_starkit_header(&kit));
    }

    #[test]
    fn extract_round_trips_bytes() {
        let body_a: &[u8] = b"package require Tcl 8.6\nputs {hello from disrobe}\n";
        let body_b: &[u8] = b"proc add {a b} { return [expr {$a + $b}] }\n";
        let kit: Vec<u8> = build_zip_starkit(
            true,
            &[("app/main.tcl", body_a), ("app/lib/util.tcl", body_b)],
        );
        let c: StarkitContainer = extract(&kit).expect("extract");
        assert_eq!(c.entries.len(), 2);
        let main: &StarkitEntry = c
            .entries
            .iter()
            .find(|e: &&StarkitEntry| e.path == "app/main.tcl")
            .expect("main present");
        assert_eq!(main.contents, body_a);
        let util: &StarkitEntry = c
            .entries
            .iter()
            .find(|e: &&StarkitEntry| e.path == "app/lib/util.tcl")
            .expect("util present");
        assert_eq!(util.contents, body_b);
        assert_eq!(c.tcl_source_files.len(), 2);
    }

    #[test]
    fn rejects_non_starkit() {
        assert!(!is_starkit(
            b"this is plainly not a starkit container at all"
        ));
    }

    #[test]
    fn rejects_path_traversal() {
        assert!(sanitize_path("../etc/passwd").is_err());
        assert!(sanitize_path("/abs/path").is_err());
        assert!(sanitize_path("C:/win").is_err());
        assert!(sanitize_path("app/main.tcl:payload").is_err());
        assert_eq!(sanitize_path("app/main.tcl").unwrap(), "app/main.tcl");
    }

    #[test]
    fn zip_entry_reader_rejects_over_cap() {
        let err: Error =
            read_zip_entry_to_limit(Cursor::new(b"abcd"), "app/main.tcl", 4, 3).expect_err("cap");
        assert!(matches!(err, Error::StarkitZip(message) if message.contains("exceeds quota")));
    }

    #[test]
    fn zip_extraction_rejects_total_uncompressed_bytes_over_cap() {
        let kit: Vec<u8> = build_zip_starkit(true, &[("a.tcl", b"abc"), ("b.tcl", b"def")]);
        let err: Error =
            extract_zip_with_limits(&kit, true, MAX_ENTRY_BYTES, 4).expect_err("aggregate cap");
        assert!(matches!(err, Error::StarkitZip(message) if message.contains("exceeds quota")));
    }

    #[test]
    fn metakit_scan_caps_filename_candidates() {
        let mut bytes: Vec<u8> = Vec::new();
        for i in 0..(MAX_ENTRIES + 32usize) {
            let name: String = format!("file{i:05}.tcl");
            bytes.extend_from_slice(name.as_bytes());
            bytes.push(0u8);
        }
        let entries: Vec<StarkitEntry> = scan_metakit_files(&bytes);
        assert_eq!(entries.len(), MAX_ENTRIES);
        assert_eq!(entries[0].path, "file00000.tcl");
        assert_eq!(entries[MAX_ENTRIES - 1usize].path, "file65535.tcl");
    }

    #[test]
    fn metakit_scan_skips_oversized_token_without_candidate() {
        let mut bytes: Vec<u8> = vec![b'a'; MAX_METAKIT_NAME_LEN + 16usize];
        bytes.extend_from_slice(b".tcl");
        bytes.push(0u8);
        bytes.extend_from_slice(b"safe.tcl");
        let entries: Vec<StarkitEntry> = scan_metakit_files(&bytes);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, "safe.tcl");
    }

    fn build_schema_only_metakit() -> Vec<u8> {
        let mut kit: Vec<u8> = Vec::new();
        kit.extend_from_slice(STARKIT_SHEBANG);
        kit.extend_from_slice(b"\n");
        kit.extend_from_slice(STARKIT_HEADER_MARKER);
        kit.extend_from_slice(b"\n");
        kit.extend_from_slice(METAKIT_MAGIC);
        kit.extend_from_slice(b"\x00\x01\xd1\x10<root>\x00");
        kit.extend_from_slice(METAKIT_SCHEMA);
        kit.extend_from_slice(b"main.tcl");
        kit
    }

    #[test]
    fn detects_metakit_schema() {
        let kit: Vec<u8> = build_schema_only_metakit();
        let c: StarkitContainer = extract(&kit).expect("extract metakit");
        assert_eq!(c.format, StarkitFormat::Metakit);
        assert!(c.tcl_source_files.iter().any(|p: &String| p == "main.tcl"));
    }

    #[test]
    fn a_metakit_body_without_a_commit_mark_lists_names_and_recovers_nothing() {
        let kit: Vec<u8> = build_schema_only_metakit();
        let c: StarkitContainer = extract(&kit).expect("extract metakit");
        assert_eq!(c.completeness.recovered_with_contents, 0);
        assert!(decode_metakit(&kit).is_err());
    }

    const SDX_KIT: &[u8] = include_bytes!("../../tests/fixtures/sdx.kit");

    #[test]
    fn metakit_extraction_rejects_total_uncompressed_bytes_over_cap() {
        let err: Error =
            decode_metakit_with_limits(SDX_KIT, MAX_ENTRY_BYTES, 4096u64).expect_err("cap");
        assert!(matches!(err, Error::StarkitZip(message) if message.contains("exceeds quota")));
    }

    #[test]
    fn metakit_extraction_declines_a_member_over_the_per_entry_cap_and_keeps_the_rest() {
        let entries: Vec<StarkitEntry> =
            decode_metakit_with_limits(SDX_KIT, 1024u64, MAX_TOTAL_ENTRY_BYTES)
                .expect("small members still recover");
        let recovered: usize = entries
            .iter()
            .filter(|entry: &&StarkitEntry| !entry.contents.is_empty())
            .count();
        assert!(recovered > 0 && recovered < entries.len());
        assert!(
            entries
                .iter()
                .all(|entry: &StarkitEntry| entry.contents.len() as u64 <= 1024u64)
        );
    }

    #[test]
    fn a_metakit_member_over_the_entry_quota_is_declined_without_allocating_it() {
        let member: MetakitMember<'_> = MetakitMember {
            path: "big.tcl".to_owned(),
            declared_size: 1usize << 40,
            stored: b"\x78\x9c",
        };
        let err: Error = member_bytes(&member, MAX_ENTRY_BYTES).expect_err("quota");
        assert!(
            matches!(err, Error::StarkitMetakit { ref reason } if reason.contains("exceeds quota"))
        );
    }

    #[test]
    fn a_metakit_member_whose_stream_underflows_its_declared_size_is_declined() {
        let member: MetakitMember<'_> = MetakitMember {
            path: "short.tcl".to_owned(),
            declared_size: 4096usize,
            stored: b"\x78\x9c\x03\x00\x00\x00\x00\x01",
        };
        let err: Error = member_bytes(&member, MAX_ENTRY_BYTES).expect_err("underflow");
        assert!(matches!(err, Error::StarkitMetakit { ref reason } if reason.contains("inflate")));
    }

    const OBFUSCATED_TCL: &[u8] = b"\
set cmd [binary format a* [base64::decode $payload]]\n\
proc [lindex $names 0] {args} { eval $body }\n\
namespace eval ::secret { uplevel 1 [subst -nocommands $code] }\n\
interp eval slave [string map $rewrite $template]\n";

    const CLEAN_TCL: &[u8] = b"\
package require Tcl 8.6\n\
proc greet {name} { return \"Hello, $name!\" }\n\
puts [greet disrobe]\n";

    #[test]
    fn flags_obfuscated_tcl_with_multiple_idioms() {
        let kit: Vec<u8> = build_zip_starkit(true, &[("app/loader.tcl", OBFUSCATED_TCL)]);
        let c: StarkitContainer = extract(&kit).expect("extract");
        assert!(
            c.obfuscation.obfuscated,
            "loader using eval+subst+dynamic-proc must be flagged: {:?}",
            c.obfuscation
        );
        assert!(c.obfuscation.indirect_call_hits >= 1);
        assert!(c.obfuscation.dynamic_proc_hits >= 1);
        assert!(c.obfuscation.subst_hits >= 1);
        assert!(
            c.obfuscation
                .hits
                .iter()
                .any(|h: &TclObfuscationHit| h.kind == TclObfuscationKind::IndirectCall)
        );
    }

    #[test]
    fn does_not_flag_clean_tcl() {
        let kit: Vec<u8> = build_zip_starkit(true, &[("app/main.tcl", CLEAN_TCL)]);
        let c: StarkitContainer = extract(&kit).expect("extract");
        assert!(
            !c.obfuscation.obfuscated,
            "ordinary proc/puts source must not be flagged: {:?}",
            c.obfuscation
        );
    }

    #[test]
    fn zip_extraction_is_complete() {
        let kit: Vec<u8> = build_zip_starkit(
            true,
            &[("app/main.tcl", CLEAN_TCL), ("app/data.dat", b"\x00\x01")],
        );
        let c: StarkitContainer = extract(&kit).expect("extract");
        assert_eq!(c.completeness.declared_entries, 2);
        assert_eq!(c.completeness.recovered_with_contents, 2);
        assert!((c.completeness.ratio() - 1.0).abs() < f64::EPSILON);
    }
}
