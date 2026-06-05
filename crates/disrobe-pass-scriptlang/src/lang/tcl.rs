use std::io::{Cursor, Read};

use serde::Serialize;

use crate::error::{Error, Result};

const STARKIT_SHEBANG: &[u8] = b"#!/bin/sh";
const STARKIT_HEADER_MARKER: &[u8] = b"package require starkit";
const METAKIT_MAGIC: &[u8] = b"JL\x1a\x00";
const METAKIT_SCHEMA: &[u8] = b"dirs[name:S,parent:I,files[name:S,size:I,date:I,contents:B]]";
const ZIP_EOCD: &[u8] = b"PK\x05\x06";
const ZIP_LOCAL: &[u8] = b"PK\x03\x04";
const MAX_ENTRY_BYTES: u64 = 64 * 1024 * 1024;
const MAX_ENTRIES: usize = 65_536usize;

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
    /// Fraction of declared container members whose bytes were actually recovered (0.0..=1.0).
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
        && (has_starkit_header(bytes) || find_zip_start(bytes).is_some())
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
    let start: usize = find_zip_start(bytes).ok_or(Error::NotStarkit)?;
    let archive_bytes: &[u8] = &bytes[start..];
    let cursor: Cursor<&[u8]> = Cursor::new(archive_bytes);
    let mut zip: zip::ZipArchive<Cursor<&[u8]>> = zip::ZipArchive::new(cursor)?;
    let mut entries: Vec<StarkitEntry> = Vec::with_capacity(zip.len().min(MAX_ENTRIES));
    for i in 0..zip.len().min(MAX_ENTRIES) {
        let mut file: zip::read::ZipFile<'_> = zip.by_index(i)?;
        let name: String = file.name().to_owned();
        if file.is_dir() {
            continue;
        }
        let safe: String = sanitize_path(&name)?;
        if file.size() > MAX_ENTRY_BYTES {
            return Err(Error::StarkitZip(format!(
                "entry '{name}' size {} exceeds quota",
                file.size()
            )));
        }
        let mut contents: Vec<u8> = Vec::with_capacity(file.size() as usize);
        file.read_to_end(&mut contents)?;
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
    let entries: Vec<StarkitEntry> = scan_metakit_files(bytes);
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

fn scan_metakit_files(bytes: &[u8]) -> Vec<StarkitEntry> {
    let mut names: Vec<String> = Vec::new();
    let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let limit: usize = bytes.len().saturating_sub(4);
    let mut i: usize = 0usize;
    while i < limit {
        if let Some((name, next)) = read_metakit_token(bytes, i) {
            if is_plausible_filename(&name) && seen.insert(name.clone()) {
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

fn read_metakit_token(bytes: &[u8], at: usize) -> Option<(String, usize)> {
    let b: u8 = *bytes.get(at)?;
    if !is_filename_byte(b) {
        return None;
    }
    let mut end: usize = at;
    while end < bytes.len() && is_filename_byte(bytes[end]) {
        end += 1;
    }
    let slice: &[u8] = &bytes[at..end];
    let text: &str = std::str::from_utf8(slice).ok()?;
    Some((text.to_owned(), end))
}

fn is_plausible_filename(name: &str) -> bool {
    let known: [&str; 8] = [".tcl", ".tm", ".msg", ".dat", ".txt", ".rc", ".sh", ".gif"];
    name.len() >= 4
        && name.len() <= 255
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
        || normalized.chars().nth(1) == Some(':')
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
        assert_eq!(sanitize_path("app/main.tcl").unwrap(), "app/main.tcl");
    }

    #[test]
    fn detects_metakit_schema() {
        let mut kit: Vec<u8> = Vec::new();
        kit.extend_from_slice(STARKIT_SHEBANG);
        kit.extend_from_slice(b"\n");
        kit.extend_from_slice(STARKIT_HEADER_MARKER);
        kit.extend_from_slice(b"\n");
        kit.extend_from_slice(METAKIT_MAGIC);
        kit.extend_from_slice(b"\x00\x01\xd1\x10<root>\x00");
        kit.extend_from_slice(METAKIT_SCHEMA);
        kit.extend_from_slice(b"main.tcl");
        let c: StarkitContainer = extract(&kit).expect("extract metakit");
        assert_eq!(c.format, StarkitFormat::Metakit);
        assert!(c.tcl_source_files.iter().any(|p: &String| p == "main.tcl"));
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
