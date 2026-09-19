#![allow(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::module_name_repetitions,
    clippy::duration_suboptimal_units
)]

use std::collections::BTreeMap;
use std::fs::{File, Metadata, OpenOptions};
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use disrobe_core::scratch::ScratchDir;
use disrobe_tool_process::opened_file_matches_path;
use serde::{Deserialize, Serialize};

use crate::backends::{AndroidBackend, BackendInvocation, invoke_android_captured};
use crate::dalvik_decompile::{DecompiledDex, decompile_dex_bytes};
use crate::error::{Error, Result};

const JADX_TIMEOUT: Duration = Duration::from_secs(300);
const MAX_JADX_SOURCE_FILES: usize = 65_536;
const MAX_JADX_SOURCE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_JADX_TOTAL_SOURCE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_JADX_OUTPUT_TREE_ENTRIES: usize = 262_144;
const MAX_JADX_OUTPUT_TREE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_JADX_INPUT_FILE_NAME_BYTES: usize = 255;
const MAX_JADX_INPUT_FILE_NAME_UTF16_UNITS: usize = 255;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AndroidDecompiler {
    InHouseDalvik,
    Jadx,
}

impl AndroidDecompiler {
    #[inline]
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::InHouseDalvik => "in-house Dalvik decompiler",
            Self::Jadx => "jadx",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AndroidDecompileOutput {
    pub engine: AndroidDecompiler,
    pub sources: BTreeMap<String, String>,
    pub class_count: usize,
    pub method_count: usize,
    pub notes: Vec<String>,
}

#[derive(Debug)]
#[non_exhaustive]
pub enum JadxOutcome {
    Recovered(AndroidDecompileOutput),
    ProducerFailed {
        tool: String,
        status: i32,
        stderr: String,
        emitted_methods: usize,
    },
    Refused(JadxRefusal),
}

#[derive(Debug)]
#[non_exhaustive]
pub enum JadxCapturedOutcome {
    Recovered(AndroidDecompileOutput),
    ProducerFailed {
        tool: String,
        status: i32,
        input_path: PathBuf,
        stdout: String,
        stderr: String,
        output: AndroidDecompileOutput,
        emitted_methods: usize,
    },
    Refused(JadxRefusal),
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum JadxRefusal {
    #[error("JADX output {kind} {actual} exceeds the configured limit {limit}")]
    OutputLimit {
        kind: &'static str,
        actual: u64,
        limit: u64,
    },
    #[error("invalid JADX input filename")]
    InvalidInputFileName,
    #[error("unsafe JADX output path: {detail}")]
    UnsafeOutputPath { detail: String },
}

#[derive(Debug, thiserror::Error)]
enum JadxFailure {
    #[error(transparent)]
    Public(#[from] Error),
    #[error(transparent)]
    Refusal(#[from] JadxRefusal),
}

impl From<std::io::Error> for JadxFailure {
    fn from(error: std::io::Error) -> Self {
        Self::Public(Error::Io(error))
    }
}

type JadxResult<T> = core::result::Result<T, JadxFailure>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendPreference {
    PreferInHouse,
    PreferJadxIfAvailable,
    ForceJadx,
}

impl Default for BackendPreference {
    #[inline]
    fn default() -> Self {
        Self::PreferInHouse
    }
}

pub fn decompile_dex(
    dex_bytes: &[u8],
    preference: BackendPreference,
) -> Result<AndroidDecompileOutput> {
    match preference {
        BackendPreference::ForceJadx => run_jadx_on_bytes(dex_bytes, "input.dex"),
        BackendPreference::PreferJadxIfAvailable => {
            match run_jadx_on_bytes(dex_bytes, "input.dex") {
                Ok(out) => Ok(out),
                Err(Error::MissingTool(_)) => decompile_dex_in_house(dex_bytes),
                Err(e) => Err(e),
            }
        }
        BackendPreference::PreferInHouse => decompile_dex_in_house(dex_bytes),
    }
}

fn decompile_dex_in_house(dex_bytes: &[u8]) -> Result<AndroidDecompileOutput> {
    let dex: crate::dex::DexFile = crate::dex::parse(dex_bytes)?;
    let recovered_defaults: Vec<crate::dalvik_decompile::TranslatedDefaultMethod> =
        crate::dalvik_decompile::translated_default_methods(&dex, dex_bytes);
    let translated: crate::dex2jar::Dex2JarResult = crate::dex2jar::translate_dex_bytes(dex_bytes)?;
    let mut classes: BTreeMap<String, crate::classfile::ClassFile> = BTreeMap::new();
    let mut unparsed: Vec<String> = Vec::new();
    for (entry, bytes) in &translated.jar_entries {
        match crate::parse_classfile(bytes) {
            Ok(parsed) => {
                classes.insert(entry.clone(), parsed);
            }
            Err(error) => unparsed.push(format!("{entry}: {error}")),
        }
    }
    let (sources, refused_sources): (BTreeMap<String, String>, Vec<String>) =
        render_translated_classes(&classes, &recovered_defaults);
    if sources.is_empty() {
        return decompile_dex_directly(dex_bytes);
    }
    let mut notes: Vec<String> = vec![format!(
        "in-house Dalvik decompiler: {} of {} method bodies recovered, {} stubbed",
        translated.bodies_recovered, translated.method_total, translated.stubbed_body_count
    )];
    if !refused_sources.is_empty() {
        notes.push(format!(
            "{} translated class source(s) were refused and carry no recovered source: {}",
            refused_sources.len(),
            refused_sources.join("; ")
        ));
    }
    if !unparsed.is_empty() {
        notes.push(format!(
            "{} translated class file(s) did not parse back and carry no recovered source: {}",
            unparsed.len(),
            unparsed.join("; ")
        ));
    }
    Ok(AndroidDecompileOutput {
        engine: AndroidDecompiler::InHouseDalvik,
        class_count: sources.len(),
        method_count: translated.method_total,
        sources,
        notes,
    })
}

fn render_translated_classes(
    classes: &BTreeMap<String, crate::classfile::ClassFile>,
    recovered_defaults: &[crate::dalvik_decompile::TranslatedDefaultMethod],
) -> (BTreeMap<String, String>, Vec<String>) {
    let mut rendered_sources: Vec<(String, String)> = Vec::new();
    for (entry, class) in classes {
        let stem: &str = entry.trim_end_matches(".class");
        if stem.contains('$') {
            continue;
        }
        let nested_prefix: String = format!("{stem}$");
        let inners: BTreeMap<String, crate::classfile::ClassFile> = classes
            .iter()
            .filter(|(other, _): &(&String, &crate::classfile::ClassFile)| {
                other.trim_end_matches(".class").starts_with(&nested_prefix)
            })
            .map(|(other, inner): (&String, &crate::classfile::ClassFile)| {
                (other.clone(), inner.clone())
            })
            .collect();
        let rendered: crate::decompile::DecompiledClass =
            crate::decompile::decompile_class_with_inners(class, &inners);
        let mut source: String = rendered.source;
        for recovered in recovered_defaults
            .iter()
            .filter(|recovered| recovered.source_stem == stem)
        {
            replace_unique_generated_method(
                &mut source,
                &recovered.owner,
                &recovered.abstract_declaration,
                &recovered.definition,
            );
        }
        rendered_sources.push((stem.to_owned(), source));
    }
    assemble_translated_sources(rendered_sources)
}

fn assemble_translated_sources(
    rendered_sources: Vec<(String, String)>,
) -> (BTreeMap<String, String>, Vec<String>) {
    let mut sources: BTreeMap<String, String> = BTreeMap::new();
    let mut refused: Vec<String> = Vec::new();
    for (stem, source) in rendered_sources {
        let path: String = match translated_source_path(&stem, &source) {
            Ok(path) => path,
            Err(error) => {
                refused.push(format!("{stem}: {error}"));
                continue;
            }
        };
        if sources.contains_key(&path) {
            refused.push(format!("{stem}: {}", Error::DuplicateDex2JarPath(path)));
            continue;
        }
        sources.insert(path, source);
    }
    (sources, refused)
}

#[derive(Clone, Copy)]
struct GeneratedTypeSpan<'a> {
    name: &'a str,
    interface: bool,
    open: usize,
    close: usize,
}

fn replace_unique_generated_method(
    source: &mut String,
    owner: &[String],
    declaration: &str,
    definition: &str,
) {
    let masked: String = mask_java_literals_and_comments(source);
    let spans: Vec<GeneratedTypeSpan<'_>> = generated_type_spans(&masked);
    let matching: Vec<GeneratedTypeSpan<'_>> = spans
        .iter()
        .copied()
        .filter(|span: &GeneratedTypeSpan<'_>| {
            span.interface && generated_type_owner(&spans, *span) == owner
        })
        .collect();
    let [interface]: &[GeneratedTypeSpan<'_>] = matching.as_slice() else {
        return;
    };
    let body_start: usize = interface.open.saturating_add(1);
    let Some(body): Option<&str> = masked.get(body_start..interface.close) else {
        return;
    };
    let mut matches = body
        .match_indices(declaration)
        .map(|(offset, matched): (usize, &str)| (body_start + offset, matched))
        .filter(|(start, _matched): &(usize, &str)| {
            !spans.iter().any(|nested: &GeneratedTypeSpan<'_>| {
                nested.open > interface.open
                    && nested.close < interface.close
                    && *start > nested.open
                    && *start < nested.close
            })
        });
    let Some((start, _matched)): Option<(usize, &str)> = matches.next() else {
        return;
    };
    if matches.next().is_some() {
        return;
    }
    let line_start: usize = source[..start]
        .rfind('\n')
        .map_or(0, |offset: usize| offset + 1);
    let indent: &str = &source[line_start..start];
    if !indent.chars().all(char::is_whitespace) {
        return;
    }
    let replacement: String = definition
        .lines()
        .enumerate()
        .map(|(index, line): (usize, &str)| {
            if index == 0 {
                line.to_owned()
            } else {
                format!("{indent}{line}")
            }
        })
        .collect::<Vec<String>>()
        .join("\n");
    source.replace_range(start..start + declaration.len(), &replacement);
}

fn generated_type_owner(
    spans: &[GeneratedTypeSpan<'_>],
    target: GeneratedTypeSpan<'_>,
) -> Vec<String> {
    let mut owners: Vec<GeneratedTypeSpan<'_>> = spans
        .iter()
        .copied()
        .filter(|span: &GeneratedTypeSpan<'_>| {
            span.open <= target.open && span.close >= target.close
        })
        .collect();
    owners.sort_by_key(|span: &GeneratedTypeSpan<'_>| span.open);
    owners
        .into_iter()
        .map(|span: GeneratedTypeSpan<'_>| span.name.to_owned())
        .collect()
}

fn generated_type_spans(masked: &str) -> Vec<GeneratedTypeSpan<'_>> {
    let bytes: &[u8] = masked.as_bytes();
    let mut spans: Vec<GeneratedTypeSpan<'_>> = Vec::new();
    let mut offset: usize = 0;
    while offset < bytes.len() {
        if !bytes[offset].is_ascii_alphabetic() {
            offset += 1;
            continue;
        }
        let keyword_start: usize = offset;
        while offset < bytes.len()
            && (bytes[offset].is_ascii_alphanumeric() || matches!(bytes[offset], b'_' | b'$'))
        {
            offset += 1;
        }
        let Some(keyword): Option<&str> = masked.get(keyword_start..offset) else {
            continue;
        };
        if !matches!(keyword, "class" | "interface" | "enum" | "record") {
            continue;
        }
        while offset < bytes.len() && bytes[offset].is_ascii_whitespace() {
            offset += 1;
        }
        let name_start: usize = offset;
        while offset < bytes.len()
            && (bytes[offset].is_ascii_alphanumeric() || matches!(bytes[offset], b'_' | b'$'))
        {
            offset += 1;
        }
        if name_start == offset {
            continue;
        }
        let Some(name): Option<&str> = masked.get(name_start..offset) else {
            continue;
        };
        let Some(open): Option<usize> = bytes[offset..]
            .iter()
            .position(|byte: &u8| matches!(*byte, b'{' | b';' | b'}'))
            .and_then(|relative: usize| {
                let absolute: usize = offset + relative;
                (bytes[absolute] == b'{').then_some(absolute)
            })
        else {
            continue;
        };
        let mut depth: usize = 0;
        let mut close: Option<usize> = None;
        for (relative, byte) in bytes[open..].iter().enumerate() {
            match *byte {
                b'{' => depth += 1,
                b'}' => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        close = Some(open + relative);
                        break;
                    }
                }
                _ => {}
            }
        }
        if let Some(close) = close {
            spans.push(GeneratedTypeSpan {
                name,
                interface: keyword == "interface",
                open,
                close,
            });
        }
    }
    spans
}

fn mask_java_literals_and_comments(source: &str) -> String {
    let bytes: &[u8] = source.as_bytes();
    let mut masked: Vec<u8> = bytes.to_vec();
    let mut offset: usize = 0;
    while offset < bytes.len() {
        let (delimiter, line): (u8, bool) = match bytes[offset] {
            b'"' => (b'"', false),
            b'\'' => (b'\'', false),
            b'/' if bytes.get(offset + 1) == Some(&b'/') => (b'\n', true),
            b'/' if bytes.get(offset + 1) == Some(&b'*') => (b'/', false),
            _ => {
                offset += 1;
                continue;
            }
        };
        let block_comment: bool = bytes[offset] == b'/' && delimiter == b'/';
        let start: usize = offset;
        offset += if bytes[start] == b'/' { 2 } else { 1 };
        while offset < bytes.len() {
            if line && bytes[offset] == b'\n' {
                break;
            }
            if block_comment && bytes.get(offset..offset + 2) == Some(&b"*/"[..]) {
                offset += 2;
                break;
            }
            if !line && !block_comment && bytes[offset] == delimiter {
                offset += 1;
                break;
            }
            if !line && !block_comment && bytes[offset] == b'\\' {
                offset = offset.saturating_add(2);
            } else {
                offset += 1;
            }
        }
        for byte in masked.iter_mut().take(offset.min(bytes.len())).skip(start) {
            if *byte != b'\n' {
                *byte = b' ';
            }
        }
    }
    String::from_utf8(masked).unwrap_or_default()
}

fn translated_source_path(stem: &str, source: &str) -> Result<String> {
    let mut names = source.lines().filter_map(|line: &str| {
        if line.starts_with(char::is_whitespace) {
            return None;
        }
        let tokens: Vec<&str> = line.split_ascii_whitespace().collect();
        let kind: usize = tokens.iter().position(|token: &&str| {
            matches!(
                *token,
                "class" | "interface" | "enum" | "record" | "@interface"
            )
        })?;
        let candidate: &str = tokens.get(kind + 1)?.split('<').next()?;
        crate::name_disambig::is_java_source_identifier(candidate).then_some(candidate)
    });
    let Some(name): Option<&str> = names.next() else {
        return Err(Error::MalformedDex2JarClass {
            class: stem.to_owned(),
            reason: "translated source has no top-level declaration",
        });
    };
    if names.next().is_some() {
        return Err(Error::MalformedDex2JarClass {
            class: stem.to_owned(),
            reason: "translated source has multiple top-level declarations",
        });
    }
    let parent: Option<&str> = stem.rsplit_once('/').map(|(parent, _leaf)| parent);
    Ok(parent.map_or_else(
        || format!("{name}.java"),
        |parent: &str| format!("{parent}/{name}.java"),
    ))
}

fn decompile_dex_directly(dex_bytes: &[u8]) -> Result<AndroidDecompileOutput> {
    let decompiled: DecompiledDex = decompile_dex_bytes(dex_bytes)?;
    let mut sources: BTreeMap<String, String> = decompiled.sources;
    if sources.is_empty() {
        sources.insert("decompiled.java".to_string(), decompiled.source);
    }
    Ok(AndroidDecompileOutput {
        engine: AndroidDecompiler::InHouseDalvik,
        sources,
        class_count: decompiled.class_count,
        method_count: decompiled.method_count,
        notes: vec![format!(
            "in-house Dalvik decompiler: {} fully lifted, {} fallback methods",
            decompiled.fully_lifted_methods, decompiled.fallback_methods
        )],
    })
}

pub fn run_jadx_on_bytes(input_bytes: &[u8], file_name: &str) -> Result<AndroidDecompileOutput> {
    legacy_jadx_outcome(run_jadx_on_bytes_detailed(input_bytes, file_name)?)
}

fn legacy_jadx_outcome(outcome: JadxOutcome) -> Result<AndroidDecompileOutput> {
    match outcome {
        JadxOutcome::Recovered(output) => Ok(output),
        JadxOutcome::ProducerFailed {
            tool,
            status,
            stderr,
            emitted_methods: _,
        } => Err(Error::BackendFailed {
            tool,
            status,
            stderr,
        }),
        JadxOutcome::Refused(refusal) => Err(Error::BackendFailed {
            tool: "jadx".to_owned(),
            status: -1,
            stderr: refusal.to_string(),
        }),
    }
}

pub fn run_jadx_on_bytes_detailed(input_bytes: &[u8], file_name: &str) -> Result<JadxOutcome> {
    Ok(match run_jadx_on_bytes_captured(input_bytes, file_name)? {
        JadxCapturedOutcome::Recovered(output) => JadxOutcome::Recovered(output),
        JadxCapturedOutcome::ProducerFailed {
            tool,
            status,
            stderr,
            emitted_methods,
            ..
        } => JadxOutcome::ProducerFailed {
            tool,
            status,
            stderr,
            emitted_methods,
        },
        JadxCapturedOutcome::Refused(refusal) => JadxOutcome::Refused(refusal),
    })
}

pub fn run_jadx_on_bytes_captured(
    input_bytes: &[u8],
    file_name: &str,
) -> Result<JadxCapturedOutcome> {
    match run_jadx_on_bytes_detailed_inner(input_bytes, file_name) {
        Ok(outcome) => Ok(outcome),
        Err(JadxFailure::Public(error)) => Err(error),
        Err(JadxFailure::Refusal(refusal)) => Ok(JadxCapturedOutcome::Refused(refusal)),
    }
}

fn run_jadx_on_bytes_detailed_inner(
    input_bytes: &[u8],
    file_name: &str,
) -> JadxResult<JadxCapturedOutcome> {
    validate_jadx_input_file_name(file_name)?;
    let work: ScratchDir = make_work_dir()?;
    let input_path: PathBuf = work.path().join(file_name);
    std::fs::write(&input_path, input_bytes)?;
    let out_dir: PathBuf = work.path().join("out");
    let result: JadxResult<JadxCapturedOutcome> = run_jadx_on_path_detailed(&input_path, &out_dir);
    result
}

fn validate_jadx_input_file_name(file_name: &str) -> core::result::Result<(), JadxRefusal> {
    let file_name_bytes: usize = file_name.len();
    let file_name_utf16_units: usize = file_name.encode_utf16().count();
    let component_too_long: bool = file_name_bytes > MAX_JADX_INPUT_FILE_NAME_BYTES
        || file_name_utf16_units > MAX_JADX_INPUT_FILE_NAME_UTF16_UNITS;
    let path: &Path = Path::new(file_name);
    let mut components: std::path::Components<'_> = path.components();
    let one_normal_component: bool = matches!(
        (components.next(), components.next()),
        (Some(std::path::Component::Normal(_)), None)
    );
    let forbidden_character: bool = file_name.chars().any(|character: char| {
        character.is_control()
            || matches!(
                character,
                '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*'
            )
    });
    let device_stem: &str = file_name
        .split('.')
        .next()
        .map_or("", |stem: &str| stem)
        .trim_end_matches([' ', '.']);
    let device_name: bool = matches!(
        device_stem.to_ascii_uppercase().as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
    );
    if !one_normal_component
        || forbidden_character
        || file_name.is_empty()
        || file_name.ends_with([' ', '.'])
        || device_name
        || component_too_long
    {
        return Err(JadxRefusal::InvalidInputFileName);
    }
    Ok(())
}

fn run_jadx_on_path_detailed(input_path: &Path, out_dir: &Path) -> JadxResult<JadxCapturedOutcome> {
    let args: Vec<String> = vec![
        "--no-debug-info".to_string(),
        "--threads-count".to_string(),
        "1".to_string(),
        "-d".to_string(),
        out_dir.to_string_lossy().into_owned(),
        input_path.to_string_lossy().into_owned(),
    ];
    let invocation: Result<BackendInvocation> =
        invoke_android_captured(AndroidBackend::Jadx, &args, JADX_TIMEOUT);
    finalize_jadx_output(invocation, input_path, out_dir)
}

fn finalize_jadx_output(
    invocation: Result<BackendInvocation>,
    input_path: &Path,
    out_dir: &Path,
) -> JadxResult<JadxCapturedOutcome> {
    let invocation: BackendInvocation = invocation.map_err(JadxFailure::Public)?;
    let stdout: String = String::from_utf8_lossy(&invocation.stdout).into_owned();
    let stderr: String = String::from_utf8_lossy(&invocation.stderr).into_owned();
    preflight_jadx_output_tree(
        out_dir,
        MAX_JADX_OUTPUT_TREE_ENTRIES,
        MAX_JADX_OUTPUT_TREE_BYTES,
    )?;
    let sources: BTreeMap<String, String> = collect_java_sources(out_dir)?;
    if sources.is_empty() && invocation.exit_code == 0 {
        return Err(Error::BackendFailed {
            tool: "jadx".to_string(),
            status: -1,
            stderr: format!("jadx produced no .java sources; stderr: {stderr}"),
        }
        .into());
    }
    let method_count: usize = sources
        .values()
        .map(|s: &String| count_method_signatures(s))
        .sum();
    let output: AndroidDecompileOutput = AndroidDecompileOutput {
        engine: AndroidDecompiler::Jadx,
        class_count: sources.len(),
        method_count,
        notes: vec!["jadx external backend".to_string()],
        sources,
    };
    if invocation.exit_code != 0 {
        return Ok(JadxCapturedOutcome::ProducerFailed {
            tool: "jadx".to_owned(),
            status: invocation.exit_code,
            input_path: input_path.to_owned(),
            stdout,
            stderr,
            output,
            emitted_methods: method_count,
        });
    }
    Ok(JadxCapturedOutcome::Recovered(output))
}

fn make_work_dir() -> Result<ScratchDir> {
    Ok(ScratchDir::create("disrobe_jadx")?)
}

fn collect_java_sources(out_dir: &Path) -> JadxResult<BTreeMap<String, String>> {
    collect_java_sources_with_limits(
        out_dir,
        MAX_JADX_SOURCE_FILES,
        MAX_JADX_SOURCE_BYTES,
        MAX_JADX_TOTAL_SOURCE_BYTES,
    )
}

fn collect_java_sources_with_limits(
    out_dir: &Path,
    max_files: usize,
    max_file_bytes: u64,
    max_total_bytes: u64,
) -> JadxResult<BTreeMap<String, String>> {
    let mut sources: BTreeMap<String, String> = BTreeMap::new();
    let Some(scan_root): Option<PathBuf> = resolve_jadx_scan_root(out_dir)? else {
        return Ok(sources);
    };
    preflight_jadx_output_tree(
        &scan_root,
        MAX_JADX_OUTPUT_TREE_ENTRIES,
        MAX_JADX_OUTPUT_TREE_BYTES,
    )?;
    if scan_root.is_dir() {
        let mut total_bytes: u64 = 0;
        walk_java(
            &scan_root,
            &mut sources,
            &mut total_bytes,
            max_files,
            max_file_bytes,
            max_total_bytes,
        )?;
    }
    Ok(sources)
}

fn resolve_jadx_scan_root(out_dir: &Path) -> JadxResult<Option<PathBuf>> {
    let out_metadata: std::fs::Metadata = match std::fs::symlink_metadata(out_dir) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if out_metadata.file_type().is_symlink() {
        return Err(JadxRefusal::UnsafeOutputPath {
            detail: format!("JADX output directory is a symlink: {}", out_dir.display()),
        }
        .into());
    }
    if !out_metadata.is_dir() {
        return Ok(None);
    }
    let sources_root: PathBuf = out_dir.join("sources");
    let scan_root: PathBuf = match std::fs::symlink_metadata(&sources_root) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(JadxRefusal::UnsafeOutputPath {
                detail: format!(
                    "JADX source directory is a symlink: {}",
                    sources_root.display()
                ),
            }
            .into());
        }
        Ok(metadata) if metadata.is_dir() => sources_root,
        Ok(_) => out_dir.to_owned(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => out_dir.to_owned(),
        Err(error) => return Err(error.into()),
    };
    let canonical_out: PathBuf = std::fs::canonicalize(out_dir)?;
    let canonical_scan: PathBuf = std::fs::canonicalize(&scan_root)?;
    if !canonical_scan.starts_with(&canonical_out) {
        return Err(JadxRefusal::UnsafeOutputPath {
            detail: format!(
                "JADX source directory escaped its output directory: {}",
                scan_root.display()
            ),
        }
        .into());
    }
    Ok(Some(canonical_scan))
}

fn preflight_jadx_output_tree(root: &Path, max_entries: usize, max_bytes: u64) -> JadxResult<()> {
    let metadata: std::fs::Metadata = match std::fs::symlink_metadata(root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if metadata.file_type().is_symlink() {
        return Err(JadxRefusal::UnsafeOutputPath {
            detail: format!("JADX output root is a symlink: {}", root.display()),
        }
        .into());
    }
    if !metadata.is_dir() {
        return Ok(());
    }
    let canonical_root: PathBuf = std::fs::canonicalize(root)?;
    let mut pending: Vec<PathBuf> = vec![root.to_owned()];
    let mut entries: usize = 0;
    let mut total_bytes: u64 = 0;
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let entry: std::fs::DirEntry = entry?;
            entries = entries.saturating_add(1);
            if entries > max_entries {
                return Err(JadxRefusal::OutputLimit {
                    kind: "output tree entry count",
                    actual: u64::try_from(entries).unwrap_or(u64::MAX),
                    limit: u64::try_from(max_entries).unwrap_or(u64::MAX),
                }
                .into());
            }
            let file_type: std::fs::FileType = entry.file_type()?;
            let path: PathBuf = entry.path();
            if file_type.is_symlink() {
                return Err(JadxRefusal::UnsafeOutputPath {
                    detail: format!("JADX output contains a symlink: {}", path.display()),
                }
                .into());
            }
            let canonical_path: PathBuf = std::fs::canonicalize(&path)?;
            if !canonical_path.starts_with(&canonical_root) {
                return Err(JadxRefusal::UnsafeOutputPath {
                    detail: format!("JADX output escaped its root: {}", path.display()),
                }
                .into());
            }
            if file_type.is_dir() {
                pending.push(path);
                continue;
            }
            if file_type.is_file() {
                total_bytes = total_bytes.checked_add(entry.metadata()?.len()).ok_or(
                    JadxRefusal::OutputLimit {
                        kind: "output tree bytes",
                        actual: u64::MAX,
                        limit: max_bytes,
                    },
                )?;
                if total_bytes > max_bytes {
                    return Err(JadxRefusal::OutputLimit {
                        kind: "output tree bytes",
                        actual: total_bytes,
                        limit: max_bytes,
                    }
                    .into());
                }
            }
        }
    }
    Ok(())
}

fn open_java_source(root: &Path, path: &Path) -> JadxResult<File> {
    let reparse_before: bool = path_contains_reparse_component(root, path)?;
    if reparse_before {
        return Err(JadxRefusal::UnsafeOutputPath {
            detail: format!(
                "JADX source path contains a reparse point: {}",
                path.display()
            ),
        }
        .into());
    }
    let canonical_root: PathBuf = std::fs::canonicalize(root)?;
    let canonical_before: PathBuf = std::fs::canonicalize(path)?;
    if !canonical_before.starts_with(&canonical_root) {
        return Err(JadxRefusal::UnsafeOutputPath {
            detail: format!("JADX source escaped its output root: {}", path.display()),
        }
        .into());
    }
    let before: Metadata = std::fs::symlink_metadata(path)?;
    if metadata_is_reparse_or_symlink(&before) || !before.is_file() {
        return Err(JadxRefusal::UnsafeOutputPath {
            detail: format!("JADX source is not a regular file: {}", path.display()),
        }
        .into());
    }
    let file: File = open_java_source_file(path)?;
    let opened: Metadata = file.metadata()?;
    if metadata_is_reparse_or_symlink(&opened) || !opened.is_file() {
        return Err(JadxRefusal::UnsafeOutputPath {
            detail: format!(
                "JADX source opened through a reparse point: {}",
                path.display()
            ),
        }
        .into());
    }
    let after: Metadata = std::fs::symlink_metadata(path)?;
    let canonical_after: PathBuf = std::fs::canonicalize(path)?;
    let reparse_after: bool = path_contains_reparse_component(root, path)?;
    let identities_match: bool =
        same_opened_file_identity(path, &file)? && before.is_file() && after.is_file();
    if reparse_after
        || metadata_is_reparse_or_symlink(&after)
        || !after.is_file()
        || canonical_after != canonical_before
        || !canonical_after.starts_with(&canonical_root)
        || !identities_match
    {
        return Err(JadxRefusal::UnsafeOutputPath {
            detail: format!("JADX source changed during safe open: {}", path.display()),
        }
        .into());
    }
    Ok(file)
}

fn path_contains_reparse_component(root: &Path, path: &Path) -> JadxResult<bool> {
    let relative: &Path = path
        .strip_prefix(root)
        .map_err(|_| JadxRefusal::UnsafeOutputPath {
            detail: format!(
                "JADX source path is outside its output root: {}",
                path.display()
            ),
        })?;
    let mut current: PathBuf = root.to_owned();
    let root_metadata: Metadata = std::fs::symlink_metadata(&current)?;
    if metadata_is_reparse_or_symlink(&root_metadata) {
        return Ok(true);
    }
    for component in relative.components() {
        current.push(component.as_os_str());
        let metadata: Metadata = std::fs::symlink_metadata(&current)?;
        if metadata_is_reparse_or_symlink(&metadata) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn open_java_source_file(path: &Path) -> std::io::Result<File> {
    let mut options: OpenOptions = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    #[cfg(all(
        unix,
        any(
            target_os = "android",
            target_os = "linux",
            target_os = "macos",
            target_os = "ios",
            target_os = "freebsd",
            target_os = "netbsd",
            target_os = "openbsd"
        )
    ))]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        #[cfg(any(target_os = "android", target_os = "linux"))]
        const O_NOFOLLOW: i32 = 0x20_000;
        #[cfg(any(
            target_os = "freebsd",
            target_os = "ios",
            target_os = "macos",
            target_os = "netbsd",
            target_os = "openbsd"
        ))]
        const O_NOFOLLOW: i32 = 0x100;
        options.custom_flags(O_NOFOLLOW);
    }
    options.open(path)
}

fn metadata_is_reparse_or_symlink(metadata: &Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        metadata.file_type().is_symlink()
            || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    {
        metadata.file_type().is_symlink()
    }
}

fn same_opened_file_identity(path: &Path, file: &File) -> JadxResult<bool> {
    Ok(opened_file_matches_path(path, file)?)
}

fn walk_java(
    root: &Path,
    out: &mut BTreeMap<String, String>,
    total_bytes: &mut u64,
    max_files: usize,
    max_file_bytes: u64,
    max_total_bytes: u64,
) -> JadxResult<()> {
    let mut pending: Vec<PathBuf> = vec![root.to_owned()];
    let canonical_root: PathBuf = std::fs::canonicalize(root)?;
    let max_tree_entries: usize = max_files.saturating_mul(4);
    let mut tree_entries: usize = 0;
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(dir)? {
            let entry: std::fs::DirEntry = entry?;
            tree_entries = tree_entries.saturating_add(1);
            if tree_entries > max_tree_entries {
                return Err(JadxRefusal::OutputLimit {
                    kind: "output tree entry count",
                    actual: u64::try_from(tree_entries).unwrap_or(u64::MAX),
                    limit: u64::try_from(max_tree_entries).unwrap_or(u64::MAX),
                }
                .into());
            }
            let file_type: std::fs::FileType = entry.file_type()?;
            let path: PathBuf = entry.path();
            if file_type.is_symlink() {
                return Err(JadxRefusal::UnsafeOutputPath {
                    detail: format!("JADX output contains a symlink: {}", path.display()),
                }
                .into());
            }
            let canonical_path: PathBuf = std::fs::canonicalize(&path)?;
            if !canonical_path.starts_with(&canonical_root) {
                return Err(JadxRefusal::UnsafeOutputPath {
                    detail: format!("JADX output escaped its root: {}", path.display()),
                }
                .into());
            }
            if file_type.is_dir() {
                pending.push(path);
                continue;
            }
            if !file_type.is_file()
                || path
                    .extension()
                    .and_then(|extension: &std::ffi::OsStr| extension.to_str())
                    != Some("java")
            {
                continue;
            }
            let next_files: usize = out.len().saturating_add(1);
            if next_files > max_files {
                return Err(JadxRefusal::OutputLimit {
                    kind: "source file count",
                    actual: u64::try_from(next_files).unwrap_or(u64::MAX),
                    limit: u64::try_from(max_files).unwrap_or(u64::MAX),
                }
                .into());
            }
            let metadata: std::fs::Metadata = entry.metadata()?;
            let declared_bytes: u64 = metadata.len();
            if declared_bytes > max_file_bytes {
                return Err(JadxRefusal::OutputLimit {
                    kind: "source file bytes",
                    actual: declared_bytes,
                    limit: max_file_bytes,
                }
                .into());
            }
            let mut bytes: Vec<u8> = Vec::new();
            let mut limited: std::io::Take<File> =
                open_java_source(root, &path)?.take(max_file_bytes.saturating_add(1));
            let read_bytes: usize = limited.read_to_end(&mut bytes)?;
            let read_bytes_u64: u64 = u64::try_from(read_bytes).unwrap_or(u64::MAX);
            if read_bytes_u64 > max_file_bytes {
                return Err(JadxRefusal::OutputLimit {
                    kind: "source file bytes",
                    actual: read_bytes_u64,
                    limit: max_file_bytes,
                }
                .into());
            }
            *total_bytes =
                total_bytes
                    .checked_add(read_bytes_u64)
                    .ok_or(JadxRefusal::OutputLimit {
                        kind: "aggregate source bytes",
                        actual: u64::MAX,
                        limit: max_total_bytes,
                    })?;
            if *total_bytes > max_total_bytes {
                return Err(JadxRefusal::OutputLimit {
                    kind: "aggregate source bytes",
                    actual: *total_bytes,
                    limit: max_total_bytes,
                }
                .into());
            }
            let rel: &Path = path.strip_prefix(root).map_err(|_| Error::BackendFailed {
                tool: "jadx".to_owned(),
                status: -1,
                stderr: "JADX source escaped its output root".to_owned(),
            })?;
            let rel: String = rel
                .to_str()
                .ok_or_else(|| Error::BackendFailed {
                    tool: "jadx".to_owned(),
                    status: -1,
                    stderr: "JADX emitted a non-Unicode Java source path".to_owned(),
                })?
                .replace('\\', "/");
            let content: String =
                String::from_utf8(bytes).map_err(|error| Error::BackendFailed {
                    tool: "jadx".to_owned(),
                    status: -1,
                    stderr: format!("JADX emitted non-UTF-8 Java source: {error}"),
                })?;
            if out.insert(rel, content).is_some() {
                return Err(Error::BackendFailed {
                    tool: "jadx".to_owned(),
                    status: -1,
                    stderr: "JADX emitted duplicate Java source paths".to_owned(),
                }
                .into());
            }
        }
    }
    Ok(())
}

fn count_method_signatures(src: &str) -> usize {
    src.lines()
        .filter(|line: &&str| {
            let t: &str = line.trim();
            (t.contains('(') && t.contains(')'))
                && (t.ends_with('{') || t.ends_with(';'))
                && (t.contains("public ")
                    || t.contains("private ")
                    || t.contains("protected ")
                    || t.contains("static "))
                && !t.starts_with("//")
                && !t.starts_with('*')
        })
        .count()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn default_preference_is_in_house() {
        assert_eq!(
            BackendPreference::default(),
            BackendPreference::PreferInHouse
        );
    }

    #[test]
    fn engine_labels() {
        assert_eq!(AndroidDecompiler::Jadx.label(), "jadx");
        assert_eq!(
            AndroidDecompiler::InHouseDalvik.label(),
            "in-house Dalvik decompiler"
        );
    }

    #[test]
    fn count_method_signatures_counts_declarations() {
        let src: &str = "public class Foo {\n  public int bar() {\n  private void baz(int x) {\n}";
        assert_eq!(count_method_signatures(src), 2);
    }

    #[test]
    fn translated_source_assembly_refuses_only_the_offending_classes() {
        let rendered: Vec<(String, String)> = vec![
            (
                "pkg/A-B".to_owned(),
                "package pkg;\npublic class A_u002D_B {\n}\n".to_owned(),
            ),
            (
                "pkg/A_u002D_B".to_owned(),
                "package pkg;\npublic class A_u002D_B {\n    int second;\n}\n".to_owned(),
            ),
            ("pkg/NoDeclaration".to_owned(), "package pkg;\n".to_owned()),
            (
                "pkg/Twice".to_owned(),
                "package pkg;\nclass Twice {\n}\nclass Other {\n}\n".to_owned(),
            ),
            (
                "pkg/Kept".to_owned(),
                "package pkg;\npublic class Kept {\n}\n".to_owned(),
            ),
        ];
        let (sources, refused): (BTreeMap<String, String>, Vec<String>) =
            assemble_translated_sources(rendered);
        assert_eq!(
            sources.keys().cloned().collect::<Vec<String>>(),
            vec!["pkg/A_u002D_B.java".to_owned(), "pkg/Kept.java".to_owned()]
        );
        assert!(!sources["pkg/A_u002D_B.java"].contains("second"));
        assert_eq!(refused.len(), 3, "{refused:?}");
        assert!(refused[0].starts_with("pkg/A_u002D_B: "), "{refused:?}");
        assert!(refused[0].contains("pkg/A_u002D_B.java"), "{refused:?}");
        assert!(refused[1].starts_with("pkg/NoDeclaration: "), "{refused:?}");
        assert!(
            refused[1].contains("no top-level declaration"),
            "{refused:?}"
        );
        assert!(refused[2].starts_with("pkg/Twice: "), "{refused:?}");
        assert!(
            refused[2].contains("multiple top-level declarations"),
            "{refused:?}"
        );
    }

    #[test]
    fn recovered_default_does_not_bind_to_matching_implementor_declaration() {
        let original: &str = "public class Outer {\n    interface ShapeMangled {\n        public abstract String label();\n    }\n    class Implementor {\n        public abstract String label();\n    }\n}\n";
        let mut source: String = original.to_owned();
        replace_unique_generated_method(
            &mut source,
            &["Outer".to_owned(), "Shape".to_owned()],
            "public abstract String label();",
            "public default String label() {\n    return \"shape\";\n}",
        );
        assert_eq!(source, original);
    }

    #[test]
    fn jadx_input_file_name_accepts_one_normal_filename() {
        for file_name in ["input.dex", "EdgeCases.dex", "a"] {
            assert!(
                validate_jadx_input_file_name(file_name).is_ok(),
                "normal filename was rejected: {file_name}"
            );
        }
    }

    #[test]
    fn jadx_input_file_name_rejects_paths_and_device_forms() {
        for file_name in [
            "",
            ".",
            "..",
            "../input.dex",
            r"..\input.dex",
            "/input.dex",
            r"\input.dex",
            "C:/input.dex",
            r"C:\input.dex",
            "foo/bar.dex",
            r"foo\bar.dex",
            "NUL",
            "NUL.dex",
            "CON",
            "COM1",
            r"\\.\NUL",
            r"\\?\C:\input.dex",
        ] {
            assert!(
                matches!(
                    run_jadx_on_bytes_detailed(&[], file_name),
                    Ok(JadxOutcome::Refused(JadxRefusal::InvalidInputFileName))
                ),
                "unsafe filename was accepted: {file_name}"
            );
        }
    }

    #[test]
    fn jadx_input_file_name_enforces_platform_component_limits_before_echoing_input() {
        let accepted: String = "a".repeat(MAX_JADX_INPUT_FILE_NAME_BYTES);
        assert!(validate_jadx_input_file_name(&accepted).is_ok());

        let rejected: String = "a".repeat(MAX_JADX_INPUT_FILE_NAME_BYTES.saturating_add(1));
        let error: Error = run_jadx_on_bytes(&[], &rejected).expect_err("long name");
        assert_eq!(
            error.to_string(),
            "DR-JVM-0016: external tool 'jadx' exited with status -1: invalid JADX input filename"
        );

        #[cfg(windows)]
        {
            let accepted_utf16: String = "é".repeat(MAX_JADX_INPUT_FILE_NAME_UTF16_UNITS / 2);
            assert!(validate_jadx_input_file_name(&accepted_utf16).is_ok());
            let rejected_utf16: String =
                "é".repeat((MAX_JADX_INPUT_FILE_NAME_UTF16_UNITS / 2).saturating_add(1));
            assert!(validate_jadx_input_file_name(&rejected_utf16).is_err());
        }
    }

    #[test]
    fn nonzero_jadx_invocation_preserves_streams_and_partial_sources() -> Result<()> {
        let scratch: ScratchDir = ScratchDir::create("disrobe_jadx_partial_failure")?;
        let sources: PathBuf = scratch.path().join("out").join("sources");
        std::fs::create_dir_all(&sources)?;
        std::fs::write(
            sources.join("EdgeCases.java"),
            b"class EdgeCases {\n  public void recovered() {\n  }\n}",
        )?;
        let invocation: Result<BackendInvocation> = Ok(BackendInvocation {
            stdout: b"producer detail".to_vec(),
            stderr: b"launcher detail".to_vec(),
            exit_code: 7,
        });
        let outcome: JadxCapturedOutcome = finalize_jadx_output(
            invocation,
            scratch.path().join("EdgeCases.dex").as_path(),
            scratch.path().join("out").as_path(),
        )
        .map_err(|failure: JadxFailure| Error::BackendFailed {
            tool: "test".to_owned(),
            status: -1,
            stderr: failure.to_string(),
        })?;
        let JadxCapturedOutcome::ProducerFailed {
            input_path,
            stdout,
            stderr,
            output,
            tool,
            status,
            emitted_methods,
        } = outcome
        else {
            return Err(Error::BackendFailed {
                tool: "test".to_owned(),
                status: -1,
                stderr: "nonzero invocation was not preserved as a producer failure".to_owned(),
            });
        };
        assert_eq!(tool, "jadx");
        assert_eq!(status, 7);
        assert_eq!(input_path, scratch.path().join("EdgeCases.dex"));
        assert_eq!(stdout, "producer detail");
        assert_eq!(stderr, "launcher detail");
        assert_eq!(emitted_methods, 1);
        assert_eq!(output.method_count, 1);
        assert!(output.sources.contains_key("EdgeCases.java"));
        Ok(())
    }

    #[test]
    fn legacy_jadx_api_preserves_backend_failure() -> Result<()> {
        let scratch: ScratchDir = ScratchDir::create("disrobe_jadx_legacy_failure")?;
        let sources: PathBuf = scratch.path().join("out").join("sources");
        std::fs::create_dir_all(&sources)?;
        std::fs::write(
            sources.join("EdgeCases.java"),
            b"class EdgeCases {\n  public void recovered() {\n  }\n}",
        )?;
        let captured: JadxCapturedOutcome = finalize_jadx_output(
            Ok(BackendInvocation {
                stdout: b"producer output".to_vec(),
                stderr: b"launcher output".to_vec(),
                exit_code: 7,
            }),
            scratch.path().join("EdgeCases.dex").as_path(),
            scratch.path().join("out").as_path(),
        )
        .map_err(|failure: JadxFailure| match failure {
            JadxFailure::Public(error) => error,
            JadxFailure::Refusal(refusal) => Error::BackendFailed {
                tool: "jadx".to_owned(),
                status: -1,
                stderr: refusal.to_string(),
            },
        })?;
        let detailed: JadxOutcome = match captured {
            JadxCapturedOutcome::ProducerFailed {
                tool,
                status,
                stderr,
                emitted_methods,
                ..
            } => JadxOutcome::ProducerFailed {
                tool,
                status,
                stderr,
                emitted_methods,
            },
            _ => unreachable!("producer failure expected"),
        };
        let legacy: Error = legacy_jadx_outcome(detailed).expect_err("producer failure expected");
        assert!(matches!(
            legacy,
            Error::BackendFailed {
                tool,
                status: 7,
                stderr,
            } if tool == "jadx"
                && stderr == "launcher output"
        ));
        Ok(())
    }

    #[test]
    fn jadx_output_preflight_bounds_non_java_tree_bytes() -> Result<()> {
        let scratch: ScratchDir = ScratchDir::create("disrobe_jadx_tree_preflight")?;
        let output: PathBuf = scratch.path().join("out");
        std::fs::create_dir(&output)?;
        std::fs::write(output.join("ignored.bin"), b"12")?;
        assert!(matches!(
            preflight_jadx_output_tree(&output, 4, 1),
            Err(JadxFailure::Refusal(JadxRefusal::OutputLimit {
                kind: "output tree bytes",
                ..
            }))
        ));
        Ok(())
    }

    #[cfg(unix)]
    fn create_directory_symlink(
        target: &std::path::Path,
        link: &std::path::Path,
    ) -> std::io::Result<()> {
        std::os::unix::fs::symlink(target, link)
    }

    #[cfg(windows)]
    fn create_directory_symlink(
        target: &std::path::Path,
        link: &std::path::Path,
    ) -> std::io::Result<()> {
        std::os::windows::fs::symlink_dir(target, link)
    }

    #[cfg(unix)]
    fn create_file_symlink(
        target: &std::path::Path,
        link: &std::path::Path,
    ) -> std::io::Result<()> {
        std::os::unix::fs::symlink(target, link)
    }

    #[cfg(windows)]
    fn create_file_symlink(
        target: &std::path::Path,
        link: &std::path::Path,
    ) -> std::io::Result<()> {
        std::os::windows::fs::symlink_file(target, link)
    }

    #[test]
    #[cfg(any(unix, windows))]
    fn jadx_source_open_rejects_symlinked_file() -> Result<()> {
        let scratch: ScratchDir = ScratchDir::create("disrobe_jadx_symlink_file")?;
        let outside: ScratchDir = ScratchDir::create("disrobe_jadx_symlink_file_target")?;
        let target: PathBuf = outside.path().join("Escaped.java");
        std::fs::write(&target, b"class Escaped {}")?;
        let link: PathBuf = scratch.path().join("Escaped.java");
        match create_file_symlink(&target, &link) {
            Ok(()) => {}
            Err(error)
                if cfg!(windows)
                    && matches!(
                        error.kind(),
                        std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::Unsupported
                    ) =>
            {
                eprintln!("SKIP: file symlinks unavailable: {error}");
                return Ok(());
            }
            Err(error) => return Err(error.into()),
        }
        let result: JadxResult<File> = open_java_source(scratch.path(), &link);
        assert!(matches!(
            result,
            Err(JadxFailure::Refusal(JadxRefusal::UnsafeOutputPath { .. }))
        ));
        Ok(())
    }

    #[test]
    #[cfg(windows)]
    fn windows_file_identity_rejects_replacement_metadata() -> Result<()> {
        let scratch: ScratchDir = ScratchDir::create("disrobe_jadx_windows_identity")?;
        let first: PathBuf = scratch.path().join("first.java");
        let replacement: PathBuf = scratch.path().join("replacement.java");
        std::fs::write(&first, b"class First {}")?;
        std::fs::write(&replacement, b"class Replacement { int value = 1; }")?;
        let first_file: File = open_java_source_file(&first)?;
        let replacement_file: File = open_java_source_file(&replacement)?;
        assert!(!opened_file_matches_path(&replacement, &first_file)?);
        assert!(opened_file_matches_path(&replacement, &replacement_file)?);
        Ok(())
    }

    #[test]
    #[cfg(any(unix, windows))]
    fn jadx_source_collection_rejects_symlinked_sources_root() -> Result<()> {
        let scratch: ScratchDir = ScratchDir::create("disrobe_jadx_symlink_root")?;
        let outside: ScratchDir = ScratchDir::create("disrobe_jadx_symlink_target")?;
        std::fs::write(outside.path().join("Escaped.java"), b"class Escaped {}")?;
        let sources: PathBuf = scratch.path().join("sources");
        match create_directory_symlink(outside.path(), &sources) {
            Ok(()) => {}
            Err(error)
                if cfg!(windows)
                    && matches!(
                        error.kind(),
                        std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::Unsupported
                    ) =>
            {
                eprintln!("SKIP: directory symlinks unavailable: {error}");
                return Ok(());
            }
            Err(error) => return Err(error.into()),
        }
        let result: JadxResult<BTreeMap<String, String>> =
            collect_java_sources_with_limits(scratch.path(), 4, 64, 128);
        assert!(matches!(
            result,
            Err(JadxFailure::Refusal(JadxRefusal::UnsafeOutputPath { .. }))
        ));
        Ok(())
    }

    #[test]
    #[cfg(any(unix, windows))]
    fn jadx_source_collection_rejects_symlinked_output_entries() -> Result<()> {
        let scratch: ScratchDir = ScratchDir::create("disrobe_jadx_symlink_entry")?;
        let outside: ScratchDir = ScratchDir::create("disrobe_jadx_symlink_entry_target")?;
        std::fs::write(outside.path().join("Escaped.java"), b"class Escaped {}")?;
        let sources: PathBuf = scratch.path().join("sources");
        std::fs::create_dir(&sources)?;
        let link: PathBuf = sources.join("escaped");
        match create_directory_symlink(outside.path(), &link) {
            Ok(()) => {}
            Err(error)
                if cfg!(windows)
                    && matches!(
                        error.kind(),
                        std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::Unsupported
                    ) =>
            {
                eprintln!("SKIP: directory symlinks unavailable: {error}");
                return Ok(());
            }
            Err(error) => return Err(error.into()),
        }
        let result: JadxResult<BTreeMap<String, String>> =
            collect_java_sources_with_limits(scratch.path(), 4, 64, 128);
        assert!(matches!(
            result,
            Err(JadxFailure::Refusal(JadxRefusal::UnsafeOutputPath { .. }))
        ));
        Ok(())
    }

    #[test]
    fn jadx_source_collection_enforces_file_and_byte_limits() -> Result<()> {
        let scratch: ScratchDir = ScratchDir::create("disrobe_jadx_source_limits")?;
        let sources: PathBuf = scratch.path().join("sources");
        std::fs::create_dir(&sources)?;
        std::fs::write(sources.join("A.java"), b"1234")?;
        std::fs::write(sources.join("B.java"), b"5678")?;

        assert!(collect_java_sources_with_limits(scratch.path(), 2, 4, 8).is_ok());
        assert!(matches!(
            collect_java_sources_with_limits(scratch.path(), 1, 4, 8),
            Err(JadxFailure::Refusal(JadxRefusal::OutputLimit {
                kind: "source file count",
                ..
            }))
        ));
        assert!(matches!(
            collect_java_sources_with_limits(scratch.path(), 2, 3, 8),
            Err(JadxFailure::Refusal(JadxRefusal::OutputLimit {
                kind: "source file bytes",
                ..
            }))
        ));
        assert!(matches!(
            collect_java_sources_with_limits(scratch.path(), 2, 4, 7),
            Err(JadxFailure::Refusal(JadxRefusal::OutputLimit {
                kind: "aggregate source bytes",
                ..
            }))
        ));
        for index in 0..7 {
            std::fs::write(sources.join(format!("ignored-{index}.txt")), b"")?;
        }
        assert!(matches!(
            collect_java_sources_with_limits(scratch.path(), 2, 4, 8),
            Err(JadxFailure::Refusal(JadxRefusal::OutputLimit {
                kind: "output tree entry count",
                ..
            }))
        ));
        Ok(())
    }
}
