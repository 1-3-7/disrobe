use std::collections::BTreeMap;

use base64::Engine;
use serde::{Deserialize, Serialize};

use super::sourcemap_synth::{DecodedMappings, MappingSegment, decode_mappings, encode_mappings};
use crate::error::{Error, Result};

const XSSI_PREFIX: &str = ")]}'";
const MAX_MAP_BYTES: usize = 256 * 1024 * 1024;
const MAX_SECTIONS: usize = 1 << 20;
const MAX_SOURCES: usize = 1 << 22;
const STUB_BANNER: &str = "// disrobe: original sourcesContent absent from this map; \
this is a reconstructed skeleton from sources[]/names[]/mappings, not the original file.";

#[derive(Debug, Clone, Deserialize)]
struct RawV3 {
    #[serde(default)]
    version: u8,
    #[serde(default)]
    file: Option<String>,
    #[serde(rename = "sourceRoot", default)]
    source_root: Option<String>,
    #[serde(default)]
    sources: Vec<Option<String>>,
    #[serde(rename = "sourcesContent", default)]
    sources_content: Vec<Option<String>>,
    #[serde(default)]
    names: Vec<String>,
    #[serde(default)]
    mappings: String,
    #[serde(rename = "ignoreList", default)]
    ignore_list: Vec<usize>,
    #[serde(rename = "x_google_ignoreList", default)]
    legacy_ignore_list: Vec<usize>,
    #[serde(default)]
    sections: Vec<RawSection>,
    #[serde(rename = "debugId", default)]
    debug_id: Option<String>,
    #[serde(rename = "debug_id", default)]
    debug_id_snake: Option<String>,
    #[serde(rename = "x_facebook_sources", default)]
    facebook_sources: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize)]
struct RawSection {
    #[serde(default)]
    offset: Option<RawOffset>,
    #[serde(default)]
    map: Option<RawV3>,
}

#[derive(Debug, Clone, Copy, Default, Deserialize)]
struct RawOffset {
    #[serde(default)]
    line: i64,
    #[serde(default)]
    column: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct SourceMap {
    pub version: u8,
    pub file: Option<String>,
    pub source_root: Option<String>,
    pub sources: Vec<String>,
    pub sources_content: Vec<Option<String>>,
    pub names: Vec<String>,
    pub mappings: String,
    pub ignore_list: Vec<usize>,
    pub debug_id: Option<String>,
    pub hermes: bool,
}

impl SourceMap {
    #[must_use]
    pub const fn entry_count(&self) -> usize {
        self.sources.len()
    }

    #[must_use]
    pub fn has_content(&self) -> bool {
        self.sources_content
            .iter()
            .any(|c: &Option<String>| c.as_ref().is_some_and(|s: &String| !s.is_empty()))
    }
}

fn strip_xssi_and_bom(raw: &str) -> &str {
    let no_bom: &str = raw.strip_prefix('\u{feff}').unwrap_or(raw);
    let trimmed: &str = no_bom.trim_start();
    trimmed
        .strip_prefix(XSSI_PREFIX)
        .map_or(trimmed, |rest: &str| rest.trim_start())
}

fn flatten(raw: RawV3) -> RawV3 {
    if raw.sections.is_empty() {
        return raw;
    }
    let mut sources: Vec<Option<String>> = raw.sources;
    let mut sources_content: Vec<Option<String>> = raw.sources_content;
    let mut names: Vec<String> = raw.names;
    let mut ignore_list: Vec<usize> = merge_ignore_lists(raw.ignore_list, raw.legacy_ignore_list);
    let mut composed: Vec<Vec<MappingSegment>> = Vec::new();
    let mut hermes: bool = raw.facebook_sources.is_some();
    let mut debug_id: Option<String> = raw.debug_id.or(raw.debug_id_snake);
    for section in raw.sections.into_iter().take(MAX_SECTIONS) {
        let Some(map) = section.map else {
            continue;
        };
        let offset: RawOffset = section.offset.unwrap_or_default();
        let inner: RawV3 = flatten(map);
        let source_base: usize = sources.len();
        let name_base: usize = names.len();
        hermes = hermes || inner.facebook_sources.is_some();
        if debug_id.is_none() {
            debug_id = inner.debug_id.or(inner.debug_id_snake);
        }
        if sources.len().saturating_add(inner.sources.len()) <= MAX_SOURCES {
            sources.extend(inner.sources);
            for (idx, content) in inner.sources_content.into_iter().enumerate() {
                let target: usize = source_base + idx;
                while sources_content.len() <= target {
                    sources_content.push(None);
                }
                sources_content[target] = content;
            }
        }
        names.extend(inner.names);
        for ignored in inner.ignore_list {
            if let Some(rebased) = source_base.checked_add(ignored) {
                ignore_list.push(rebased);
            }
        }
        if let Some(decoded) = decode_mappings(&inner.mappings) {
            append_rebased_section(&mut composed, &decoded, offset, source_base, name_base);
        }
    }
    let mappings: String = encode_mappings(&DecodedMappings {
        segment_count: composed.iter().map(Vec::len).sum(),
        lines: composed,
    });
    RawV3 {
        version: if raw.version == 0 { 3 } else { raw.version },
        file: raw.file,
        source_root: raw.source_root,
        sources,
        sources_content,
        names,
        mappings,
        ignore_list,
        legacy_ignore_list: Vec::new(),
        sections: Vec::new(),
        debug_id,
        debug_id_snake: None,
        facebook_sources: hermes.then_some(serde_json::Value::Bool(true)),
    }
}

fn append_rebased_section(
    composed: &mut Vec<Vec<MappingSegment>>,
    decoded: &DecodedMappings,
    offset: RawOffset,
    source_base: usize,
    name_base: usize,
) {
    let source_base_i64: i64 = i64::try_from(source_base).unwrap_or(i64::MAX);
    let name_base_i64: i64 = i64::try_from(name_base).unwrap_or(i64::MAX);
    for (line_idx, line) in decoded.lines.iter().enumerate() {
        let target_line: usize = usize::try_from(offset.line)
            .map_or(line_idx, |base: usize| base.saturating_add(line_idx));
        while composed.len() <= target_line {
            composed.push(Vec::new());
        }
        let column_offset: i64 = if line_idx == 0 { offset.column } else { 0 };
        let Some(target) = composed.get_mut(target_line) else {
            continue;
        };
        for segment in line {
            target.push(MappingSegment {
                generated_column: segment.generated_column.saturating_add(column_offset),
                source_index: segment
                    .source_index
                    .map(|i: i64| i.saturating_add(source_base_i64)),
                source_line: segment.source_line,
                source_column: segment.source_column,
                name_index: segment
                    .name_index
                    .map(|i: i64| i.saturating_add(name_base_i64)),
            });
        }
    }
}

fn merge_ignore_lists(primary: Vec<usize>, legacy: Vec<usize>) -> Vec<usize> {
    let mut merged: Vec<usize> = primary;
    for index in legacy {
        if !merged.contains(&index) {
            merged.push(index);
        }
    }
    merged
}

pub fn parse(raw_json: &str) -> Result<SourceMap> {
    if raw_json.len() > MAX_MAP_BYTES {
        return Err(Error::OxcParse(format!(
            "source map of {} bytes exceeds the {MAX_MAP_BYTES} byte bound",
            raw_json.len(),
        )));
    }
    let cleaned: &str = strip_xssi_and_bom(raw_json);
    let raw: RawV3 = serde_json::from_str(cleaned)
        .map_err(|e: serde_json::Error| Error::OxcParse(e.to_string()))?;
    let hermes: bool = raw.facebook_sources.is_some();
    let debug_id: Option<String> = raw.debug_id.clone().or_else(|| raw.debug_id_snake.clone());
    let raw: RawV3 = flatten(raw);
    let hermes: bool = hermes || raw.facebook_sources.is_some();
    let debug_id: Option<String> = debug_id.or(raw.debug_id).or(raw.debug_id_snake);
    let sources: Vec<String> = raw
        .sources
        .into_iter()
        .take(MAX_SOURCES)
        .map(|s: Option<String>| s.unwrap_or_default())
        .collect();
    let ignore_list: Vec<usize> = merge_ignore_lists(raw.ignore_list, raw.legacy_ignore_list)
        .into_iter()
        .filter(|i: &usize| *i < sources.len())
        .collect();
    Ok(SourceMap {
        version: if raw.version == 0 { 3 } else { raw.version },
        file: raw.file,
        source_root: raw.source_root,
        sources,
        sources_content: raw.sources_content,
        names: raw.names,
        mappings: raw.mappings,
        ignore_list,
        debug_id,
        hermes,
    })
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct SourceCoverage {
    pub mapped_segments: usize,
    pub first_original_line: Option<u32>,
    pub last_original_line: Option<u32>,
    pub named_segments: usize,
    pub names: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RecoveredFile {
    pub relative_path: String,
    pub bytes: Vec<u8>,
    pub reconstructed: bool,
    pub ignored: bool,
    pub coverage: SourceCoverage,
}

#[derive(Debug, Clone, Serialize)]
pub struct RecoveryReport {
    pub file: Option<String>,
    pub source_root: Option<String>,
    pub total_sources: usize,
    pub with_content: usize,
    pub reconstructed_stubs: usize,
    pub ignored_sources: usize,
    pub mapped_segments: usize,
    pub debug_id: Option<String>,
    pub hermes: bool,
    pub files: Vec<RecoveredFile>,
}

#[derive(Debug, Clone, Copy)]
pub struct RecoverOptions {
    pub emit_stubs: bool,
}

impl Default for RecoverOptions {
    fn default() -> Self {
        Self { emit_stubs: true }
    }
}

#[must_use]
pub fn recover(map: &SourceMap, options: RecoverOptions) -> RecoveryReport {
    let decoded: Option<DecodedMappings> = if map.mappings.is_empty() {
        None
    } else {
        decode_mappings(&map.mappings)
    };
    let coverage_by_source: BTreeMap<usize, SourceCoverage> =
        collect_coverage_by_source(map, decoded.as_ref());
    let mapped_segments: usize = decoded
        .as_ref()
        .map_or(0, |d: &DecodedMappings| d.segment_count);

    let ignored_set: std::collections::BTreeSet<usize> = map.ignore_list.iter().copied().collect();
    let mut files: Vec<RecoveredFile> = Vec::with_capacity(map.sources.len());
    let mut used: BTreeMap<String, usize> = BTreeMap::new();
    let mut with_content: usize = 0;
    let mut reconstructed_stubs: usize = 0;

    for (index, raw_source) in map.sources.iter().enumerate() {
        let rel: String =
            safe_relative_path(map.source_root.as_deref(), raw_source, index, &mut used);
        let ignored: bool = ignored_set.contains(&index);
        let coverage: SourceCoverage = coverage_by_source.get(&index).cloned().unwrap_or_default();
        let content: Option<&String> = map
            .sources_content
            .get(index)
            .and_then(|c: &Option<String>| c.as_ref())
            .filter(|c: &&String| !c.is_empty());
        match content {
            Some(text) => {
                with_content += 1;
                files.push(RecoveredFile {
                    relative_path: rel,
                    bytes: text.clone().into_bytes(),
                    reconstructed: false,
                    ignored,
                    coverage,
                });
            }
            None if options.emit_stubs => {
                reconstructed_stubs += 1;
                let stub: String = build_stub(raw_source, &coverage);
                files.push(RecoveredFile {
                    relative_path: rel,
                    bytes: stub.into_bytes(),
                    reconstructed: true,
                    ignored,
                    coverage,
                });
            }
            None => {}
        }
    }

    RecoveryReport {
        file: map.file.clone(),
        source_root: map.source_root.clone(),
        total_sources: map.sources.len(),
        with_content,
        reconstructed_stubs,
        ignored_sources: ignored_set.len(),
        mapped_segments,
        debug_id: map.debug_id.clone(),
        hermes: map.hermes,
        files,
    }
}

const MAX_NAMES_PER_SOURCE: usize = 4096;

fn collect_coverage_by_source(
    map: &SourceMap,
    decoded: Option<&DecodedMappings>,
) -> BTreeMap<usize, SourceCoverage> {
    let mut out: BTreeMap<usize, SourceCoverage> = BTreeMap::new();
    let Some(mappings) = decoded else {
        return out;
    };
    let mut seen_names: BTreeMap<usize, std::collections::BTreeSet<usize>> = BTreeMap::new();
    for line in &mappings.lines {
        for segment in line {
            let Some(src): Option<i64> = segment.source_index else {
                continue;
            };
            let Ok(si): core::result::Result<usize, _> = usize::try_from(src) else {
                continue;
            };
            let entry: &mut SourceCoverage = out.entry(si).or_default();
            entry.mapped_segments = entry.mapped_segments.saturating_add(1);
            if let Some(orig_line) = segment.source_line.and_then(|l: i64| u32::try_from(l).ok()) {
                entry.first_original_line = Some(
                    entry
                        .first_original_line
                        .map_or(orig_line, |cur: u32| cur.min(orig_line)),
                );
                entry.last_original_line = Some(
                    entry
                        .last_original_line
                        .map_or(orig_line, |cur: u32| cur.max(orig_line)),
                );
            }
            if let Some(name_raw) = segment.name_index
                && let Ok(ni) = usize::try_from(name_raw)
            {
                entry.named_segments = entry.named_segments.saturating_add(1);
                if seen_names.entry(si).or_default().insert(ni)
                    && entry.names.len() < MAX_NAMES_PER_SOURCE
                    && let Some(name) = map.names.get(ni)
                {
                    entry.names.push(name.clone());
                }
            }
        }
    }
    out
}

fn push_format(out: &mut String, args: std::fmt::Arguments<'_>) {
    let result: std::result::Result<(), std::fmt::Error> = std::fmt::write(out, args);
    if let Err(error) = result {
        unreachable!("string formatting failed: {error}");
    }
}

fn build_stub(raw_source: &str, coverage: &SourceCoverage) -> String {
    let mut out: String = String::new();
    out.push_str(STUB_BANNER);
    out.push('\n');
    push_format(&mut out, format_args!("// source: {raw_source}\n"));
    if let (Some(first), Some(last)) = (coverage.first_original_line, coverage.last_original_line) {
        push_format(
            &mut out,
            format_args!(
                "// {} mapped segment(s) span original lines {}..={}\n",
                coverage.mapped_segments, first, last
            ),
        );
    }
    if coverage.names.is_empty() {
        out.push_str("// no identifiers were recorded in the map names[] for this source.\n");
    } else {
        push_format(
            &mut out,
            format_args!(
                "// {} identifier(s) referenced from this source:\n",
                coverage.names.len()
            ),
        );
        for name in &coverage.names {
            push_format(&mut out, format_args!("//   {name}\n"));
        }
    }
    out
}

fn strip_virtual_scheme(raw: &str) -> &str {
    for scheme in ["webpack://", "webpack-internal://", "rollup://", "file://"] {
        if let Some(rest) = raw.strip_prefix(scheme) {
            return rest.trim_start_matches('/');
        }
    }
    raw
}

fn join_root(source_root: Option<&str>, source: &str) -> String {
    let Some(root) = source_root.filter(|r: &&str| !r.is_empty()) else {
        return source.to_owned();
    };
    if source.contains("://") || source.starts_with('/') {
        return source.to_owned();
    }
    if root.ends_with('/') {
        format!("{root}{source}")
    } else {
        format!("{root}/{source}")
    }
}

fn safe_relative_path(
    source_root: Option<&str>,
    raw_source: &str,
    index: usize,
    used: &mut BTreeMap<String, usize>,
) -> String {
    let joined: String = join_root(source_root, raw_source);
    let stripped: &str = strip_virtual_scheme(&joined);
    let normalized: String = normalize_components(stripped);
    let candidate: String = if normalized.is_empty() {
        format!("source-{index}.js")
    } else {
        normalized
    };
    dedupe(candidate, index, used)
}

fn normalize_components(path: &str) -> String {
    let unified: String = path.replace('\\', "/");
    let mut parts: Vec<&str> = Vec::new();
    for part in unified.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            other => parts.push(other),
        }
    }
    parts
        .into_iter()
        .map(sanitize_component)
        .collect::<Vec<String>>()
        .join("/")
}

fn sanitize_component(component: &str) -> String {
    let mut out: String = String::with_capacity(component.len());
    for ch in component.chars() {
        match ch {
            '\u{0}'..='\u{1f}' | '<' | '>' | ':' | '"' | '|' | '?' | '*' => out.push('_'),
            _ => out.push(ch),
        }
    }
    let trimmed: &str = out.trim_matches(|c: char| c == ' ' || c == '.');
    if trimmed.is_empty() {
        "_".to_owned()
    } else {
        trimmed.to_owned()
    }
}

fn dedupe(candidate: String, index: usize, used: &mut BTreeMap<String, usize>) -> String {
    match used.get_mut(&candidate) {
        None => {
            used.insert(candidate.clone(), 1);
            candidate
        }
        Some(count) => {
            *count += 1;
            let (stem, ext): (&str, &str) = match candidate.rsplit_once('.') {
                Some((s, e)) if !s.is_empty() => (s, e),
                _ => (candidate.as_str(), ""),
            };
            let disambiguated: String = if ext.is_empty() {
                format!("{stem}.{index}")
            } else {
                format!("{stem}.{index}.{ext}")
            };
            used.insert(disambiguated.clone(), 1);
            disambiguated
        }
    }
}

pub fn recover_from_json(raw_json: &str, options: RecoverOptions) -> Result<RecoveryReport> {
    let map: SourceMap = parse(raw_json)?;
    Ok(recover(&map, options))
}

pub fn recover_from_inline_data_url(url: &str, options: RecoverOptions) -> Result<RecoveryReport> {
    let raw_json: String = decode_data_url_json(url)?;
    recover_from_json(&raw_json, options)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum SourceMapLocation {
    Inline,
    External { url: String },
    Absent,
}

#[derive(Debug, Clone, Serialize)]
pub struct SourceTreeRecovery {
    pub location: SourceMapLocation,
    pub report: Option<RecoveryReport>,
}

pub fn recover_source_tree_from_js<F>(
    source: &str,
    options: RecoverOptions,
    resolve_external: F,
) -> Result<SourceTreeRecovery>
where
    F: FnOnce(&str) -> Option<String>,
{
    let Some(info): Option<super::sourcemap::SourceMapInfo> = super::sourcemap::find(source) else {
        return Ok(SourceTreeRecovery {
            location: SourceMapLocation::Absent,
            report: None,
        });
    };
    if info.inline {
        let raw_json: String = decode_data_url_json(&info.url)?;
        let report: RecoveryReport = recover_from_json(&raw_json, options)?;
        return Ok(SourceTreeRecovery {
            location: SourceMapLocation::Inline,
            report: Some(report),
        });
    }
    let Some(raw_json): Option<String> = resolve_external(&info.url) else {
        return Ok(SourceTreeRecovery {
            location: SourceMapLocation::External { url: info.url },
            report: None,
        });
    };
    let report: RecoveryReport = recover_from_json(&raw_json, options)?;
    Ok(SourceTreeRecovery {
        location: SourceMapLocation::External { url: info.url },
        report: Some(report),
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum NoMapFallback {
    Deobfuscated { source: String },
    OriginalUnchanged,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeployedRecovery {
    pub location: SourceMapLocation,
    pub report: Option<RecoveryReport>,
    pub fallback: Option<NoMapFallback>,
}

pub fn recover_deployed_source<F>(
    source: &str,
    options: RecoverOptions,
    resolve_external: F,
) -> Result<DeployedRecovery>
where
    F: FnOnce(&str) -> Option<String>,
{
    let tree: SourceTreeRecovery = recover_source_tree_from_js(source, options, resolve_external)?;
    if tree.report.is_some() {
        return Ok(DeployedRecovery {
            location: tree.location,
            report: tree.report,
            fallback: None,
        });
    }
    let (deobfuscated, _): (String, crate::unminify::UnminifyStats) =
        crate::unminify::unminify(source);
    let fallback: NoMapFallback = if deobfuscated == source {
        NoMapFallback::OriginalUnchanged
    } else {
        NoMapFallback::Deobfuscated {
            source: deobfuscated,
        }
    };
    Ok(DeployedRecovery {
        location: tree.location,
        report: None,
        fallback: Some(fallback),
    })
}

#[derive(Debug, Clone, Serialize)]
pub struct MergedTreeRecovery {
    pub files: Vec<RecoveredFile>,
    pub total_sources: usize,
    pub with_content: usize,
    pub reconstructed_stubs: usize,
    pub mapped_segments: usize,
    pub chunks_with_map: usize,
    pub chunks_without_map: usize,
    pub debug_ids: Vec<String>,
    pub hermes: bool,
}

pub fn merge_reports(reports: &[RecoveryReport]) -> MergedTreeRecovery {
    let mut by_path: BTreeMap<String, RecoveredFile> = BTreeMap::new();
    let mut mapped_segments: usize = 0;
    let mut debug_ids: Vec<String> = Vec::new();
    let mut hermes: bool = false;
    for report in reports {
        mapped_segments = mapped_segments.saturating_add(report.mapped_segments);
        hermes = hermes || report.hermes;
        if let Some(id) = report.debug_id.as_ref()
            && !debug_ids.contains(id)
        {
            debug_ids.push(id.clone());
        }
        for file in &report.files {
            match by_path.get(&file.relative_path) {
                Some(existing) if !existing.reconstructed => {}
                Some(existing) if existing.reconstructed && !file.reconstructed => {
                    by_path.insert(file.relative_path.clone(), file.clone());
                }
                Some(_) => {}
                None => {
                    by_path.insert(file.relative_path.clone(), file.clone());
                }
            }
        }
    }
    let files: Vec<RecoveredFile> = by_path.into_values().collect();
    let with_content: usize = files
        .iter()
        .filter(|f: &&RecoveredFile| !f.reconstructed)
        .count();
    let reconstructed_stubs: usize = files
        .iter()
        .filter(|f: &&RecoveredFile| f.reconstructed)
        .count();
    let chunks_with_map: usize = reports.len();
    MergedTreeRecovery {
        total_sources: files.len(),
        with_content,
        reconstructed_stubs,
        mapped_segments,
        chunks_with_map,
        chunks_without_map: 0,
        debug_ids,
        hermes,
        files,
    }
}

pub fn recover_source_tree_from_chunks<'a, I, F>(
    chunks: I,
    options: RecoverOptions,
    mut resolve_external: F,
) -> Result<MergedTreeRecovery>
where
    I: IntoIterator<Item = &'a str>,
    F: FnMut(&str) -> Option<String>,
{
    let mut reports: Vec<RecoveryReport> = Vec::new();
    let mut chunks_without_map: usize = 0;
    for chunk in chunks {
        let Some(info): Option<super::sourcemap::SourceMapInfo> = super::sourcemap::find(chunk)
        else {
            chunks_without_map += 1;
            continue;
        };
        let raw_json: Option<String> = if info.inline {
            Some(decode_data_url_json(&info.url)?)
        } else {
            resolve_external(&info.url)
        };
        let Some(json) = raw_json else {
            chunks_without_map += 1;
            continue;
        };
        reports.push(recover_from_json(&json, options)?);
    }
    let mut merged: MergedTreeRecovery = merge_reports(&reports);
    merged.chunks_without_map = chunks_without_map;
    Ok(merged)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OriginalPosition {
    pub source: String,
    pub source_index: usize,
    pub line: u32,
    pub column: u32,
    pub name: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PositionResolver {
    lines: Vec<Vec<MappingSegment>>,
    resolved_sources: Vec<String>,
    names: Vec<String>,
}

impl PositionResolver {
    pub fn from_map(map: &SourceMap) -> Result<Self> {
        let decoded: DecodedMappings = decode_mappings(&map.mappings)
            .ok_or_else(|| Error::OxcParse("malformed source map mappings".to_owned()))?;
        let mut used: BTreeMap<String, usize> = BTreeMap::new();
        let resolved_sources: Vec<String> = map
            .sources
            .iter()
            .enumerate()
            .map(|(index, raw): (usize, &String)| {
                safe_relative_path(map.source_root.as_deref(), raw, index, &mut used)
            })
            .collect();
        Ok(Self {
            lines: decoded.lines,
            resolved_sources,
            names: map.names.clone(),
        })
    }

    pub fn from_json(raw_json: &str) -> Result<Self> {
        let map: SourceMap = parse(raw_json)?;
        Self::from_map(&map)
    }

    #[must_use]
    pub fn resolve(&self, generated_line: u32, generated_column: u32) -> Option<OriginalPosition> {
        let line: &Vec<MappingSegment> = self.lines.get(generated_line as usize)?;
        let target: i64 = i64::from(generated_column);
        let mut best: Option<&MappingSegment> = None;
        for segment in line {
            if segment.generated_column <= target {
                best = Some(segment);
            } else {
                break;
            }
        }
        let segment: &MappingSegment = best?;
        let source_index_raw: i64 = segment.source_index?;
        let source_index: usize = usize::try_from(source_index_raw).ok()?;
        let source_line: i64 = segment.source_line?;
        let source_column: i64 = segment.source_column?;
        let line_u32: u32 = u32::try_from(source_line).ok()?;
        let column_u32: u32 = u32::try_from(source_column).ok()?;
        let source: String = self.resolved_sources.get(source_index)?.clone();
        let name: Option<String> = segment
            .name_index
            .and_then(|n: i64| usize::try_from(n).ok())
            .and_then(|i: usize| self.names.get(i).cloned());
        Some(OriginalPosition {
            source,
            source_index,
            line: line_u32,
            column: column_u32,
            name,
        })
    }
}

pub fn decode_data_url_json(url: &str) -> Result<String> {
    let rest: &str = url
        .strip_prefix("data:")
        .ok_or_else(|| Error::OxcParse("not a data: url".to_owned()))?;
    let comma: usize = rest
        .find(',')
        .ok_or_else(|| Error::OxcParse("data: url has no comma".to_owned()))?;
    let header: &str = &rest[..comma];
    let payload: &str = &rest[comma + 1..];
    if header
        .split(';')
        .any(|p: &str| p.trim().eq_ignore_ascii_case("base64"))
    {
        let bytes: Vec<u8> = base64::engine::general_purpose::STANDARD
            .decode(payload.as_bytes())
            .map_err(|e: base64::DecodeError| Error::OxcParse(e.to_string()))?;
        String::from_utf8(bytes).map_err(|_| Error::Utf8)
    } else {
        let decoded: Vec<u8> =
            disrobe_core::codec::web_escape::percent_decode_lenient(payload.as_bytes(), false);
        Ok(String::from_utf8_lossy(&decoded).into_owned())
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn map_with_content() -> &'static str {
        r#"{
            "version": 3,
            "file": "app.min.js",
            "sourceRoot": "",
            "sources": ["src/index.ts", "src/util.ts"],
            "sourcesContent": ["export const x = 1;\n", "export function add(a, b) { return a + b; }\n"],
            "names": ["x", "add"],
            "mappings": "AAAA"
        }"#
    }

    #[test]
    fn parses_v3_fields() {
        let map: SourceMap = parse(map_with_content()).expect("parse");
        assert_eq!(map.version, 3);
        assert_eq!(map.sources, vec!["src/index.ts", "src/util.ts"]);
        assert!(map.has_content());
        assert_eq!(map.entry_count(), 2);
    }

    #[test]
    fn recovers_files_byte_for_byte() {
        let map: SourceMap = parse(map_with_content()).expect("parse");
        let report: RecoveryReport = recover(&map, RecoverOptions::default());
        assert_eq!(report.with_content, 2);
        assert_eq!(report.reconstructed_stubs, 0);
        let index: &RecoveredFile = report
            .files
            .iter()
            .find(|f: &&RecoveredFile| f.relative_path == "src/index.ts")
            .expect("index.ts present");
        assert_eq!(index.bytes, b"export const x = 1;\n");
        assert!(!index.reconstructed);
    }

    #[test]
    fn strips_xssi_prefix_and_bom() {
        let xssi: String = format!("\u{feff})]}}'\n{}", map_with_content());
        let map: SourceMap = parse(&xssi).expect("parse xssi+bom");
        assert_eq!(map.sources.len(), 2);
    }

    #[test]
    fn strips_webpack_virtual_scheme() {
        let raw: &str = r#"{"version":3,"sources":["webpack:///./src/a.js"],"sourcesContent":["a"],"names":[],"mappings":""}"#;
        let map: SourceMap = parse(raw).expect("parse");
        let report: RecoveryReport = recover(&map, RecoverOptions::default());
        assert_eq!(report.files[0].relative_path, "src/a.js");
    }

    #[test]
    fn blocks_path_traversal() {
        let raw: &str = r#"{"version":3,"sources":["../../../etc/passwd","/abs/secret"],"sourcesContent":["x","y"],"names":[],"mappings":""}"#;
        let map: SourceMap = parse(raw).expect("parse");
        let report: RecoveryReport = recover(&map, RecoverOptions::default());
        for f in &report.files {
            assert!(!f.relative_path.contains(".."), "{}", f.relative_path);
            assert!(!f.relative_path.starts_with('/'), "{}", f.relative_path);
            assert!(
                !std::path::Path::new(&f.relative_path).is_absolute(),
                "{}",
                f.relative_path
            );
        }
        assert_eq!(report.files[0].relative_path, "etc/passwd");
        assert_eq!(report.files[1].relative_path, "abs/secret");
    }

    #[test]
    fn applies_source_root_prefix() {
        let raw: &str = r#"{"version":3,"sourceRoot":"webpack://app","sources":["a.js"],"sourcesContent":["a"],"names":[],"mappings":""}"#;
        let map: SourceMap = parse(raw).expect("parse");
        let report: RecoveryReport = recover(&map, RecoverOptions::default());
        assert_eq!(report.files[0].relative_path, "app/a.js");
    }

    #[test]
    fn builds_stub_when_content_absent() {
        let raw: &str =
            r#"{"version":3,"sources":["src/a.ts"],"names":["greet"],"mappings":"AAAA,SAAAA"}"#;
        let map: SourceMap = parse(raw).expect("parse");
        assert!(!map.has_content());
        let report: RecoveryReport = recover(&map, RecoverOptions::default());
        assert_eq!(report.with_content, 0);
        assert_eq!(report.reconstructed_stubs, 1);
        let stub: &RecoveredFile = &report.files[0];
        assert!(stub.reconstructed);
        let text: String = String::from_utf8(stub.bytes.clone()).expect("utf8");
        assert!(text.contains("greet"), "{text}");
        assert!(text.contains("src/a.ts"), "{text}");
    }

    #[test]
    fn skips_stub_when_disabled() {
        let raw: &str = r#"{"version":3,"sources":["src/a.ts"],"names":[],"mappings":""}"#;
        let map: SourceMap = parse(raw).expect("parse");
        let report: RecoveryReport = recover(&map, RecoverOptions { emit_stubs: false });
        assert!(report.files.is_empty());
    }

    #[test]
    fn dedupes_colliding_paths() {
        let raw: &str = r#"{"version":3,"sources":["a.js","a.js"],"sourcesContent":["one","two"],"names":[],"mappings":""}"#;
        let map: SourceMap = parse(raw).expect("parse");
        let report: RecoveryReport = recover(&map, RecoverOptions::default());
        assert_eq!(report.files[0].relative_path, "a.js");
        assert_ne!(report.files[1].relative_path, "a.js");
    }

    #[test]
    fn empty_source_name_falls_back() {
        let raw: &str =
            r#"{"version":3,"sources":[""],"sourcesContent":["x"],"names":[],"mappings":""}"#;
        let map: SourceMap = parse(raw).expect("parse");
        let report: RecoveryReport = recover(&map, RecoverOptions::default());
        assert_eq!(report.files[0].relative_path, "source-0.js");
    }

    #[test]
    fn decodes_inline_base64_data_url() {
        let json: &str = map_with_content();
        let b64: String = base64::engine::general_purpose::STANDARD.encode(json.as_bytes());
        let url: String = format!("data:application/json;base64,{b64}");
        let report: RecoveryReport =
            recover_from_inline_data_url(&url, RecoverOptions::default()).expect("recover inline");
        assert_eq!(report.with_content, 2);
    }

    #[test]
    fn decodes_inline_percent_encoded_data_url() {
        let json: &str =
            r#"{"version":3,"sources":["a.js"],"sourcesContent":["hi"],"names":[],"mappings":""}"#;
        let encoded: String = json.replace('"', "%22").replace(' ', "%20");
        let url: String = format!("data:application/json,{encoded}");
        let report: RecoveryReport =
            recover_from_inline_data_url(&url, RecoverOptions::default()).expect("recover inline");
        assert_eq!(report.files[0].bytes, b"hi");
    }

    #[test]
    fn flattens_indexed_sections_map() {
        let raw: &str = r#"{
            "version": 3,
            "sections": [
                {"offset": {"line": 0, "column": 0}, "map": {"version":3,"sources":["a.js"],"sourcesContent":["aa"],"names":[],"mappings":""}},
                {"offset": {"line": 10, "column": 0}, "map": {"version":3,"sources":["b.js"],"sourcesContent":["bb"],"names":[],"mappings":""}}
            ]
        }"#;
        let map: SourceMap = parse(raw).expect("parse sectioned");
        assert_eq!(map.sources, vec!["a.js", "b.js"]);
        let report: RecoveryReport = recover(&map, RecoverOptions::default());
        assert_eq!(report.with_content, 2);
    }

    #[test]
    fn sectioned_map_composes_mappings_with_rebased_indices_and_offsets() {
        let raw: &str = r#"{
            "version": 3,
            "sections": [
                {"offset": {"line": 0, "column": 0}, "map": {"version":3,"sources":["a.js"],"names":["alpha"],"mappings":"AAAA,SAAAA"}},
                {"offset": {"line": 2, "column": 5}, "map": {"version":3,"sources":["b.js"],"names":["beta"],"mappings":"AAAA,IAAA,EAAAA"}}
            ]
        }"#;
        let map: SourceMap = parse(raw).expect("parse sectioned with mappings");
        assert_eq!(map.sources, vec!["a.js", "b.js"]);
        assert_eq!(map.names, vec!["alpha", "beta"]);
        let resolver: PositionResolver = PositionResolver::from_map(&map).expect("resolver");

        let first: OriginalPosition = resolver.resolve(0, 0).expect("section 0 line 0");
        assert_eq!(first.source, "a.js");
        assert_eq!(first.source_index, 0);

        let alpha: OriginalPosition = resolver.resolve(0, 9).expect("section 0 named seg @col 9");
        assert_eq!(alpha.name.as_deref(), Some("alpha"));
        assert_eq!(alpha.source, "a.js");

        let second_start: OriginalPosition = resolver
            .resolve(2, 5)
            .expect("section 1 starts at generated line 2 with column offset 5");
        assert_eq!(second_start.source, "b.js");
        assert_eq!(second_start.source_index, 1);

        let beta: OriginalPosition = resolver
            .resolve(2, 11)
            .expect("section 1 named seg at generated col 6+5");
        assert_eq!(beta.name.as_deref(), Some("beta"));
        assert_eq!(beta.source, "b.js");
        assert_eq!(beta.source_index, 1);
    }

    #[test]
    fn parses_debug_id_camel_and_snake() {
        let camel: &str = r#"{"version":3,"sources":["a.js"],"sourcesContent":["x"],"names":[],"mappings":"","debugId":"85314830-023f-4cf1-a267-535f4e37bb17"}"#;
        let map: SourceMap = parse(camel).expect("parse debugId");
        assert_eq!(
            map.debug_id.as_deref(),
            Some("85314830-023f-4cf1-a267-535f4e37bb17")
        );
        let report: RecoveryReport = recover(&map, RecoverOptions::default());
        assert_eq!(
            report.debug_id.as_deref(),
            Some("85314830-023f-4cf1-a267-535f4e37bb17")
        );

        let snake: &str = r#"{"version":3,"sources":["a.js"],"sourcesContent":["x"],"names":[],"mappings":"","debug_id":"deadbeef-0000-0000-0000-000000000000"}"#;
        let map2: SourceMap = parse(snake).expect("parse debug_id");
        assert_eq!(
            map2.debug_id.as_deref(),
            Some("deadbeef-0000-0000-0000-000000000000")
        );
    }

    #[test]
    fn flags_hermes_facebook_sources() {
        let raw: &str = r#"{"version":3,"sources":["a.js"],"sourcesContent":["x"],"names":[],"mappings":"","x_facebook_sources":[[{"names":["<global>"],"mappings":"AAA"}]]}"#;
        let map: SourceMap = parse(raw).expect("parse hermes");
        assert!(map.hermes);
        let report: RecoveryReport = recover(&map, RecoverOptions::default());
        assert!(report.hermes);
    }

    #[test]
    fn merge_reports_prefers_real_content_over_stub_for_same_path() {
        let stubbed: &str =
            r#"{"version":3,"sources":["src/shared.ts"],"names":["x"],"mappings":"AAAA,SAAAA"}"#;
        let withcontent: &str = r#"{"version":3,"sources":["src/shared.ts"],"sourcesContent":["export const x = 1;\n"],"names":[],"mappings":"AAAA"}"#;
        let r1: RecoveryReport =
            recover_from_json(stubbed, RecoverOptions::default()).expect("stub report");
        let r2: RecoveryReport =
            recover_from_json(withcontent, RecoverOptions::default()).expect("content report");
        let merged: MergedTreeRecovery = merge_reports(&[r1, r2]);
        assert_eq!(merged.total_sources, 1);
        assert_eq!(merged.with_content, 1);
        assert_eq!(merged.reconstructed_stubs, 0);
        assert_eq!(merged.files[0].relative_path, "src/shared.ts");
        assert_eq!(merged.files[0].bytes, b"export const x = 1;\n");
        assert!(!merged.files[0].reconstructed);
    }

    #[test]
    fn recover_source_tree_from_chunks_merges_two_inline_maps() {
        let map_a: &str = r#"{"version":3,"sources":["src/a.ts"],"sourcesContent":["export const a = 1;\n"],"names":[],"mappings":""}"#;
        let map_b: &str = r#"{"version":3,"sources":["src/b.ts"],"sourcesContent":["export const b = 2;\n"],"names":[],"mappings":""}"#;
        let b64_a: String = base64::engine::general_purpose::STANDARD.encode(map_a.as_bytes());
        let b64_b: String = base64::engine::general_purpose::STANDARD.encode(map_b.as_bytes());
        let chunk_a: String =
            format!("const a=1;\n//# sourceMappingURL=data:application/json;base64,{b64_a}\n");
        let chunk_b: String =
            format!("const b=2;\n//# sourceMappingURL=data:application/json;base64,{b64_b}\n");
        let chunks: [&str; 2] = [chunk_a.as_str(), chunk_b.as_str()];
        let merged: MergedTreeRecovery =
            recover_source_tree_from_chunks(chunks, RecoverOptions::default(), |_url: &str| None)
                .expect("merge chunks");
        assert_eq!(merged.total_sources, 2);
        assert_eq!(merged.with_content, 2);
        assert_eq!(merged.chunks_with_map, 2);
        assert_eq!(merged.chunks_without_map, 0);
        let a: &RecoveredFile = merged
            .files
            .iter()
            .find(|f: &&RecoveredFile| f.relative_path == "src/a.ts")
            .expect("a present");
        assert_eq!(a.bytes, b"export const a = 1;\n");
    }

    #[test]
    fn recover_deployed_source_falls_back_to_deob_when_no_map() {
        let minified: &str = "var x=!0;var y=!1;\n";
        let recovery: DeployedRecovery =
            recover_deployed_source(minified, RecoverOptions::default(), |_url: &str| None)
                .expect("deployed recovery");
        assert_eq!(recovery.location, SourceMapLocation::Absent);
        assert!(recovery.report.is_none());
        match recovery.fallback {
            Some(NoMapFallback::Deobfuscated { source }) => {
                assert!(
                    source.contains("true"),
                    "!0 should unminify to true: {source}"
                );
                assert!(
                    source.contains("false"),
                    "!1 should unminify to false: {source}"
                );
            }
            other => panic!("expected a deobfuscated fallback, got {other:?}"),
        }
    }

    #[test]
    fn recover_deployed_source_uses_map_when_present() {
        let json: &str = map_with_content();
        let b64: String = base64::engine::general_purpose::STANDARD.encode(json.as_bytes());
        let js: String =
            format!("const x=1;\n//# sourceMappingURL=data:application/json;base64,{b64}\n");
        let recovery: DeployedRecovery =
            recover_deployed_source(&js, RecoverOptions::default(), |_url: &str| None)
                .expect("deployed recovery");
        assert_eq!(recovery.location, SourceMapLocation::Inline);
        assert!(recovery.fallback.is_none());
        assert_eq!(recovery.report.expect("report").with_content, 2);
    }

    #[test]
    fn preserves_non_js_extensions() {
        let raw: &str = r#"{"version":3,"sources":["icons/arrow.svg","style.css"],"sourcesContent":["<svg></svg>","body{}"],"names":[],"mappings":""}"#;
        let map: SourceMap = parse(raw).expect("parse");
        let report: RecoveryReport = recover(&map, RecoverOptions::default());
        assert_eq!(report.files[0].relative_path, "icons/arrow.svg");
        assert_eq!(report.files[0].bytes, b"<svg></svg>");
        assert_eq!(report.files[1].relative_path, "style.css");
    }

    #[test]
    fn rejects_oversized_input() {
        let big: String = "a".repeat(MAX_MAP_BYTES + 1);
        assert!(parse(&big).is_err());
    }

    #[test]
    fn parses_and_flags_ignore_list() {
        let raw: &str = r#"{"version":3,"sources":["app.js","node_modules/vendor.js"],"sourcesContent":["a","v"],"ignoreList":[1],"names":[],"mappings":""}"#;
        let map: SourceMap = parse(raw).expect("parse");
        assert_eq!(map.ignore_list, vec![1]);
        let report: RecoveryReport = recover(&map, RecoverOptions::default());
        assert_eq!(report.ignored_sources, 1);
        let vendor: &RecoveredFile = report
            .files
            .iter()
            .find(|f: &&RecoveredFile| f.relative_path == "node_modules/vendor.js")
            .expect("vendor present");
        assert!(vendor.ignored);
        let app: &RecoveredFile = report
            .files
            .iter()
            .find(|f: &&RecoveredFile| f.relative_path == "app.js")
            .expect("app present");
        assert!(!app.ignored);
    }

    #[test]
    fn accepts_legacy_google_ignore_list_alias() {
        let raw: &str = r#"{"version":3,"sources":["a.js","b.js"],"sourcesContent":["a","b"],"x_google_ignoreList":[0],"names":[],"mappings":""}"#;
        let map: SourceMap = parse(raw).expect("parse");
        assert_eq!(map.ignore_list, vec![0]);
    }

    #[test]
    fn drops_out_of_range_ignore_index() {
        let raw: &str = r#"{"version":3,"sources":["a.js"],"sourcesContent":["a"],"ignoreList":[7],"names":[],"mappings":""}"#;
        let map: SourceMap = parse(raw).expect("parse");
        assert!(map.ignore_list.is_empty());
    }

    #[test]
    fn resolver_maps_generated_position_to_original() {
        let raw: &str = r#"{"version":3,"file":"out.js","sources":["a.js","b.js"],"names":["greet"],"mappings":"AAAA;ICAA,SAAAA"}"#;
        let resolver: PositionResolver = PositionResolver::from_json(raw).expect("resolver");
        let first: OriginalPosition = resolver.resolve(0, 0).expect("line 0 col 0 resolves");
        assert_eq!(first.source, "a.js");
        assert_eq!(first.source_index, 0);
        assert_eq!(first.line, 0);
        assert_eq!(first.column, 0);
        assert_eq!(first.name, None);

        assert!(
            resolver.resolve(1, 1).is_none(),
            "line 1's first mapped column is 4; column 1 precedes any segment"
        );

        let second_start: OriginalPosition = resolver.resolve(1, 4).expect("line 1 col 4 resolves");
        assert_eq!(second_start.source, "b.js");
        assert_eq!(second_start.source_index, 1);

        let named: OriginalPosition = resolver.resolve(1, 13).expect("line 1 col 13 resolves");
        assert_eq!(named.name.as_deref(), Some("greet"));
    }

    #[test]
    fn resolver_picks_last_segment_at_or_before_column() {
        let raw: &str =
            r#"{"version":3,"sources":["a.js"],"names":[],"mappings":"AAAA,IAAC,IAAC"}"#;
        let resolver: PositionResolver = PositionResolver::from_json(raw).expect("resolver");
        let at_zero: OriginalPosition = resolver.resolve(0, 0).expect("col 0");
        assert_eq!(at_zero.column, 0);
        let between: OriginalPosition = resolver.resolve(0, 5).expect("col 5 falls back to seg @4");
        assert_eq!(between.column, 1);
        let at_eight: OriginalPosition = resolver.resolve(0, 8).expect("col 8 lands on seg @8");
        assert_eq!(at_eight.column, 2);
    }

    #[test]
    fn resolver_returns_none_past_last_line() {
        let raw: &str = r#"{"version":3,"sources":["a.js"],"names":[],"mappings":"AAAA"}"#;
        let resolver: PositionResolver = PositionResolver::from_json(raw).expect("resolver");
        assert!(resolver.resolve(99, 0).is_none());
    }

    #[test]
    fn report_carries_per_source_mapping_coverage() {
        let raw: &str = r#"{"version":3,"sources":["a.js","b.js"],"sourcesContent":["aa","bb"],"names":["greet"],"mappings":"AAAA;ICAA,SAAAA"}"#;
        let map: SourceMap = parse(raw).expect("parse");
        let report: RecoveryReport = recover(&map, RecoverOptions::default());
        assert_eq!(report.mapped_segments, 3);
        let a: &RecoveredFile = report
            .files
            .iter()
            .find(|f: &&RecoveredFile| f.relative_path == "a.js")
            .expect("a.js present");
        assert_eq!(a.coverage.mapped_segments, 1);
        assert_eq!(a.coverage.named_segments, 0);
        assert!(a.coverage.names.is_empty());
        let b: &RecoveredFile = report
            .files
            .iter()
            .find(|f: &&RecoveredFile| f.relative_path == "b.js")
            .expect("b.js present");
        assert_eq!(b.coverage.mapped_segments, 2);
        assert_eq!(b.coverage.named_segments, 1);
        assert_eq!(b.coverage.names, vec!["greet"]);
        assert_eq!(b.coverage.first_original_line, Some(0));
        assert_eq!(b.coverage.last_original_line, Some(0));
    }

    #[test]
    fn stub_records_original_line_span_and_names() {
        let raw: &str =
            r#"{"version":3,"sources":["src/a.ts"],"names":["greet"],"mappings":"AAAA,SAAAA"}"#;
        let map: SourceMap = parse(raw).expect("parse");
        let report: RecoveryReport = recover(&map, RecoverOptions::default());
        let stub: &RecoveredFile = &report.files[0];
        let text: String = String::from_utf8(stub.bytes.clone()).expect("utf8");
        assert!(text.contains("greet"), "{text}");
        assert!(
            text.contains("mapped segment(s) span original lines"),
            "{text}"
        );
    }

    #[test]
    fn recovers_full_tree_from_js_with_inline_data_url() {
        let json: &str = map_with_content();
        let b64: String = base64::engine::general_purpose::STANDARD.encode(json.as_bytes());
        let js: String =
            format!("const x=1;\n//# sourceMappingURL=data:application/json;base64,{b64}\n");
        let recovery: SourceTreeRecovery =
            recover_source_tree_from_js(&js, RecoverOptions::default(), |_url: &str| None)
                .expect("recover tree");
        assert_eq!(recovery.location, SourceMapLocation::Inline);
        let report: RecoveryReport = recovery.report.expect("inline map yields a report");
        assert_eq!(report.total_sources, 2);
        assert_eq!(report.with_content, 2);
    }

    #[test]
    fn recovers_full_tree_from_js_with_external_map_via_resolver() {
        let json: &str = map_with_content();
        let js: &str = "const x=1;\n//# sourceMappingURL=app.min.js.map\n";
        let recovery: SourceTreeRecovery =
            recover_source_tree_from_js(js, RecoverOptions::default(), |url: &str| {
                if url == "app.min.js.map" {
                    Some(json.to_owned())
                } else {
                    None
                }
            })
            .expect("recover tree");
        assert_eq!(
            recovery.location,
            SourceMapLocation::External {
                url: "app.min.js.map".to_owned()
            }
        );
        let report: RecoveryReport = recovery.report.expect("external map resolves to a report");
        assert_eq!(report.with_content, 2);
    }

    #[test]
    fn tree_recovery_reports_unresolved_external_map() {
        let js: &str = "const x=1;\n//# sourceMappingURL=missing.js.map\n";
        let recovery: SourceTreeRecovery =
            recover_source_tree_from_js(js, RecoverOptions::default(), |_url: &str| None)
                .expect("recover tree");
        assert_eq!(
            recovery.location,
            SourceMapLocation::External {
                url: "missing.js.map".to_owned()
            }
        );
        assert!(
            recovery.report.is_none(),
            "an unresolvable external map yields no report, honestly walled"
        );
    }

    #[test]
    fn tree_recovery_reports_absent_source_map() {
        let js: &str = "const x = 1;\nconsole.log(x);\n";
        let recovery: SourceTreeRecovery =
            recover_source_tree_from_js(js, RecoverOptions::default(), |_url: &str| None)
                .expect("recover tree");
        assert_eq!(recovery.location, SourceMapLocation::Absent);
        assert!(recovery.report.is_none());
    }
}
