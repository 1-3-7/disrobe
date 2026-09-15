use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineRange {
    pub obfuscated_start: u32,
    pub obfuscated_end: u32,
    pub original_start: u32,
    pub original_end: u32,
}

impl LineRange {
    #[inline]
    #[must_use]
    pub const fn contains_obfuscated(&self, line: u32) -> bool {
        line >= self.obfuscated_start && line <= self.obfuscated_end
    }

    #[must_use]
    pub const fn original_for(&self, obfuscated_line: u32) -> u32 {
        if self.original_start == self.original_end {
            return self.original_start;
        }
        let obf_span: u32 = self.obfuscated_end.saturating_sub(self.obfuscated_start);
        if obf_span == 0 {
            return self.original_start;
        }
        let offset: u32 = obfuscated_line.saturating_sub(self.obfuscated_start);
        let capped: u32 = if offset > obf_span { obf_span } else { offset };
        self.original_start.saturating_add(capped)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MethodMapping {
    pub original_name: String,
    pub param_count: usize,
    pub params: String,
    pub descriptor_params: String,
    pub return_type: String,
    pub line_ranges: Vec<LineRange>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MethodLineRecord {
    pub original_name: String,
    pub holder_class: Option<String>,
    pub params: String,
    pub param_count: usize,
    pub descriptor_params: String,
    pub return_type: String,
    pub line_range: Option<LineRange>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetracedFrame {
    pub class_name: String,
    pub method_name: String,
    pub original_line: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldMapping {
    pub original_name: String,
    pub source_type: String,
    pub descriptor_type: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClassMapping {
    pub original_name: String,
    pub obfuscated_name: String,
    pub fields: BTreeMap<String, String>,
    pub field_overloads: BTreeMap<String, Vec<FieldMapping>>,
    pub methods: BTreeMap<String, Vec<MethodMapping>>,
    pub line_records: BTreeMap<String, Vec<MethodLineRecord>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Mapping {
    pub classes: BTreeMap<String, ClassMapping>,
    pub by_original: BTreeMap<String, String>,
}

impl Mapping {
    #[inline]
    #[must_use]
    pub fn lookup_obfuscated_class(&self, obfuscated: &str) -> Option<&ClassMapping> {
        self.classes.get(obfuscated)
    }

    #[inline]
    #[must_use]
    pub fn lookup_original_class(&self, original: &str) -> Option<&str> {
        self.by_original.get(original).map(String::as_str)
    }

    #[must_use]
    pub fn original_binary_for_obfuscated(&self, obfuscated_binary: &str) -> Option<String> {
        let dotted: String = obfuscated_binary.replace('/', ".");
        self.classes
            .get(&dotted)
            .map(|c: &ClassMapping| c.original_name.replace('.', "/"))
    }
}

pub fn parse(text: &str) -> Result<Mapping> {
    let mut mapping: Mapping = Mapping::default();
    let mut current: Option<ClassMapping> = None;
    for (line_no, raw) in text.lines().enumerate() {
        let line: &str = strip_comment(raw);
        if line.is_empty() {
            continue;
        }
        if !line.starts_with(|c: char| c.is_whitespace()) {
            if let Some(cls) = current.take() {
                commit_class(&mut mapping, cls);
            }
            let Some(arrow): Option<usize> = line.find(" -> ") else {
                return Err(Error::BadMapping(
                    line_no + 1,
                    "expected ' -> ' in class header".into(),
                ));
            };
            let original_name: String = line[..arrow].trim().to_string();
            let rest: &str = &line[arrow + 4..];
            let obfuscated: String = rest.trim_end_matches(':').trim().to_string();
            if original_name.is_empty() || obfuscated.is_empty() {
                return Err(Error::BadMapping(
                    line_no + 1,
                    "empty original or obfuscated name".into(),
                ));
            }
            current = Some(ClassMapping {
                original_name,
                obfuscated_name: obfuscated,
                fields: BTreeMap::new(),
                field_overloads: BTreeMap::new(),
                methods: BTreeMap::new(),
                line_records: BTreeMap::new(),
            });
            continue;
        }
        let trimmed: &str = line.trim();
        let Some(arrow): Option<usize> = trimmed.find(" -> ") else {
            continue;
        };
        let lhs: &str = trimmed[..arrow].trim();
        let rhs: &str = trimmed[arrow + 4..].trim();
        let Some(cls): Option<&mut ClassMapping> = current.as_mut() else {
            return Err(Error::BadMapping(
                line_no + 1,
                "member line outside class block".into(),
            ));
        };
        let (obf_range, lhs): (Option<(u32, u32)>, &str) = split_line_prefix(lhs);
        let (orig_range, lhs): (Option<(u32, u32)>, &str) = split_line_suffix(lhs);
        if let Some(paren_open) = lhs.find('(') {
            ingest_method_line(cls, lhs, paren_open, rhs, obf_range, orig_range);
        } else {
            ingest_field_line(cls, lhs, rhs);
        }
    }
    if let Some(cls) = current.take() {
        commit_class(&mut mapping, cls);
    }
    Ok(mapping)
}

fn commit_class(mapping: &mut Mapping, mut cls: ClassMapping) {
    build_overload_table(&mut cls);
    mapping
        .by_original
        .insert(cls.original_name.clone(), cls.obfuscated_name.clone());
    mapping.classes.insert(cls.obfuscated_name.clone(), cls);
}

struct ParsedMethodLine {
    holder_class: Option<String>,
    method_name: String,
    params: String,
    param_count: usize,
    descriptor_params: String,
    return_type: String,
    line_range: Option<LineRange>,
}

fn parse_method_line(
    lhs: &str,
    paren_open: usize,
    obf_range: Option<(u32, u32)>,
    orig_range: Option<(u32, u32)>,
) -> ParsedMethodLine {
    let prefix: &str = &lhs[..paren_open];
    let mut prefix_tokens: std::str::SplitWhitespace<'_> = prefix.split_whitespace();
    let return_type: &str = prefix_tokens.next().unwrap_or_default();
    let raw_name: &str = prefix_tokens.next().unwrap_or(return_type);
    let (holder_class, method_name): (Option<String>, String) = match raw_name.rsplit_once('.') {
        Some((qual, simple)) => (Some(qual.to_string()), simple.to_string()),
        None => (None, raw_name.to_string()),
    };
    let paren_close: usize = lhs.find(')').unwrap_or(lhs.len());
    let params: &str = &lhs[paren_open + 1..paren_close.min(lhs.len())];
    let param_count: usize = if params.trim().is_empty() {
        0
    } else {
        params.split(',').count()
    };
    let descriptor_params: String = source_params_to_descriptor(params);
    let line_range: Option<LineRange> = match (obf_range, orig_range) {
        (Some((obf_lo, obf_hi)), Some((orig_lo, orig_hi))) => Some(LineRange {
            obfuscated_start: obf_lo,
            obfuscated_end: obf_hi,
            original_start: orig_lo,
            original_end: orig_hi,
        }),
        (Some((obf_lo, obf_hi)), None) => Some(LineRange {
            obfuscated_start: obf_lo,
            obfuscated_end: obf_hi,
            original_start: obf_lo,
            original_end: obf_hi,
        }),
        _ => None,
    };
    ParsedMethodLine {
        holder_class,
        method_name,
        params: params.to_string(),
        param_count,
        descriptor_params,
        return_type: return_type.to_string(),
        line_range,
    }
}

fn ingest_method_line(
    cls: &mut ClassMapping,
    lhs: &str,
    paren_open: usize,
    rhs: &str,
    obf_range: Option<(u32, u32)>,
    orig_range: Option<(u32, u32)>,
) {
    let parsed: ParsedMethodLine = parse_method_line(lhs, paren_open, obf_range, orig_range);
    cls.line_records
        .entry(rhs.to_string())
        .or_default()
        .push(MethodLineRecord {
            original_name: parsed.method_name,
            holder_class: parsed.holder_class,
            params: parsed.params,
            param_count: parsed.param_count,
            descriptor_params: parsed.descriptor_params,
            return_type: parsed.return_type,
            line_range: parsed.line_range,
        });
}

const fn ranges_overlap(a: &LineRange, b: &LineRange) -> bool {
    a.obfuscated_start <= b.obfuscated_end && b.obfuscated_start <= a.obfuscated_end
}

fn build_overload_table(cls: &mut ClassMapping) {
    for (obf_name, records) in &cls.line_records {
        let outers: Vec<&MethodLineRecord> = select_physical_methods(records);
        let table: &mut Vec<MethodMapping> = cls.methods.entry(obf_name.clone()).or_default();
        for rec in outers {
            if rec.holder_class.is_some() {
                continue;
            }
            if let Some(existing) = table
                .iter_mut()
                .find(|m: &&mut MethodMapping| m.descriptor_params == rec.descriptor_params)
            {
                if let Some(range) = rec.line_range
                    && !existing.line_ranges.contains(&range)
                {
                    existing.line_ranges.push(range);
                }
            } else {
                table.push(MethodMapping {
                    original_name: rec.original_name.clone(),
                    param_count: rec.param_count,
                    params: rec.params.clone(),
                    descriptor_params: rec.descriptor_params.clone(),
                    return_type: rec.return_type.clone(),
                    line_ranges: rec.line_range.into_iter().collect(),
                });
            }
        }
        if table.is_empty() {
            cls.methods.remove(obf_name);
        }
    }
}

fn select_physical_methods(records: &[MethodLineRecord]) -> Vec<&MethodLineRecord> {
    let mut outers: Vec<&MethodLineRecord> = Vec::new();
    let mut i: usize = 0;
    while i < records.len() {
        let base: &MethodLineRecord = &records[i];
        match base.line_range {
            None => {
                outers.push(base);
                i += 1;
            }
            Some(base_range) => {
                let mut last: &MethodLineRecord = base;
                let mut j: usize = i + 1;
                while j < records.len() {
                    let Some(next_range): Option<LineRange> = records[j].line_range else {
                        break;
                    };
                    if ranges_overlap(&base_range, &next_range) {
                        last = &records[j];
                        j += 1;
                    } else {
                        break;
                    }
                }
                outers.push(last);
                i = j;
            }
        }
    }
    outers
}

fn ingest_field_line(cls: &mut ClassMapping, lhs: &str, rhs: &str) {
    let mut parts: std::str::SplitWhitespace<'_> = lhs.split_whitespace();
    let source_type: &str = parts.next().unwrap_or_default();
    let field_name: &str = parts.next().unwrap_or(source_type);
    cls.fields.insert(rhs.to_string(), field_name.to_string());
    let descriptor_type: String = source_type_to_descriptor(source_type);
    let overloads: &mut Vec<FieldMapping> = cls.field_overloads.entry(rhs.to_string()).or_default();
    let already: bool = overloads
        .iter()
        .any(|f: &FieldMapping| f.descriptor_type == descriptor_type);
    if !already {
        overloads.push(FieldMapping {
            original_name: field_name.to_string(),
            source_type: source_type.to_string(),
            descriptor_type,
        });
    }
}

fn strip_comment(line: &str) -> &str {
    if let Some(hash) = line.find('#') {
        &line[..hash]
    } else {
        line
    }
}

fn split_line_prefix(member: &str) -> (Option<(u32, u32)>, &str) {
    let bytes: &[u8] = member.as_bytes();
    let mut idx: usize = 0;
    while idx < bytes.len() && bytes[idx].is_ascii_digit() {
        idx += 1;
    }
    if idx == 0 || idx >= bytes.len() || bytes[idx] != b':' {
        return (None, member);
    }
    let start: Option<u32> = member[..idx].parse::<u32>().ok();
    let mut second: usize = idx + 1;
    while second < bytes.len() && bytes[second].is_ascii_digit() {
        second += 1;
    }
    if second > idx + 1 && second < bytes.len() && bytes[second] == b':' {
        let end: Option<u32> = member[idx + 1..second].parse::<u32>().ok();
        let range: Option<(u32, u32)> = start.zip(end);
        return (range, &member[second + 1..]);
    }
    let range: Option<(u32, u32)> = start.map(|s: u32| (s, s));
    (range, &member[idx + 1..])
}

fn split_line_suffix(member: &str) -> (Option<(u32, u32)>, &str) {
    let Some(close): Option<usize> = member.rfind(')') else {
        return (None, member);
    };
    let tail: &str = &member[close + 1..];
    if !tail.starts_with(':') {
        return (None, member);
    }
    let parts: Vec<&str> = tail[1..].split(':').collect();
    if parts.is_empty()
        || !parts
            .iter()
            .all(|part: &&str| !part.is_empty() && part.bytes().all(|b: u8| b.is_ascii_digit()))
    {
        return (None, member);
    }
    let Some(start): Option<u32> = parts.first().and_then(|p: &&str| p.parse::<u32>().ok()) else {
        return (None, member);
    };
    let end: u32 = parts
        .get(1)
        .and_then(|p: &&str| p.parse::<u32>().ok())
        .unwrap_or(start);
    (Some((start, end)), &member[..=close])
}

#[must_use]
pub fn source_type_to_descriptor(source_type: &str) -> String {
    let trimmed: &str = source_type.trim();
    let mut dims: usize = 0;
    let mut base: &str = trimmed;
    while let Some(stripped) = base.strip_suffix("[]") {
        dims += 1;
        base = stripped.trim_end();
    }
    let mut out: String = String::with_capacity(base.len() + dims + 2);
    for _ in 0..dims {
        out.push('[');
    }
    match base {
        "void" => out.push('V'),
        "boolean" => out.push('Z'),
        "byte" => out.push('B'),
        "char" => out.push('C'),
        "short" => out.push('S'),
        "int" => out.push('I'),
        "long" => out.push('J'),
        "float" => out.push('F'),
        "double" => out.push('D'),
        "" => {}
        other => {
            out.push('L');
            out.push_str(&other.replace('.', "/"));
            out.push(';');
        }
    }
    out
}

#[must_use]
pub fn source_params_to_descriptor(params: &str) -> String {
    let trimmed: &str = params.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let mut out: String = String::new();
    for part in trimmed.split(',') {
        out.push_str(&source_type_to_descriptor(part));
    }
    out
}

fn descriptor_arg_count(descriptor: &str) -> usize {
    let bytes: &[u8] = descriptor.as_bytes();
    let Some(open): Option<usize> = descriptor.find('(') else {
        return 0;
    };
    let Some(close): Option<usize> = descriptor.find(')') else {
        return 0;
    };
    let mut count: usize = 0;
    let mut i: usize = open + 1;
    while i < close {
        match bytes[i] {
            b'[' => {
                i += 1;
            }
            b'L' => {
                count += 1;
                while i < close && bytes[i] != b';' {
                    i += 1;
                }
                i += 1;
            }
            _ => {
                count += 1;
                i += 1;
            }
        }
    }
    count
}

#[must_use]
pub fn descriptor_params_slice(descriptor: &str) -> Option<&str> {
    let open: usize = descriptor.find('(')?;
    let close: usize = descriptor.find(')')?;
    if close < open + 1 {
        return None;
    }
    Some(&descriptor[open + 1..close])
}

fn select_overload<'a>(
    overloads: &'a [MethodMapping],
    descriptor: Option<&str>,
) -> Option<&'a MethodMapping> {
    if overloads.len() == 1 {
        return overloads.first();
    }
    if let Some(desc) = descriptor {
        if let Some(params) = descriptor_params_slice(desc)
            && let Some(matched) = overloads
                .iter()
                .find(|m: &&MethodMapping| m.descriptor_params == params)
        {
            return Some(matched);
        }
        let arg_count: usize = descriptor_arg_count(desc);
        if let Some(matched) = overloads
            .iter()
            .find(|m: &&MethodMapping| m.param_count == arg_count)
        {
            return Some(matched);
        }
    }
    overloads.first()
}

fn select_field<'a>(
    overloads: &'a [FieldMapping],
    descriptor_type: Option<&str>,
) -> Option<&'a FieldMapping> {
    if overloads.len() == 1 {
        return overloads.first();
    }
    if let Some(ty) = descriptor_type
        && let Some(matched) = overloads
            .iter()
            .find(|f: &&FieldMapping| f.descriptor_type == ty)
    {
        return Some(matched);
    }
    overloads.first()
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppliedNames {
    pub class_name: Option<String>,
    pub super_name: Option<String>,
    pub interfaces: Vec<String>,
    pub fields: BTreeMap<String, String>,
    pub methods: BTreeMap<String, String>,
    pub method_descriptors: BTreeMap<String, String>,
    pub restored_count: usize,
}

#[must_use]
pub fn apply_to_classfile(mapping: &Mapping, cf: &crate::classfile::ClassFile) -> AppliedNames {
    let empty: ClassHierarchy = ClassHierarchy::new();
    apply_to_classfile_with_hierarchy(mapping, cf, &empty)
}

#[must_use]
pub fn apply_to_classfile_with_hierarchy(
    mapping: &Mapping,
    cf: &crate::classfile::ClassFile,
    hierarchy: &ClassHierarchy,
) -> AppliedNames {
    let mut applied: AppliedNames = AppliedNames::default();
    let this_binary: Option<String> = cf.this_class_name().ok().map(str::to_string);
    let dotted_this: Option<String> = this_binary.as_deref().map(|n: &str| n.replace('/', "."));
    let class_entry: Option<&ClassMapping> = dotted_this
        .as_deref()
        .and_then(|n: &str| mapping.lookup_obfuscated_class(n));

    if let Some(entry) = class_entry {
        applied.class_name = Some(entry.original_name.clone());
        applied.restored_count += 1;
    }

    if let Some(this) = this_binary.as_deref() {
        for field in &cf.fields {
            let Ok(name): Result<&str> = cf.utf8_at(field.name_index) else {
                continue;
            };
            let descriptor: Option<&str> = cf.utf8_at(field.descriptor_index).ok();
            let local: Option<&str> = class_entry.and_then(|entry: &ClassMapping| {
                entry
                    .field_overloads
                    .get(name)
                    .and_then(|ov: &Vec<FieldMapping>| select_field(ov, descriptor))
                    .map(|f: &FieldMapping| f.original_name.as_str())
                    .or_else(|| entry.fields.get(name).map(String::as_str))
            });
            let restored: Option<String> = match local {
                Some(original) => Some(original.to_string()),
                None if !hierarchy.is_empty() => mapping
                    .resolve_field_with_inheritance(hierarchy, this, name, descriptor)
                    .filter(|f: &InheritedField| f.inherited)
                    .map(|f: InheritedField| f.original_name),
                None => None,
            };
            if let Some(original) = restored {
                applied.fields.insert(field_key(name, descriptor), original);
                applied.restored_count += 1;
            }
        }
        for method in &cf.methods {
            let Ok(name): Result<&str> = cf.utf8_at(method.name_index) else {
                continue;
            };
            let descriptor: Option<&str> = cf.utf8_at(method.descriptor_index).ok();
            let local: Option<&MethodMapping> = class_entry
                .and_then(|entry: &ClassMapping| entry.methods.get(name))
                .and_then(|overloads: &Vec<MethodMapping>| select_overload(overloads, descriptor));
            let restored: Option<String> = match local {
                Some(m) => Some(m.original_name.clone()),
                None if !hierarchy.is_empty() => mapping
                    .resolve_method_with_inheritance(hierarchy, this, name, descriptor)
                    .filter(|m: &InheritedMethod| m.inherited)
                    .map(|m: InheritedMethod| m.original_name),
                None => None,
            };
            if let Some(original) = restored {
                let key: String = method_key(name, descriptor);
                applied.methods.insert(key.clone(), original);
                if let Some(desc) = descriptor
                    && let Some(remapped) = remap_descriptor(mapping, desc)
                {
                    applied.method_descriptors.insert(key, remapped);
                }
                applied.restored_count += 1;
            }
        }
    }

    if cf.super_class != 0
        && let Ok(super_name) = cf.class_name(cf.super_class)
    {
        let dotted: String = super_name.replace('/', ".");
        if let Some(entry) = mapping.lookup_obfuscated_class(&dotted) {
            applied.super_name = Some(entry.original_name.clone());
            applied.restored_count += 1;
        }
    }

    for iface in &cf.interfaces {
        if let Ok(iface_name) = cf.class_name(*iface) {
            let dotted: String = iface_name.replace('/', ".");
            if let Some(entry) = mapping.lookup_obfuscated_class(&dotted) {
                applied.interfaces.push(entry.original_name.clone());
                applied.restored_count += 1;
            }
        }
    }

    applied
}

#[must_use]
pub fn remap_descriptor(mapping: &Mapping, descriptor: &str) -> Option<String> {
    if !descriptor.contains('L') {
        return None;
    }
    let bytes: &[u8] = descriptor.as_bytes();
    let mut out: String = String::with_capacity(descriptor.len());
    let mut changed: bool = false;
    let mut i: usize = 0;
    while i < bytes.len() {
        if bytes[i] == b'L'
            && let Some(rel) = descriptor[i..].find(';')
        {
            let end: usize = i + rel;
            let internal: &str = &descriptor[i + 1..end];
            out.push('L');
            if let Some(original) = mapping.original_binary_for_obfuscated(internal) {
                out.push_str(&original);
                changed = true;
            } else {
                out.push_str(internal);
            }
            out.push(';');
            i = end + 1;
            continue;
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    changed.then_some(out)
}

impl Mapping {
    #[must_use]
    pub fn retrace(
        &self,
        obfuscated_class: &str,
        obfuscated_method: &str,
        obfuscated_line: u32,
    ) -> Vec<RetracedFrame> {
        let dotted: String = obfuscated_class.replace('/', ".");
        let Some(cls): Option<&ClassMapping> = self.classes.get(&dotted) else {
            return Vec::new();
        };
        let Some(records): Option<&Vec<MethodLineRecord>> = cls.line_records.get(obfuscated_method)
        else {
            return Vec::new();
        };
        let containing: Vec<&MethodLineRecord> = records
            .iter()
            .filter(|rec: &&MethodLineRecord| {
                rec.line_range
                    .is_some_and(|r: LineRange| r.contains_obfuscated(obfuscated_line))
            })
            .collect();
        let tightest: Option<u32> = containing
            .iter()
            .filter_map(|rec: &&MethodLineRecord| {
                rec.line_range
                    .map(|r: LineRange| r.obfuscated_end.saturating_sub(r.obfuscated_start))
            })
            .min();
        let group: Vec<&MethodLineRecord> = match tightest {
            Some(span) => containing
                .into_iter()
                .filter(|rec: &&MethodLineRecord| {
                    rec.line_range.is_some_and(|r: LineRange| {
                        r.obfuscated_end.saturating_sub(r.obfuscated_start) == span
                    })
                })
                .collect(),
            None => containing,
        };
        let mut frames: Vec<RetracedFrame> = Vec::with_capacity(group.len().max(1));
        if group.is_empty() {
            let any_ranges: bool = records
                .iter()
                .any(|r: &MethodLineRecord| r.line_range.is_some());
            if !any_ranges
                && let Some(rec) = records
                    .iter()
                    .find(|r: &&MethodLineRecord| r.holder_class.is_none())
            {
                frames.push(RetracedFrame {
                    class_name: cls.original_name.clone(),
                    method_name: rec.original_name.clone(),
                    original_line: None,
                });
            }
            return frames;
        }
        for rec in group {
            let class_name: String = match &rec.holder_class {
                Some(holder) => self
                    .original_binary_for_obfuscated(&holder.replace('.', "/"))
                    .map_or_else(|| holder.replace('/', "."), |b: String| b.replace('/', ".")),
                None => cls.original_name.clone(),
            };
            let original_line: Option<u32> = rec
                .line_range
                .map(|r: LineRange| r.original_for(obfuscated_line));
            frames.push(RetracedFrame {
                class_name,
                method_name: rec.original_name.clone(),
                original_line,
            });
        }
        frames
    }

    #[must_use]
    pub fn resolve_method_with_inheritance(
        &self,
        hierarchy: &ClassHierarchy,
        obfuscated_class: &str,
        obfuscated_method: &str,
        descriptor: Option<&str>,
    ) -> Option<InheritedMethod> {
        let mut current: Option<String> = Some(obfuscated_class.replace('/', "."));
        let mut depth: usize = 0;
        while let Some(obf) = current {
            depth += 1;
            if depth > MAX_HIERARCHY_DEPTH {
                return None;
            }
            if let Some(cls) = self.classes.get(&obf)
                && let Some(overloads) = cls.methods.get(obfuscated_method)
                && let Some(m) = select_overload(overloads, descriptor)
            {
                return Some(InheritedMethod {
                    original_name: m.original_name.clone(),
                    declaring_class: cls.original_name.clone(),
                    inherited: !obf.eq_ignore_ascii_case(&obfuscated_class.replace('/', ".")),
                });
            }
            current = hierarchy
                .super_of(&obf.replace('.', "/"))
                .map(|s: &str| s.replace('/', "."));
        }
        None
    }

    #[must_use]
    pub fn resolve_field_with_inheritance(
        &self,
        hierarchy: &ClassHierarchy,
        obfuscated_class: &str,
        obfuscated_field: &str,
        descriptor: Option<&str>,
    ) -> Option<InheritedField> {
        let mut current: Option<String> = Some(obfuscated_class.replace('/', "."));
        let mut depth: usize = 0;
        while let Some(obf) = current {
            depth += 1;
            if depth > MAX_HIERARCHY_DEPTH {
                return None;
            }
            if let Some(cls) = self.classes.get(&obf) {
                let chosen: Option<&str> =
                    match (descriptor, cls.field_overloads.get(obfuscated_field)) {
                        (Some(ty), Some(ov)) => ov
                            .iter()
                            .find(|f: &&FieldMapping| f.descriptor_type == ty)
                            .map(|f: &FieldMapping| f.original_name.as_str()),
                        (None, Some(ov)) => {
                            ov.first().map(|f: &FieldMapping| f.original_name.as_str())
                        }
                        (_, None) => cls.fields.get(obfuscated_field).map(String::as_str),
                    };
                if let Some(original) = chosen {
                    return Some(InheritedField {
                        original_name: original.to_string(),
                        declaring_class: cls.original_name.clone(),
                        inherited: !obf.eq_ignore_ascii_case(&obfuscated_class.replace('/', ".")),
                    });
                }
            }
            current = hierarchy
                .super_of(&obf.replace('.', "/"))
                .map(|s: &str| s.replace('/', "."));
        }
        None
    }
}

const MAX_HIERARCHY_DEPTH: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InheritedMethod {
    pub original_name: String,
    pub declaring_class: String,
    pub inherited: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InheritedField {
    pub original_name: String,
    pub declaring_class: String,
    pub inherited: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClassHierarchy {
    super_class: BTreeMap<String, String>,
}

impl ClassHierarchy {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&mut self, obfuscated_binary: &str, super_binary: &str) {
        if obfuscated_binary != super_binary {
            self.super_class
                .insert(obfuscated_binary.to_string(), super_binary.to_string());
        }
    }

    pub fn record_classfile(&mut self, cf: &crate::classfile::ClassFile) {
        let Ok(this_name): Result<&str> = cf.this_class_name() else {
            return;
        };
        let this_owned: String = this_name.to_string();
        if cf.super_class == 0 {
            return;
        }
        if let Ok(super_name) = cf.class_name(cf.super_class) {
            self.record(&this_owned, super_name);
        }
    }

    #[must_use]
    pub fn super_of(&self, obfuscated_binary: &str) -> Option<&str> {
        self.super_class.get(obfuscated_binary).map(String::as_str)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.super_class.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.super_class.is_empty()
    }
}

#[must_use]
fn field_key(name: &str, descriptor: Option<&str>) -> String {
    match descriptor {
        Some(d) => format!("{name}:{d}"),
        None => name.to_string(),
    }
}

#[must_use]
fn method_key(name: &str, descriptor: Option<&str>) -> String {
    match descriptor {
        Some(d) => format!("{name}{d}"),
        None => name.to_string(),
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnmappedHeuristics {
    pub mapped: BTreeMap<String, String>,
}

#[must_use]
pub fn heuristic_recover(obfuscated_names: &[String]) -> UnmappedHeuristics {
    let mut out: UnmappedHeuristics = UnmappedHeuristics::default();
    let mut jbco_index: usize = 0;
    for name in obfuscated_names {
        if is_proguard_short(name) {
            let recovered: String = synthesize_name(name);
            out.mapped.insert(name.clone(), recovered);
        } else if is_jbco_mangled(name) {
            let recovered: String = synthesize_jbco_name(name, jbco_index);
            jbco_index += 1;
            out.mapped.insert(name.clone(), recovered);
        }
    }
    out
}

fn is_proguard_short(name: &str) -> bool {
    if name.is_empty() || name.len() > 3 {
        return false;
    }
    name.chars().all(|c| c.is_ascii_lowercase())
}

fn synthesize_name(name: &str) -> String {
    let mut out: String = String::with_capacity(name.len() + 4);
    out.push_str("sym_");
    out.push_str(name);
    out
}

const JBCO_CONFUSABLE: [char; 8] = ['I', 'l', '1', '0', 'O', 'o', 'S', '5'];

fn is_jbco_mangled(name: &str) -> bool {
    if name.is_empty() || name == "<init>" || name == "<clinit>" {
        return false;
    }
    if !name
        .chars()
        .all(|c: char| c.is_ascii_alphanumeric() || c == '$' || c == '_')
    {
        return false;
    }
    let leads_dollar: bool = name.starts_with('$');
    let has_dollar: bool = name.contains('$');
    let has_digit: bool = name.chars().any(|c: char| c.is_ascii_digit());
    let confusable_only: bool = name
        .chars()
        .all(|c: char| JBCO_CONFUSABLE.contains(&c) || c == '$');
    if name.len() < 4 && !leads_dollar {
        return false;
    }
    leads_dollar || confusable_only || (has_dollar && has_digit)
}

fn jbco_kind_prefix(name: &str) -> &'static str {
    if name.starts_with('$') {
        return "fn";
    }
    if name.chars().any(|c: char| c.is_ascii_uppercase()) {
        return "cls";
    }
    "var"
}

fn synthesize_jbco_name(name: &str, index: usize) -> String {
    format!("{}_{index}", jbco_kind_prefix(name))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn parses_simple_class_header() {
        let src: &str = "com.example.Foo -> a.a:\n    int counter -> a\n";
        let m: Mapping = parse(src).expect("parse");
        let cls: &ClassMapping = m.classes.get("a.a").expect("class present");
        assert_eq!(cls.original_name, "com.example.Foo");
        assert_eq!(cls.fields.get("a").map(String::as_str), Some("counter"));
    }

    #[test]
    fn parses_method() {
        let src: &str = "com.example.Foo -> a.a:\n    void run(int) -> b\n";
        let m: Mapping = parse(src).expect("parse");
        let cls: &ClassMapping = m.classes.get("a.a").expect("class");
        assert!(cls.methods.contains_key("b"));
    }

    #[test]
    fn heuristic_recovers_short_names() {
        let names: Vec<String> = vec!["a".into(), "ab".into(), "myLongName".into()];
        let h: UnmappedHeuristics = heuristic_recover(&names);
        assert!(h.mapped.contains_key("a"));
        assert!(h.mapped.contains_key("ab"));
        assert!(!h.mapped.contains_key("myLongName"));
    }

    #[test]
    fn heuristic_canonicalizes_jbco_mangled_names() {
        let names: Vec<String> = vec![
            "l1Ill".into(),
            "$$S5$".into(),
            "IIIlI".into(),
            "Foo".into(),
            "longName".into(),
            "utf8At".into(),
        ];
        let h: UnmappedHeuristics = heuristic_recover(&names);
        for jbco in ["l1Ill", "$$S5$", "IIIlI"] {
            let canonical: &String = h
                .mapped
                .get(jbco)
                .expect("jbco token must be canonicalized");
            assert_ne!(canonical, jbco, "canonical name must differ from raw token");
            assert!(
                canonical.starts_with("cls_")
                    || canonical.starts_with("fn_")
                    || canonical.starts_with("var_"),
                "JBCO canonical name must use a stable cls_/fn_/var_ prefix, got {canonical}"
            );
        }
        assert!(
            h.mapped
                .get("$$S5$")
                .is_some_and(|n: &String| n.starts_with("fn_")),
            "a leading-dollar JBCO token canonicalizes to a fn_ slot"
        );
        for real in ["Foo", "longName", "utf8At"] {
            assert!(
                !h.mapped.contains_key(real),
                "real identifier {real} must not be treated as JBCO-mangled"
            );
        }
    }

    #[test]
    fn rejects_member_without_class() {
        let src: &str = "    int x -> a\n";
        let err: Error = parse(src).expect_err("orphan");
        assert!(matches!(err, Error::BadMapping(_, _)));
    }

    #[test]
    fn comments_are_stripped() {
        let src: &str = "# header comment\ncom.example.Foo -> a.a:\n";
        let m: Mapping = parse(src).expect("parse");
        assert!(m.classes.contains_key("a.a"));
    }

    #[test]
    fn parses_r8_line_numbered_members() {
        let src: &str = "Hello -> Hello:\n    int counter -> a\n    1:3:void <init>(java.lang.String):6:8 -> <init>\n    1:1:void main(java.lang.String[]):24:24 -> main\n";
        let m: Mapping = parse(src).expect("parse r8");
        let cls: &ClassMapping = m.classes.get("Hello").expect("Hello");
        assert_eq!(cls.fields.get("a").map(String::as_str), Some("counter"));
        assert!(cls.methods.contains_key("<init>"));
        assert!(cls.methods.contains_key("main"));
    }

    #[test]
    fn overloaded_methods_with_same_obf_name_keep_distinct_signatures() {
        let src: &str =
            "Foo -> a:\n    void process(int) -> b\n    void process(java.lang.String,int) -> b\n";
        let m: Mapping = parse(src).expect("parse");
        let cls: &ClassMapping = m.classes.get("a").expect("a");
        let overloads: &Vec<MethodMapping> = cls.methods.get("b").expect("b overloads");
        assert_eq!(overloads.len(), 2);
        let by_desc: Option<&MethodMapping> =
            select_overload(overloads, Some("(Ljava/lang/String;I)V"));
        assert_eq!(
            by_desc.map(|m: &MethodMapping| m.params.as_str()),
            Some("java.lang.String,int")
        );
        let by_one: Option<&MethodMapping> = select_overload(overloads, Some("(I)V"));
        assert_eq!(
            by_one.map(|m: &MethodMapping| m.params.as_str()),
            Some("int")
        );
    }

    #[test]
    fn descriptor_arg_count_counts_params() {
        assert_eq!(descriptor_arg_count("(Ljava/lang/String;I)V"), 2);
        assert_eq!(descriptor_arg_count("()V"), 0);
        assert_eq!(descriptor_arg_count("([I[[Ljava/lang/Object;J)Z"), 3);
    }

    #[test]
    fn split_line_suffix_removes_trailing_source_range() {
        assert_eq!(
            split_line_suffix("void main(java.lang.String[]):24:24"),
            (Some((24, 24)), "void main(java.lang.String[])")
        );
        assert_eq!(
            split_line_suffix("void main(int):7"),
            (Some((7, 7)), "void main(int)")
        );
        assert_eq!(split_line_suffix("void main()"), (None, "void main()"));
    }

    #[test]
    fn r8_inlined_members_keep_first_mapping() {
        let src: &str = "Hello -> Hello:\n    1:1:void main(java.lang.String[]):24:24 -> a\n    2:2:int bumpCounter():12:12 -> a\n";
        let m: Mapping = parse(src).expect("parse");
        let cls: &ClassMapping = m.classes.get("Hello").expect("Hello");
        let overloads: &Vec<MethodMapping> = cls.methods.get("a").expect("a overloads");
        assert_eq!(
            overloads
                .first()
                .map(|m: &MethodMapping| m.original_name.as_str()),
            Some("main")
        );
    }

    #[test]
    fn split_line_prefix_removes_two_number_prefix() {
        assert_eq!(
            split_line_prefix("1:3:void <init>(java.lang.String)"),
            (Some((1, 3)), "void <init>(java.lang.String)")
        );
        assert_eq!(split_line_prefix("void run()"), (None, "void run()"));
        assert_eq!(split_line_prefix("int counter"), (None, "int counter"));
    }

    #[test]
    fn apply_restores_names_on_synthetic_class() {
        use crate::classfile::{ClassFile, ConstantPoolEntry, FieldInfo};
        let src: &str = "com.example.Foo -> a:\n    int counter -> b\n";
        let m: Mapping = parse(src).expect("parse");
        let mut cp: Vec<ConstantPoolEntry> = vec![ConstantPoolEntry::Placeholder];
        cp.push(ConstantPoolEntry::Utf8("a".into()));
        cp.push(ConstantPoolEntry::Class { name_index: 1 });
        cp.push(ConstantPoolEntry::Utf8("b".into()));
        cp.push(ConstantPoolEntry::Utf8("I".into()));
        let cf: ClassFile = ClassFile {
            minor_version: 0,
            major_version: 52,
            constant_pool: cp,
            access_flags: 0,
            this_class: 2,
            super_class: 0,
            interfaces: Vec::new(),
            fields: vec![FieldInfo {
                access_flags: 0,
                name_index: 3,
                descriptor_index: 4,
                attributes: Vec::new(),
            }],
            methods: Vec::new(),
            attributes: Vec::new(),
        };
        let applied: AppliedNames = apply_to_classfile(&m, &cf);
        assert_eq!(applied.class_name.as_deref(), Some("com.example.Foo"));
        assert_eq!(
            applied.fields.get("b:I").map(String::as_str),
            Some("counter")
        );
        assert!(applied.restored_count >= 2);
    }

    #[test]
    fn source_type_descriptor_round_trip() {
        assert_eq!(source_type_to_descriptor("int"), "I");
        assert_eq!(
            source_type_to_descriptor("java.lang.String"),
            "Ljava/lang/String;"
        );
        assert_eq!(source_type_to_descriptor("double[]"), "[D");
        assert_eq!(
            source_type_to_descriptor("EdgeCases$Pair"),
            "LEdgeCases$Pair;"
        );
        assert_eq!(source_type_to_descriptor("void"), "V");
        assert_eq!(
            source_params_to_descriptor("java.lang.String,int"),
            "Ljava/lang/String;I"
        );
        assert_eq!(source_params_to_descriptor(""), "");
    }

    #[test]
    fn select_overload_matches_full_descriptor_not_just_arity() {
        let src: &str = "C -> a:\n    void classify(java.lang.Object) -> a\n    int recursiveFactorial(int) -> a\n    java.lang.String multiCatch(java.lang.String) -> a\n";
        let m: Mapping = parse(src).expect("parse");
        let cls: &ClassMapping = m.classes.get("a").expect("a");
        let ov: &Vec<MethodMapping> = cls.methods.get("a").expect("a overloads");
        assert_eq!(ov.len(), 3);
        assert_eq!(
            select_overload(ov, Some("(I)I")).map(|m: &MethodMapping| m.original_name.as_str()),
            Some("recursiveFactorial")
        );
        assert_eq!(
            select_overload(ov, Some("(Ljava/lang/String;)Ljava/lang/String;"))
                .map(|m: &MethodMapping| m.original_name.as_str()),
            Some("multiCatch")
        );
        assert_eq!(
            select_overload(ov, Some("(Ljava/lang/Object;)Ljava/lang/String;"))
                .map(|m: &MethodMapping| m.original_name.as_str()),
            Some("classify")
        );
    }

    #[test]
    fn field_overloads_disambiguate_by_type() {
        let src: &str =
            "C -> a:\n    int instanceField -> a\n    java.lang.String transientField -> a\n";
        let m: Mapping = parse(src).expect("parse");
        let cls: &ClassMapping = m.classes.get("a").expect("a");
        let ov: &Vec<FieldMapping> = cls.field_overloads.get("a").expect("a field overloads");
        assert_eq!(ov.len(), 2);
        assert_eq!(
            select_field(ov, Some("I")).map(|f: &FieldMapping| f.original_name.as_str()),
            Some("instanceField")
        );
        assert_eq!(
            select_field(ov, Some("Ljava/lang/String;"))
                .map(|f: &FieldMapping| f.original_name.as_str()),
            Some("transientField")
        );
    }

    #[test]
    fn inline_residual_frames_from_other_classes_are_skipped() {
        let src: &str = "EdgeCases -> EdgeCases:\n    783:797:java.lang.String unpackPair(EdgeCases$Pair) -> a\n    3783:3783:java.lang.Object EdgeCases$Pair.first():783:783 -> a\n";
        let m: Mapping = parse(src).expect("parse");
        let cls: &ClassMapping = m.classes.get("EdgeCases").expect("EdgeCases");
        let ov: &Vec<MethodMapping> = cls.methods.get("a").expect("a overloads");
        assert_eq!(ov.len(), 1);
        assert_eq!(ov[0].original_name, "unpackPair");
    }

    #[test]
    fn remap_descriptor_rewrites_obfuscated_class_refs() {
        let src: &str = "com.example.Foo -> a.a:\n    void run() -> b\ncom.example.Bar -> a.b:\n    void init() -> c\n";
        let m: Mapping = parse(src).expect("parse");
        assert_eq!(
            remap_descriptor(&m, "(La/a;La/b;)V").as_deref(),
            Some("(Lcom/example/Foo;Lcom/example/Bar;)V")
        );
        assert_eq!(remap_descriptor(&m, "(I)V"), None);
    }
}
