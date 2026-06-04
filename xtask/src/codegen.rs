use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use eyre::{Result, WrapErr, bail};
use serde_json::{Map, Value};

#[derive(Debug, Clone, Copy)]
pub(crate) enum Lang {
    Python,
    TypeScript,
}

impl Lang {
    #[must_use]
    pub(crate) const fn extension(self) -> &'static str {
        match self {
            Self::Python => "pyi",
            Self::TypeScript => "d.ts",
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct SchemaArtifact {
    pub(crate) base: String,
    pub(crate) schema: Value,
    pub(crate) bytes: Vec<u8>,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct CodegenSummary {
    pub(crate) py_written: usize,
    pub(crate) ts_written: usize,
    pub(crate) py_skipped: usize,
    pub(crate) ts_skipped: usize,
}

pub(crate) fn load_schemas(schemas_dir: &Path) -> Result<Vec<SchemaArtifact>> {
    if !schemas_dir.is_dir() {
        bail!("schemas dir missing: {}", schemas_dir.display());
    }
    let mut out: Vec<SchemaArtifact> = Vec::new();
    for entry in walkdir::WalkDir::new(schemas_dir)
        .min_depth(1)
        .max_depth(1)
        .sort_by_file_name()
    {
        let dirent: walkdir::DirEntry = entry?;
        let path: &Path = dirent.path();
        let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
            continue;
        };
        if !ext.eq_ignore_ascii_case("json") {
            continue;
        }
        let bytes: Vec<u8> =
            fs::read(path).wrap_err_with(|| format!("reading {}", path.display()))?;
        let schema: Value = serde_json::from_slice(&bytes)
            .wrap_err_with(|| format!("parsing JSON schema {}", path.display()))?;
        let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        let base: String = stem.replace(".schema", "");
        out.push(SchemaArtifact {
            base,
            schema,
            bytes,
        });
    }
    Ok(out)
}

pub(crate) fn write_bindings(
    schemas: &[SchemaArtifact],
    py_dir: &Path,
    ts_dir: &Path,
) -> Result<CodegenSummary> {
    fs::create_dir_all(py_dir).wrap_err_with(|| format!("creating {}", py_dir.display()))?;
    fs::create_dir_all(ts_dir).wrap_err_with(|| format!("creating {}", ts_dir.display()))?;

    let mut py_checksums: BTreeMap<String, String> = load_checksums(py_dir)?;
    let mut ts_checksums: BTreeMap<String, String> = load_checksums(ts_dir)?;
    let mut summary: CodegenSummary = CodegenSummary::default();

    for artifact in schemas {
        let digest: String = blake3_hex(&artifact.bytes);
        let py_path: PathBuf =
            py_dir.join(format!("{}.{}", artifact.base, Lang::Python.extension()));
        let ts_path: PathBuf = ts_dir.join(format!(
            "{}.{}",
            artifact.base,
            Lang::TypeScript.extension()
        ));

        if py_checksums.get(&artifact.base) == Some(&digest) && py_path.is_file() {
            summary.py_skipped += 1;
        } else {
            let body: String = render_pyi(&artifact.base, &artifact.schema);
            fs::write(&py_path, body).wrap_err_with(|| format!("writing {}", py_path.display()))?;
            py_checksums.insert(artifact.base.clone(), digest.clone());
            summary.py_written += 1;
        }

        if ts_checksums.get(&artifact.base) == Some(&digest) && ts_path.is_file() {
            summary.ts_skipped += 1;
        } else {
            let body: String = render_dts(&artifact.base, &artifact.schema);
            fs::write(&ts_path, body).wrap_err_with(|| format!("writing {}", ts_path.display()))?;
            ts_checksums.insert(artifact.base.clone(), digest);
            summary.ts_written += 1;
        }
    }

    save_checksums(py_dir, &py_checksums)?;
    save_checksums(ts_dir, &ts_checksums)?;
    Ok(summary)
}

const CHECKSUM_FILE: &str = ".checksum.json";

fn load_checksums(dir: &Path) -> Result<BTreeMap<String, String>> {
    let path: PathBuf = dir.join(CHECKSUM_FILE);
    if !path.is_file() {
        return Ok(BTreeMap::new());
    }
    let bytes: Vec<u8> = fs::read(&path).wrap_err_with(|| format!("reading {}", path.display()))?;
    let parsed: BTreeMap<String, String> = serde_json::from_slice(&bytes)
        .wrap_err_with(|| format!("parsing checksum file {}", path.display()))?;
    Ok(parsed)
}

fn save_checksums(dir: &Path, checksums: &BTreeMap<String, String>) -> Result<()> {
    let path: PathBuf = dir.join(CHECKSUM_FILE);
    let body: String = serde_json::to_string_pretty(checksums)
        .wrap_err_with(|| format!("serializing checksums for {}", dir.display()))?;
    fs::write(&path, format!("{body}\n"))
        .wrap_err_with(|| format!("writing {}", path.display()))?;
    Ok(())
}

fn blake3_hex(bytes: &[u8]) -> String {
    let hash: blake3::Hash = blake3::hash(bytes);
    hash.to_hex().to_string()
}

#[derive(Debug, Clone)]
struct DefBlock {
    name: String,
    body: String,
}

fn pascal(input: &str) -> String {
    let mut out: String = String::with_capacity(input.len());
    let mut capitalize: bool = true;
    for ch in input.chars() {
        if matches!(ch, '-' | '_' | '.' | '/' | ' ') {
            capitalize = true;
            continue;
        }
        if capitalize {
            for upper in ch.to_uppercase() {
                out.push(upper);
            }
            capitalize = false;
        } else {
            out.push(ch);
        }
    }
    out
}

fn root_title(base: &str, schema: &Value) -> String {
    schema
        .get("title")
        .and_then(Value::as_str)
        .map_or_else(|| pascal(base), str::to_owned)
}

fn extract_defs(schema: &Value) -> Map<String, Value> {
    schema
        .get("$defs")
        .or_else(|| schema.get("definitions"))
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default()
}

fn resolve_ref<'a>(
    schema: &'a Value,
    defs: &'a Map<String, Value>,
    reference: &str,
) -> Option<&'a Value> {
    reference.strip_prefix("#/$defs/").map_or_else(
        || {
            reference.strip_prefix("#/definitions/").and_then(|name| {
                defs.get(name)
                    .or_else(|| schema.get("definitions").and_then(|d| d.get(name)))
            })
        },
        |name| defs.get(name),
    )
}

fn ref_name(reference: &str) -> Option<String> {
    reference
        .strip_prefix("#/$defs/")
        .or_else(|| reference.strip_prefix("#/definitions/"))
        .map(pascal)
}

fn merge_all_of(value: &Value) -> Option<Value> {
    let arr: &Vec<Value> = value.get("allOf")?.as_array()?;
    let mut merged: Map<String, Value> = Map::new();
    let mut properties: Map<String, Value> = Map::new();
    let mut required: Vec<Value> = Vec::new();
    for entry in arr {
        let Some(obj) = entry.as_object() else {
            continue;
        };
        if let Some(props) = obj.get("properties").and_then(Value::as_object) {
            for (k, v) in props {
                properties.insert(k.clone(), v.clone());
            }
        }
        if let Some(req) = obj.get("required").and_then(Value::as_array) {
            for r in req {
                required.push(r.clone());
            }
        }
        for (k, v) in obj {
            if matches!(k.as_str(), "properties" | "required") {
                continue;
            }
            merged.insert(k.clone(), v.clone());
        }
    }
    merged.insert("type".to_owned(), Value::String("object".to_owned()));
    merged.insert("properties".to_owned(), Value::Object(properties));
    if !required.is_empty() {
        merged.insert("required".to_owned(), Value::Array(required));
    }
    Some(Value::Object(merged))
}

fn render_pyi(base: &str, schema: &Value) -> String {
    let title: String = root_title(base, schema);
    let defs: Map<String, Value> = extract_defs(schema);

    let mut header: String = String::with_capacity(256);
    header.push_str("from __future__ import annotations\n\n");
    header.push_str("from typing import Any, Literal, TypedDict, Union\n\n");

    let mut blocks: Vec<DefBlock> = Vec::new();

    for (name, def) in &defs {
        let cls_name: String = pascal(name);
        let body: String = render_python_def(&cls_name, def, schema, &defs);
        blocks.push(DefBlock {
            name: cls_name,
            body,
        });
    }

    let root_body: String = render_python_def(&title, schema, schema, &defs);
    blocks.push(DefBlock {
        name: title,
        body: root_body,
    });

    let mut out: String = header;
    let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for block in blocks {
        if !seen.insert(block.name) {
            continue;
        }
        out.push_str(&block.body);
        if !out.ends_with('\n') {
            out.push('\n');
        }
        out.push('\n');
    }

    out
}

fn render_python_def(name: &str, def: &Value, schema: &Value, defs: &Map<String, Value>) -> String {
    let effective: Value = merge_all_of(def).unwrap_or_else(|| def.clone());
    if let Some(enum_vals) = effective.get("enum").and_then(Value::as_array) {
        let literals: Vec<String> = enum_vals.iter().map(python_literal).collect();
        return format!("{name} = Literal[{}]", literals.join(", "));
    }
    if let Some(one_of) = effective.get("oneOf").and_then(Value::as_array) {
        let variants: Vec<String> = one_of
            .iter()
            .map(|v: &Value| json_to_py(v, schema, defs))
            .collect();
        return format!("{name} = Union[{}]", variants.join(", "));
    }
    if effective.get("type").and_then(Value::as_str) != Some("object")
        && effective.get("properties").is_none()
    {
        let alias: String = json_to_py(&effective, schema, defs);
        return format!("{name} = {alias}");
    }
    let properties: Option<&Map<String, Value>> =
        effective.get("properties").and_then(Value::as_object);
    let mut out: String = String::with_capacity(256);
    let _ = writeln!(out, "class {name}(TypedDict, total=False):");
    let Some(properties) = properties else {
        out.push_str("    pass\n");
        return out;
    };
    if properties.is_empty() {
        out.push_str("    pass\n");
        return out;
    }
    for (prop_name, prop_value) in properties {
        let ty: String = json_to_py(prop_value, schema, defs);
        let _ = writeln!(out, "    {prop_name}: {ty}");
    }
    out
}

fn escape_string_literal(s: &str) -> String {
    let mut out: String = String::with_capacity(s.len() + 2);
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 || c == '\u{7f}' => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

fn python_literal(value: &Value) -> String {
    match value {
        Value::String(s) => format!("\"{}\"", escape_string_literal(s)),
        Value::Bool(b) => if *b { "True" } else { "False" }.to_owned(),
        Value::Number(n) => n.to_string(),
        Value::Null => "None".to_owned(),
        _ => "Any".to_owned(),
    }
}

fn json_to_py(value: &Value, schema: &Value, defs: &Map<String, Value>) -> String {
    if let Some(reference) = value.get("$ref").and_then(Value::as_str) {
        if let Some(name) = ref_name(reference) {
            return name;
        }
        if let Some(target) = resolve_ref(schema, defs, reference) {
            return json_to_py(target, schema, defs);
        }
    }
    if let Some(merged) = merge_all_of(value) {
        return json_to_py(&merged, schema, defs);
    }
    if let Some(enum_vals) = value.get("enum").and_then(Value::as_array) {
        let literals: Vec<String> = enum_vals.iter().map(python_literal).collect();
        return format!("Literal[{}]", literals.join(", "));
    }
    if let Some(one_of) = value.get("oneOf").and_then(Value::as_array) {
        let variants: Vec<String> = one_of
            .iter()
            .map(|v: &Value| json_to_py(v, schema, defs))
            .collect();
        return format!("Union[{}]", variants.join(", "));
    }
    if let Some(const_val) = value.get("const") {
        return format!("Literal[{}]", python_literal(const_val));
    }
    let Some(ty) = value.get("type") else {
        return "Any".to_owned();
    };
    if let Some(types) = ty.as_array() {
        let mut parts: Vec<&'static str> = types
            .iter()
            .filter_map(Value::as_str)
            .map(py_primitive)
            .collect::<Vec<&'static str>>();
        parts.sort_unstable();
        parts.dedup();
        return parts.join(" | ");
    }
    match ty.as_str() {
        Some("string") => "str".to_owned(),
        Some("integer") => "int".to_owned(),
        Some("number") => "float".to_owned(),
        Some("boolean") => "bool".to_owned(),
        Some("array") => {
            let items: String = value
                .get("items")
                .map_or_else(|| "Any".to_owned(), |v: &Value| json_to_py(v, schema, defs));
            format!("list[{items}]")
        }
        Some("object") => {
            if value.get("properties").and_then(Value::as_object).is_some() {
                "dict[str, Any]".to_owned()
            } else if let Some(addl) = value.get("additionalProperties") {
                let inner: String = json_to_py(addl, schema, defs);
                format!("dict[str, {inner}]")
            } else {
                "dict[str, Any]".to_owned()
            }
        }
        Some("null") => "None".to_owned(),
        _ => "Any".to_owned(),
    }
}

const fn py_primitive(name: &str) -> &'static str {
    match name.as_bytes() {
        b"string" => "str",
        b"integer" => "int",
        b"number" => "float",
        b"boolean" => "bool",
        b"array" => "list[Any]",
        b"object" => "dict[str, Any]",
        b"null" => "None",
        _ => "Any",
    }
}

fn render_dts(base: &str, schema: &Value) -> String {
    let title: String = root_title(base, schema);
    let defs: Map<String, Value> = extract_defs(schema);
    let mut out: String = String::with_capacity(512);
    let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();

    for (name, def) in &defs {
        let ts_name: String = pascal(name);
        if !seen.insert(ts_name.clone()) {
            continue;
        }
        out.push_str(&render_typescript_def(&ts_name, def, schema, &defs));
        if !out.ends_with('\n') {
            out.push('\n');
        }
        out.push('\n');
    }

    if seen.insert(title.clone()) {
        out.push_str(&render_typescript_def(&title, schema, schema, &defs));
        if !out.ends_with('\n') {
            out.push('\n');
        }
    }

    out
}

fn render_typescript_def(
    name: &str,
    def: &Value,
    schema: &Value,
    defs: &Map<String, Value>,
) -> String {
    let effective: Value = merge_all_of(def).unwrap_or_else(|| def.clone());
    if let Some(enum_vals) = effective.get("enum").and_then(Value::as_array) {
        let literals: Vec<String> = enum_vals.iter().map(ts_literal).collect();
        return format!("export type {name} = {};\n", literals.join(" | "));
    }
    if let Some(one_of) = effective.get("oneOf").and_then(Value::as_array) {
        let variants: Vec<String> = one_of
            .iter()
            .map(|v: &Value| json_to_ts(v, schema, defs))
            .collect();
        return format!("export type {name} = {};\n", variants.join(" | "));
    }
    if effective.get("type").and_then(Value::as_str) != Some("object")
        && effective.get("properties").is_none()
    {
        let alias: String = json_to_ts(&effective, schema, defs);
        return format!("export type {name} = {alias};\n");
    }
    let properties: Option<&Map<String, Value>> =
        effective.get("properties").and_then(Value::as_object);
    let required: std::collections::BTreeSet<&str> = effective
        .get("required")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .collect::<std::collections::BTreeSet<&str>>()
        })
        .unwrap_or_default();
    let mut out: String = String::with_capacity(256);
    let _ = writeln!(out, "export interface {name} {{");
    let Some(properties) = properties else {
        out.push_str("}\n");
        return out;
    };
    for (prop_name, prop_value) in properties {
        let optional: &str = if required.contains(prop_name.as_str()) {
            ""
        } else {
            "?"
        };
        let ty: String = json_to_ts(prop_value, schema, defs);
        let _ = writeln!(out, "  {prop_name}{optional}: {ty};");
    }
    out.push_str("}\n");
    out
}

fn ts_literal(value: &Value) -> String {
    match value {
        Value::String(s) => format!("\"{}\"", escape_string_literal(s)),
        Value::Bool(b) => if *b { "true" } else { "false" }.to_owned(),
        Value::Number(n) => n.to_string(),
        Value::Null => "null".to_owned(),
        _ => "unknown".to_owned(),
    }
}

fn json_to_ts(value: &Value, schema: &Value, defs: &Map<String, Value>) -> String {
    if let Some(reference) = value.get("$ref").and_then(Value::as_str) {
        if let Some(name) = ref_name(reference) {
            return name;
        }
        if let Some(target) = resolve_ref(schema, defs, reference) {
            return json_to_ts(target, schema, defs);
        }
    }
    if let Some(merged) = merge_all_of(value) {
        return json_to_ts(&merged, schema, defs);
    }
    if let Some(enum_vals) = value.get("enum").and_then(Value::as_array) {
        let literals: Vec<String> = enum_vals.iter().map(ts_literal).collect();
        return literals.join(" | ");
    }
    if let Some(one_of) = value.get("oneOf").and_then(Value::as_array) {
        let variants: Vec<String> = one_of
            .iter()
            .map(|v: &Value| json_to_ts(v, schema, defs))
            .collect();
        return variants.join(" | ");
    }
    if let Some(const_val) = value.get("const") {
        return ts_literal(const_val);
    }
    let Some(ty) = value.get("type") else {
        return "unknown".to_owned();
    };
    if let Some(types) = ty.as_array() {
        let mut parts: Vec<&'static str> = types
            .iter()
            .filter_map(Value::as_str)
            .map(ts_primitive)
            .collect::<Vec<&'static str>>();
        parts.sort_unstable();
        parts.dedup();
        return parts.join(" | ");
    }
    match ty.as_str() {
        Some("string") => "string".to_owned(),
        Some("integer" | "number") => "number".to_owned(),
        Some("boolean") => "boolean".to_owned(),
        Some("array") => {
            let items: String = value.get("items").map_or_else(
                || "unknown".to_owned(),
                |v: &Value| json_to_ts(v, schema, defs),
            );
            format!("Array<{items}>")
        }
        Some("object") => value.get("additionalProperties").map_or_else(
            || "Record<string, unknown>".to_owned(),
            |addl: &Value| {
                let inner: String = json_to_ts(addl, schema, defs);
                format!("Record<string, {inner}>")
            },
        ),
        Some("null") => "null".to_owned(),
        _ => "unknown".to_owned(),
    }
}

const fn ts_primitive(name: &str) -> &'static str {
    match name.as_bytes() {
        b"string" => "string",
        b"integer" | b"number" => "number",
        b"boolean" => "boolean",
        b"array" => "Array<unknown>",
        b"object" => "Record<string, unknown>",
        b"null" => "null",
        _ => "unknown",
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn typed_dict_round_trip_for_object_schema() {
        let schema: Value = json!({
            "title": "Thing",
            "type": "object",
            "required": ["name", "size"],
            "properties": {
                "name": {"type": "string"},
                "size": {"type": "integer"},
                "tags": {"type": "array", "items": {"type": "string"}}
            }
        });
        let body: String = render_pyi("thing", &schema);
        assert!(body.contains("class Thing(TypedDict, total=False):"));
        assert!(body.contains("    name: str"));
        assert!(body.contains("    size: int"));
        assert!(body.contains("    tags: list[str]"));
        let ts_body: String = render_dts("thing", &schema);
        assert!(ts_body.contains("export interface Thing {"));
        assert!(ts_body.contains("  name: string;"));
        assert!(ts_body.contains("  size: number;"));
        assert!(ts_body.contains("  tags?: Array<string>;"));
    }

    #[test]
    fn ref_resolution_emits_referenced_type_by_name() {
        let schema: Value = json!({
            "title": "Container",
            "type": "object",
            "required": ["entry"],
            "$defs": {
                "Entry": {
                    "type": "object",
                    "required": ["id"],
                    "properties": {"id": {"type": "string"}}
                }
            },
            "properties": {
                "entry": {"$ref": "#/$defs/Entry"}
            }
        });
        let py: String = render_pyi("container", &schema);
        assert!(py.contains("class Entry(TypedDict, total=False):"));
        assert!(py.contains("class Container(TypedDict, total=False):"));
        assert!(py.contains("    entry: Entry"));
        let ts: String = render_dts("container", &schema);
        assert!(ts.contains("export interface Entry {"));
        assert!(ts.contains("export interface Container {"));
        assert!(ts.contains("  entry: Entry;"));
    }

    #[test]
    fn one_of_discriminated_union_emits_union_type() {
        let schema: Value = json!({
            "title": "Shape",
            "oneOf": [
                {"type": "object", "required": ["kind"], "properties": {
                    "kind": {"const": "circle"},
                    "radius": {"type": "number"}
                }},
                {"type": "object", "required": ["kind"], "properties": {
                    "kind": {"const": "square"},
                    "side": {"type": "number"}
                }}
            ]
        });
        let py: String = render_pyi("shape", &schema);
        assert!(
            py.contains("Shape = Union["),
            "expected Union alias for oneOf, got: {py}"
        );
        let ts: String = render_dts("shape", &schema);
        assert!(
            ts.contains("export type Shape ="),
            "expected union type alias for oneOf, got: {ts}"
        );
        assert!(ts.contains('|'));
    }

    #[test]
    fn enum_emits_python_literal_and_ts_string_union() {
        let schema: Value = json!({
            "title": "Direction",
            "enum": ["north", "south", "east", "west"]
        });
        let py: String = render_pyi("direction", &schema);
        assert!(py.contains("Direction = Literal[\"north\""));
        let ts: String = render_dts("direction", &schema);
        assert!(
            ts.contains("export type Direction = \"north\" | \"south\" | \"east\" | \"west\";")
        );
    }

    #[test]
    fn all_of_merges_properties() {
        let schema: Value = json!({
            "title": "Merged",
            "allOf": [
                {"type": "object", "properties": {"a": {"type": "string"}}, "required": ["a"]},
                {"type": "object", "properties": {"b": {"type": "integer"}}, "required": ["b"]}
            ]
        });
        let py: String = render_pyi("merged", &schema);
        assert!(py.contains("class Merged(TypedDict, total=False):"));
        assert!(py.contains("    a: str"));
        assert!(py.contains("    b: int"));
        let ts: String = render_dts("merged", &schema);
        assert!(ts.contains("  a: string;"));
        assert!(ts.contains("  b: number;"));
    }

    #[test]
    fn const_with_control_byte_is_escaped_not_embedded() {
        let schema: Value = json!({
            "title": "Magic",
            "type": "object",
            "properties": {"magic": {"type": "string", "const": "DISROBE\u{0}"}}
        });
        let py: String = render_pyi("magic", &schema);
        assert!(
            !py.contains('\u{0}'),
            "rendered .pyi must not embed a raw NUL byte"
        );
        assert!(py.contains("DISROBE\\u0000"), "got: {py}");
        let ts: String = render_dts("magic", &schema);
        assert!(
            !ts.contains('\u{0}'),
            "rendered .d.ts must not embed a raw NUL byte"
        );
        assert!(ts.contains("DISROBE\\u0000"), "got: {ts}");
    }

    #[test]
    fn hash_skip_avoids_rewrite_when_schema_unchanged() {
        let tmp: tempfile::TempDir = tempfile::tempdir().expect("tempdir");
        let py_dir: PathBuf = tmp.path().join("python");
        let ts_dir: PathBuf = tmp.path().join("typescript");
        let schema: Value = json!({
            "title": "Same",
            "type": "object",
            "properties": {"x": {"type": "integer"}}
        });
        let bytes: Vec<u8> = serde_json::to_vec(&schema).expect("ser");
        let artifact: SchemaArtifact = SchemaArtifact {
            base: "same".to_owned(),
            schema,
            bytes,
        };
        let first: CodegenSummary =
            write_bindings(std::slice::from_ref(&artifact), &py_dir, &ts_dir).expect("write");
        assert_eq!(first.py_written, 1);
        assert_eq!(first.ts_written, 1);
        assert_eq!(first.py_skipped, 0);
        assert_eq!(first.ts_skipped, 0);
        let second: CodegenSummary = write_bindings(&[artifact], &py_dir, &ts_dir).expect("write");
        assert_eq!(second.py_written, 0);
        assert_eq!(second.ts_written, 0);
        assert_eq!(second.py_skipped, 1);
        assert_eq!(second.ts_skipped, 1);
    }
}
