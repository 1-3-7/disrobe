//! Schema-aligned shape constructors used by per-pass `LlmMetadataEmitter` impls.
//!
//! Each `make_*` helper returns the inner `value` payload that
//! the trait then wraps in a [`crate::PerPassEnvelope`].
//!
//! Keeping these as data-shaping helpers rather than typed structs avoids
//! coupling every pass crate to a fresh serde struct per category — passes can
//! mint payloads from their own native types with a single function call while
//! still matching `schemas/disrobe-metadata-llm-v1.json`.
#![allow(clippy::needless_pass_by_value)]

use std::collections::BTreeMap;

use serde_json::{Map, Value as Json, json};

/// Build an `AstCategory` value `{ dialect, root }`.
#[must_use]
pub fn make_ast_value(dialect: impl Into<String>, root: Json) -> Json {
    json!({
        "dialect": dialect.into(),
        "root": root,
    })
}

#[must_use]
pub fn make_ast_node(
    kind: impl Into<String>,
    name: Option<String>,
    children: Vec<Json>,
    attrs: BTreeMap<String, Json>,
) -> Json {
    let mut obj: Map<String, Json> = Map::new();
    obj.insert("kind".to_owned(), Json::String(kind.into()));
    if let Some(n) = name {
        obj.insert("name".to_owned(), Json::String(n));
    }
    if !children.is_empty() {
        obj.insert("children".to_owned(), Json::Array(children));
    }
    if !attrs.is_empty() {
        let mut a: Map<String, Json> = Map::new();
        for (k, v) in attrs {
            a.insert(k, v);
        }
        obj.insert("attrs".to_owned(), Json::Object(a));
    }
    Json::Object(obj)
}

/// Build a `DisasmCategory` value `{ bytecode_version, instructions, symbol_table }`.
#[must_use]
pub fn make_disasm_value(
    bytecode_version: impl Into<String>,
    instructions: Vec<Json>,
    symbol_table: Vec<Json>,
) -> Json {
    let mut obj: Map<String, Json> = Map::new();
    obj.insert(
        "bytecode_version".to_owned(),
        Json::String(bytecode_version.into()),
    );
    obj.insert("instructions".to_owned(), Json::Array(instructions));
    if !symbol_table.is_empty() {
        obj.insert("symbol_table".to_owned(), Json::Array(symbol_table));
    }
    Json::Object(obj)
}

#[must_use]
pub fn make_disasm_instr(
    pc: u64,
    bytes_hex: Option<String>,
    mnemonic: impl Into<String>,
    operands: Vec<String>,
    comment: Option<String>,
) -> Json {
    let mut obj: Map<String, Json> = Map::new();
    obj.insert("pc".to_owned(), json!(pc));
    if let Some(bx) = bytes_hex {
        obj.insert("bytes_hex".to_owned(), Json::String(bx));
    }
    obj.insert("mnemonic".to_owned(), Json::String(mnemonic.into()));
    if !operands.is_empty() {
        obj.insert(
            "operands".to_owned(),
            Json::Array(operands.into_iter().map(Json::String).collect()),
        );
    }
    if let Some(c) = comment {
        obj.insert("comment".to_owned(), Json::String(c));
    }
    Json::Object(obj)
}

/// Symbol entry inside a [`make_symbols_value`] array.
#[must_use]
pub fn make_symbol_entry(
    mangled: impl Into<String>,
    demangled: Option<String>,
    kind: impl Into<String>,
    address: Option<u64>,
    module: Option<String>,
    visibility: impl Into<String>,
) -> Json {
    let mut obj: Map<String, Json> = Map::new();
    obj.insert("mangled".to_owned(), Json::String(mangled.into()));
    obj.insert(
        "demangled".to_owned(),
        demangled.map_or(Json::Null, Json::String),
    );
    obj.insert("kind".to_owned(), Json::String(kind.into()));
    obj.insert(
        "address".to_owned(),
        address.map_or(Json::Null, |a| json!(a)),
    );
    obj.insert("module".to_owned(), module.map_or(Json::Null, Json::String));
    obj.insert("visibility".to_owned(), Json::String(visibility.into()));
    Json::Object(obj)
}

/// `SymbolsCategory` `value` is an array of symbol entries.
#[must_use]
pub const fn make_symbols_value(entries: Vec<Json>) -> Json {
    Json::Array(entries)
}

#[must_use]
pub fn make_string_entry(
    text: impl Into<String>,
    encoding: impl Into<String>,
    offset: Option<u64>,
    refs: Vec<(u64, Option<String>)>,
) -> Json {
    let mut obj: Map<String, Json> = Map::new();
    obj.insert("text".to_owned(), Json::String(text.into()));
    obj.insert("encoding".to_owned(), Json::String(encoding.into()));
    obj.insert("offset".to_owned(), offset.map_or(Json::Null, |o| json!(o)));
    if !refs.is_empty() {
        let refs_v: Vec<Json> = refs
            .into_iter()
            .map(|(pc, function): (u64, Option<String>)| {
                let mut r: Map<String, Json> = Map::new();
                r.insert("pc".to_owned(), json!(pc));
                if let Some(f) = function {
                    r.insert("function".to_owned(), Json::String(f));
                }
                Json::Object(r)
            })
            .collect();
        obj.insert("refs".to_owned(), Json::Array(refs_v));
    }
    Json::Object(obj)
}

/// `StringsCategory` `value` is an array of string entries.
#[must_use]
pub const fn make_strings_value(entries: Vec<Json>) -> Json {
    Json::Array(entries)
}

#[must_use]
pub fn make_import_entry(
    module: impl Into<String>,
    symbols: Vec<String>,
    alias: Option<String>,
    kind: impl Into<String>,
    version: Option<String>,
) -> Json {
    let mut obj: Map<String, Json> = Map::new();
    obj.insert("module".to_owned(), Json::String(module.into()));
    if !symbols.is_empty() {
        obj.insert(
            "symbols".to_owned(),
            Json::Array(symbols.into_iter().map(Json::String).collect()),
        );
    }
    obj.insert("alias".to_owned(), alias.map_or(Json::Null, Json::String));
    obj.insert("kind".to_owned(), Json::String(kind.into()));
    obj.insert(
        "version".to_owned(),
        version.map_or(Json::Null, Json::String),
    );
    Json::Object(obj)
}

/// `ImportsCategory` `value` is an array of import entries.
#[must_use]
pub const fn make_imports_value(entries: Vec<Json>) -> Json {
    Json::Array(entries)
}

#[must_use]
pub fn make_constant_entry(
    index: u64,
    kind: impl Into<String>,
    literal: Json,
    refs: Vec<u64>,
) -> Json {
    let mut obj: Map<String, Json> = Map::new();
    obj.insert("index".to_owned(), json!(index));
    obj.insert("kind".to_owned(), Json::String(kind.into()));
    obj.insert("literal".to_owned(), literal);
    if !refs.is_empty() {
        obj.insert(
            "refs".to_owned(),
            Json::Array(refs.into_iter().map(|r: u64| json!(r)).collect()),
        );
    }
    Json::Object(obj)
}

#[must_use]
pub const fn make_constants_value(entries: Vec<Json>) -> Json {
    Json::Array(entries)
}

#[must_use]
pub fn make_signature_entry(
    function: impl Into<String>,
    return_type: Option<String>,
    parameters: Vec<Json>,
    throws: Vec<String>,
    attributes: Vec<String>,
) -> Json {
    let mut obj: Map<String, Json> = Map::new();
    obj.insert("function".to_owned(), Json::String(function.into()));
    obj.insert(
        "return_type".to_owned(),
        return_type.map_or(Json::Null, Json::String),
    );
    obj.insert("parameters".to_owned(), Json::Array(parameters));
    if !throws.is_empty() {
        obj.insert(
            "throws".to_owned(),
            Json::Array(throws.into_iter().map(Json::String).collect()),
        );
    }
    if !attributes.is_empty() {
        obj.insert(
            "attributes".to_owned(),
            Json::Array(attributes.into_iter().map(Json::String).collect()),
        );
    }
    Json::Object(obj)
}

#[must_use]
pub fn make_signature_param(
    name: impl Into<String>,
    typ: Option<String>,
    default: Option<Json>,
    kind: impl Into<String>,
) -> Json {
    let mut obj: Map<String, Json> = Map::new();
    obj.insert("name".to_owned(), Json::String(name.into()));
    obj.insert("type".to_owned(), typ.map_or(Json::Null, Json::String));
    if let Some(d) = default {
        obj.insert("default".to_owned(), d);
    }
    obj.insert("kind".to_owned(), Json::String(kind.into()));
    Json::Object(obj)
}

#[must_use]
pub const fn make_signatures_value(entries: Vec<Json>) -> Json {
    Json::Array(entries)
}

/// `ProvenanceCategory` `{ chain: [...], kv: {...} }`.
#[must_use]
pub fn make_provenance_value(chain: Vec<Json>, kv: BTreeMap<String, String>) -> Json {
    let mut obj: Map<String, Json> = Map::new();
    obj.insert("chain".to_owned(), Json::Array(chain));
    if !kv.is_empty() {
        let mut kv_o: Map<String, Json> = Map::new();
        for (k, v) in kv {
            kv_o.insert(k, Json::String(v));
        }
        obj.insert("kv".to_owned(), Json::Object(kv_o));
    }
    Json::Object(obj)
}

#[must_use]
pub fn make_pipeline_step(
    pass: impl Into<String>,
    version: impl Into<String>,
    rung_in: impl Into<String>,
    rung_out: impl Into<String>,
    duration_ms: f64,
    config: BTreeMap<String, Json>,
) -> Json {
    let mut obj: Map<String, Json> = Map::new();
    obj.insert("pass".to_owned(), Json::String(pass.into()));
    obj.insert("version".to_owned(), Json::String(version.into()));
    obj.insert("rung_in".to_owned(), Json::String(rung_in.into()));
    obj.insert("rung_out".to_owned(), Json::String(rung_out.into()));
    obj.insert("duration_ms".to_owned(), json!(duration_ms));
    if !config.is_empty() {
        let mut c: Map<String, Json> = Map::new();
        for (k, v) in config {
            c.insert(k, v);
        }
        obj.insert("config".to_owned(), Json::Object(c));
    }
    Json::Object(obj)
}

#[must_use]
pub fn make_roundtrip_value(
    status: impl Into<String>,
    stages: Vec<Json>,
    diff: Option<Json>,
) -> Json {
    let mut obj: Map<String, Json> = Map::new();
    obj.insert("status".to_owned(), Json::String(status.into()));
    obj.insert("stages".to_owned(), Json::Array(stages));
    if let Some(d) = diff {
        obj.insert("diff".to_owned(), d);
    }
    Json::Object(obj)
}

#[must_use]
pub fn make_roundtrip_stage(name: impl Into<String>, ok: bool, details: Option<String>) -> Json {
    let mut obj: Map<String, Json> = Map::new();
    obj.insert("name".to_owned(), Json::String(name.into()));
    obj.insert("ok".to_owned(), json!(ok));
    obj.insert(
        "details".to_owned(),
        details.map_or(Json::Null, Json::String),
    );
    Json::Object(obj)
}

#[must_use]
pub fn make_manifest_value(
    path: impl Into<String>,
    size_bytes: u64,
    hash_blake3: impl Into<String>,
    magic_bytes_hex: Option<String>,
    mime: Option<String>,
    detected_formats: Vec<Json>,
    container_chain: Vec<String>,
) -> Json {
    let mut file: Map<String, Json> = Map::new();
    file.insert("path".to_owned(), Json::String(path.into()));
    file.insert("size_bytes".to_owned(), json!(size_bytes));
    file.insert("hash_blake3".to_owned(), Json::String(hash_blake3.into()));
    file.insert(
        "magic_bytes_hex".to_owned(),
        magic_bytes_hex.map_or(Json::Null, Json::String),
    );
    file.insert("mime".to_owned(), mime.map_or(Json::Null, Json::String));

    let mut obj: Map<String, Json> = Map::new();
    obj.insert("file".to_owned(), Json::Object(file));
    if !detected_formats.is_empty() {
        obj.insert("detected_formats".to_owned(), Json::Array(detected_formats));
    }
    if !container_chain.is_empty() {
        obj.insert(
            "container_chain".to_owned(),
            Json::Array(container_chain.into_iter().map(Json::String).collect()),
        );
    }
    Json::Object(obj)
}

#[must_use]
pub fn make_format_detection(
    format: impl Into<String>,
    confidence: f64,
    detector: Option<String>,
) -> Json {
    let mut obj: Map<String, Json> = Map::new();
    obj.insert("format".to_owned(), Json::String(format.into()));
    obj.insert("confidence".to_owned(), json!(confidence));
    if let Some(d) = detector {
        obj.insert("detector".to_owned(), Json::String(d));
    }
    Json::Object(obj)
}

#[must_use]
pub fn make_decryption_keys_value(authorized: bool, entries: Vec<Json>) -> Json {
    json!({
        "authorized": authorized,
        "entries": entries,
    })
}

#[must_use]
pub fn make_decryption_key_entry(
    label: impl Into<String>,
    algorithm: Option<String>,
    key_hex: impl Into<String>,
    iv_hex: Option<String>,
    salt_hex: Option<String>,
    derivation: Option<String>,
) -> Json {
    let mut obj: Map<String, Json> = Map::new();
    obj.insert("label".to_owned(), Json::String(label.into()));
    obj.insert(
        "algorithm".to_owned(),
        algorithm.map_or(Json::Null, Json::String),
    );
    obj.insert("key_hex".to_owned(), Json::String(key_hex.into()));
    obj.insert("iv_hex".to_owned(), iv_hex.map_or(Json::Null, Json::String));
    obj.insert(
        "salt_hex".to_owned(),
        salt_hex.map_or(Json::Null, Json::String),
    );
    obj.insert(
        "derivation".to_owned(),
        derivation.map_or(Json::Null, Json::String),
    );
    Json::Object(obj)
}

#[must_use]
pub fn make_confidence_entry(
    detection: impl Into<String>,
    score: f64,
    evidence: Vec<String>,
) -> Json {
    let mut obj: Map<String, Json> = Map::new();
    obj.insert("detection".to_owned(), Json::String(detection.into()));
    obj.insert("score".to_owned(), json!(score));
    if !evidence.is_empty() {
        obj.insert(
            "evidence".to_owned(),
            Json::Array(evidence.into_iter().map(Json::String).collect()),
        );
    }
    Json::Object(obj)
}

#[must_use]
pub const fn make_confidence_value(entries: Vec<Json>) -> Json {
    Json::Array(entries)
}

#[must_use]
pub fn make_opcode_coverage_value(
    bytecode_version: impl Into<String>,
    seen: Vec<String>,
    unknown: Vec<String>,
    totals: Option<BTreeMap<String, u64>>,
) -> Json {
    let mut obj: Map<String, Json> = Map::new();
    obj.insert(
        "bytecode_version".to_owned(),
        Json::String(bytecode_version.into()),
    );
    obj.insert(
        "seen".to_owned(),
        Json::Array(seen.into_iter().map(Json::String).collect()),
    );
    obj.insert(
        "unknown".to_owned(),
        Json::Array(unknown.into_iter().map(Json::String).collect()),
    );
    if let Some(t) = totals {
        let mut o: Map<String, Json> = Map::new();
        for (k, v) in t {
            o.insert(k, json!(v));
        }
        obj.insert("totals".to_owned(), Json::Object(o));
    }
    Json::Object(obj)
}
