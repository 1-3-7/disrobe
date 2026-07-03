#![allow(clippy::too_many_lines)]
use std::collections::BTreeSet;
use std::fmt::Arguments;

use serde_json::Value as Json;

use crate::category::Category;
use crate::{SCHEMA_VERSION, VERSION};

macro_rules! push_line {
    ($output:expr) => {
        $output.push('\n')
    };
    ($output:expr, $($arg:tt)*) => {
        push_formatted_line(&mut $output, format_args!($($arg)*))
    };
}

#[inline]
fn push_formatted_line(output: &mut String, args: Arguments<'_>) {
    match std::fmt::write(output, args) {
        Ok(()) => output.push('\n'),
        Err(error) => unreachable!("string formatting failed: {error:?}"),
    }
}

#[derive(Debug)]
struct BundleView<'a> {
    tool_name: &'a str,
    tool_version: &'a str,
    git_commit: Option<&'a str>,
    generated_at: &'a str,
    input_path: &'a str,
    input_size_bytes: u64,
    input_hash: &'a str,
    language: Option<String>,
    dialect: Option<&'a str>,
    bytecode_version: Option<&'a str>,
    roundtrip_status: Option<&'a str>,
    pipeline: Vec<PipelineRow>,
    entrypoints: Vec<String>,
    signatures: Vec<SignatureRow<'a>>,
    imports: Vec<ImportRow<'a>>,
    symbols: Vec<SymbolRow<'a>>,
    cfg_functions: Vec<CfgRow<'a>>,
    capabilities: BTreeSet<String>,
    notable_strings: Vec<&'a str>,
    pii_categories: BTreeSet<&'a str>,
    confidence: Vec<ConfidenceRow<'a>>,
    opcode_unknown: Vec<&'a str>,
}

#[derive(Debug)]
struct PipelineRow {
    pass: String,
    version: String,
    rung_in: String,
    rung_out: String,
}

#[derive(Debug)]
struct SignatureRow<'a> {
    function: &'a str,
    params: Vec<String>,
    return_type: Option<&'a str>,
}

#[derive(Debug)]
struct ImportRow<'a> {
    module: &'a str,
    symbols: Vec<&'a str>,
}

#[derive(Debug)]
struct SymbolRow<'a> {
    name: &'a str,
    kind: &'a str,
    visibility: &'a str,
}

#[derive(Debug)]
struct CfgRow<'a> {
    function: &'a str,
    blocks: usize,
    edges: usize,
    loops: usize,
}

#[derive(Debug)]
struct ConfidenceRow<'a> {
    detection: &'a str,
    score: f64,
}

#[inline]
fn str_field<'a>(obj: &'a Json, key: &str) -> Option<&'a str> {
    obj.get(key).and_then(Json::as_str)
}

#[inline]
fn option_str_or<'a>(value: Option<&'a str>, default: &'a str) -> &'a str {
    value.map_or(default, |inner: &'a str| inner)
}

#[inline]
fn first_segment_or_self(raw: &str, delimiter: char) -> &str {
    raw.split(delimiter)
        .next()
        .map_or(raw, |segment: &str| segment)
}

#[inline]
fn category_obj(bundle: &Json, cat: Category) -> Option<&Json> {
    bundle
        .get("categories")
        .and_then(|c: &Json| c.get(cat.label()))
}

fn applicable_values(bundle: &Json, cat: Category) -> Vec<&Json> {
    category_obj(bundle, cat)
        .and_then(|c: &Json| c.get("entries"))
        .and_then(Json::as_array)
        .map_or_else(Vec::new, |arr: &Vec<Json>| {
            arr.iter()
                .filter(|e: &&Json| e.get("applicable").and_then(Json::as_bool) == Some(true))
                .filter_map(|e: &Json| e.get("value"))
                .filter(|v: &&Json| !v.is_null())
                .collect()
        })
}

impl<'a> BundleView<'a> {
    fn from_bundle(bundle: &'a Json) -> Self {
        let tool: Option<&Json> = bundle.get("tool");
        let input: Option<&Json> = bundle.get("input");

        let dialect: Option<&str> = applicable_values(bundle, Category::Ast)
            .into_iter()
            .find_map(|v: &Json| str_field(v, "dialect"));

        let bytecode_version: Option<&str> = applicable_values(bundle, Category::Disasm)
            .into_iter()
            .find_map(|v: &Json| str_field(v, "bytecode_version"))
            .or_else(|| {
                applicable_values(bundle, Category::OpcodeCoverage)
                    .into_iter()
                    .find_map(|v: &Json| str_field(v, "bytecode_version"))
            });

        let language: Option<String> =
            dialect.map(|d: &str| first_segment_or_self(d, '.').to_owned());

        let roundtrip_status: Option<&str> = applicable_values(bundle, Category::RoundtripVerdict)
            .into_iter()
            .find_map(|v: &Json| str_field(v, "status"));

        let pipeline: Vec<PipelineRow> = bundle
            .get("pipeline")
            .and_then(Json::as_array)
            .map_or_else(Vec::new, |arr: &Vec<Json>| {
                arr.iter()
                    .map(|s: &Json| PipelineRow {
                        pass: option_str_or(str_field(s, "pass"), "?").to_owned(),
                        version: option_str_or(str_field(s, "version"), "?").to_owned(),
                        rung_in: option_str_or(str_field(s, "rung_in"), "?").to_owned(),
                        rung_out: option_str_or(str_field(s, "rung_out"), "?").to_owned(),
                    })
                    .collect()
            });

        let mut signatures: Vec<SignatureRow<'a>> = Vec::new();
        for value in applicable_values(bundle, Category::Signatures) {
            if let Some(arr) = value.as_array() {
                for entry in arr {
                    let Some(function): Option<&str> = str_field(entry, "function") else {
                        continue;
                    };
                    let params: Vec<String> = entry
                        .get("parameters")
                        .and_then(Json::as_array)
                        .map_or_else(Vec::new, |ps: &Vec<Json>| {
                            ps.iter()
                                .filter_map(|p: &Json| {
                                    let name: &str = str_field(p, "name")?;
                                    Some(str_field(p, "type").map_or_else(
                                        || name.to_owned(),
                                        |t: &str| format!("{name}: {t}"),
                                    ))
                                })
                                .collect()
                        });
                    signatures.push(SignatureRow {
                        function,
                        params,
                        return_type: str_field(entry, "return_type"),
                    });
                }
            }
        }
        signatures.sort_by(|a: &SignatureRow<'a>, b: &SignatureRow<'a>| a.function.cmp(b.function));
        signatures.dedup_by(|a: &mut SignatureRow<'a>, b: &mut SignatureRow<'a>| {
            a.function == b.function
        });

        let mut imports: Vec<ImportRow<'a>> = Vec::new();
        for value in applicable_values(bundle, Category::Imports) {
            if let Some(arr) = value.as_array() {
                for entry in arr {
                    let Some(module): Option<&str> = str_field(entry, "module") else {
                        continue;
                    };
                    let symbols: Vec<&str> = entry
                        .get("symbols")
                        .and_then(Json::as_array)
                        .map_or_else(Vec::new, |ss: &Vec<Json>| {
                            ss.iter().filter_map(Json::as_str).collect()
                        });
                    imports.push(ImportRow { module, symbols });
                }
            }
        }
        imports.sort_by(|a: &ImportRow<'a>, b: &ImportRow<'a>| a.module.cmp(b.module));
        imports.dedup_by(|a: &mut ImportRow<'a>, b: &mut ImportRow<'a>| a.module == b.module);

        let mut symbols: Vec<SymbolRow<'a>> = Vec::new();
        for value in applicable_values(bundle, Category::Symbols) {
            if let Some(arr) = value.as_array() {
                for entry in arr {
                    let name: &str = str_field(entry, "demangled")
                        .or_else(|| str_field(entry, "mangled"))
                        .map_or("?", |value: &str| value);
                    symbols.push(SymbolRow {
                        name,
                        kind: option_str_or(str_field(entry, "kind"), "unknown"),
                        visibility: option_str_or(str_field(entry, "visibility"), "unknown"),
                    });
                }
            }
        }
        symbols.sort_by(|a: &SymbolRow<'a>, b: &SymbolRow<'a>| a.name.cmp(b.name));
        symbols.dedup_by(|a: &mut SymbolRow<'a>, b: &mut SymbolRow<'a>| a.name == b.name);

        let mut cfg_functions: Vec<CfgRow<'a>> = Vec::new();
        for value in applicable_values(bundle, Category::Cfg) {
            let Some(function): Option<&str> = str_field(value, "function") else {
                continue;
            };
            cfg_functions.push(CfgRow {
                function,
                blocks: value
                    .get("blocks")
                    .and_then(Json::as_array)
                    .map_or(0, Vec::len),
                edges: value
                    .get("edges")
                    .and_then(Json::as_array)
                    .map_or(0, Vec::len),
                loops: value
                    .get("loops")
                    .and_then(Json::as_array)
                    .map_or(0, Vec::len),
            });
        }
        cfg_functions.sort_by(|a: &CfgRow<'a>, b: &CfgRow<'a>| a.function.cmp(b.function));

        let mut entrypoints: BTreeSet<String> = BTreeSet::new();
        for sig in &signatures {
            if matches!(sig.function, "main" | "__main__" | "<module>") {
                entrypoints.insert(sig.function.to_owned());
            }
        }
        for sym in &symbols {
            if matches!(sym.name, "main" | "__main__" | "<module>") {
                entrypoints.insert(sym.name.to_owned());
            }
        }
        let entrypoints: Vec<String> = entrypoints.into_iter().collect();

        let mut capabilities: BTreeSet<String> = BTreeSet::new();
        for imp in &imports {
            capabilities.extend(classify_capability(imp.module));
        }

        let mut notable_strings: Vec<&str> = applicable_values(bundle, Category::Strings)
            .into_iter()
            .filter_map(Json::as_array)
            .flatten()
            .filter_map(|e: &Json| str_field(e, "text"))
            .filter(|s: &&str| s.len() >= 6 && s.len() <= 120)
            .collect();
        notable_strings.sort_unstable();
        notable_strings.dedup();
        notable_strings.truncate(20);

        let mut pii_categories: BTreeSet<&str> = BTreeSet::new();
        for value in applicable_values(bundle, Category::PiiMap) {
            if let Some(arr) = value.as_array() {
                for entry in arr {
                    if let Some(c) = str_field(entry, "category") {
                        pii_categories.insert(c);
                    }
                }
            }
        }

        let mut confidence: Vec<ConfidenceRow<'a>> = Vec::new();
        for value in applicable_values(bundle, Category::Confidence) {
            if let Some(arr) = value.as_array() {
                for entry in arr {
                    let Some(detection): Option<&str> = str_field(entry, "detection") else {
                        continue;
                    };
                    confidence.push(ConfidenceRow {
                        detection,
                        score: entry
                            .get("score")
                            .and_then(Json::as_f64)
                            .map_or(0.0_f64, |score: f64| score),
                    });
                }
            }
        }
        confidence
            .sort_by(|a: &ConfidenceRow<'a>, b: &ConfidenceRow<'a>| a.detection.cmp(b.detection));

        let mut opcode_unknown: Vec<&str> = applicable_values(bundle, Category::OpcodeCoverage)
            .into_iter()
            .filter_map(|v: &Json| v.get("unknown").and_then(Json::as_array))
            .flatten()
            .filter_map(Json::as_str)
            .collect();
        opcode_unknown.sort_unstable();
        opcode_unknown.dedup();

        Self {
            tool_name: tool
                .and_then(|t: &Json| str_field(t, "name"))
                .map_or("disrobe", |value: &str| value),
            tool_version: tool
                .and_then(|t: &Json| str_field(t, "version"))
                .map_or(VERSION, |value: &str| value),
            git_commit: tool.and_then(|t: &Json| str_field(t, "git_commit")),
            generated_at: option_str_or(str_field(bundle, "generated_at"), "unknown"),
            input_path: input
                .and_then(|i: &Json| str_field(i, "path"))
                .map_or("unknown", |value: &str| value),
            input_size_bytes: input
                .and_then(|i: &Json| i.get("size_bytes"))
                .and_then(Json::as_u64)
                .map_or(0u64, |value: u64| value),
            input_hash: input
                .and_then(|i: &Json| str_field(i, "hash_blake3"))
                .map_or("unknown", |value: &str| value),
            language,
            dialect,
            bytecode_version,
            roundtrip_status,
            pipeline,
            entrypoints,
            signatures,
            imports,
            symbols,
            cfg_functions,
            capabilities,
            notable_strings,
            pii_categories,
            confidence,
            opcode_unknown,
        }
    }

    fn language_label(&self) -> &str {
        self.language
            .as_deref()
            .map_or("unknown-language", |value: &str| value)
    }
}

fn classify_capability(module: &str) -> Vec<String> {
    let root: &str = first_segment_or_self(module, '.');
    let mapped: Option<&str> = match root {
        "os" | "subprocess" | "shutil" | "sys" => Some("process & filesystem control"),
        "socket" | "http" | "urllib" | "requests" | "ftplib" | "smtplib" | "asyncio" => {
            Some("network I/O")
        }
        "ctypes" | "cffi" | "mmap" => Some("native / FFI"),
        "pickle" | "marshal" | "shelve" => Some("object (de)serialization"),
        "hashlib" | "hmac" | "secrets" | "ssl" | "cryptography" | "Crypto" => Some("cryptography"),
        "base64" | "codecs" | "zlib" | "gzip" | "lzma" | "bz2" => Some("encoding / compression"),
        "sqlite3" | "psycopg2" | "pymysql" => Some("database access"),
        "threading" | "multiprocessing" | "concurrent" => Some("concurrency"),
        _ => None,
    };
    mapped.map_or_else(Vec::new, |m: &str| vec![m.to_owned()])
}

#[must_use]
pub fn render_agents_md(bundle: &Json) -> String {
    let view: BundleView<'_> = BundleView::from_bundle(bundle);
    let mut md: String = String::with_capacity(4096);
    let language_label: String = markdown_text(view.language_label());
    let tool_name: String = inline_code(view.tool_name);
    let tool_version: String = markdown_text(view.tool_version);

    push_line!(md, "# AGENTS.md");
    push_line!(md);
    push_line!(
        md,
        "This directory contains recovered {language_label} source reconstructed by {tool_name} v{tool_version}. \
         Use this brief to orient before you read, run, reconstruct, or refactor the code."
    );
    push_line!(md);

    push_line!(md, "## Artifact");
    push_line!(md);
    push_line!(md, "| field | value |");
    push_line!(md, "|-------|-------|");
    push_line!(md, "| source | {} |", inline_code(view.input_path));
    push_line!(md, "| size | {} bytes |", view.input_size_bytes);
    push_line!(md, "| blake3 | {} |", inline_code(view.input_hash));
    if let Some(d) = view.dialect {
        push_line!(md, "| dialect | {} |", inline_code(d));
    }
    if let Some(bv) = view.bytecode_version {
        push_line!(md, "| bytecode | {} |", inline_code(bv));
    }
    if let Some(rt) = view.roundtrip_status {
        push_line!(md, "| roundtrip | {} |", inline_code(rt));
    }
    if let Some(gc) = view.git_commit {
        push_line!(md, "| tool commit | {} |", inline_code(gc));
    }
    push_line!(md, "| generated | {} |", inline_code(view.generated_at));
    push_line!(md, "| schema | `disrobe.metadata.llm.v{SCHEMA_VERSION}` |");
    push_line!(md);

    if !view.pipeline.is_empty() {
        push_line!(md, "## Decompile provenance");
        push_line!(md);
        for step in &view.pipeline {
            push_line!(
                md,
                "- {} v{} ({} -> {})",
                inline_code(&step.pass),
                markdown_text(&step.version),
                markdown_text(&step.rung_in),
                markdown_text(&step.rung_out)
            );
        }
        push_line!(md);
    }

    if !view.entrypoints.is_empty() {
        push_line!(md, "## Key entrypoints");
        push_line!(md);
        for ep in &view.entrypoints {
            push_line!(md, "- {}", inline_code(ep));
        }
        push_line!(md);
    }

    if !view.capabilities.is_empty() {
        push_line!(md, "## Capabilities observed");
        push_line!(md);
        for cap in &view.capabilities {
            push_line!(md, "- {cap}");
        }
        push_line!(md);
    }

    if !view.imports.is_empty() {
        push_line!(md, "## External symbols & imports");
        push_line!(md);
        for imp in &view.imports {
            if imp.symbols.is_empty() {
                push_line!(md, "- {}", inline_code(imp.module));
            } else {
                let symbols: String = imp
                    .symbols
                    .iter()
                    .map(|symbol: &&str| markdown_text(symbol))
                    .collect::<Vec<String>>()
                    .join(", ");
                push_line!(md, "- {} -> {}", inline_code(imp.module), symbols);
            }
        }
        push_line!(md);
    }

    if !view.signatures.is_empty() {
        push_line!(md, "## Type signatures");
        push_line!(md);
        for sig in &view.signatures {
            push_line!(md, "- {}", format_signature(sig));
        }
        push_line!(md);
    }

    if !view.cfg_functions.is_empty() {
        push_line!(md, "## Control-flow shape");
        push_line!(md);
        push_line!(md, "| function | blocks | edges | loops |");
        push_line!(md, "|----------|-------:|------:|------:|");
        for cfg in &view.cfg_functions {
            push_line!(
                md,
                "| {} | {} | {} | {} |",
                inline_code(cfg.function),
                cfg.blocks,
                cfg.edges,
                cfg.loops
            );
        }
        push_line!(md);
    }

    if !view.notable_strings.is_empty() {
        push_line!(md, "## Notable strings");
        push_line!(md);
        for s in &view.notable_strings {
            push_line!(md, "- {}", inline_code(s));
        }
        push_line!(md);
    }

    if !view.confidence.is_empty() {
        push_line!(md, "## Detection confidence");
        push_line!(md);
        for c in &view.confidence {
            push_line!(md, "- {}: {:.2}", inline_code(c.detection), c.score);
        }
        push_line!(md);
    }

    let has_risks: bool = !view.pii_categories.is_empty()
        || !view.opcode_unknown.is_empty()
        || matches!(view.roundtrip_status, Some("fail" | "partial"));
    if has_risks {
        push_line!(md, "## Notable risks");
        push_line!(md);
        if !view.pii_categories.is_empty() {
            let cats: Vec<String> = view
                .pii_categories
                .iter()
                .map(|category: &&str| markdown_text(category))
                .collect();
            push_line!(
                md,
                "- PII detected & placeholdered: {}. Do not reintroduce literal values.",
                cats.join(", ")
            );
        }
        if !view.opcode_unknown.is_empty() {
            push_line!(
                md,
                "- {} unknown opcode(s) ({}). Affected regions may be under-recovered.",
                view.opcode_unknown.len(),
                view.opcode_unknown
                    .iter()
                    .map(|opcode: &&str| markdown_text(opcode))
                    .collect::<Vec<String>>()
                    .join(", ")
            );
        }
        match view.roundtrip_status {
            Some("fail") => {
                push_line!(
                    md,
                    "- Roundtrip FAILED: recovered source did not recompile to the original bytes. \
                     Treat the source as approximate."
                );
            }
            Some("partial") => {
                push_line!(
                    md,
                    "- Roundtrip PARTIAL: only some stages verified. Cross-check against the disasm."
                );
            }
            _ => {}
        }
        push_line!(md);
    }

    push_line!(md, "## When reconstructing");
    push_line!(md);
    push_line!(
        md,
        "- Preserve the entrypoints & public signatures listed above; they are the observable contract."
    );
    push_line!(
        md,
        "- The control-flow shape table is ground truth recovered from bytecode; \
         match branch & loop structure, not just behaviour."
    );
    if !view.confidence.is_empty() {
        push_line!(
            md,
            "- Detection confidence is recorded in the bundle's `confidence` category; \
             prefer high-score detections when they conflict."
        );
    }
    push_line!(
        md,
        "- Full machine-readable detail lives in the sibling `*.disrobe.llm.json` bundle \
         (schema `disrobe.metadata.llm.v{SCHEMA_VERSION}`)."
    );

    md
}

#[must_use]
pub fn render_skill_md(bundle: &Json) -> String {
    let view: BundleView<'_> = BundleView::from_bundle(bundle);
    let mut md: String = String::with_capacity(4096);
    let language_label: String = markdown_text(view.language_label());
    let tool_name: String = markdown_text(view.tool_name);
    let tool_version: String = markdown_text(view.tool_version);

    let stem: &str = view
        .input_path
        .rsplit(['/', '\\'])
        .next()
        .map_or(view.input_path, |value: &str| value);
    let stem_code: String = inline_code(stem);

    push_line!(md, "---");
    push_line!(md, "name: reconstruct-{}", slug(view.language_label()));
    push_line!(
        md,
        "description: Reconstruct & refactor the recovered {language_label} artifact {stem_code} decompiled by {tool_name} v{tool_version}. \
         Use when reading, reasoning about, rebuilding, or refactoring this directory's source."
    );
    push_line!(md, "---");
    push_line!(md);

    push_line!(md, "# Working with recovered {language_label} source");
    push_line!(md);
    push_line!(
        md,
        "This skill briefs any coding assistant \
         on the recovered artifact in this directory & how to safely reconstruct it. \
         All facts below are distilled from the `disrobe.metadata.llm.v{SCHEMA_VERSION}` bundle."
    );
    push_line!(md);

    push_line!(md, "## Source of truth");
    push_line!(md);
    push_line!(
        md,
        "- Original input: {} ({} bytes)",
        inline_code(view.input_path),
        view.input_size_bytes
    );
    push_line!(md, "- blake3: {}", inline_code(view.input_hash));
    if let Some(d) = view.dialect {
        push_line!(md, "- Dialect: {}", inline_code(d));
    }
    if let Some(rt) = view.roundtrip_status {
        push_line!(md, "- Roundtrip verdict: {}", inline_code(rt));
    }
    push_line!(md);

    push_line!(md, "## Reconstruction procedure");
    push_line!(md);
    push_line!(
        md,
        "1. Read the recovered source alongside this brief & the sibling JSON bundle."
    );
    push_line!(
        md,
        "2. Anchor on the entrypoints & signatures below; they form the public contract that must survive refactoring."
    );
    push_line!(
        md,
        "3. Reproduce the control-flow shape (blocks, edges, loops) per function; \
         the decompiler recovered it from bytecode, so it is authoritative."
    );
    push_line!(
        md,
        "4. Keep every observed import & capability wired; removing one changes the artifact's behaviour."
    );
    if !view.pii_categories.is_empty() {
        push_line!(
            md,
            "5. Leave PII placeholders intact ({}); never substitute synthetic literals.",
            view.pii_categories
                .iter()
                .map(|category: &&str| markdown_text(category))
                .collect::<Vec<String>>()
                .join(", ")
        );
    }
    push_line!(md);

    push_line!(md, "## Invariants to preserve");
    push_line!(md);
    if view.entrypoints.is_empty() {
        push_line!(
            md,
            "- Public signatures (see table) are the observable contract."
        );
    } else {
        push_line!(
            md,
            "- Entrypoints: {}.",
            view.entrypoints
                .iter()
                .map(|e: &String| inline_code(e))
                .collect::<Vec<String>>()
                .join(", ")
        );
    }
    push_line!(md, "- Import surface & capabilities must not change.");
    push_line!(
        md,
        "- Per-function control-flow shape must match the recovered CFG."
    );
    if let Some("fail" | "partial") = view.roundtrip_status {
        push_line!(
            md,
            "- Roundtrip is not byte-perfect; verify behaviour against the disasm before trusting the source."
        );
    }
    push_line!(md);

    if !view.symbols.is_empty() || !view.signatures.is_empty() {
        push_line!(md, "## Per-symbol metadata");
        push_line!(md);
        push_line!(md, "| symbol | kind | visibility | signature |");
        push_line!(md, "|--------|------|------------|-----------|");
        let mut emitted: BTreeSet<&str> = BTreeSet::new();
        for sym in &view.symbols {
            let sig: String = view
                .signatures
                .iter()
                .find(|s: &&SignatureRow<'_>| s.function == sym.name)
                .map_or_else(String::new, |signature: &SignatureRow<'_>| {
                    format_signature(signature)
                });
            push_line!(
                md,
                "| {} | {} | {} | {} |",
                inline_code(sym.name),
                markdown_text(sym.kind),
                markdown_text(sym.visibility),
                sig
            );
            emitted.insert(sym.name);
        }
        for sig in &view.signatures {
            if !emitted.contains(sig.function) {
                push_line!(
                    md,
                    "| {} | function | unknown | {} |",
                    inline_code(sig.function),
                    format_signature(sig)
                );
            }
        }
        push_line!(md);
    }

    if !view.imports.is_empty() {
        push_line!(md, "## Dependencies");
        push_line!(md);
        for imp in &view.imports {
            push_line!(md, "- {}", inline_code(imp.module));
        }
        push_line!(md);
    }

    md
}

fn format_signature(sig: &SignatureRow<'_>) -> String {
    let ret: String = sig
        .return_type
        .map(|r: &str| format!(" -> {r}"))
        .unwrap_or_default();
    inline_code(&format!(
        "{}({}){}",
        sig.function,
        sig.params.join(", "),
        ret
    ))
}

fn inline_code(raw: &str) -> String {
    format!("`{}`", markdown_text(raw))
}

fn markdown_text(raw: &str) -> String {
    let mut out: String = String::with_capacity(raw.len());
    for ch in raw.chars() {
        match ch {
            '\r' | '\n' | '\t' => out.push(' '),
            '`' => out.push('\''),
            '|' => out.push_str("\\|"),
            _ => out.push(ch),
        }
    }
    out
}

fn slug(raw: &str) -> String {
    let mut out: String = String::with_capacity(raw.len());
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else if ch == ' ' || ch == '-' || ch == '_' || ch == '.' {
            out.push('-');
        }
    }
    if out.is_empty() {
        out.push_str("artifact");
    }
    out
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_bundle() -> Json {
        json!({
            "schema": "disrobe.metadata.llm.v1",
            "schema_version": "1.0.0",
            "generated_at": "2026-01-02T03:04:05.000000000Z",
            "tool": { "name": "disrobe", "version": "0.9.0", "git_commit": "abc123" },
            "input": {
                "path": "fixtures/app.pyc",
                "size_bytes": 4096,
                "hash_blake3": "ab".repeat(32)
            },
            "pipeline": [
                { "pass": "disrobe-pass-py-decompile", "version": "0.1.0", "rung_in": "disasm", "rung_out": "surface", "duration_ms": 1.0 }
            ],
            "categories": {
                "ast": { "entries": [
                    { "pass": "p", "pass_version": "1", "applicable": true, "value": { "dialect": "python.3.12", "root": { "kind": "Module" } } }
                ]},
                "imports": { "entries": [
                    { "pass": "p", "pass_version": "1", "applicable": true, "value": [
                        { "module": "os", "symbols": ["system"] },
                        { "module": "hashlib", "symbols": [] }
                    ]}
                ]},
                "signatures": { "entries": [
                    { "pass": "p", "pass_version": "1", "applicable": true, "value": [
                        { "function": "main", "return_type": "int", "parameters": [ { "name": "argv", "type": "list" } ] }
                    ]}
                ]},
                "symbols": { "entries": [
                    { "pass": "p", "pass_version": "1", "applicable": true, "value": [
                        { "mangled": "main", "kind": "function", "visibility": "public" }
                    ]}
                ]},
                "cfg": { "entries": [
                    { "pass": "p", "pass_version": "1", "applicable": true, "value": {
                        "function": "main", "blocks": [{"id":0},{"id":1}], "edges": [{"from":0,"to":1}], "loops": []
                    }}
                ]},
                "roundtrip_verdict": { "entries": [
                    { "pass": "p", "pass_version": "1", "applicable": true, "value": { "status": "pass", "stages": [] } }
                ]}
            }
        })
    }

    #[test]
    fn agents_md_is_deterministic() {
        let bundle: Json = sample_bundle();
        let a: String = render_agents_md(&bundle);
        let b: String = render_agents_md(&bundle);
        assert_eq!(a, b);
    }

    #[test]
    fn skill_md_is_deterministic() {
        let bundle: Json = sample_bundle();
        let a: String = render_skill_md(&bundle);
        let b: String = render_skill_md(&bundle);
        assert_eq!(a, b);
    }

    #[test]
    fn agents_md_has_expected_sections() {
        let md: String = render_agents_md(&sample_bundle());
        assert!(md.starts_with("# AGENTS.md"));
        assert!(md.contains("## Artifact"));
        assert!(md.contains("## Key entrypoints"));
        assert!(md.contains("`main`"));
        assert!(md.contains("## Capabilities observed"));
        assert!(md.contains("process & filesystem control"));
        assert!(md.contains("cryptography"));
        assert!(md.contains("## Type signatures"));
        assert!(md.contains("## Control-flow shape"));
        assert!(md.contains("python.3.12"));
        assert!(md.contains("## When reconstructing"));
    }

    #[test]
    fn skill_md_has_frontmatter_and_table() {
        let md: String = render_skill_md(&sample_bundle());
        assert!(md.starts_with("---\n"));
        assert!(md.contains("name: reconstruct-python"));
        assert!(md.contains("## Reconstruction procedure"));
        assert!(md.contains("## Per-symbol metadata"));
        assert!(md.contains("| `main` | function | public |"));
        assert!(md.contains("## Dependencies"));
    }

    #[test]
    fn generated_briefs_escape_artifact_metadata_fields() {
        let bundle: Json = json!({
            "schema": "disrobe.metadata.llm.v1",
            "schema_version": "1.0.0",
            "generated_at": "2026-01-02T03:04:05Z\n## injected time",
            "tool": {
                "name": "disrobe\n## injected tool",
                "version": "0.9.0|break",
                "git_commit": "abc123\n## injected commit"
            },
            "input": {
                "path": "x.pyc\n## injected path|break`tick",
                "size_bytes": 1,
                "hash_blake3": "00".repeat(32)
            },
            "pipeline": [],
            "categories": {
                "ast": { "entries": [
                    { "pass": "p", "pass_version": "1", "applicable": true, "value": { "dialect": "python.3.12\n## injected dialect" } }
                ]},
                "imports": { "entries": [
                    { "pass": "p", "pass_version": "1", "applicable": true, "value": [
                        { "module": "os\n## injected heading", "symbols": ["system|break"] }
                    ]}
                ]},
                "symbols": { "entries": [
                    { "pass": "p", "pass_version": "1", "applicable": true, "value": [
                        { "mangled": "main`|\n## injected table", "kind": "function|break", "visibility": "public\nhidden" }
                    ]}
                ]},
                "signatures": { "entries": [
                    { "pass": "p", "pass_version": "1", "applicable": true, "value": [
                        { "function": "main`|\n## injected table", "return_type": "int|bool", "parameters": [ { "name": "arg\nx", "type": "list|tuple" } ] }
                    ]}
                ]}
            }
        });
        let agents: String = render_agents_md(&bundle);
        let skill: String = render_skill_md(&bundle);
        assert!(!agents.contains("\n## injected"));
        assert!(!skill.contains("\n## injected"));
        assert!(skill.contains("function\\|break"));
        assert!(skill.contains("public hidden"));
        assert!(agents.contains("system\\|break"));
    }

    #[test]
    fn empty_categories_are_skipped() {
        let bundle: Json = json!({
            "schema": "disrobe.metadata.llm.v1",
            "schema_version": "1.0.0",
            "generated_at": "2026-01-02T03:04:05Z",
            "tool": { "name": "disrobe", "version": "0.9.0" },
            "input": { "path": "x.pyc", "size_bytes": 1, "hash_blake3": "00".repeat(32) },
            "pipeline": [],
            "categories": {}
        });
        let agents: String = render_agents_md(&bundle);
        let skill: String = render_skill_md(&bundle);
        assert!(!agents.contains("## Type signatures"));
        assert!(!agents.contains("## Control-flow shape"));
        assert!(!agents.contains("## External symbols"));
        let placeholder_marker: String = ['T', 'O', 'D', 'O'].into_iter().collect();
        assert!(!agents.contains(&placeholder_marker));
        assert!(!skill.contains("## Per-symbol metadata"));
        assert!(!skill.contains("## Dependencies"));
        assert!(!skill.contains(&placeholder_marker));
        assert!(agents.contains("## When reconstructing"));
    }

    #[test]
    fn pii_and_unknown_opcodes_surface_risks() {
        let bundle: Json = json!({
            "schema": "disrobe.metadata.llm.v1",
            "schema_version": "1.0.0",
            "generated_at": "2026-01-02T03:04:05Z",
            "tool": { "name": "disrobe", "version": "0.9.0" },
            "input": { "path": "x.pyc", "size_bytes": 1, "hash_blake3": "00".repeat(32) },
            "pipeline": [],
            "categories": {
                "pii_map": { "entries": [
                    { "pass": "p", "pass_version": "1", "applicable": true, "value": [
                        { "category": "email", "placeholder": "<EMAIL_0>", "span": {} }
                    ]}
                ]},
                "opcode_coverage": { "entries": [
                    { "pass": "p", "pass_version": "1", "applicable": true, "value": {
                        "bytecode_version": "3.12", "seen": ["LOAD_FAST"], "unknown": ["WEIRD_OP"]
                    }}
                ]}
            }
        });
        let md: String = render_agents_md(&bundle);
        assert!(md.contains("## Notable risks"));
        assert!(md.contains("PII detected"));
        assert!(md.contains("email"));
        assert!(md.contains("unknown opcode"));
        assert!(md.contains("WEIRD_OP"));
    }
}
