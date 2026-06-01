//! Deterministic markdown brief renderers for the `disrobe --llm` bundle.
//!
//! Two pure functions distill a finalized `disrobe.metadata.llm.v1` bundle
//! (the JSON value produced by [`crate::BundleBuilder::finalize`]) into the two
//! agent-facing artifacts the README promises:
//!
//! - [`render_agents_md`] - an `AGENTS.md` orientation brief: what the recovered
//!   artifact is, its provenance, its entrypoints, capabilities, and the
//!   per-category facts a coding agent needs to reason about it.
//! - [`render_skill_md`] - a `SKILL.md` in the Claude-Skill / AGENTS convention:
//!   frontmatter + a focused reconstruction procedure + a per-symbol table.
//!
//! Both are deterministic: same bundle in, byte-identical markdown out. They
//! read only the bundle's own provenance fields (never wall-clock), sort every
//! collection, and skip any category whose payload is empty rather than emit
//! placeholder text.
#![allow(clippy::too_many_lines)]

use std::collections::BTreeSet;
use std::fmt::Write as _;

use serde_json::Value as Json;

use crate::category::Category;
use crate::{SCHEMA_VERSION, VERSION};

/// Distilled view over a finalized bundle, computed once and shared by both
/// renderers so the two outputs stay consistent.
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
fn category_obj(bundle: &Json, cat: Category) -> Option<&Json> {
    bundle
        .get("categories")
        .and_then(|c: &Json| c.get(cat.label()))
}

/// Iterate the `value` payloads of every applicable envelope in a standard
/// `{ entries: [PerPassEnvelope] }` category.
fn applicable_values(bundle: &Json, cat: Category) -> Vec<&Json> {
    category_obj(bundle, cat)
        .and_then(|c: &Json| c.get("entries"))
        .and_then(Json::as_array)
        .map(|arr: &Vec<Json>| {
            arr.iter()
                .filter(|e: &&Json| e.get("applicable").and_then(Json::as_bool) == Some(true))
                .filter_map(|e: &Json| e.get("value"))
                .filter(|v: &&Json| !v.is_null())
                .collect()
        })
        .unwrap_or_default()
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
            dialect.map(|d: &str| d.split('.').next().unwrap_or(d).to_owned());

        let roundtrip_status: Option<&str> = applicable_values(bundle, Category::RoundtripVerdict)
            .into_iter()
            .find_map(|v: &Json| str_field(v, "status"));

        let pipeline: Vec<PipelineRow> = bundle
            .get("pipeline")
            .and_then(Json::as_array)
            .map(|arr: &Vec<Json>| {
                arr.iter()
                    .map(|s: &Json| PipelineRow {
                        pass: str_field(s, "pass").unwrap_or("?").to_owned(),
                        version: str_field(s, "version").unwrap_or("?").to_owned(),
                        rung_in: str_field(s, "rung_in").unwrap_or("?").to_owned(),
                        rung_out: str_field(s, "rung_out").unwrap_or("?").to_owned(),
                    })
                    .collect()
            })
            .unwrap_or_default();

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
                        .map(|ps: &Vec<Json>| {
                            ps.iter()
                                .filter_map(|p: &Json| {
                                    let name: &str = str_field(p, "name")?;
                                    Some(str_field(p, "type").map_or_else(
                                        || name.to_owned(),
                                        |t: &str| format!("{name}: {t}"),
                                    ))
                                })
                                .collect()
                        })
                        .unwrap_or_default();
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
                        .map(|ss: &Vec<Json>| ss.iter().filter_map(Json::as_str).collect())
                        .unwrap_or_default();
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
                        .unwrap_or("?");
                    symbols.push(SymbolRow {
                        name,
                        kind: str_field(entry, "kind").unwrap_or("unknown"),
                        visibility: str_field(entry, "visibility").unwrap_or("unknown"),
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
                        score: entry.get("score").and_then(Json::as_f64).unwrap_or(0.0),
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
                .unwrap_or("disrobe"),
            tool_version: tool
                .and_then(|t: &Json| str_field(t, "version"))
                .unwrap_or(VERSION),
            git_commit: tool.and_then(|t: &Json| str_field(t, "git_commit")),
            generated_at: str_field(bundle, "generated_at").unwrap_or("unknown"),
            input_path: input
                .and_then(|i: &Json| str_field(i, "path"))
                .unwrap_or("unknown"),
            input_size_bytes: input
                .and_then(|i: &Json| i.get("size_bytes"))
                .and_then(Json::as_u64)
                .unwrap_or(0),
            input_hash: input
                .and_then(|i: &Json| str_field(i, "hash_blake3"))
                .unwrap_or("unknown"),
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
        self.language.as_deref().unwrap_or("unknown-language")
    }
}

fn classify_capability(module: &str) -> Vec<String> {
    let root: &str = module.split('.').next().unwrap_or(module);
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
    mapped.map(|m: &str| vec![m.to_owned()]).unwrap_or_default()
}

/// Render the agent-orientation `AGENTS.md` for a finalized LLM bundle.
///
/// Output is deterministic for a given bundle. Empty categories are skipped
/// rather than emitting placeholder sections.
#[must_use]
pub fn render_agents_md(bundle: &Json) -> String {
    let view: BundleView<'_> = BundleView::from_bundle(bundle);
    let mut md: String = String::with_capacity(4096);

    let _ = writeln!(md, "# AGENTS.md");
    let _ = writeln!(md);
    let _ = writeln!(
        md,
        "This directory contains recovered {} source reconstructed by `{}` v{}. \
         Use this brief to orient before you read, run, reconstruct, or refactor the code.",
        view.language_label(),
        view.tool_name,
        view.tool_version
    );
    let _ = writeln!(md);

    let _ = writeln!(md, "## Artifact");
    let _ = writeln!(md);
    let _ = writeln!(md, "| field | value |");
    let _ = writeln!(md, "|-------|-------|");
    let _ = writeln!(md, "| source | `{}` |", view.input_path);
    let _ = writeln!(md, "| size | {} bytes |", view.input_size_bytes);
    let _ = writeln!(md, "| blake3 | `{}` |", view.input_hash);
    if let Some(d) = view.dialect {
        let _ = writeln!(md, "| dialect | `{d}` |");
    }
    if let Some(bv) = view.bytecode_version {
        let _ = writeln!(md, "| bytecode | `{bv}` |");
    }
    if let Some(rt) = view.roundtrip_status {
        let _ = writeln!(md, "| roundtrip | `{rt}` |");
    }
    if let Some(gc) = view.git_commit {
        let _ = writeln!(md, "| tool commit | `{gc}` |");
    }
    let _ = writeln!(md, "| generated | `{}` |", view.generated_at);
    let _ = writeln!(md, "| schema | `disrobe.metadata.llm.v{SCHEMA_VERSION}` |");
    let _ = writeln!(md);

    if !view.pipeline.is_empty() {
        let _ = writeln!(md, "## Decompile provenance");
        let _ = writeln!(md);
        for step in &view.pipeline {
            let _ = writeln!(
                md,
                "- `{}` v{} ({} -> {})",
                step.pass, step.version, step.rung_in, step.rung_out
            );
        }
        let _ = writeln!(md);
    }

    if !view.entrypoints.is_empty() {
        let _ = writeln!(md, "## Key entrypoints");
        let _ = writeln!(md);
        for ep in &view.entrypoints {
            let _ = writeln!(md, "- `{ep}`");
        }
        let _ = writeln!(md);
    }

    if !view.capabilities.is_empty() {
        let _ = writeln!(md, "## Capabilities observed");
        let _ = writeln!(md);
        for cap in &view.capabilities {
            let _ = writeln!(md, "- {cap}");
        }
        let _ = writeln!(md);
    }

    if !view.imports.is_empty() {
        let _ = writeln!(md, "## External symbols & imports");
        let _ = writeln!(md);
        for imp in &view.imports {
            if imp.symbols.is_empty() {
                let _ = writeln!(md, "- `{}`", imp.module);
            } else {
                let _ = writeln!(md, "- `{}` -> {}", imp.module, imp.symbols.join(", "));
            }
        }
        let _ = writeln!(md);
    }

    if !view.signatures.is_empty() {
        let _ = writeln!(md, "## Type signatures");
        let _ = writeln!(md);
        for sig in &view.signatures {
            let ret: String = sig
                .return_type
                .map(|r: &str| format!(" -> {r}"))
                .unwrap_or_default();
            let _ = writeln!(md, "- `{}({}){}`", sig.function, sig.params.join(", "), ret);
        }
        let _ = writeln!(md);
    }

    if !view.cfg_functions.is_empty() {
        let _ = writeln!(md, "## Control-flow shape");
        let _ = writeln!(md);
        let _ = writeln!(md, "| function | blocks | edges | loops |");
        let _ = writeln!(md, "|----------|-------:|------:|------:|");
        for cfg in &view.cfg_functions {
            let _ = writeln!(
                md,
                "| `{}` | {} | {} | {} |",
                cfg.function, cfg.blocks, cfg.edges, cfg.loops
            );
        }
        let _ = writeln!(md);
    }

    if !view.notable_strings.is_empty() {
        let _ = writeln!(md, "## Notable strings");
        let _ = writeln!(md);
        for s in &view.notable_strings {
            let _ = writeln!(md, "- `{}`", s.replace('`', "'"));
        }
        let _ = writeln!(md);
    }

    if !view.confidence.is_empty() {
        let _ = writeln!(md, "## Detection confidence");
        let _ = writeln!(md);
        for c in &view.confidence {
            let _ = writeln!(md, "- `{}`: {:.2}", c.detection, c.score);
        }
        let _ = writeln!(md);
    }

    let has_risks: bool = !view.pii_categories.is_empty()
        || !view.opcode_unknown.is_empty()
        || matches!(view.roundtrip_status, Some("fail" | "partial"));
    if has_risks {
        let _ = writeln!(md, "## Notable risks");
        let _ = writeln!(md);
        if !view.pii_categories.is_empty() {
            let cats: Vec<&str> = view.pii_categories.iter().copied().collect();
            let _ = writeln!(
                md,
                "- PII detected & placeholdered: {}. Do not reintroduce literal values.",
                cats.join(", ")
            );
        }
        if !view.opcode_unknown.is_empty() {
            let _ = writeln!(
                md,
                "- {} unknown opcode(s) ({}). Affected regions may be under-recovered.",
                view.opcode_unknown.len(),
                view.opcode_unknown.join(", ")
            );
        }
        match view.roundtrip_status {
            Some("fail") => {
                let _ = writeln!(
                    md,
                    "- Roundtrip FAILED: recovered source did not recompile to the original bytes. \
                     Treat the source as approximate."
                );
            }
            Some("partial") => {
                let _ = writeln!(
                    md,
                    "- Roundtrip PARTIAL: only some stages verified. Cross-check against the disasm."
                );
            }
            _ => {}
        }
        let _ = writeln!(md);
    }

    let _ = writeln!(md, "## When reconstructing");
    let _ = writeln!(md);
    let _ = writeln!(
        md,
        "- Preserve the entrypoints & public signatures listed above; they are the observable contract."
    );
    let _ = writeln!(
        md,
        "- The control-flow shape table is ground truth recovered from bytecode; \
         match branch & loop structure, not just behaviour."
    );
    if !view.confidence.is_empty() {
        let _ = writeln!(
            md,
            "- Detection confidence is recorded in the bundle's `confidence` category; \
             prefer high-score detections when they conflict."
        );
    }
    let _ = writeln!(
        md,
        "- Full machine-readable detail lives in the sibling `*.disrobe.llm.json` bundle \
         (schema `disrobe.metadata.llm.v{SCHEMA_VERSION}`)."
    );

    md
}

/// Render the `SKILL.md` reconstruction brief for a finalized LLM bundle.
///
/// Frontmatter + a model-agnostic procedure + a per-symbol metadata table.
/// Deterministic; empty categories are skipped.
#[must_use]
pub fn render_skill_md(bundle: &Json) -> String {
    let view: BundleView<'_> = BundleView::from_bundle(bundle);
    let mut md: String = String::with_capacity(4096);

    let stem: &str = view
        .input_path
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(view.input_path);

    let _ = writeln!(md, "---");
    let _ = writeln!(md, "name: reconstruct-{}", slug(view.language_label()));
    let _ = writeln!(
        md,
        "description: Reconstruct & refactor the recovered {} artifact `{}` decompiled by {} v{}. \
         Use when reading, reasoning about, rebuilding, or refactoring this directory's source.",
        view.language_label(),
        stem,
        view.tool_name,
        view.tool_version
    );
    let _ = writeln!(md, "---");
    let _ = writeln!(md);

    let _ = writeln!(
        md,
        "# Working with recovered {} source",
        view.language_label()
    );
    let _ = writeln!(md);
    let _ = writeln!(
        md,
        "This skill briefs any coding agent (Claude, Cursor, Copilot, or a local model) \
         on the recovered artifact in this directory & how to safely reconstruct it. \
         All facts below are distilled from the `disrobe.metadata.llm.v{SCHEMA_VERSION}` bundle."
    );
    let _ = writeln!(md);

    let _ = writeln!(md, "## Source of truth");
    let _ = writeln!(md);
    let _ = writeln!(
        md,
        "- Original input: `{}` ({} bytes)",
        view.input_path, view.input_size_bytes
    );
    let _ = writeln!(md, "- blake3: `{}`", view.input_hash);
    if let Some(d) = view.dialect {
        let _ = writeln!(md, "- Dialect: `{d}`");
    }
    if let Some(rt) = view.roundtrip_status {
        let _ = writeln!(md, "- Roundtrip verdict: `{rt}`");
    }
    let _ = writeln!(md);

    let _ = writeln!(md, "## Reconstruction procedure");
    let _ = writeln!(md);
    let _ = writeln!(
        md,
        "1. Read the recovered source alongside this brief & the sibling JSON bundle."
    );
    let _ = writeln!(
        md,
        "2. Anchor on the entrypoints & signatures below; they form the public contract that must survive refactoring."
    );
    let _ = writeln!(
        md,
        "3. Reproduce the control-flow shape (blocks, edges, loops) per function; \
         the decompiler recovered it from bytecode, so it is authoritative."
    );
    let _ = writeln!(
        md,
        "4. Keep every observed import & capability wired; removing one changes the artifact's behaviour."
    );
    if !view.pii_categories.is_empty() {
        let _ = writeln!(
            md,
            "5. Leave PII placeholders intact ({}); never substitute synthetic literals.",
            view.pii_categories
                .iter()
                .copied()
                .collect::<Vec<&str>>()
                .join(", ")
        );
    }
    let _ = writeln!(md);

    let _ = writeln!(md, "## Invariants to preserve");
    let _ = writeln!(md);
    if view.entrypoints.is_empty() {
        let _ = writeln!(
            md,
            "- Public signatures (see table) are the observable contract."
        );
    } else {
        let _ = writeln!(
            md,
            "- Entrypoints: {}.",
            view.entrypoints
                .iter()
                .map(|e: &String| format!("`{e}`"))
                .collect::<Vec<String>>()
                .join(", ")
        );
    }
    let _ = writeln!(md, "- Import surface & capabilities must not change.");
    let _ = writeln!(
        md,
        "- Per-function control-flow shape must match the recovered CFG."
    );
    if let Some("fail" | "partial") = view.roundtrip_status {
        let _ = writeln!(
            md,
            "- Roundtrip is not byte-perfect; verify behaviour against the disasm before trusting the source."
        );
    }
    let _ = writeln!(md);

    if !view.symbols.is_empty() || !view.signatures.is_empty() {
        let _ = writeln!(md, "## Per-symbol metadata");
        let _ = writeln!(md);
        let _ = writeln!(md, "| symbol | kind | visibility | signature |");
        let _ = writeln!(md, "|--------|------|------------|-----------|");
        let mut emitted: BTreeSet<&str> = BTreeSet::new();
        for sym in &view.symbols {
            let sig: String = view
                .signatures
                .iter()
                .find(|s: &&SignatureRow<'_>| s.function == sym.name)
                .map(format_signature)
                .unwrap_or_default();
            let _ = writeln!(
                md,
                "| `{}` | {} | {} | {} |",
                sym.name, sym.kind, sym.visibility, sig
            );
            emitted.insert(sym.name);
        }
        for sig in &view.signatures {
            if !emitted.contains(sig.function) {
                let _ = writeln!(
                    md,
                    "| `{}` | function | unknown | {} |",
                    sig.function,
                    format_signature(sig)
                );
            }
        }
        let _ = writeln!(md);
    }

    if !view.imports.is_empty() {
        let _ = writeln!(md, "## Dependencies");
        let _ = writeln!(md);
        for imp in &view.imports {
            let _ = writeln!(md, "- `{}`", imp.module);
        }
        let _ = writeln!(md);
    }

    md
}

fn format_signature(sig: &SignatureRow<'_>) -> String {
    let ret: String = sig
        .return_type
        .map(|r: &str| format!(" -> {r}"))
        .unwrap_or_default();
    format!("`{}({}){}`", sig.function, sig.params.join(", "), ret)
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
        assert!(!agents.contains("TODO"));
        assert!(!skill.contains("## Per-symbol metadata"));
        assert!(!skill.contains("## Dependencies"));
        assert!(!skill.contains("TODO"));
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
