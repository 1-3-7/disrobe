use std::collections::BTreeMap;

use crate::ast_eval::{EvalReport, evaluate_source};
use crate::error::Result;
use crate::obfuscators::pyminifier_variants::{
    VariantKind, VariantReport, canonicalize_token_renames, classify, decompress, strip_prepend,
    tabs_to_spaces,
};
use crate::obfuscators::{DetectReport, Obfuscator, ObfuscatorPass, PeelOutcome, Quality};

#[derive(Debug, Clone, Copy)]
pub struct PyminifierPass;

const SIDECAR_PREFIX: &str = "# pyminifier-reverse-map: ";
const BANNER: &str = "# pyminifier output";

impl ObfuscatorPass for PyminifierPass {
    fn id(&self) -> Obfuscator {
        Obfuscator::Pyminifier
    }

    fn detect(&self, source: &[u8]) -> DetectReport {
        let head: &[u8] = &source[..source.len().min(64 * 1024)];
        let text: &str = std::str::from_utf8(head).unwrap_or("");
        let banner: bool = text.contains("pyminifier") || text.contains("__pyminifier__");
        let upstream_credit: bool = text.contains("Created by pyminifier")
            || text.contains("github.com/liftoff/pyminifier");
        let mut markers: Vec<String> = Vec::new();
        if banner {
            markers.push("pyminifier-banner".to_owned());
        }
        if upstream_credit {
            markers.push("pyminifier-upstream-credit".to_owned());
        }
        let matched: bool = banner || upstream_credit;
        let confidence: f32 = if upstream_credit {
            0.95
        } else if banner {
            0.85
        } else {
            0.0
        };
        DetectReport {
            obfuscator: self.id(),
            matched,
            confidence,
            markers,
        }
    }

    fn peel(&self, source: &[u8]) -> Result<PeelOutcome> {
        let text: String = String::from_utf8_lossy(source).into_owned();
        if text.contains("Created by pyminifier") || text.contains("github.com/liftoff/pyminifier")
        {
            return Ok(peel_upstream(self.id(), &text));
        }
        Ok(peel_baked_sidecar(self.id(), &text))
    }
}

fn peel_baked_sidecar(id: Obfuscator, text: &str) -> PeelOutcome {
    let mut stages: Vec<String> = Vec::new();
    let map: BTreeMap<String, String> = parse(text);
    stages.push("reverse-map-extract".to_owned());
    let stripped: String = strip(text);
    stages.push("metadata-strip".to_owned());
    let reformat: String = apply(&stripped, &map);
    stages.push("identifier-restore".to_owned());
    let mut diagnostics: BTreeMap<String, String> = BTreeMap::new();
    diagnostics.insert("mapped".to_owned(), map.len().to_string());
    let quality: Quality = if map.is_empty() {
        Quality::Partial
    } else {
        Quality::Full
    };
    PeelOutcome {
        obfuscator: id,
        stages_applied: stages,
        recovered_source: reformat,
        confidence: if map.is_empty() { 0.55 } else { 0.92 },
        quality,
        lossy_notes: vec![
            "pyminifier --gzip / --bzip2 wraps in eval; this pass handles plain mode".to_owned(),
        ],
        diagnostics,
    }
}

fn peel_upstream(id: Obfuscator, text: &str) -> PeelOutcome {
    let mut stages: Vec<String> = Vec::with_capacity(8);
    stages.push("upstream-credit-strip".to_owned());

    let report: VariantReport = classify(text);
    let stripped_credit: String = strip_upstream_credit(text);
    let stripped_prepend: String = strip_prepend(&stripped_credit, report.prepend_lines);
    if report.prepend_lines > 0 {
        stages.push("prepend-strip".to_owned());
    }

    let (post_compression, recursion_depth): (String, usize) =
        peel_compression(&stripped_prepend, &mut stages, report.kind);

    let normalized: String = if report.use_tabs {
        stages.push("use-tabs-normalize".to_owned());
        tabs_to_spaces(&post_compression)
    } else {
        post_compression
    };

    let alias_map: BTreeMap<String, String> = extract_aliases(&normalized);
    let dealiased: String = if alias_map.is_empty() {
        normalized
    } else {
        stages.push("alias-unrename".to_owned());
        apply_aliases(&normalized, &alias_map)
    };

    let (post_rename, rename_map): (String, BTreeMap<String, String>) =
        if matches!(report.kind, VariantKind::ObfuscateTokens) {
            stages.push("token-rename-canonicalize".to_owned());
            canonicalize_token_renames(&dealiased)
        } else {
            (dealiased, BTreeMap::new())
        };

    let effective_kind: VariantKind = if recursion_depth > 0 {
        classify(&post_rename).kind
    } else {
        report.kind
    };
    let (ast_folded, ast_report, ast_ok): (String, EvalReport, bool) =
        if should_skip_ast(effective_kind, &post_rename) {
            (post_rename, EvalReport::default(), false)
        } else {
            match evaluate_source(&post_rename) {
                Ok((s, r)) => {
                    stages.push("ast-eval".to_owned());
                    let ok: bool = r.exprs_folded > 0 || r.bindings_learned > 0;
                    (s, r, ok)
                }
                Err(_) => (post_rename, EvalReport::default(), false),
            }
        };

    let mut diagnostics: BTreeMap<String, String> = BTreeMap::new();
    diagnostics.insert("original_bytes".to_owned(), text.len().to_string());
    diagnostics.insert("variant".to_owned(), describe_variant(report.kind));
    diagnostics.insert("prepend_lines".to_owned(), report.prepend_lines.to_string());
    diagnostics.insert("use_tabs".to_owned(), report.use_tabs.to_string());
    diagnostics.insert("recursion_depth".to_owned(), recursion_depth.to_string());
    diagnostics.insert("aliases_recovered".to_owned(), alias_map.len().to_string());
    diagnostics.insert(
        "tokens_canonicalized".to_owned(),
        rename_map.len().to_string(),
    );
    diagnostics.insert(
        "ast_exprs_folded".to_owned(),
        ast_report.exprs_folded.to_string(),
    );
    diagnostics.insert(
        "ast_bindings_learned".to_owned(),
        ast_report.bindings_learned.to_string(),
    );
    diagnostics.insert(
        "ast_bindings_skipped_dynamic".to_owned(),
        ast_report.bindings_skipped_dynamic.to_string(),
    );

    let upgraded: bool = !alias_map.is_empty()
        || !rename_map.is_empty()
        || ast_ok
        || recursion_depth > 0
        || matches!(report.kind, VariantKind::NoMinify);

    let (quality, confidence, notes): (Quality, f32, Vec<String>) = if upgraded {
        (
            Quality::Full,
            0.88,
            vec![format!(
                "pyminifier {variant}: {compressed_layers} compression layers, {aliases} aliases, {tokens} tokens canonicalized, AST folded {exprs}/{binds}",
                variant = describe_variant(report.kind),
                compressed_layers = recursion_depth,
                aliases = alias_map.len(),
                tokens = rename_map.len(),
                exprs = ast_report.exprs_folded,
                binds = ast_report.bindings_learned,
            )],
        )
    } else {
        (
            Quality::Partial,
            0.7,
            vec!["pyminifier upstream: no transforms detected - credit-strip only".to_owned()],
        )
    };

    PeelOutcome {
        obfuscator: id,
        stages_applied: stages,
        recovered_source: ast_folded,
        confidence,
        quality,
        lossy_notes: notes,
        diagnostics,
    }
}

fn peel_compression(
    source: &str,
    stages: &mut Vec<String>,
    initial_kind: VariantKind,
) -> (String, usize) {
    let mut current: String = source.to_owned();
    let mut depth: usize = 0;
    let mut kind: VariantKind = initial_kind;
    while matches!(
        kind,
        VariantKind::GzipPack | VariantKind::LzmaPack | VariantKind::Bz2Pack
    ) {
        let Some(decoded): Option<String> = decompress(&current, kind) else {
            break;
        };
        stages.push(format!("decompress-{}", codec_name(kind)));
        current = strip_upstream_credit(&decoded);
        depth += 1;
        kind = classify(&current).kind;
        if depth > 4 {
            break;
        }
    }
    (current, depth)
}

const fn should_skip_ast(_kind: VariantKind, source: &str) -> bool {
    source.len() > 64 * 1024
}

const fn codec_name(kind: VariantKind) -> &'static str {
    match kind {
        VariantKind::GzipPack => "zlib",
        VariantKind::LzmaPack => "lzma",
        VariantKind::Bz2Pack => "bz2",
        _ => "none",
    }
}

fn describe_variant(kind: VariantKind) -> String {
    match kind {
        VariantKind::None => "none",
        VariantKind::GzipPack => "gzip-pack",
        VariantKind::LzmaPack => "lzma-pack",
        VariantKind::Bz2Pack => "bz2-pack",
        VariantKind::ObfuscateBuiltins => "obfuscate-builtins",
        VariantKind::ObfuscateTokens => "obfuscate-tokens",
        VariantKind::NoMinify => "nominify",
    }
    .to_owned()
}

fn extract_aliases(text: &str) -> BTreeMap<String, String> {
    let mut map: BTreeMap<String, String> = BTreeMap::new();
    for line in text.lines() {
        let trimmed: &str = line.trim_start();
        let Some((lhs, rhs)) = trimmed.split_once('=') else {
            continue;
        };
        let lhs_t: &str = lhs.trim();
        let rhs_t: &str = rhs.trim();
        if !is_short_identifier(lhs_t) || !is_builtin_name(rhs_t) {
            continue;
        }
        map.insert(lhs_t.to_owned(), rhs_t.to_owned());
    }
    map
}

fn is_short_identifier(s: &str) -> bool {
    if s.is_empty() || s.len() > 3 {
        return false;
    }
    let mut chars: core::str::Chars<'_> = s.chars();
    let Some(first): Option<char> = chars.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    chars.all(|c: char| c.is_ascii_alphanumeric() || c == '_')
}

fn is_builtin_name(s: &str) -> bool {
    matches!(
        s,
        "print"
            | "True"
            | "False"
            | "None"
            | "int"
            | "str"
            | "list"
            | "dict"
            | "tuple"
            | "set"
            | "len"
            | "range"
            | "open"
            | "input"
            | "type"
            | "object"
            | "bytes"
            | "bytearray"
            | "float"
            | "bool"
            | "abs"
            | "min"
            | "max"
            | "sum"
            | "map"
            | "filter"
            | "sorted"
            | "reversed"
            | "enumerate"
            | "zip"
            | "iter"
            | "next"
            | "isinstance"
            | "issubclass"
            | "hasattr"
            | "getattr"
            | "setattr"
            | "callable"
            | "id"
            | "hash"
            | "repr"
            | "ord"
            | "chr"
            | "hex"
            | "oct"
            | "bin"
            | "exit"
            | "quit"
            | "globals"
            | "locals"
            | "vars"
            | "Exception"
            | "ValueError"
            | "TypeError"
            | "KeyError"
            | "IndexError"
            | "OverflowError"
            | "RuntimeError"
            | "ImportError"
            | "OSError"
            | "IOError"
            | "AttributeError"
            | "NotImplementedError"
            | "StopIteration"
            | "frozenset"
            | "complex"
            | "memoryview"
            | "slice"
            | "property"
            | "classmethod"
            | "staticmethod"
            | "super"
    )
}

fn apply_aliases(text: &str, map: &BTreeMap<String, String>) -> String {
    let mut without_alias_defs: String = String::with_capacity(text.len());
    for line in text.lines() {
        let trimmed: &str = line.trim_start();
        let is_alias_line: bool = trimmed
            .split_once('=')
            .is_some_and(|(lhs, _rhs): (&str, &str)| map.contains_key(lhs.trim()));
        if is_alias_line {
            continue;
        }
        without_alias_defs.push_str(line);
        without_alias_defs.push('\n');
    }
    crate::obfuscators::pyminifier_variants::apply_mapping_skipping_strings(
        &without_alias_defs,
        map,
    )
}

fn strip_upstream_credit(text: &str) -> String {
    let mut out: String = String::with_capacity(text.len());
    for line in text.lines() {
        let trimmed: &str = line.trim_start();
        if trimmed.starts_with("# Created by pyminifier")
            || trimmed.contains("github.com/liftoff/pyminifier")
        {
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

fn parse(text: &str) -> BTreeMap<String, String> {
    let mut map: BTreeMap<String, String> = BTreeMap::new();
    for line in text.lines() {
        let Some(rest): Option<&str> = line.strip_prefix(SIDECAR_PREFIX) else {
            continue;
        };
        for pair in rest.split(';') {
            let trimmed: &str = pair.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Some((m, o)) = trimmed.split_once('=') {
                map.insert(m.trim().to_owned(), o.trim().to_owned());
            }
        }
    }
    map
}

fn strip(text: &str) -> String {
    let mut out: String = String::with_capacity(text.len());
    for line in text.lines() {
        if line.starts_with(SIDECAR_PREFIX)
            || line.starts_with(BANNER)
            || line.starts_with("__pyminifier__")
        {
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

fn apply(text: &str, map: &BTreeMap<String, String>) -> String {
    if map.is_empty() {
        return text.to_owned();
    }
    let mut keys: Vec<&String> = map.keys().collect();
    keys.sort_by_key(|k: &&String| core::cmp::Reverse(k.len()));
    let mut out: String = text.to_owned();
    for k in keys {
        let v: &String = match map.get(k) {
            Some(s) => s,
            None => continue,
        };
        out = replace_identifier(&out, k, v);
    }
    out
}

fn replace_identifier(text: &str, needle: &str, repl: &str) -> String {
    let bytes: &[u8] = text.as_bytes();
    let n: &[u8] = needle.as_bytes();
    if n.is_empty() {
        return text.to_owned();
    }
    let mut out: String = String::with_capacity(text.len());
    let mut i: usize = 0;
    while i < bytes.len() {
        if i + n.len() <= bytes.len()
            && &bytes[i..i + n.len()] == n
            && left_boundary(bytes, i)
            && right_boundary(bytes, i + n.len())
        {
            out.push_str(repl);
            i += n.len();
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    out
}

fn left_boundary(bytes: &[u8], pos: usize) -> bool {
    if pos == 0 {
        return true;
    }
    let c: u8 = bytes[pos - 1];
    !(c.is_ascii_alphanumeric() || c == b'_')
}

fn right_boundary(bytes: &[u8], pos: usize) -> bool {
    if pos == bytes.len() {
        return true;
    }
    let c: u8 = bytes[pos];
    !(c.is_ascii_alphanumeric() || c == b'_')
}

#[must_use]
pub fn bake(source: &str) -> String {
    let mut map: BTreeMap<String, String> = BTreeMap::new();
    let mut renamed: String = source.to_owned();
    for (idx, ident) in collect(source).into_iter().enumerate() {
        let short: String = format!("o{idx}");
        renamed = replace_identifier(&renamed, &ident, &short);
        map.insert(short, ident);
    }
    let sidecar: String = map
        .iter()
        .map(|(k, v): (&String, &String)| format!("{k}={v}"))
        .collect::<Vec<String>>()
        .join("; ");
    format!("{BANNER}\n__pyminifier__ = '2.1'\n{SIDECAR_PREFIX}{sidecar}\n{renamed}")
}

fn collect(source: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in source.lines() {
        let trimmed: &str = line.trim_start();
        for prefix in ["def ", "class ", "async def "] {
            if let Some(rest) = trimmed.strip_prefix(prefix) {
                let end: usize = rest
                    .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                    .unwrap_or(rest.len());
                let ident: &str = &rest[..end];
                if !ident.is_empty() && !out.iter().any(|s: &String| s == ident) {
                    out.push(ident.to_owned());
                }
            }
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn pyminifier_roundtrip() {
        let original: &str =
            "def long_function_name(parameter_value):\n    return parameter_value\n";
        let obf: String = bake(original);
        assert!(PyminifierPass.detect(obf.as_bytes()).matched);
        let out: PeelOutcome = PyminifierPass.peel(obf.as_bytes()).expect("peel");
        assert!(out.recovered_source.contains("def long_function_name"));
    }

    #[test]
    fn pyminifier_upstream_unaliases_print() {
        let src: &str = "q('hello world')\nq=print\nx=int\ny=str\n# Created by pyminifier (https://github.com/liftoff/pyminifier)\n";
        let det: DetectReport = PyminifierPass.detect(src.as_bytes());
        assert!(det.matched, "{det:?}");
        let out: PeelOutcome = PyminifierPass.peel(src.as_bytes()).expect("peel");
        assert_eq!(out.quality, Quality::Full);
        assert!(
            out.recovered_source.contains("print("),
            "got: {}",
            out.recovered_source
        );
        assert!(
            !out.recovered_source.contains("q=print"),
            "alias must be removed: {}",
            out.recovered_source
        );
    }

    #[test]
    fn extract_aliases_finds_short_assignments() {
        let src: &str = "q=print\nx=int\ndef foo(): pass\n";
        let map: BTreeMap<String, String> = extract_aliases(src);
        assert_eq!(map.len(), 2);
        assert_eq!(map.get("q"), Some(&"print".to_owned()));
        assert_eq!(map.get("x"), Some(&"int".to_owned()));
    }
}
