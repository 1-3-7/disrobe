//! Per-variant decoders for every Pyminifier 2.1 CLI mode.
//!
//! Variants supported (see `pyminifier --help`):
//! - `--obfuscate` / `--obfuscate-classes` / `--obfuscate-functions` /
//!   `--obfuscate-variables` / `--obfuscate-import-methods` - token rename
//! - `--obfuscate-builtins` - short-alias hoist (`q=print`)
//! - `--gzip` / `--lzma` / `--bzip2` - `import X, base64; exec(X.decompress(base64.b64decode(b'...')))`
//! - `--replacement-length=N` - controls alias length (1/2/3)
//! - `--prepend=<file>` - cosmetic prefix lines
//! - `--use-tabs` - tab indentation
//! - `--nominify` - whitespace preserved
//!
//! Detection is wire-format only (no full AST). Each detector returns a
//! `VariantKind` so `peel()` can dispatch the correct inverse.

use std::collections::BTreeMap;

use base64::Engine;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VariantKind {
    None,
    GzipPack,
    LzmaPack,
    Bz2Pack,
    ObfuscateBuiltins,
    ObfuscateTokens,
    NoMinify,
}

#[derive(Debug, Clone)]
pub struct VariantReport {
    pub kind: VariantKind,
    pub prepend_lines: usize,
    pub use_tabs: bool,
    pub trailer_credit: bool,
}

#[must_use]
pub fn classify(source: &str) -> VariantReport {
    let trailer_credit: bool = source.contains("github.com/liftoff/pyminifier");
    let (prepend_lines, body_start): (usize, usize) = detect_prepend(source);
    let body: &str = &source[body_start..];
    let use_tabs: bool = detect_use_tabs(body);
    let kind: VariantKind = classify_kind(body);
    VariantReport {
        kind,
        prepend_lines,
        use_tabs,
        trailer_credit,
    }
}

fn classify_kind(body: &str) -> VariantKind {
    if find_compressed(body, "zlib").is_some() {
        return VariantKind::GzipPack;
    }
    if find_compressed(body, "lzma").is_some() {
        return VariantKind::LzmaPack;
    }
    if find_compressed(body, "bz2").is_some() {
        return VariantKind::Bz2Pack;
    }
    let aliases: bool = has_builtin_aliases(body);
    let tokens: bool = has_obfuscated_tokens(body);
    if aliases && tokens {
        return VariantKind::ObfuscateTokens;
    }
    if aliases {
        return VariantKind::ObfuscateBuiltins;
    }
    if tokens {
        return VariantKind::ObfuscateTokens;
    }
    if has_pyminifier_marker(body) {
        return VariantKind::NoMinify;
    }
    VariantKind::None
}

fn has_pyminifier_marker(text: &str) -> bool {
    text.contains("# Created by pyminifier") || text.contains("github.com/liftoff/pyminifier")
}

fn detect_prepend(source: &str) -> (usize, usize) {
    let mut line_count: usize = 0;
    let mut byte_offset: usize = 0;
    for line in source.lines() {
        let trimmed: &str = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            line_count += 1;
            byte_offset += line.len() + 1;
            continue;
        }
        break;
    }
    (line_count, byte_offset.min(source.len()))
}

fn detect_use_tabs(body: &str) -> bool {
    let mut tab_indents: usize = 0;
    let mut space_indents: usize = 0;
    for line in body.lines().take(500) {
        let Some(first): Option<char> = line.chars().next() else {
            continue;
        };
        if first == '\t' {
            tab_indents += 1;
        } else if first == ' ' {
            space_indents += 1;
        }
    }
    tab_indents > space_indents
}

fn has_builtin_aliases(body: &str) -> bool {
    let mut count: usize = 0;
    for line in body.lines().take(120) {
        let trimmed: &str = line.trim_start();
        let Some((lhs, rhs)) = trimmed.split_once('=') else {
            continue;
        };
        if is_short_ident(lhs.trim()) && is_pyminifier_builtin(rhs.trim()) {
            count += 1;
            if count >= 3 {
                return true;
            }
        }
    }
    false
}

fn has_obfuscated_tokens(body: &str) -> bool {
    let mut hit: usize = 0;
    for line in body.lines().take(400) {
        let trimmed: &str = line.trim_start();
        for prefix in ["def ", "class ", "async def "] {
            if let Some(rest) = trimmed.strip_prefix(prefix) {
                let end: usize = rest
                    .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                    .unwrap_or(rest.len());
                let ident: &str = &rest[..end];
                if is_short_ident(ident) {
                    hit += 1;
                    if hit >= 2 {
                        return true;
                    }
                }
            }
        }
    }
    false
}

fn is_short_ident(s: &str) -> bool {
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

fn is_pyminifier_builtin(s: &str) -> bool {
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

fn find_compressed<'a>(body: &'a str, codec: &str) -> Option<&'a str> {
    let needle_decompress: String = format!("{codec}.decompress(base64.b64decode(");
    let import_marker: String = format!("import {codec}");
    if !body.contains(&import_marker) {
        return None;
    }
    let start: usize = body.find(&needle_decompress)?;
    let after_open: usize = start + needle_decompress.len();
    let rest: &[u8] = body.as_bytes().get(after_open..)?;
    let quote: u8 = match rest.first()? {
        b'\'' | b'"' => *rest.first()?,
        b'b' => {
            let q: u8 = *rest.get(1)?;
            if q != b'\'' && q != b'"' {
                return None;
            }
            q
        }
        _ => return None,
    };
    let prefix_len: usize = if rest.first() == Some(&b'b') { 2 } else { 1 };
    let blob_start: usize = after_open + prefix_len;
    let blob_bytes: &[u8] = body.as_bytes().get(blob_start..)?;
    let end_rel: usize = blob_bytes.iter().position(|b: &u8| *b == quote)?;
    let blob_end: usize = blob_start + end_rel;
    body.get(blob_start..blob_end)
}

#[must_use]
pub fn decompress(body: &str, kind: VariantKind) -> Option<String> {
    let codec: &str = match kind {
        VariantKind::GzipPack => "zlib",
        VariantKind::LzmaPack => "lzma",
        VariantKind::Bz2Pack => "bz2",
        _ => return None,
    };
    let b64_blob: &str = find_compressed(body, codec)?;
    let engine: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;
    let compressed: Vec<u8> = engine.decode(b64_blob.trim()).ok()?;
    let bytes: Vec<u8> = match kind {
        VariantKind::GzipPack => decompress_zlib(&compressed)?,
        VariantKind::LzmaPack => decompress_lzma(&compressed)?,
        VariantKind::Bz2Pack => decompress_bz2(&compressed)?,
        _ => return None,
    };
    String::from_utf8(bytes).ok()
}

fn decompress_zlib(input: &[u8]) -> Option<Vec<u8>> {
    let decoder: flate2::read::ZlibDecoder<&[u8]> = flate2::read::ZlibDecoder::new(input);
    crate::codec::bounded_read_to_end(decoder).ok()?
}

fn decompress_lzma(input: &[u8]) -> Option<Vec<u8>> {
    let decoder: liblzma::read::XzDecoder<&[u8]> = liblzma::read::XzDecoder::new(input);
    crate::codec::bounded_read_to_end(decoder).ok()?
}

fn decompress_bz2(input: &[u8]) -> Option<Vec<u8>> {
    let decoder: bzip2_rs::DecoderReader<&[u8]> = bzip2_rs::DecoderReader::new(input);
    crate::codec::bounded_read_to_end(decoder).ok()?
}

#[must_use]
pub fn strip_prepend(source: &str, lines: usize) -> String {
    if lines == 0 {
        return source.to_owned();
    }
    let mut out: String = String::with_capacity(source.len());
    let mut skipped: usize = 0;
    for line in source.split_inclusive('\n') {
        if skipped < lines {
            skipped += 1;
            continue;
        }
        out.push_str(line);
    }
    out
}

#[must_use]
pub fn tabs_to_spaces(source: &str) -> String {
    if !source.contains('\t') {
        return source.to_owned();
    }
    let mut out: String = String::with_capacity(source.len() + 64);
    for line in source.split_inclusive('\n') {
        let mut converted: bool = false;
        for ch in line.chars() {
            if !converted && ch == '\t' {
                out.push_str("    ");
            } else {
                if ch != '\t' {
                    converted = true;
                }
                out.push(ch);
            }
        }
    }
    out
}

#[must_use]
pub fn canonicalize_token_renames(source: &str) -> (String, BTreeMap<String, String>) {
    let mut def_idx: usize = 0;
    let mut class_idx: usize = 0;
    let mut var_idx: usize = 0;
    let mut mapping: BTreeMap<String, String> = BTreeMap::new();
    for line in source.lines() {
        let trimmed: &str = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix("def ") {
            if let Some(ident) = take_ident(rest)
                && is_short_ident(ident)
                && !mapping.contains_key(ident)
            {
                let canonical: String = format!("func_{def_idx}");
                mapping.insert(ident.to_owned(), canonical);
                def_idx += 1;
            }
        } else if let Some(rest) = trimmed.strip_prefix("async def ") {
            if let Some(ident) = take_ident(rest)
                && is_short_ident(ident)
                && !mapping.contains_key(ident)
            {
                let canonical: String = format!("func_{def_idx}");
                mapping.insert(ident.to_owned(), canonical);
                def_idx += 1;
            }
        } else if let Some(rest) = trimmed.strip_prefix("class ") {
            if let Some(ident) = take_ident(rest)
                && is_short_ident(ident)
                && !mapping.contains_key(ident)
            {
                let canonical: String = format!("Cls_{class_idx}");
                mapping.insert(ident.to_owned(), canonical);
                class_idx += 1;
            }
        } else if let Some((lhs, _rhs)) = trimmed.split_once('=') {
            let bare: &str = lhs.split(':').next().unwrap_or(lhs).trim();
            if is_short_ident(bare) && !is_pyminifier_builtin(bare) && !mapping.contains_key(bare) {
                let canonical: String = format!("var_{var_idx}");
                mapping.insert(bare.to_owned(), canonical);
                var_idx += 1;
            }
        }
    }
    let rewritten: String = apply_mapping(source, &mapping);
    (rewritten, mapping)
}

fn take_ident(rest: &str) -> Option<&str> {
    let end: usize = rest
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .unwrap_or(rest.len());
    if end == 0 { None } else { Some(&rest[..end]) }
}

#[must_use]
pub fn apply_mapping_skipping_strings(text: &str, map: &BTreeMap<String, String>) -> String {
    apply_mapping(text, map)
}

fn apply_mapping(text: &str, map: &BTreeMap<String, String>) -> String {
    if map.is_empty() {
        return text.to_owned();
    }
    let mut keys: Vec<&String> = map.keys().collect();
    keys.sort_by_key(|k: &&String| core::cmp::Reverse(k.len()));
    let bytes: &[u8] = text.as_bytes();
    let mut out: String = String::with_capacity(text.len());
    let mut i: usize = 0;
    while i < bytes.len() {
        let b: u8 = bytes[i];
        if b == b'#' {
            while i < bytes.len() && bytes[i] != b'\n' {
                out.push(bytes[i] as char);
                i += 1;
            }
            continue;
        }
        if b == b'"' || b == b'\'' {
            let end: usize = skip_string_literal(bytes, i);
            let slice_end: usize = end.min(bytes.len());
            for chunk in &bytes[i..slice_end] {
                out.push(*chunk as char);
            }
            i = end;
            continue;
        }
        let mut matched: bool = false;
        for k in &keys {
            let n: &[u8] = k.as_bytes();
            if i + n.len() <= bytes.len()
                && &bytes[i..i + n.len()] == n
                && left_boundary(bytes, i)
                && right_boundary(bytes, i + n.len())
            {
                let Some(repl): Option<&String> = map.get(*k) else {
                    continue;
                };
                out.push_str(repl);
                i += n.len();
                matched = true;
                break;
            }
        }
        if !matched {
            out.push(b as char);
            i += 1;
        }
    }
    out
}

fn skip_string_literal(bytes: &[u8], start: usize) -> usize {
    let quote: u8 = bytes[start];
    let triple: bool =
        start + 2 < bytes.len() && bytes[start + 1] == quote && bytes[start + 2] == quote;
    let end_position: Option<usize> = if triple {
        let mut i: usize = start + 3;
        let mut found: Option<usize> = None;
        while i + 2 < bytes.len() {
            if bytes[i] == b'\\' {
                i += 2;
                continue;
            }
            if bytes[i] == quote && bytes[i + 1] == quote && bytes[i + 2] == quote {
                found = Some(i + 3);
                break;
            }
            i += 1;
        }
        found
    } else {
        let mut i: usize = start + 1;
        let mut found: Option<usize> = None;
        while i < bytes.len() {
            if bytes[i] == b'\\' && i + 1 < bytes.len() {
                i += 2;
                continue;
            }
            if bytes[i] == quote {
                found = Some(i + 1);
                break;
            }
            if bytes[i] == b'\n' {
                found = Some(i);
                break;
            }
            i += 1;
        }
        found
    };
    end_position.unwrap_or(bytes.len())
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

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn detect_gzip_variant() {
        let src: &str = "import zlib, base64\nexec(zlib.decompress(base64.b64decode('eJw=')))\n# Created by pyminifier (https://github.com/liftoff/pyminifier)\n";
        let r: VariantReport = classify(src);
        assert_eq!(r.kind, VariantKind::GzipPack);
        assert!(r.trailer_credit);
    }

    #[test]
    fn detect_bz2_variant() {
        let src: &str = "import bz2, base64\nexec(bz2.decompress(base64.b64decode('QlpoOQ==')))\n# Created by pyminifier (https://github.com/liftoff/pyminifier)\n";
        let r: VariantReport = classify(src);
        assert_eq!(r.kind, VariantKind::Bz2Pack);
    }

    #[test]
    fn detect_lzma_variant() {
        let src: &str = "import lzma, base64\nexec(lzma.decompress(base64.b64decode('/Td6')))\n";
        let r: VariantReport = classify(src);
        assert_eq!(r.kind, VariantKind::LzmaPack);
    }

    #[test]
    fn detect_obfuscate_builtins() {
        let src: &str = "q=print\nx=int\ny=str\ndef foo(): q('ok')\n";
        let r: VariantReport = classify(src);
        assert_eq!(r.kind, VariantKind::ObfuscateBuiltins);
    }

    #[test]
    fn detect_obfuscate_tokens() {
        let src: &str = "def f(a): return a\ndef g(b): return b\nclass C: pass\n";
        let r: VariantReport = classify(src);
        assert_eq!(r.kind, VariantKind::ObfuscateTokens);
    }

    #[test]
    fn detect_prepend_lines() {
        let src: &str = "# Copyright header\n# Another comment\nimport zlib, base64\nexec(zlib.decompress(base64.b64decode('eJw=')))\n";
        let (lines, _): (usize, usize) = detect_prepend(src);
        assert_eq!(lines, 2);
    }

    #[test]
    fn canonicalize_renames_defs_and_classes() {
        let src: &str = "def k(a): return a\nclass C: pass\nz = 1\n";
        let (out, map): (String, BTreeMap<String, String>) = canonicalize_token_renames(src);
        assert!(map.contains_key("k"));
        assert!(map.contains_key("C"));
        assert!(map.contains_key("z"));
        assert!(out.contains("func_0"));
        assert!(out.contains("Cls_0"));
        assert!(out.contains("var_0"));
    }

    #[test]
    fn roundtrip_gzip_decompression() {
        use flate2::Compression;
        use flate2::write::ZlibEncoder;
        use std::io::Write;
        let body: &str = "print('hello world')\n";
        let mut enc: ZlibEncoder<Vec<u8>> = ZlibEncoder::new(Vec::new(), Compression::default());
        enc.write_all(body.as_bytes()).expect("encode");
        let compressed: Vec<u8> = enc.finish().expect("finish");
        let engine: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;
        let b64: String = engine.encode(&compressed);
        let wire: String = format!(
            "import zlib, base64\nexec(zlib.decompress(base64.b64decode('{b64}')))\n# Created by pyminifier (https://github.com/liftoff/pyminifier)\n"
        );
        let restored: String = decompress(&wire, VariantKind::GzipPack).expect("decompress");
        assert_eq!(restored, body);
    }

    #[test]
    fn tabs_converted_to_spaces() {
        let src: &str = "def f():\n\treturn 1\n";
        let out: String = tabs_to_spaces(src);
        assert!(out.contains("    return"));
        assert!(!out.contains('\t'));
    }
}
