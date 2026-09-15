use std::collections::BTreeSet;
use std::path::Path;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
pub enum DetectedLanguage {
    Haxe,
    Perl,
    PerlBytecode,
    Tcl,
    Tclkit,
    R,
    RcppBlob,
    Crystal,
    Nim,
    Zig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectionReport {
    pub detected: BTreeSet<DetectedLanguage>,
    pub evidence: Vec<String>,
}

const MAX_RUNTIME_SYMBOL_SCAN_BYTES: usize = 64 << 20;
const MAX_SHEBANG_LINE_BYTES: usize = 256;
const MAX_BYTELOADER_LINE_BYTES: usize = 64;
const MAX_ARCHNAME_BYTES: usize = 64;
const BYTELOADER_USE: &[u8] = b"use ByteLoader";
const PLBC_LITTLE_ENDIAN: [u8; 4] = [0x50, 0x4c, 0x42, 0x43];
const PLBC_BIG_ENDIAN: [u8; 4] = [0x43, 0x42, 0x4c, 0x50];

#[must_use]
pub fn detect_source_or_binary(bytes: &[u8], filename_hint: Option<&str>) -> DetectionReport {
    detect_with_symbol_scan_limit(bytes, filename_hint, MAX_RUNTIME_SYMBOL_SCAN_BYTES)
}

fn detect_with_symbol_scan_limit(
    bytes: &[u8],
    filename_hint: Option<&str>,
    symbol_scan_limit: usize,
) -> DetectionReport {
    let mut detected: BTreeSet<DetectedLanguage> = BTreeSet::new();
    let mut evidence_static: Vec<&'static str> = Vec::new();

    if let Some(name) = filename_hint {
        let ext_lower: Option<String> = Path::new(name)
            .extension()
            .and_then(|e: &std::ffi::OsStr| e.to_str())
            .map(|e: &str| e.to_ascii_lowercase());
        if let Some(ext) = ext_lower {
            match ext.as_str() {
                "hx" => {
                    detected.insert(DetectedLanguage::Haxe);
                    evidence_static.push("filename suffix .hx");
                }
                "pl" | "pm" => {
                    detected.insert(DetectedLanguage::Perl);
                    evidence_static.push("filename suffix .pl/.pm");
                }
                "tcl" => {
                    detected.insert(DetectedLanguage::Tcl);
                    evidence_static.push("filename suffix .tcl");
                }
                "r" | "rdata" | "rds" => {
                    detected.insert(DetectedLanguage::R);
                    evidence_static.push("filename suffix .r/.rdata/.rds");
                }
                "cr" => {
                    detected.insert(DetectedLanguage::Crystal);
                    evidence_static.push("filename suffix .cr");
                }
                "nim" | "nims" => {
                    detected.insert(DetectedLanguage::Nim);
                    evidence_static.push("filename suffix .nim/.nims");
                }
                "zig" => {
                    detected.insert(DetectedLanguage::Zig);
                    evidence_static.push("filename suffix .zig");
                }
                _ => {}
            }
        }
    }

    if bytes.starts_with(b"#!") {
        let head: &[u8] = if bytes.len() > 256 {
            &bytes[..256]
        } else {
            bytes
        };
        if memmem(head, b"perl") {
            detected.insert(DetectedLanguage::Perl);
            evidence_static.push("shebang references perl");
        }
        if memmem(head, b"tclsh") || memmem(head, b"wish") {
            detected.insert(DetectedLanguage::Tcl);
            evidence_static.push("shebang references tclsh/wish");
        }
        if memmem(head, b"Rscript") {
            detected.insert(DetectedLanguage::R);
            evidence_static.push("shebang references Rscript");
        }
    }

    if bytes.starts_with(b"package ") && bytes.contains(&b';') {
        let head: &[u8] = if bytes.len() > 4096 {
            &bytes[..4096]
        } else {
            bytes
        };
        if memmem(head, b"haxe.") {
            detected.insert(DetectedLanguage::Haxe);
            evidence_static.push("haxe namespace reference");
        }
    }

    let head_2k: &[u8] = if bytes.len() > 2048 {
        &bytes[..2048]
    } else {
        bytes
    };
    if memmem(head_2k, b"class ") && memmem(head_2k, b"haxe.") {
        detected.insert(DetectedLanguage::Haxe);
        evidence_static.push("haxe class reference");
    }

    if memmem(head_2k, b"library(Rcpp)") || memmem(head_2k, b"sourceCpp(") {
        detected.insert(DetectedLanguage::R);
        detected.insert(DetectedLanguage::RcppBlob);
        evidence_static.push("Rcpp invocation");
    }

    let symbol_window: &[u8] = bytes.get(..symbol_scan_limit).unwrap_or(bytes);

    if is_byteloader_stream(bytes) {
        detected.insert(DetectedLanguage::PerlBytecode);
        evidence_static.push("Perl B::Bytecode magic");
    }

    if bytes.starts_with(b"#!/usr/bin/env tclkit") || memmem(head_2k, b"tclkit") {
        detected.insert(DetectedLanguage::Tclkit);
        evidence_static.push("tclkit envelope reference");
    }

    if memmem(symbol_window, b"NIM_VERSION") || memmem(symbol_window, b"NimMain") {
        detected.insert(DetectedLanguage::Nim);
        evidence_static.push("Nim runtime symbols");
    }

    if memmem(symbol_window, b"crystal_main") || memmem(symbol_window, b"__crystal_") {
        detected.insert(DetectedLanguage::Crystal);
        evidence_static.push("Crystal runtime symbols");
    }

    if memmem(symbol_window, b"__zig_probe_stack") || memmem(symbol_window, b"std.builtin") {
        detected.insert(DetectedLanguage::Zig);
        evidence_static.push("Zig builtin symbols");
    }

    let evidence: Vec<String> = evidence_static.into_iter().map(str::to_owned).collect();
    DetectionReport { detected, evidence }
}

fn skip_line<'a>(bytes: &'a [u8], prefix: &[u8], max_line_bytes: usize) -> &'a [u8] {
    if !bytes.starts_with(prefix) {
        return bytes;
    }
    let window: &[u8] = bytes.get(..max_line_bytes).unwrap_or(bytes);
    window
        .iter()
        .position(|byte: &u8| *byte == b'\n')
        .and_then(|newline: usize| bytes.get(newline + 1..))
        .unwrap_or(bytes)
}

fn is_byteloader_stream(bytes: &[u8]) -> bool {
    let after_shebang: &[u8] = skip_line(bytes, b"#!", MAX_SHEBANG_LINE_BYTES);
    let stream: &[u8] = skip_line(after_shebang, BYTELOADER_USE, MAX_BYTELOADER_LINE_BYTES);
    let Some((magic, header)): Option<(&[u8], &[u8])> = stream
        .split_first_chunk::<4>()
        .map(|(magic, header): (&[u8; 4], &[u8])| (magic.as_slice(), header))
    else {
        return false;
    };
    if magic != PLBC_LITTLE_ENDIAN && magic != PLBC_BIG_ENDIAN {
        return false;
    }
    let archname_window: &[u8] = header.get(..=MAX_ARCHNAME_BYTES).unwrap_or(header);
    archname_window
        .iter()
        .position(|byte: &u8| *byte == 0)
        .is_some_and(|length: usize| {
            length > 0
                && archname_window[..length]
                    .iter()
                    .all(|byte: &u8| byte.is_ascii_graphic())
        })
}

fn memmem(haystack: &[u8], needle: &[u8]) -> bool {
    disrobe_core::byte_search::contains(haystack, needle)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn detects_haxe_by_extension() {
        let r: DetectionReport =
            detect_source_or_binary(b"package main;\nclass Foo {}", Some("Foo.hx"));
        assert!(r.detected.contains(&DetectedLanguage::Haxe));
    }

    #[test]
    fn detects_perl_by_shebang() {
        let r: DetectionReport = detect_source_or_binary(b"#!/usr/bin/perl\nprint 'hi'\n", None);
        assert!(r.detected.contains(&DetectedLanguage::Perl));
    }

    #[test]
    fn detects_nothing_in_plain_bytes() {
        let r: DetectionReport = detect_source_or_binary(b"hello world", None);
        assert!(r.detected.is_empty());
    }

    fn byteloader(prefix: &[u8], magic: [u8; 4], archname: &[u8]) -> Vec<u8> {
        let mut bytes: Vec<u8> = prefix.to_vec();
        bytes.extend_from_slice(&magic);
        bytes.extend_from_slice(archname);
        bytes.extend_from_slice(b"0.06\0\x04\0\0\0");
        bytes
    }

    fn is_perl_bytecode(bytes: &[u8]) -> bool {
        detect_source_or_binary(bytes, None)
            .detected
            .contains(&DetectedLanguage::PerlBytecode)
    }

    #[test]
    fn detects_byteloader_streams_with_and_without_the_loader_header() {
        let archname: &[u8] = b"MSWin32-x86-multi-thread\0";
        assert!(is_perl_bytecode(&byteloader(
            b"",
            PLBC_LITTLE_ENDIAN,
            archname
        )));
        assert!(is_perl_bytecode(&byteloader(
            b"",
            PLBC_BIG_ENDIAN,
            archname
        )));
        assert!(is_perl_bytecode(&byteloader(
            b"#!/usr/bin/perl\nuse ByteLoader 0.06;\n",
            PLBC_LITTLE_ENDIAN,
            archname,
        )));
        assert!(is_perl_bytecode(&byteloader(
            b"use ByteLoader 0.06;\n",
            PLBC_LITTLE_ENDIAN,
            archname,
        )));
    }

    #[test]
    fn rejects_byte_strings_that_are_not_byteloader_streams() {
        assert!(!is_perl_bytecode(b"perlbc\0\x01\x02"));
        assert!(!is_perl_bytecode(b"#!/usr/bin/perl\nprint \"PLBC\";\n"));
        assert!(!is_perl_bytecode(&byteloader(
            b"",
            PLBC_LITTLE_ENDIAN,
            b"\0"
        )));
        assert!(!is_perl_bytecode(&byteloader(
            b"",
            PLBC_LITTLE_ENDIAN,
            &[b'x'; 80]
        )));
        assert!(!is_perl_bytecode(&byteloader(
            b"#!/usr/bin/perl\nuse strict;\n",
            PLBC_LITTLE_ENDIAN,
            b"x86_64-linux\0",
        )));
        let mut long_shebang: Vec<u8> = b"#!".to_vec();
        long_shebang.extend(std::iter::repeat_n(b'p', MAX_SHEBANG_LINE_BYTES));
        long_shebang.push(b'\n');
        assert!(!is_perl_bytecode(&byteloader(
            &long_shebang,
            PLBC_LITTLE_ENDIAN,
            b"x86_64-linux\0",
        )));
    }

    #[test]
    fn runtime_symbols_are_found_anywhere_inside_the_scan_limit() {
        let mut image: Vec<u8> = vec![0u8; 8192];
        image.extend_from_slice(b"NimMain");
        assert!(
            detect_source_or_binary(&image, None)
                .detected
                .contains(&DetectedLanguage::Nim)
        );
        let limit: usize = image.len();
        assert!(
            detect_with_symbol_scan_limit(&image, None, limit)
                .detected
                .contains(&DetectedLanguage::Nim)
        );
        assert!(
            !detect_with_symbol_scan_limit(&image, None, limit - 1)
                .detected
                .contains(&DetectedLanguage::Nim)
        );
    }
}
