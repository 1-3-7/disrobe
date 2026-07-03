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

#[must_use]
pub fn detect_source_or_binary(bytes: &[u8], filename_hint: Option<&str>) -> DetectionReport {
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

    if bytes.starts_with(b"perlbc\0") {
        detected.insert(DetectedLanguage::PerlBytecode);
        evidence_static.push("Perl B::Bytecode magic");
    }

    if bytes.starts_with(b"#!/usr/bin/env tclkit") || memmem(head_2k, b"tclkit") {
        detected.insert(DetectedLanguage::Tclkit);
        evidence_static.push("tclkit envelope reference");
    }

    if memmem(head_2k, b"NIM_VERSION") || memmem(head_2k, b"NimMain") {
        detected.insert(DetectedLanguage::Nim);
        evidence_static.push("Nim runtime symbols");
    }

    if memmem(head_2k, b"crystal_main") || memmem(head_2k, b"__crystal_") {
        detected.insert(DetectedLanguage::Crystal);
        evidence_static.push("Crystal runtime symbols");
    }

    if memmem(head_2k, b"__zig_probe_stack") || memmem(head_2k, b"std.builtin") {
        detected.insert(DetectedLanguage::Zig);
        evidence_static.push("Zig builtin symbols");
    }

    let evidence: Vec<String> = evidence_static.into_iter().map(str::to_owned).collect();
    DetectionReport { detected, evidence }
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

    #[test]
    fn detects_perl_bytecode_magic() {
        let r: DetectionReport = detect_source_or_binary(b"perlbc\0\x01\x02", None);
        assert!(r.detected.contains(&DetectedLanguage::PerlBytecode));
    }
}
