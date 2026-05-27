use serde::{Deserialize, Serialize};

use crate::error::{Result, RubyError};

pub(crate) const YARV_MAGIC: &[u8; 4] = b"YARB";
pub(crate) const RITE_MAGIC: &[u8; 4] = b"RITE";
pub(crate) const JVM_CLASS_MAGIC: &[u8; 4] = b"\xCA\xFE\xBA\xBE";
pub(crate) const TRUFFLE_AOT_MARKER: &[u8] = b"TruffleRuby-NativeImage";
pub(crate) const RUBY2EXE_MARKER: &[u8] = b"Ruby2Exe";
pub(crate) const OCRA_MARKER: &[u8] = b"OcraStub";
pub(crate) const PE_MAGIC: &[u8; 2] = b"MZ";
pub(crate) const ELF_MAGIC: &[u8; 4] = b"\x7FELF";
pub(crate) const MACHO_MAGIC_BE: &[u8; 4] = b"\xFE\xED\xFA\xCE";
pub(crate) const MACHO_MAGIC_LE: &[u8; 4] = b"\xCE\xFA\xED\xFE";
pub(crate) const MACHO_MAGIC_LE_64: &[u8; 4] = b"\xCF\xFA\xED\xFE";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Flavor {
    MriSource,
    YarvBinary,
    MrubyBinary,
    JrubyClass,
    TruffleRubyAot,
    Ruby2Exe,
    Ocra,
}

#[inline]
pub(crate) fn sniff(bytes: &[u8], source_path: &str) -> Result<Flavor> {
    if bytes.is_empty() {
        return Err(RubyError::EmptyInput);
    }
    if bytes.len() >= 4 {
        let head: &[u8] = &bytes[..4];
        if head == YARV_MAGIC {
            return Ok(Flavor::YarvBinary);
        }
        if head == RITE_MAGIC {
            return Ok(Flavor::MrubyBinary);
        }
        if head == JVM_CLASS_MAGIC {
            return Ok(Flavor::JrubyClass);
        }
        if head == MACHO_MAGIC_BE
            || head == MACHO_MAGIC_LE
            || head == MACHO_MAGIC_LE_64
            || head == ELF_MAGIC
        {
            if contains_window(bytes, TRUFFLE_AOT_MARKER) {
                return Ok(Flavor::TruffleRubyAot);
            }
            if contains_window(bytes, RUBY2EXE_MARKER) {
                return Ok(Flavor::Ruby2Exe);
            }
            if contains_window(bytes, OCRA_MARKER) {
                return Ok(Flavor::Ocra);
            }
        }
    }
    if bytes.len() >= 2 && &bytes[..2] == PE_MAGIC {
        if contains_window(bytes, RUBY2EXE_MARKER) {
            return Ok(Flavor::Ruby2Exe);
        }
        if contains_window(bytes, OCRA_MARKER) {
            return Ok(Flavor::Ocra);
        }
        if contains_window(bytes, TRUFFLE_AOT_MARKER) {
            return Ok(Flavor::TruffleRubyAot);
        }
    }
    if looks_like_ruby_source(bytes, source_path) {
        return Ok(Flavor::MriSource);
    }
    let take: usize = bytes.len().min(8);
    let mut hex_head: String = String::with_capacity(take * 2);
    for b in &bytes[..take] {
        let _: core::result::Result<(), core::fmt::Error> =
            core::fmt::Write::write_fmt(&mut hex_head, format_args!("{b:02x}"));
    }
    Err(RubyError::UnknownFlavor { hex_head })
}

#[inline]
fn looks_like_ruby_source(bytes: &[u8], source_path: &str) -> bool {
    let lower: String = source_path.to_ascii_lowercase();
    let by_ext: bool = ends_with_any(&lower, &[".rb", ".gemspec", ".rake", "rakefile", "gemfile"]);
    let by_shebang: bool =
        bytes.starts_with(b"#!") && contains_window(&bytes[..bytes.len().min(128)], b"ruby");
    let by_marker: bool = {
        let probe: &[u8] = &bytes[..bytes.len().min(2048)];
        contains_window(probe, b"\nend")
            || contains_window(probe, b"def ")
            || contains_window(probe, b"require")
            || contains_window(probe, b"puts ")
            || contains_window(probe, b"module ")
            || contains_window(probe, b"class ")
    };
    by_ext || by_shebang || by_marker
}

#[inline]
fn ends_with_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|n| haystack.ends_with(n))
}

#[inline]
fn contains_window(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn sniff_yarv() {
        let bytes: Vec<u8> = b"YARB\x00\x00\x00\x00".to_vec();
        assert_eq!(sniff(&bytes, "x.yarb").expect("sniff"), Flavor::YarvBinary);
    }

    #[test]
    fn sniff_rite() {
        let bytes: Vec<u8> = b"RITE0300".to_vec();
        assert_eq!(sniff(&bytes, "x.mrb").expect("sniff"), Flavor::MrubyBinary);
    }

    #[test]
    fn sniff_jruby_class() {
        let bytes: Vec<u8> = b"\xCA\xFE\xBA\xBE\x00\x00\x00\x34".to_vec();
        assert_eq!(sniff(&bytes, "x.class").expect("sniff"), Flavor::JrubyClass);
    }

    #[test]
    fn sniff_mri_by_extension() {
        let bytes: Vec<u8> = b"x = 1\n".to_vec();
        assert_eq!(sniff(&bytes, "tiny.rb").expect("sniff"), Flavor::MriSource);
    }

    #[test]
    fn sniff_mri_by_shebang() {
        let bytes: Vec<u8> = b"#!/usr/bin/env ruby\nputs 'hi'\n".to_vec();
        assert_eq!(sniff(&bytes, "anon").expect("sniff"), Flavor::MriSource);
    }

    #[test]
    fn sniff_truffleruby_aot() {
        let mut bytes: Vec<u8> = b"\x7FELF".to_vec();
        bytes.extend_from_slice(&[0u8; 64]);
        bytes.extend_from_slice(TRUFFLE_AOT_MARKER);
        assert_eq!(
            sniff(&bytes, "tr-anon").expect("sniff"),
            Flavor::TruffleRubyAot
        );
    }

    #[test]
    fn sniff_ruby2exe_pe() {
        let mut bytes: Vec<u8> = b"MZ".to_vec();
        bytes.extend_from_slice(&[0u8; 32]);
        bytes.extend_from_slice(RUBY2EXE_MARKER);
        assert_eq!(sniff(&bytes, "x.exe").expect("sniff"), Flavor::Ruby2Exe);
    }

    #[test]
    fn sniff_ocra_pe() {
        let mut bytes: Vec<u8> = b"MZ".to_vec();
        bytes.extend_from_slice(&[0u8; 32]);
        bytes.extend_from_slice(OCRA_MARKER);
        assert_eq!(sniff(&bytes, "x.exe").expect("sniff"), Flavor::Ocra);
    }

    #[test]
    fn sniff_empty_errors() {
        assert!(matches!(sniff(&[], "x.rb"), Err(RubyError::EmptyInput)));
    }

    #[test]
    fn sniff_unknown_errors() {
        let bytes: Vec<u8> = b"\xDE\xAD\xBE\xEF".to_vec();
        assert!(matches!(
            sniff(&bytes, "x"),
            Err(RubyError::UnknownFlavor { .. })
        ));
    }
}
