use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::demangle;
use crate::error::Result;
use crate::macho::{self, ParsedSlice, Section};
use crate::swift_reflect::{self, SwiftTypeReflection};

pub const SEG_TEXT: &str = "__TEXT";
pub const SECT_SWIFT5_TYPES: &str = "__swift5_types";
pub const SECT_SWIFT5_PROTOS: &str = "__swift5_protos";
pub const SECT_SWIFT5_PROTO_CONF: &str = "__swift5_proto";
pub const SECT_SWIFT5_FIELDMD: &str = "__swift5_fieldmd";
pub const SECT_SWIFT5_REFLSTR: &str = "__swift5_reflstr";
pub const SECT_SWIFT5_ASSOCTY: &str = "__swift5_assocty";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwiftRelativePointer {
    pub source_offset: u32,
    pub target_offset: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwiftSectionPointers {
    pub seg: String,
    pub name: String,
    pub pointer_count: usize,
    pub pointers: Vec<SwiftRelativePointer>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwiftReflectionStrings {
    pub seg: String,
    pub name: String,
    pub strings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwiftClassDump {
    pub types_section: Option<SwiftSectionPointers>,
    pub protos_section: Option<SwiftSectionPointers>,
    pub proto_conf_section: Option<SwiftSectionPointers>,
    pub fieldmd_section: Option<SwiftSectionPointers>,
    pub assocty_section: Option<SwiftSectionPointers>,
    pub reflection_strings: Option<SwiftReflectionStrings>,
    pub reflected_types: Vec<SwiftTypeReflection>,
    pub mangled_symbols: Vec<String>,
    pub demangled: BTreeMap<String, String>,
}

pub fn class_dump(slice: &[u8], parsed: &ParsedSlice) -> SwiftClassDump {
    let types_section: Option<SwiftSectionPointers> =
        section_pointers(slice, parsed, SEG_TEXT, SECT_SWIFT5_TYPES);
    let protos_section: Option<SwiftSectionPointers> =
        section_pointers(slice, parsed, SEG_TEXT, SECT_SWIFT5_PROTOS);
    let proto_conf_section: Option<SwiftSectionPointers> =
        section_pointers(slice, parsed, SEG_TEXT, SECT_SWIFT5_PROTO_CONF);
    let fieldmd_section: Option<SwiftSectionPointers> =
        section_pointers(slice, parsed, SEG_TEXT, SECT_SWIFT5_FIELDMD);
    let assocty_section: Option<SwiftSectionPointers> =
        section_pointers(slice, parsed, SEG_TEXT, SECT_SWIFT5_ASSOCTY);
    let reflection_strings: Option<SwiftReflectionStrings> =
        section_strings(slice, parsed, SEG_TEXT, SECT_SWIFT5_REFLSTR);

    let demangle_fn: &dyn Fn(&str) -> Option<String> = &|m: &str| demangle::demangle_type(m);
    let reflected_types: Vec<SwiftTypeReflection> =
        swift_reflect::parse_field_descriptors(slice, parsed, demangle_fn);

    let mut mangled_symbols: Vec<String> =
        collect_mangled_swift_strings(reflection_strings.as_ref());
    for sym in macho::symbol_names(slice, parsed) {
        if demangle::looks_like_swift_mangled(&sym) {
            mangled_symbols.push(sym);
        }
    }
    mangled_symbols.sort_unstable();
    mangled_symbols.dedup();
    let mut demangled: BTreeMap<String, String> = BTreeMap::new();
    for sym in &mangled_symbols {
        if let Ok(d) = demangle::demangle(sym) {
            demangled.insert(sym.clone(), d);
        }
    }

    SwiftClassDump {
        types_section,
        protos_section,
        proto_conf_section,
        fieldmd_section,
        assocty_section,
        reflection_strings,
        reflected_types,
        mangled_symbols,
        demangled,
    }
}

fn section_pointers(
    slice: &[u8],
    parsed: &ParsedSlice,
    seg: &str,
    name: &str,
) -> Option<SwiftSectionPointers> {
    let section: &Section = macho::find_section(parsed, seg, name)?;
    let bytes: &[u8] = macho::section_bytes(slice, section)?;
    let pointer_count: usize = bytes.len() / 4;
    let mut pointers: Vec<SwiftRelativePointer> = Vec::with_capacity(pointer_count);
    for i in 0..pointer_count {
        let off: usize = i * 4;
        let arr: [u8; 4] = [bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]];
        let signed: i32 = i32::from_le_bytes(arr);
        let signed_off: i64 = i64::try_from(off).unwrap_or(i64::MAX);
        let target_offset: i64 = i64::from(section.offset) + signed_off + i64::from(signed);
        let row_u32: u32 = u32::try_from(off).unwrap_or(u32::MAX);
        pointers.push(SwiftRelativePointer {
            source_offset: section.offset.saturating_add(row_u32),
            target_offset,
        });
    }
    Some(SwiftSectionPointers {
        seg: seg.to_owned(),
        name: name.to_owned(),
        pointer_count,
        pointers,
    })
}

fn section_strings(
    slice: &[u8],
    parsed: &ParsedSlice,
    seg: &str,
    name: &str,
) -> Option<SwiftReflectionStrings> {
    let section: &Section = macho::find_section(parsed, seg, name)?;
    let bytes: &[u8] = macho::section_bytes(slice, section)?;
    let strings: Vec<String> = split_cstrings(bytes);
    Some(SwiftReflectionStrings {
        seg: seg.to_owned(),
        name: name.to_owned(),
        strings,
    })
}

fn split_cstrings(bytes: &[u8]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut start: usize = 0;
    for (i, b) in bytes.iter().enumerate() {
        if *b == 0 {
            if i > start {
                let chunk: &[u8] = &bytes[start..i];
                if chunk
                    .iter()
                    .all(|c: &u8| c.is_ascii_graphic() || *c == b' ')
                {
                    out.push(String::from_utf8_lossy(chunk).into_owned());
                }
            }
            start = i + 1;
        }
    }
    out
}

fn collect_mangled_swift_strings(reflstr: Option<&SwiftReflectionStrings>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let Some(r) = reflstr else {
        return out;
    };
    for s in &r.strings {
        if looks_like_swift_mangled(s) {
            out.push(s.clone());
        }
    }
    out
}

#[must_use]
pub fn looks_like_swift_mangled(s: &str) -> bool {
    demangle::looks_like_swift_mangled(s)
}

pub fn demangle(symbol: &str) -> Result<String> {
    demangle::demangle(symbol)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidentialDecryptResult {
    pub recovered: Vec<String>,
    pub key: u8,
    pub candidates_scanned: usize,
}

pub fn confidential_xor_decrypt(payload: &[u8], key: u8) -> Vec<u8> {
    payload.iter().map(|b: &u8| b ^ key).collect()
}

pub fn confidential_recover_strings(blob: &[u8], key: u8) -> ConfidentialDecryptResult {
    let decrypted: Vec<u8> = confidential_xor_decrypt(blob, key);
    let strings: Vec<String> = split_printable_runs(&decrypted, MIN_PRINTABLE_RUN_LEN);
    ConfidentialDecryptResult {
        recovered: strings,
        key,
        candidates_scanned: blob.len(),
    }
}

const MIN_PRINTABLE_RUN_LEN: usize = 2;

fn split_printable_runs(bytes: &[u8], min_len: usize) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut start: usize = 0;
    let mut in_run: bool = false;
    for (i, b) in bytes.iter().enumerate() {
        let printable: bool = b.is_ascii_graphic() || *b == b' ';
        if printable {
            if !in_run {
                start = i;
                in_run = true;
            }
        } else if in_run {
            if i - start >= min_len {
                let chunk: &[u8] = &bytes[start..i];
                out.push(String::from_utf8_lossy(chunk).into_owned());
            }
            in_run = false;
        }
    }
    if in_run && bytes.len() - start >= min_len {
        let chunk: &[u8] = &bytes[start..];
        out.push(String::from_utf8_lossy(chunk).into_owned());
    }
    out
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwiftShieldUndoMap {
    pub mappings: BTreeMap<String, String>,
}

pub fn swiftshield_undo_from_dsym_text(text: &str) -> SwiftShieldUndoMap {
    let mut mappings: BTreeMap<String, String> = BTreeMap::new();
    for line in text.lines() {
        let trimmed: &str = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = trimmed.split("==>").map(str::trim).collect();
        if parts.len() == 2 && !parts[0].is_empty() && !parts[1].is_empty() {
            mappings.insert(parts[0].to_owned(), parts[1].to_owned());
        }
    }
    SwiftShieldUndoMap { mappings }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn demangle_simple_class() {
        let mangled: &str = "$s5Hello5WorldC";
        let out: String = demangle(mangled).expect("demangle");
        assert_eq!(out, "Hello.World (class)");
    }

    #[test]
    fn demangle_simple_struct() {
        let mangled: &str = "$s3App4UserV";
        let out: String = demangle(mangled).expect("demangle");
        assert_eq!(out, "App.User (struct)");
    }

    #[test]
    fn demangle_rejects_non_swift() {
        assert!(demangle("foo").is_err());
    }

    #[test]
    fn confidential_xor_roundtrip() {
        let plain: &[u8] = b"secret\0literal\0";
        let key: u8 = 0x5A;
        let enc: Vec<u8> = confidential_xor_decrypt(plain, key);
        let dec: ConfidentialDecryptResult = confidential_recover_strings(&enc, key);
        assert_eq!(
            dec.recovered,
            vec!["secret".to_owned(), "literal".to_owned()]
        );
    }

    #[test]
    fn swiftshield_undo_parses_mapping() {
        let txt: &str = "a8X9k2 ==> LoginViewController\nz7q3w1 ==> AuthService\n# comment\n";
        let m: SwiftShieldUndoMap = swiftshield_undo_from_dsym_text(txt);
        assert_eq!(
            m.mappings.get("a8X9k2").map(String::as_str),
            Some("LoginViewController")
        );
        assert_eq!(
            m.mappings.get("z7q3w1").map(String::as_str),
            Some("AuthService")
        );
    }

    #[test]
    fn looks_like_swift_mangled_detects_dollar_s() {
        assert!(looks_like_swift_mangled("$s5Hello5WorldC"));
        assert!(looks_like_swift_mangled("_$s5Hello5WorldC"));
        assert!(!looks_like_swift_mangled("plain"));
    }
}
