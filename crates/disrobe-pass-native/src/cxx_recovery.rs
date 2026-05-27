use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CxxAbi {
    Itanium,
    Msvc,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CxxDemangled {
    pub mangled: String,
    pub demangled: String,
    pub abi: CxxAbi,
}

pub fn demangle_itanium(mangled: &str) -> Result<CxxDemangled> {
    let sym: cpp_demangle::Symbol<&str> =
        cpp_demangle::Symbol::new(mangled).map_err(|e: cpp_demangle::error::Error| {
            Error::Demangle {
                lang: "itanium-cxx",
                message: e.to_string(),
            }
        })?;
    let demangled: String = sym
        .demangle()
        .map_err(|e: std::fmt::Error| Error::Demangle {
            lang: "itanium-cxx",
            message: e.to_string(),
        })?;
    Ok(CxxDemangled {
        mangled: mangled.to_owned(),
        demangled,
        abi: CxxAbi::Itanium,
    })
}

pub fn demangle_msvc(mangled: &str) -> Result<CxxDemangled> {
    let demangled: String =
        msvc_demangler::demangle(mangled, msvc_demangler::DemangleFlags::llvm()).map_err(
            |e: msvc_demangler::Error| Error::Demangle {
                lang: "msvc-cxx",
                message: e.to_string(),
            },
        )?;
    Ok(CxxDemangled {
        mangled: mangled.to_owned(),
        demangled,
        abi: CxxAbi::Msvc,
    })
}

pub fn demangle_auto(mangled: &str) -> Result<CxxDemangled> {
    if mangled.starts_with('?') {
        demangle_msvc(mangled)
    } else {
        demangle_itanium(mangled)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RttiEntry {
    pub class_name: String,
    pub base_classes: Vec<String>,
    pub vtable_address: u64,
}

pub fn recover_itanium_rtti(symbols: &[&str]) -> Vec<RttiEntry> {
    let mut by_class: BTreeMap<String, RttiEntry> = BTreeMap::new();
    for (i, s) in symbols.iter().enumerate() {
        if !(s.starts_with("_ZTV") || s.starts_with("_ZTI") || s.starts_with("_ZTS")) {
            continue;
        }
        let class_part: &str = &s[4..];
        let entry: &mut RttiEntry =
            by_class
                .entry(class_part.to_owned())
                .or_insert_with(|| RttiEntry {
                    class_name: class_part.to_owned(),
                    base_classes: Vec::new(),
                    vtable_address: 0,
                });
        if s.starts_with("_ZTV") {
            entry.vtable_address = i as u64;
        }
    }
    by_class.into_values().collect()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EhEntry {
    pub start: u64,
    pub end: u64,
    pub landing_pad: u64,
    pub action: u32,
}

pub fn parse_itanium_lsda(bytes: &[u8]) -> Result<Vec<EhEntry>> {
    if bytes.len() < 4 {
        return Err(Error::Truncated {
            needed: 4,
            had: bytes.len(),
        });
    }
    let mut out: Vec<EhEntry> = Vec::new();
    let mut idx: usize = 4;
    while idx + 16 <= bytes.len() {
        let start: u64 =
            u32::from_le_bytes([bytes[idx], bytes[idx + 1], bytes[idx + 2], bytes[idx + 3]]) as u64;
        let end: u64 = u32::from_le_bytes([
            bytes[idx + 4],
            bytes[idx + 5],
            bytes[idx + 6],
            bytes[idx + 7],
        ]) as u64;
        let landing_pad: u64 = u32::from_le_bytes([
            bytes[idx + 8],
            bytes[idx + 9],
            bytes[idx + 10],
            bytes[idx + 11],
        ]) as u64;
        let action: u32 = u32::from_le_bytes([
            bytes[idx + 12],
            bytes[idx + 13],
            bytes[idx + 14],
            bytes[idx + 15],
        ]);
        out.push(EhEntry {
            start,
            end,
            landing_pad,
            action,
        });
        idx += 16;
    }
    Ok(out)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SehScopeEntry {
    pub begin_address: u32,
    pub end_address: u32,
    pub handler_address: u32,
    pub jump_target: u32,
}

pub fn parse_windows_seh_scope_table(bytes: &[u8]) -> Result<Vec<SehScopeEntry>> {
    if bytes.len() < 4 {
        return Err(Error::Truncated {
            needed: 4,
            had: bytes.len(),
        });
    }
    let count: usize = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    let needed: usize = 4 + count * 16;
    if bytes.len() < needed {
        return Err(Error::Truncated {
            needed,
            had: bytes.len(),
        });
    }
    let mut out: Vec<SehScopeEntry> = Vec::with_capacity(count);
    let mut idx: usize = 4;
    for _ in 0..count {
        out.push(SehScopeEntry {
            begin_address: u32::from_le_bytes([
                bytes[idx],
                bytes[idx + 1],
                bytes[idx + 2],
                bytes[idx + 3],
            ]),
            end_address: u32::from_le_bytes([
                bytes[idx + 4],
                bytes[idx + 5],
                bytes[idx + 6],
                bytes[idx + 7],
            ]),
            handler_address: u32::from_le_bytes([
                bytes[idx + 8],
                bytes[idx + 9],
                bytes[idx + 10],
                bytes[idx + 11],
            ]),
            jump_target: u32::from_le_bytes([
                bytes[idx + 12],
                bytes[idx + 13],
                bytes[idx + 14],
                bytes[idx + 15],
            ]),
        });
        idx += 16;
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn itanium_demangle_basic() {
        let d: CxxDemangled = demangle_itanium("_ZN3foo3barEv").expect("itanium");
        assert!(d.demangled.contains("foo::bar"));
        assert_eq!(d.abi, CxxAbi::Itanium);
    }

    #[test]
    fn msvc_demangle_basic() {
        let d: CxxDemangled = demangle_msvc("?foo@@YAXXZ").expect("msvc");
        assert!(d.demangled.contains("foo"));
        assert_eq!(d.abi, CxxAbi::Msvc);
    }

    #[test]
    fn auto_dispatch_picks_msvc_for_question_mark() {
        let d: CxxDemangled = demangle_auto("?bar@@YAHH@Z").expect("auto-msvc");
        assert_eq!(d.abi, CxxAbi::Msvc);
    }

    #[test]
    fn auto_dispatch_picks_itanium_for_underscore_z() {
        let d: CxxDemangled = demangle_auto("_ZN1A1BEv").expect("auto-itanium");
        assert_eq!(d.abi, CxxAbi::Itanium);
    }

    #[test]
    fn rtti_recovery_groups_typed_symbols() {
        let syms: [&str; 3] = ["_ZTV3Foo", "_ZTI3Foo", "_ZTS3Foo"];
        let out: Vec<RttiEntry> = recover_itanium_rtti(&syms);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].class_name, "3Foo");
    }

    #[test]
    fn itanium_lsda_parses_minimal_entries() {
        let mut buf: Vec<u8> = vec![0x01, 0x02, 0x03, 0x04];
        buf.extend_from_slice(&100u32.to_le_bytes());
        buf.extend_from_slice(&200u32.to_le_bytes());
        buf.extend_from_slice(&300u32.to_le_bytes());
        buf.extend_from_slice(&1u32.to_le_bytes());
        let out: Vec<EhEntry> = parse_itanium_lsda(&buf).expect("lsda");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].start, 100);
        assert_eq!(out[0].landing_pad, 300);
    }

    #[test]
    fn windows_seh_scope_table_parses_count_prefixed() {
        let count: u32 = 1;
        let mut buf: Vec<u8> = count.to_le_bytes().to_vec();
        buf.extend_from_slice(&10u32.to_le_bytes());
        buf.extend_from_slice(&20u32.to_le_bytes());
        buf.extend_from_slice(&30u32.to_le_bytes());
        buf.extend_from_slice(&40u32.to_le_bytes());
        let out: Vec<SehScopeEntry> = parse_windows_seh_scope_table(&buf).expect("seh");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].begin_address, 10);
    }
}
