use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DemangledSymbol {
    pub mangled: String,
    pub demangled: String,
    pub scheme: DemangleScheme,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DemangleScheme {
    RustLegacy,
    RustV0,
    Unknown,
}

pub fn demangle(mangled: &str) -> Result<DemangledSymbol> {
    let try_result: core::result::Result<rustc_demangle::Demangle<'_>, _> =
        rustc_demangle::try_demangle(mangled);
    let scheme: DemangleScheme = if mangled.starts_with("_R") || mangled.starts_with("R") {
        DemangleScheme::RustV0
    } else if mangled.starts_with("_Z") || mangled.starts_with("__Z") {
        DemangleScheme::RustLegacy
    } else {
        DemangleScheme::Unknown
    };
    match try_result {
        Ok(d) => Ok(DemangledSymbol {
            mangled: mangled.to_owned(),
            demangled: d.to_string(),
            scheme,
        }),
        Err(_e) => Err(Error::Demangle {
            lang: "rust",
            message: format!("not a valid Rust mangled symbol: {mangled}"),
        }),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PanicSignature {
    pub address: u64,
    pub kind: PanicKind,
    pub call_target: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PanicKind {
    CorePanicking,
    StdPanic,
    FormatArgs,
    UnwindResume,
    Unknown,
}

#[must_use]
pub fn detect_panic_signatures(symbols: &[&str]) -> Vec<PanicSignature> {
    let mut out: Vec<PanicSignature> = Vec::new();
    for (i, s) in symbols.iter().enumerate() {
        let kind: PanicKind = if s.contains("core::panicking::panic") {
            PanicKind::CorePanicking
        } else if s.contains("std::panic") {
            PanicKind::StdPanic
        } else if s.contains("core::fmt::Arguments::new") || s.contains("core::fmt::format") {
            PanicKind::FormatArgs
        } else if s.contains("_Unwind_Resume") || s.contains("rust_eh_personality") {
            PanicKind::UnwindResume
        } else {
            continue;
        };
        out.push(PanicSignature {
            address: i as u64,
            kind,
            call_target: Some((*s).to_owned()),
        });
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VtableEntry {
    pub address: u64,
    pub function: String,
    pub trait_name: Option<String>,
}

#[must_use]
pub fn recover_trait_vtables(symbols: &[&str]) -> Vec<VtableEntry> {
    let mut out: Vec<VtableEntry> = Vec::new();
    for (i, s) in symbols.iter().enumerate() {
        if !s.contains("$LT$") && !s.contains("vtable") && !s.contains(" as ") {
            continue;
        }
        let trait_name: Option<String> = extract_trait_name(s);
        out.push(VtableEntry {
            address: i as u64,
            function: (*s).to_owned(),
            trait_name,
        });
    }
    out
}

fn extract_trait_name(symbol: &str) -> Option<String> {
    let legacy_after_as: Option<&str> = symbol.split("$u20$as$u20$").nth(1);
    if let Some(after_as) = legacy_after_as {
        return after_as
            .split("$GT$")
            .next()
            .map(str::trim)
            .filter(|t: &&str| !t.is_empty())
            .map(str::to_owned);
    }
    let lt: usize = symbol.find('<')?;
    let inner: &str = &symbol[lt + 1..];
    let close: usize = matching_angle_close(inner)?;
    let impl_clause: &str = &inner[..close];
    let (_, after_as): (&str, &str) = impl_clause.rsplit_once(" as ")?;
    let trimmed: &str = after_as.split('<').next().unwrap_or(after_as).trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

fn matching_angle_close(s: &str) -> Option<usize> {
    let mut depth: u32 = 0;
    for (idx, ch) in s.char_indices() {
        match ch {
            '<' => depth += 1,
            '>' if depth == 0 => return Some(idx),
            '>' => depth -= 1,
            _ => {}
        }
    }
    None
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnumDiscriminant {
    pub type_name: String,
    pub variants: BTreeMap<u64, String>,
}

#[must_use]
pub fn recover_enum_discriminants(symbols: &[&str]) -> Vec<EnumDiscriminant> {
    let mut by_ty: BTreeMap<String, BTreeMap<u64, String>> = BTreeMap::new();
    for (i, s) in symbols.iter().enumerate() {
        if !s.contains("::") {
            continue;
        }
        let parts: Vec<&str> = s.split("::").collect();
        if parts.len() < 2 {
            continue;
        }
        let ty: String = parts[..parts.len() - 1].join("::");
        let variant: String = (*parts.last().unwrap_or(&"")).to_owned();
        if variant.is_empty() {
            continue;
        }
        by_ty.entry(ty).or_default().insert(i as u64, variant);
    }
    by_ty
        .into_iter()
        .map(|(type_name, variants)| EnumDiscriminant {
            type_name,
            variants,
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MonomorphizationGroup {
    pub generic_origin: String,
    pub instances: BTreeSet<String>,
}

#[must_use]
pub fn group_monomorphizations(symbols: &[&str]) -> Vec<MonomorphizationGroup> {
    let mut by_origin: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for s in symbols {
        let Some(origin): Option<String> = monomorphization_origin(s) else {
            continue;
        };
        by_origin.entry(origin).or_default().insert((*s).to_owned());
    }
    by_origin
        .into_iter()
        .filter(|(_origin, set)| set.len() > 1)
        .map(|(generic_origin, instances)| MonomorphizationGroup {
            generic_origin,
            instances,
        })
        .collect()
}

fn monomorphization_origin(symbol: &str) -> Option<String> {
    let cut: usize = symbol
        .find("$LT$")
        .map(|i: usize| (i, "$LT$".len()))
        .into_iter()
        .chain(symbol.find('<').map(|i: usize| (i, '<'.len_utf8())))
        .min_by_key(|(i, _len): &(usize, usize)| *i)
        .map(|(i, _len): (usize, usize)| i)?;
    let stem: &str = symbol[..cut].trim_end_matches("::");
    if stem.is_empty() {
        None
    } else {
        Some(stem.to_owned())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditableSbom {
    pub format_version: u32,
    pub crates: Vec<AuditableCrate>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditableCrate {
    pub name: String,
    pub version: String,
    pub source: Option<String>,
}

pub fn parse_auditable_section(bytes: &[u8]) -> Result<AuditableSbom> {
    let decompressed: Vec<u8> = if bytes.starts_with(&[0x1F, 0x8B]) {
        return Err(Error::SignatureDb(
            "auditable section gzip wrapper not handled in v0.1; pre-inflate before invocation"
                .to_owned(),
        ));
    } else {
        bytes.to_vec()
    };
    let value: serde_json::Value = serde_json::from_slice(&decompressed)
        .map_err(|e: serde_json::Error| Error::SignatureDb(e.to_string()))?;
    let pkgs: &Vec<serde_json::Value> = value
        .get("packages")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| Error::SignatureDb("missing 'packages' array".to_owned()))?;
    let mut crates: Vec<AuditableCrate> = Vec::with_capacity(pkgs.len());
    for p in pkgs {
        let name: String = p
            .get("name")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| Error::SignatureDb("package missing name".to_owned()))?
            .to_owned();
        let version: String = p
            .get("version")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| Error::SignatureDb("package missing version".to_owned()))?
            .to_owned();
        let source: Option<String> = p
            .get("source")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned);
        crates.push(AuditableCrate {
            name,
            version,
            source,
        });
    }
    Ok(AuditableSbom {
        format_version: 0,
        crates,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn demangle_v0() {
        let d: DemangledSymbol = demangle("_RNvCs9ltgdHTiPiY_3foo3bar").expect("demangle v0");
        assert_eq!(d.scheme, DemangleScheme::RustV0);
        assert!(d.demangled.contains("bar"));
    }

    #[test]
    fn demangle_legacy() {
        let d: DemangledSymbol = demangle("_ZN3foo3barE").expect("legacy");
        assert_eq!(d.scheme, DemangleScheme::RustLegacy);
        assert!(d.demangled.contains("bar"));
    }

    #[test]
    fn panic_signatures_detect_core_panicking() {
        let syms: [&str; 2] = [
            "core::panicking::panic_fmt::h0",
            "core::fmt::Arguments::new_v1::h1",
        ];
        let out: Vec<PanicSignature> = detect_panic_signatures(&syms);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].kind, PanicKind::CorePanicking);
        assert_eq!(out[1].kind, PanicKind::FormatArgs);
    }

    #[test]
    fn vtable_recovery_finds_trait_impls() {
        let syms: [&str; 1] =
            ["_ZN54_$LT$alloc..vec..Vec$LT$T$GT$$u20$as$u20$core..fmt..Debug$GT$3fmt17h0E"];
        let out: Vec<VtableEntry> = recover_trait_vtables(&syms);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].trait_name.as_deref(), Some("core..fmt..Debug"));
    }

    #[test]
    fn vtable_recovery_extracts_trait_from_v0_demangled() {
        let syms: [&str; 1] = ["<alloc::vec::Vec<T> as core::fmt::Debug>::fmt"];
        let out: Vec<VtableEntry> = recover_trait_vtables(&syms);
        assert_eq!(out.len(), 1);
        assert_eq!(
            out[0].trait_name.as_deref(),
            Some("core::fmt::Debug"),
            "v0-demangled trait impls must yield the trait name, not None",
        );
    }

    #[test]
    fn vtable_recovery_handles_generic_trait_in_v0_form() {
        let syms: [&str; 1] = ["<std::collections::HashMap<K, V> as core::ops::Index<Q>>::index"];
        let out: Vec<VtableEntry> = recover_trait_vtables(&syms);
        assert_eq!(out.len(), 1);
        assert_eq!(
            out[0].trait_name.as_deref(),
            Some("core::ops::Index"),
            "the generic trait's args must be trimmed from the recovered name",
        );
    }

    #[test]
    fn vtable_recovery_inherent_impl_has_no_trait() {
        let syms: [&str; 1] = ["<core::option::Option<T>>::unwrap"];
        let out: Vec<VtableEntry> = recover_trait_vtables(&syms);
        assert!(
            out.is_empty() || out[0].trait_name.is_none(),
            "an inherent impl (no `as Trait`) must not fabricate a trait name",
        );
    }

    #[test]
    fn enum_disc_groups_variants_by_type() {
        let syms: [&str; 3] = ["my::Color::Red", "my::Color::Green", "my::Color::Blue"];
        let out: Vec<EnumDiscriminant> = recover_enum_discriminants(&syms);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].type_name, "my::Color");
        assert_eq!(out[0].variants.len(), 3);
    }

    #[test]
    fn mono_grouper_finds_generic_origins() {
        let syms: [&str; 3] = [
            "core::option::Option$LT$u32$GT$::unwrap",
            "core::option::Option$LT$u64$GT$::unwrap",
            "lone_function::run",
        ];
        let out: Vec<MonomorphizationGroup> = group_monomorphizations(&syms);
        assert_eq!(out.len(), 1);
        assert!(out[0].generic_origin.contains("Option"));
        assert!(out[0].instances.len() >= 2);
    }

    #[test]
    fn mono_grouper_handles_v0_demangled_generics() {
        let syms: [&str; 3] = [
            "core::option::Option<u32>::unwrap",
            "core::option::Option<u64>::unwrap",
            "lone_function::run",
        ];
        let out: Vec<MonomorphizationGroup> = group_monomorphizations(&syms);
        assert_eq!(
            out.len(),
            1,
            "v0-demangled monomorphizations must group by their generic origin",
        );
        assert_eq!(out[0].generic_origin, "core::option::Option");
        assert_eq!(out[0].instances.len(), 2);
    }

    #[test]
    fn mono_grouper_prefers_earliest_bracket_across_encodings() {
        assert_eq!(
            monomorphization_origin("a::b<T>::c").as_deref(),
            Some("a::b"),
        );
        assert_eq!(
            monomorphization_origin("a::b$LT$T$GT$::c").as_deref(),
            Some("a::b"),
        );
        assert!(monomorphization_origin("a::b::c").is_none());
    }

    #[test]
    fn auditable_sbom_parses_minimal_json() {
        let blob: &[u8] = br#"{"packages":[{"name":"serde","version":"1.0.0"},{"name":"x","version":"0.1.0","source":"crates.io"}]}"#;
        let sbom: AuditableSbom = parse_auditable_section(blob).expect("parse");
        assert_eq!(sbom.crates.len(), 2);
        assert_eq!(sbom.crates[0].name, "serde");
        assert_eq!(sbom.crates[1].source.as_deref(), Some("crates.io"));
    }
}
