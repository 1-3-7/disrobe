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

pub fn recover_trait_vtables(symbols: &[&str]) -> Vec<VtableEntry> {
    let mut out: Vec<VtableEntry> = Vec::new();
    for (i, s) in symbols.iter().enumerate() {
        if !s.contains("$LT$") && !s.contains("vtable") && !s.contains(" as ") {
            continue;
        }
        let trait_name: Option<String> = s
            .split("$LT$")
            .nth(1)
            .and_then(|tail: &str| tail.split("$u20$as$u20$").nth(1))
            .and_then(|tail: &str| tail.split("$GT$").next())
            .map(str::to_owned);
        out.push(VtableEntry {
            address: i as u64,
            function: (*s).to_owned(),
            trait_name,
        });
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnumDiscriminant {
    pub type_name: String,
    pub variants: BTreeMap<u64, String>,
}

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

pub fn group_monomorphizations(symbols: &[&str]) -> Vec<MonomorphizationGroup> {
    let mut by_origin: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for s in symbols {
        let origin: String = match s.split("$LT$").next() {
            Some(stem) if stem.len() < s.len() => stem.trim_end_matches("::").to_owned(),
            _ => continue,
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
    fn auditable_sbom_parses_minimal_json() {
        let blob: &[u8] = br#"{"packages":[{"name":"serde","version":"1.0.0"},{"name":"x","version":"0.1.0","source":"crates.io"}]}"#;
        let sbom: AuditableSbom = parse_auditable_section(blob).expect("parse");
        assert_eq!(sbom.crates.len(), 2);
        assert_eq!(sbom.crates[0].name, "serde");
        assert_eq!(sbom.crates[1].source.as_deref(), Some("crates.io"));
    }
}
