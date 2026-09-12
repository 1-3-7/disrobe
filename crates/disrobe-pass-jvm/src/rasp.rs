#![allow(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::module_name_repetitions
)]

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::dex::DexFile;
use crate::error::Result;
use crate::jar::{ApkExtract, extract_apk};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RaspVendor {
    PromonShield,
    GuardsquareDexGuard,
    GuardsquareThreatCast,
    AppdomeMobileShield,
    OneSpan,
    Arxan,
    Zimperium,
    BuildSecureDexProtector,
}

impl RaspVendor {
    #[inline]
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::PromonShield => "Promon SHIELD (AppShield)",
            Self::GuardsquareDexGuard => "Guardsquare DexGuard RASP",
            Self::GuardsquareThreatCast => "Guardsquare ThreatCast",
            Self::AppdomeMobileShield => "Appdome Mobile Shield",
            Self::OneSpan => "OneSpan (Vasco) Mobile App Shielding",
            Self::Arxan => "Arxan / Digital.ai App Protection",
            Self::Zimperium => "Zimperium zShield",
            Self::BuildSecureDexProtector => "Licel DexProtector",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RaspSignal {
    pub vendor: RaspVendor,
    pub confidence: u8,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RaspReport {
    pub signals: Vec<RaspSignal>,
    pub native_libs: Vec<String>,
    pub notes: Vec<String>,
}

impl RaspReport {
    #[inline]
    #[must_use]
    pub const fn is_protected(&self) -> bool {
        !self.signals.is_empty()
    }

    #[inline]
    #[must_use]
    pub fn detected(&self, vendor: RaspVendor) -> bool {
        self.signals.iter().any(|s: &RaspSignal| s.vendor == vendor)
    }
}

struct VendorRule {
    vendor: RaspVendor,
    lib_markers: &'static [&'static str],
    string_markers: &'static [&'static str],
    type_markers: &'static [&'static str],
}

const RULES: &[VendorRule] = &[
    VendorRule {
        vendor: RaspVendor::PromonShield,
        lib_markers: &["libshield.so", "libpromon", "libshieldruntime"],
        string_markers: &["Promon", "SHIELD", "no.promon"],
        type_markers: &["Lno/promon/", "Lcom/promon/"],
    },
    VendorRule {
        vendor: RaspVendor::GuardsquareDexGuard,
        lib_markers: &["libdexguard", "libdgrasp"],
        string_markers: &["DexGuard", "com.guardsquare", "dexguard.runtime"],
        type_markers: &["Lcom/guardsquare/dexguard/", "Ldexguard/"],
    },
    VendorRule {
        vendor: RaspVendor::GuardsquareThreatCast,
        lib_markers: &["libthreatcast"],
        string_markers: &["ThreatCast", "threatcast"],
        type_markers: &["Lcom/guardsquare/threatcast/"],
    },
    VendorRule {
        vendor: RaspVendor::AppdomeMobileShield,
        lib_markers: &["libappdome", "libloader.appdome"],
        string_markers: &["Appdome", "com.appdome"],
        type_markers: &["Lcom/appdome/"],
    },
    VendorRule {
        vendor: RaspVendor::OneSpan,
        lib_markers: &["libonespan", "libvasco"],
        string_markers: &["OneSpan", "com.onespan", "com.vasco"],
        type_markers: &["Lcom/onespan/", "Lcom/vasco/"],
    },
    VendorRule {
        vendor: RaspVendor::Arxan,
        lib_markers: &["libarxan", "libdigitalai"],
        string_markers: &["Arxan", "com.arxan", "Digital.ai"],
        type_markers: &["Lcom/arxan/"],
    },
    VendorRule {
        vendor: RaspVendor::Zimperium,
        lib_markers: &["libzdetection", "libzshield"],
        string_markers: &["Zimperium", "com.zimperium", "zShield"],
        type_markers: &["Lcom/zimperium/"],
    },
    VendorRule {
        vendor: RaspVendor::BuildSecureDexProtector,
        lib_markers: &["libdexprotector", "libdexpro"],
        string_markers: &["DexProtector", "com.licel"],
        type_markers: &["Lcom/licel/", "Lcom/dexprotector/"],
    },
];

#[must_use]
pub fn detect_in_dex(dex: &DexFile) -> RaspReport {
    detect_in_strings_types(&dex.strings, &dex.type_names)
}

fn detect_in_strings_types(strings: &[String], types: &[String]) -> RaspReport {
    let mut report: RaspReport = RaspReport::default();
    for rule in RULES {
        let mut evidence: Vec<String> = Vec::new();
        let mut score: u8 = 0;
        for marker in rule.string_markers {
            if strings.iter().any(|s: &String| s.contains(marker)) {
                score = score.saturating_add(40);
                evidence.push(format!("string marker '{marker}'"));
            }
        }
        for marker in rule.type_markers {
            if types.iter().any(|t: &String| t.starts_with(marker)) {
                score = score.saturating_add(50);
                evidence.push(format!("type prefix '{marker}'"));
            }
        }
        for marker in rule.lib_markers {
            if strings.iter().any(|s: &String| s.contains(marker)) {
                score = score.saturating_add(45);
                evidence.push(format!("native lib reference '{marker}'"));
            }
        }
        if score >= 40 {
            report.signals.push(RaspSignal {
                vendor: rule.vendor,
                confidence: score.min(100),
                evidence,
            });
        }
    }
    if report.signals.is_empty() {
        report
            .notes
            .push("no RASP/app-shielding vendor signatures present (detect-only pass)".to_string());
    }
    report
}

pub fn detect_in_apk(apk_bytes: &[u8]) -> Result<RaspReport> {
    let apk: ApkExtract = extract_apk(apk_bytes)?;
    let mut report: RaspReport = RaspReport::default();
    for path in apk.jar.entries.iter().map(|e| e.path.as_str()) {
        if path.starts_with("lib/") && path.ends_with(".so") {
            let leaf: &str = path.rsplit('/').next().unwrap_or(path);
            report.native_libs.push(leaf.to_string());
        }
    }
    let mut merged_signals: BTreeMap<RaspVendor, RaspSignal> = BTreeMap::new();
    for dex_bytes in apk.dex_files.values() {
        if let Ok(dex) = crate::dex::parse(dex_bytes) {
            let dex_report: RaspReport = detect_in_dex(&dex);
            for signal in dex_report.signals {
                merged_signals
                    .entry(signal.vendor)
                    .and_modify(|existing: &mut RaspSignal| {
                        existing.confidence = existing.confidence.max(signal.confidence);
                        existing.evidence.extend(signal.evidence.clone());
                    })
                    .or_insert(signal);
            }
        }
    }
    for rule in RULES {
        for lib in &report.native_libs {
            if rule.lib_markers.iter().any(|m: &&str| lib.contains(m)) {
                merged_signals
                    .entry(rule.vendor)
                    .and_modify(|s: &mut RaspSignal| {
                        s.confidence = s.confidence.saturating_add(45).min(100);
                        s.evidence.push(format!("packaged native lib '{lib}'"));
                    })
                    .or_insert_with(|| RaspSignal {
                        vendor: rule.vendor,
                        confidence: 60,
                        evidence: vec![format!("packaged native lib '{lib}'")],
                    });
            }
        }
    }
    report.signals = merged_signals.into_values().collect();
    if report.signals.is_empty() {
        report
            .notes
            .push("APK carries no RASP vendor signatures (detect-only; real protected APKs are enterprise-gated)".to_string());
    }
    Ok(report)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn vendor_names_are_stable() {
        assert_eq!(RaspVendor::PromonShield.name(), "Promon SHIELD (AppShield)");
        assert_eq!(
            RaspVendor::GuardsquareDexGuard.name(),
            "Guardsquare DexGuard RASP"
        );
    }

    #[test]
    fn empty_inputs_yield_no_signals() {
        let report: RaspReport = detect_in_strings_types(&[], &[]);
        assert!(!report.is_protected());
        assert!(!report.notes.is_empty());
    }

    #[test]
    fn promon_markers_trigger_detection() {
        let strings: Vec<String> = vec!["Promon SHIELD".to_string(), "no.promon".to_string()];
        let types: Vec<String> = vec!["Lno/promon/shield/Runtime;".to_string()];
        let report: RaspReport = detect_in_strings_types(&strings, &types);
        assert!(report.detected(RaspVendor::PromonShield));
        assert!(report.is_protected());
    }
}
