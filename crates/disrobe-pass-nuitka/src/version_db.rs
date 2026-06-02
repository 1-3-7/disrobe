use serde::{Deserialize, Serialize};

use crate::markers::NuitkaEraGuess;
use crate::util::find_subslice;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExactNuitkaVersion {
    pub major: u32,
    pub minor: u32,
    pub micro: u32,
    pub release_level: String,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct VersionSignature {
    pub era: NuitkaEraGuess,
    pub py_abi_min: Option<(u8, u8)>,
    pub py_abi_max: Option<(u8, u8)>,
    pub present: &'static [&'static [u8]],
    pub absent: &'static [&'static [u8]],
    pub label: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum VersionConfidence {
    Exact,
    Range,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NuitkaVersionReport {
    pub confidence: VersionConfidence,
    pub exact: Option<ExactNuitkaVersion>,
    pub era: Option<String>,
    pub era_label: Option<String>,
    pub python_abi: Option<(u8, u8)>,
    pub matched_present: Vec<String>,
    pub matched_absent_violations: Vec<String>,
}

const VERSION_DB: &[VersionSignature] = &[
    VersionSignature {
        era: NuitkaEraGuess::V1_4ToV1_9,
        py_abi_min: Some((3, 7)),
        py_abi_max: Some((3, 12)),
        present: &[b"createGlobalConstants", b"loadConstantsBlob"],
        absent: &[b"nuitka_module_loader", b"Nuitka_Err_NormalizeException"],
        label: "1.4-1.9 (changelog-derived, unverified against older corpus)",
    },
    VersionSignature {
        era: NuitkaEraGuess::V2_4ToV2_6,
        py_abi_min: Some((3, 8)),
        py_abi_max: Some((3, 13)),
        present: &[
            b"MAKE_CELL",
            b"CALL_FUNCTION_FAST",
            b"Nuitka_AsyncgenObject",
        ],
        absent: &[b"nuitka_module_loader"],
        label: "2.4-2.6 (changelog-derived, unverified against older corpus)",
    },
    VersionSignature {
        era: NuitkaEraGuess::V3OrV4,
        py_abi_min: Some((3, 11)),
        py_abi_max: None,
        present: &[
            b"__nuitka_version__",
            b"nuitka_module_loader",
            b"nuitka_resource_reader",
            b"nuitka_distribution",
            b"Nuitka_Err_NormalizeException",
            b"__compiled__",
        ],
        absent: &[],
        label: "4.x / modern 3.x loader (verified against 4.1.1 corpus)",
    },
];

#[must_use]
pub fn parse_exact_version_from_constants_c(c_source: &[u8]) -> Option<ExactNuitkaVersion> {
    let major: u32 = scan_set_item_long(c_source, 0)?;
    let minor: u32 = scan_set_item_long(c_source, 1)?;
    let micro: u32 = scan_set_item_long(c_source, 2)?;
    let release_level: String = scan_release_level(c_source)?;
    Some(ExactNuitkaVersion {
        major,
        minor,
        micro,
        release_level,
    })
}

fn scan_set_item_long(c_source: &[u8], field: u8) -> Option<u32> {
    let token: String =
        format!("SET_ITEM(Nuitka_dunder_compiled_value, {field}, Nuitka_PyInt_FromLong(");
    let start: usize = find_subslice(c_source, token.as_bytes())? + token.len();
    scan_ascii_u32(c_source, start)
}

fn scan_release_level(c_source: &[u8]) -> Option<String> {
    let token: &[u8] = b"SET_ITEM(Nuitka_dunder_compiled_value, 3, Nuitka_String_FromString(\"";
    let start: usize = find_subslice(c_source, token)? + token.len();
    let end: usize = c_source[start..]
        .iter()
        .position(|&b: &u8| b == b'"')
        .map(|rel: usize| start + rel)?;
    let slice: &[u8] = &c_source[start..end];
    if slice.is_empty() || !slice.iter().all(u8::is_ascii_graphic) {
        return None;
    }
    core::str::from_utf8(slice).ok().map(str::to_owned)
}

fn scan_ascii_u32(bytes: &[u8], start: usize) -> Option<u32> {
    let mut value: u32 = 0u32;
    let mut seen: bool = false;
    for &b in &bytes[start..] {
        if b.is_ascii_digit() {
            value = value.checked_mul(10)?.checked_add(u32::from(b - b'0'))?;
            seen = true;
        } else {
            break;
        }
    }
    seen.then_some(value)
}

#[must_use]
pub(crate) fn detect_version_signature(
    bytes: &[u8],
    python_abi: Option<(u8, u8)>,
) -> NuitkaVersionReport {
    let mut best: Option<(usize, i64)> = None;

    for (index, sig) in VERSION_DB.iter().enumerate() {
        if !abi_in_range(python_abi, sig.py_abi_min, sig.py_abi_max) {
            continue;
        }
        let present_hits: i64 = sig
            .present
            .iter()
            .filter(|needle: &&&[u8]| find_subslice(bytes, needle).is_some())
            .count() as i64;
        let absent_hits: i64 = sig
            .absent
            .iter()
            .filter(|needle: &&&[u8]| find_subslice(bytes, needle).is_some())
            .count() as i64;
        let score: i64 = present_hits - 1000 * absent_hits;
        if score <= 0 {
            continue;
        }
        match best {
            Some((_, best_score)) if best_score > score => {}
            _ => best = Some((index, score)),
        }
    }

    let Some((index, _)): Option<(usize, i64)> = best else {
        return NuitkaVersionReport {
            confidence: VersionConfidence::Unknown,
            exact: None,
            era: None,
            era_label: None,
            python_abi,
            matched_present: Vec::new(),
            matched_absent_violations: Vec::new(),
        };
    };

    let sig: &VersionSignature = &VERSION_DB[index];
    let matched_present: Vec<String> = sig
        .present
        .iter()
        .filter(|needle: &&&[u8]| find_subslice(bytes, needle).is_some())
        .map(|needle: &&[u8]| String::from_utf8_lossy(needle).into_owned())
        .collect();
    let matched_absent_violations: Vec<String> = sig
        .absent
        .iter()
        .filter(|needle: &&&[u8]| find_subslice(bytes, needle).is_some())
        .map(|needle: &&[u8]| String::from_utf8_lossy(needle).into_owned())
        .collect();

    NuitkaVersionReport {
        confidence: VersionConfidence::Range,
        exact: None,
        era: Some(format!("{:?}", sig.era)),
        era_label: Some(sig.label.to_owned()),
        python_abi,
        matched_present,
        matched_absent_violations,
    }
}

#[must_use]
pub fn detect_nuitka_version(
    binary: &[u8],
    constants_c: Option<&[u8]>,
    python_abi: Option<(u8, u8)>,
) -> NuitkaVersionReport {
    if let Some(c_source) = constants_c
        && let Some(exact) = parse_exact_version_from_constants_c(c_source)
    {
        let mut report: NuitkaVersionReport = detect_version_signature(binary, python_abi);
        report.confidence = VersionConfidence::Exact;
        report.exact = Some(exact);
        return report;
    }
    detect_version_signature(binary, python_abi)
}

fn abi_in_range(abi: Option<(u8, u8)>, min: Option<(u8, u8)>, max: Option<(u8, u8)>) -> bool {
    let Some(abi_pair): Option<(u8, u8)> = abi else {
        return true;
    };
    if let Some(lo) = min
        && abi_pair < lo
    {
        return false;
    }
    if let Some(hi) = max
        && abi_pair > hi
    {
        return false;
    }
    true
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    const MODULE_CONSTANTS_C: &[u8] =
        include_bytes!("../../../corpus/python/nuitka/module/hello.build/__constants.c");

    #[test]
    fn parses_exact_version_4_1_1_release() {
        let v: ExactNuitkaVersion =
            parse_exact_version_from_constants_c(MODULE_CONSTANTS_C).expect("version block");
        assert_eq!((v.major, v.minor, v.micro), (4, 1, 1));
        assert_eq!(v.release_level, "release");
    }

    #[test]
    fn missing_version_block_returns_none() {
        let junk: &[u8] = b"no version block here";
        assert!(parse_exact_version_from_constants_c(junk).is_none());
    }

    #[test]
    fn scan_ascii_u32_reads_multi_digit() {
        assert_eq!(scan_ascii_u32(b"4123)", 0), Some(4123));
        assert_eq!(scan_ascii_u32(b")", 0), None);
    }

    #[test]
    fn detect_version_signature_picks_modern_loader() {
        let mut bytes: Vec<u8> = vec![0u8; 8192];
        bytes[0..18].copy_from_slice(b"__nuitka_version__");
        bytes[100..120].copy_from_slice(b"nuitka_module_loader");
        bytes[200..222].copy_from_slice(b"nuitka_resource_reader");
        bytes[300..319].copy_from_slice(b"nuitka_distribution");
        bytes[400..429].copy_from_slice(b"Nuitka_Err_NormalizeException");
        bytes[500..512].copy_from_slice(b"__compiled__");
        let report: NuitkaVersionReport = detect_version_signature(&bytes, Some((3, 14)));
        assert_eq!(report.confidence, VersionConfidence::Range);
        assert_eq!(report.era_label.as_deref(), Some(VERSION_DB[2].label));
        assert!(
            report
                .matched_present
                .iter()
                .any(|s: &String| s == "__compiled__")
        );
    }

    #[test]
    fn detect_version_signature_unknown_on_empty() {
        let report: NuitkaVersionReport = detect_version_signature(&[], None);
        assert_eq!(report.confidence, VersionConfidence::Unknown);
        assert!(report.era.is_none());
    }

    #[test]
    fn absent_violation_disqualifies_older_row() {
        let mut bytes: Vec<u8> = vec![0u8; 8192];
        bytes[0..21].copy_from_slice(b"createGlobalConstants");
        bytes[100..117].copy_from_slice(b"loadConstantsBlob");
        bytes[200..220].copy_from_slice(b"nuitka_module_loader");
        let report: NuitkaVersionReport = detect_version_signature(&bytes, Some((3, 9)));
        assert_ne!(report.era_label.as_deref(), Some(VERSION_DB[0].label));
    }

    #[test]
    fn detect_nuitka_version_prefers_exact_from_constants_c() {
        let report: NuitkaVersionReport =
            detect_nuitka_version(&[], Some(MODULE_CONSTANTS_C), Some((3, 14)));
        assert_eq!(report.confidence, VersionConfidence::Exact);
        let exact: &ExactNuitkaVersion = report.exact.as_ref().expect("exact");
        assert_eq!((exact.major, exact.minor, exact.micro), (4, 1, 1));
    }

    #[test]
    fn abi_range_excludes_below_minimum() {
        assert!(!abi_in_range(Some((3, 9)), Some((3, 11)), None));
        assert!(abi_in_range(Some((3, 14)), Some((3, 11)), None));
        assert!(abi_in_range(None, Some((3, 11)), Some((3, 12))));
    }
}
