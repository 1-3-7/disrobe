#![allow(clippy::doc_markdown)]
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::debug::dbg_kv;
use crate::error::Result;
use crate::peel::obfuscar_strings::{
    MAX_IMAGE_BYTES, ObfuscarScanState, ObfuscarStringRecovery, recover_obfuscar_strings_with_state,
};
use crate::peel::{
    HeapsView, NameClassification, PeelReport, PeelStrategy, classify_names, read_heaps,
    static_decrypt,
};
use crate::protectors::Protector;

pub const OBFUSCAR_ALPHABET: &[u8; 52] = b"AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz";

const ODOMETER_CEILING: u32 = 20_000;

const STRONG_RUN: usize = 4;

const WEAK_RUN: usize = 2;

const LOW_CORE_MIN: usize = 4;

const LOW_CORE_BAND_FACTOR: u32 = 4;

const RADIX: u32 = OBFUSCAR_ALPHABET.len() as u32;

#[must_use]
pub fn unique_name(index: u32) -> String {
    let mut digits: Vec<u8> = Vec::with_capacity(4);
    let mut n: u32 = index;
    loop {
        digits.push(OBFUSCAR_ALPHABET[(n % RADIX) as usize]);
        if n < RADIX {
            break;
        }
        n /= RADIX;
    }
    digits.reverse();
    String::from_utf8(digits).unwrap_or_default()
}

#[must_use]
pub fn odometer_index(name: &str) -> Option<u32> {
    if name.is_empty() {
        return None;
    }
    let mut acc: u64 = 0;
    for c in name.chars() {
        let pos: usize = OBFUSCAR_ALPHABET
            .iter()
            .position(|&a: &u8| a == c as u8 && c.is_ascii())?;
        acc = acc.checked_mul(u64::from(RADIX))?.checked_add(pos as u64)?;
        if acc > u64::from(ODOMETER_CEILING) {
            return None;
        }
    }
    u32::try_from(acc).ok()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObfuscarEvidence {
    pub odometer_members: u32,

    pub longest_run: u32,

    pub max_index: u32,

    pub is_obfuscar: bool,
}

#[must_use]
pub fn classify_obfuscar_naming(strings: &BTreeMap<u32, String>) -> ObfuscarEvidence {
    let mut indices: Vec<u32> = strings
        .values()
        .filter_map(|s: &String| odometer_index(s))
        .collect();
    indices.sort_unstable();
    indices.dedup();

    let members: u32 = u32::try_from(indices.len()).unwrap_or(u32::MAX);
    if indices.len() < WEAK_RUN {
        return ObfuscarEvidence {
            odometer_members: members,
            longest_run: members,
            max_index: indices.last().copied().unwrap_or(0),
            is_obfuscar: false,
        };
    }

    let mut longest: usize = 1;
    let mut longest_multichar: usize = 1;
    let mut current: usize = 1;
    let mut current_has_multichar: bool = indices[0] >= RADIX;
    for w in indices.windows(2) {
        if w[1] == w[0] + 1 {
            current += 1;
            current_has_multichar = current_has_multichar || w[1] >= RADIX;
            longest = longest.max(current);
            if current_has_multichar {
                longest_multichar = longest_multichar.max(current);
            }
        } else {
            current = 1;
            current_has_multichar = w[1] >= RADIX;
        }
    }
    let max_index: u32 = indices.last().copied().unwrap_or(0);
    let span: u32 = max_index.saturating_add(1);
    let dense_low_cluster: bool = longest >= WEAK_RUN
        && u64::from(members) * 2 >= u64::from(span)
        && u64::from(max_index) <= u64::from(members) * 3;
    let dense_low_core: bool = has_dense_low_core(&indices);
    let is_obfuscar: bool = longest_multichar >= STRONG_RUN || dense_low_cluster || dense_low_core;

    ObfuscarEvidence {
        odometer_members: members,
        longest_run: u32::try_from(longest).unwrap_or(u32::MAX),
        max_index,
        is_obfuscar,
    }
}

fn has_dense_low_core(indices: &[u32]) -> bool {
    let members: usize = indices.len();
    if members < LOW_CORE_MIN {
        return false;
    }
    let band: u32 =
        u32::try_from(members.saturating_mul(LOW_CORE_BAND_FACTOR as usize)).unwrap_or(u32::MAX);
    let core: Vec<u32> = indices
        .iter()
        .copied()
        .filter(|&i: &u32| i <= band)
        .collect();
    let core_count: usize = core.len();
    if core_count < LOW_CORE_MIN {
        return false;
    }
    let core_max: u32 = core.last().copied().unwrap_or(0);
    let core_span: u64 = u64::from(core_max).saturating_add(1);
    let starts_at_zero: bool = core.first() == Some(&0);
    let min_fill_numerator: u64 = if starts_at_zero { 9 } else { 10 };
    u64::from(u32::try_from(core_count).unwrap_or(u32::MAX)) * 20 >= core_span * min_fill_numerator
}

#[must_use]
pub fn detect_obfuscar(image: &[u8]) -> bool {
    if image.len() > MAX_IMAGE_BYTES {
        return false;
    }
    let Ok(heaps): Result<HeapsView> = read_heaps(image) else {
        return false;
    };
    classify_obfuscar_naming(&heaps.strings).is_obfuscar
}

pub fn peel_obfuscar(bytes: &[u8]) -> Result<PeelReport> {
    let (recovery, scan_state): (ObfuscarStringRecovery, ObfuscarScanState) =
        recover_obfuscar_strings_with_state(bytes);
    if scan_state == ObfuscarScanState::Rejected {
        return Ok(rejected_report(bytes, recovery));
    }
    let heaps: HeapsView = read_heaps(bytes)?;
    let classification: NameClassification = classify_names(&heaps.strings);
    let evidence: ObfuscarEvidence = classify_obfuscar_naming(&heaps.strings);
    let bytes_in: u32 = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    let decoders: static_decrypt::StaticDecryptReport =
        static_decrypt::recover_static_decoders(bytes).unwrap_or_default();
    dbg_kv("obfuscar-strings", || {
        format!(
            "carriers={} accessors={} recovered={} state={}",
            recovery.carrier_count,
            recovery.accessor_count,
            recovery.recovered.len(),
            if recovery.unknown_reason.is_some() {
                "unknown"
            } else {
                "complete"
            }
        )
    });
    let mut report: PeelReport = PeelReport {
        protector: Protector::Obfuscar,
        strategy: PeelStrategy::AttributeStripAndReport,
        attributes_stripped: Vec::new(),
        strings_total: u32::try_from(heaps.strings.len()).unwrap_or(u32::MAX),
        strings_obfuscated_count: classification.renamable,
        us_strings_total: u32::try_from(heaps.us_strings.len()).unwrap_or(u32::MAX),
        renamable_identifiers: classification.renamable,
        unobfuscatable_identifiers: classification.human,
        bytes_in,
        bytes_out: bytes_in,
        recovered_decoders: decoders.pure_decoders_found,
        recovered_constants: decoders.constants_recovered,
        recovered_strings: Vec::new(),
        recovered_methods: Vec::new(),
        recovered_resources: Vec::new(),
        notes: vec![format!(
            "Obfuscar NameMaker odometer detected: {} base-52 members, longest contiguous run {}, \
             max index {}. Default config embeds no in-PE name map; original identifiers are not \
             statically recoverable (the optional Mapping.txt is written beside the build, not into \
             the assembly). Renamed slots classified and reported.",
            evidence.odometer_members, evidence.longest_run, evidence.max_index
        )],
        native_surface: None,
    };
    if let Some(reason) = recovery.unknown_reason {
        report
            .notes
            .push(format!("Obfuscar HideStrings: Unknown ({reason})."));
    } else {
        let recovered_count: usize = recovery.recovered.len();
        report.strategy = PeelStrategy::StaticStringRecovery;
        report.recovered_strings = recovery.recovered;
        let literal_label: &str = if recovered_count == 1 {
            "literal"
        } else {
            "literals"
        };
        report.notes.push(format!(
            "Obfuscar HideStrings: recovered {recovered_count}/{} UTF-8 {literal_label} from {} complete FieldRVA carrier graph.",
            recovery.accessor_count, recovery.carrier_count
        ));
    }
    Ok(report)
}

fn rejected_report(bytes: &[u8], recovery: ObfuscarStringRecovery) -> PeelReport {
    let bytes_in: u32 = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    let reason: String = recovery
        .unknown_reason
        .unwrap_or_else(|| "bounded structural scan rejected the image".to_owned());
    PeelReport {
        protector: Protector::Obfuscar,
        strategy: PeelStrategy::AttributeStripAndReport,
        attributes_stripped: Vec::new(),
        strings_total: 0,
        strings_obfuscated_count: 0,
        us_strings_total: 0,
        renamable_identifiers: 0,
        unobfuscatable_identifiers: 0,
        bytes_in,
        bytes_out: bytes_in,
        recovered_decoders: 0,
        recovered_constants: Vec::new(),
        recovered_strings: Vec::new(),
        recovered_methods: Vec::new(),
        recovered_resources: Vec::new(),
        notes: vec![format!("Obfuscar HideStrings: Unknown ({reason}).")],
        native_surface: None,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn unique_name_matches_upstream_namemaker() {
        assert_eq!(unique_name(0), "A");
        assert_eq!(unique_name(1), "a");
        assert_eq!(unique_name(2), "B");
        assert_eq!(unique_name(51), "z");
        assert_eq!(unique_name(52), "aA");
        assert_eq!(unique_name(53), "aa");
        assert_eq!(unique_name(104), "BA");
    }

    #[test]
    fn odometer_index_is_exact_inverse() {
        for i in [0u32, 1, 2, 51, 52, 53, 104, 105, 2703, 19_999] {
            assert_eq!(odometer_index(&unique_name(i)), Some(i), "index {i}");
        }
    }

    #[test]
    fn odometer_index_rejects_non_alphabet_and_overflow() {
        assert_eq!(odometer_index("_123"), None);
        assert_eq!(odometer_index("Greeting"), None);
        assert_eq!(odometer_index(""), None);
        assert_eq!(odometer_index("aaaaaaaa"), None);
    }

    #[test]
    fn alphabet_has_52_distinct_chars() {
        let mut seen: Vec<u8> = OBFUSCAR_ALPHABET.to_vec();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), 52);
    }

    fn heap(names: &[&str]) -> BTreeMap<u32, String> {
        names
            .iter()
            .enumerate()
            .map(|(i, n): (usize, &&str)| (i as u32, (*n).to_string()))
            .collect()
    }

    #[test]
    fn detects_dense_two_char_odometer_block() {
        let names: Vec<String> = (52..80u32).map(unique_name).collect();
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        let ev: ObfuscarEvidence = classify_obfuscar_naming(&heap(&refs));
        assert!(ev.is_obfuscar, "{ev:?}");
        assert!(ev.longest_run >= STRONG_RUN as u32);
    }

    #[test]
    fn detects_tiny_two_member_prefix() {
        let ev: ObfuscarEvidence = classify_obfuscar_naming(&heap(&["A", "a", "Greeting", "name"]));
        assert!(ev.is_obfuscar, "small A,a cluster must be Obfuscar: {ev:?}");
    }

    #[test]
    fn human_names_in_alphabet_are_not_obfuscar() {
        let ev: ObfuscarEvidence = classify_obfuscar_naming(&heap(&[
            "Cat",
            "Dog",
            "Bfs",
            "Dfs",
            "ParseFile",
            "Greeting",
        ]));
        assert!(
            !ev.is_obfuscar,
            "scattered human names must not flag: {ev:?}"
        );
    }

    #[test]
    fn confuser_underscore_names_are_not_obfuscar() {
        let ev: ObfuscarEvidence =
            classify_obfuscar_naming(&heap(&["_1234", "_5678", "\u{200b}x", "pb", "lc", "lp"]));
        assert!(
            !ev.is_obfuscar,
            "Confuser-style names must not flag: {ev:?}"
        );
    }

    #[test]
    fn empty_heap_is_not_obfuscar() {
        let ev: ObfuscarEvidence = classify_obfuscar_naming(&heap(&[]));
        assert!(!ev.is_obfuscar);
    }

    #[test]
    fn dense_low_core_survives_bcl_outlier() {
        let mut names: Vec<String> = [0u32, 1, 4, 6, 8, 10, 11, 12, 14]
            .iter()
            .map(|i: &u32| unique_name(*i))
            .collect();
        names.push("Add".to_string());
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        let ev: ObfuscarEvidence = classify_obfuscar_naming(&heap(&refs));
        assert!(
            ev.is_obfuscar,
            "real Obfuscar #Strings shape (dense low odometer core + a BCL collision like Add) \
             must flag: {ev:?}"
        );
    }

    #[test]
    fn single_letter_run_alone_is_not_obfuscar() {
        let low: [u32; 38] = [
            0, 1, 2, 3, 4, 5, 7, 9, 10, 11, 13, 15, 17, 19, 20, 21, 23, 25, 27, 29, 31, 32, 33, 34,
            35, 37, 38, 39, 41, 42, 43, 44, 45, 46, 47, 48, 49, 51,
        ];
        let high: [u32; 12] = [
            193, 299, 501, 797, 921, 1500, 3000, 6017, 10907, 14001, 16833, 19837,
        ];
        let names: Vec<String> = low
            .iter()
            .chain(high.iter())
            .map(|i: &u32| unique_name(*i))
            .collect();
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        let ev: ObfuscarEvidence = classify_obfuscar_naming(&heap(&refs));
        assert!(
            !ev.is_obfuscar,
            "the real FSharp.Core #Strings shape (a long run inside the single-letter band 0..51 \
             plus scattered high human-word indices, sparse overall) must not flag: {ev:?}"
        );
    }

    #[test]
    fn multichar_run_still_flags() {
        let names: Vec<String> = (52u32..58).map(unique_name).collect();
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        let ev: ObfuscarEvidence = classify_obfuscar_naming(&heap(&refs));
        assert!(
            ev.is_obfuscar,
            "a contiguous run of multi-character odometer names is genuine Obfuscar output and \
             must still flag: {ev:?}"
        );
    }

    #[test]
    fn sparse_high_indices_are_not_obfuscar() {
        let names: Vec<String> = [6017u32, 10907, 16833, 17745]
            .iter()
            .map(|i: &u32| unique_name(*i))
            .collect();
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        let ev: ObfuscarEvidence = classify_obfuscar_naming(&heap(&refs));
        assert!(
            !ev.is_obfuscar,
            "human identifiers that happen to decode to scattered high indices must not flag: {ev:?}"
        );
    }
}
