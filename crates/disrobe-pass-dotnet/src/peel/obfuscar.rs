//! Obfuscar (FOSS, MIT) detection + peel.

#![allow(clippy::doc_markdown)]

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::peel::{
    HeapsView, NameClassification, PeelReport, PeelStrategy, classify_names, read_heaps,
    static_decrypt,
};
use crate::protectors::Protector;

/// Default `NameMaker` alphabet: 52 alternating-case ASCII letters, upstream order.
pub const OBFUSCAR_ALPHABET: &[u8; 52] = b"AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz";

/// Highest odometer index counted as a member.
const ODOMETER_CEILING: u32 = 20_000;

/// Minimum contiguous odometer run that alone proves Obfuscar renaming.
const STRONG_RUN: usize = 4;

/// Minimum contiguous run for the small-assembly path (paired with density guards).
const WEAK_RUN: usize = 2;

const RADIX: u32 = OBFUSCAR_ALPHABET.len() as u32;

/// Base-52 conversion over [`OBFUSCAR_ALPHABET`], most-significant digit first.
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

/// Closed-form inverse of [`unique_name`]: decode an identifier to its odometer index, or `None`.
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
    /// Distinct #Strings entries that are exact members of the odometer sequence.
    pub odometer_members: u32,
    /// Length of the longest run of consecutive odometer indices present in the heap.
    pub longest_run: u32,
    /// Highest odometer index observed; a from-zero renamer keeps this small and dense.
    pub max_index: u32,
    /// Final verdict: the naming is Obfuscar's `NameMaker` output.
    pub is_obfuscar: bool,
}

/// Inspect the #Strings heap for Obfuscar's `NameMaker` odometer fingerprint.
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
    let mut current: usize = 1;
    for w in indices.windows(2) {
        if w[1] == w[0] + 1 {
            current += 1;
            longest = longest.max(current);
        } else {
            current = 1;
        }
    }
    let max_index: u32 = indices.last().copied().unwrap_or(0);
    let span: u32 = max_index.saturating_add(1);
    let dense_low_cluster: bool = longest >= WEAK_RUN
        && u64::from(members) * 2 >= u64::from(span)
        && u64::from(max_index) <= u64::from(members) * 3;
    let is_obfuscar: bool = longest >= STRONG_RUN || dense_low_cluster;

    ObfuscarEvidence {
        odometer_members: members,
        longest_run: u32::try_from(longest).unwrap_or(u32::MAX),
        max_index,
        is_obfuscar,
    }
}

/// Heap-aware Obfuscar detection via the odometer discriminator, failing safe to `false`.
#[must_use]
pub fn detect_obfuscar(image: &[u8]) -> bool {
    let Ok(heaps): Result<HeapsView> = read_heaps(image) else {
        return false;
    };
    classify_obfuscar_naming(&heaps.strings).is_obfuscar
}

/// Report-only peel: classify the renamed slots and report.
pub fn peel_obfuscar(bytes: &[u8]) -> Result<PeelReport> {
    let heaps: HeapsView = read_heaps(bytes)?;
    let classification: NameClassification = classify_names(&heaps.strings);
    let evidence: ObfuscarEvidence = classify_obfuscar_naming(&heaps.strings);
    let bytes_in: u32 = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    let decoders: static_decrypt::StaticDecryptReport =
        static_decrypt::recover_static_decoders(bytes).unwrap_or_default();
    Ok(PeelReport {
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
        notes: vec![format!(
            "Obfuscar NameMaker odometer detected: {} base-52 members, longest contiguous run {}, \
             max index {}. Default config embeds no in-PE name map; original identifiers are not \
             statically recoverable (the optional Mapping.txt is written beside the build, not into \
             the assembly). Renamed slots classified and reported.",
            evidence.odometer_members, evidence.longest_run, evidence.max_index
        )],
    })
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
}
