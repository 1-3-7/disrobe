//! Deterministic precedence comparator for [`super::detection::DetectVerdict`].
//!
//! Implements section §7.1 of the chain-detect spec: the comparator is total,
//! has no wall-clock or hashmap-ordering input, and breaks every tie
//! lexicographically on `pass_id`. Same registry + same input always yields
//! the same pick, byte-for-byte.

use std::cmp::Ordering;

use super::detection::DetectVerdict;

pub const FAMILY_OBFUSCATOR_WRAPPER: &str = "obfuscator-wrapper";
pub const FAMILY_PACKER_ARCHIVE: &str = "packer-archive";
pub const FAMILY_INTERPRETER_BYTECODE: &str = "interpreter-bytecode";
pub const FAMILY_SOURCE: &str = "source";
pub const FAMILY_CONTAINER: &str = "container";
pub const FAMILY_NATIVE_FORMAT: &str = "native-format";
pub const FAMILY_UNKNOWN: &str = "unknown";

/// Family precedence table (spec §7.4). Lower number = ranked first.
///
/// ```
/// # #[cfg(feature = "chain")] {
/// use disrobe_core::chain::{family_precedence,
///     FAMILY_OBFUSCATOR_WRAPPER, FAMILY_INTERPRETER_BYTECODE};
/// assert!(family_precedence(FAMILY_OBFUSCATOR_WRAPPER)
///     < family_precedence(FAMILY_INTERPRETER_BYTECODE));
/// # }
/// ```
#[inline]
#[must_use]
pub fn family_precedence(family: &str) -> u16 {
    match family {
        FAMILY_OBFUSCATOR_WRAPPER => 10,
        FAMILY_PACKER_ARCHIVE => 20,
        FAMILY_INTERPRETER_BYTECODE => 30,
        FAMILY_SOURCE => 40,
        FAMILY_CONTAINER => 50,
        FAMILY_NATIVE_FORMAT => 60,
        FAMILY_UNKNOWN => 100,
        _ => 200,
    }
}

/// Total ordering for verdicts. Larger = wins.
///
/// Order of comparison keys (each subsequent key is only consulted when the
/// previous ones tie):
/// 1. `band` (High > Medium > Low)
/// 2. `confidence` (numeric, larger wins)
/// 3. `specificity` (smaller wins, i.e. more specific)
/// 4. `family_precedence(family)` (smaller wins)
/// 5. `pass_id` lexicographic (smaller wins - deterministic tiebreak)
///
/// `Ordering::Greater` means `a` wins over `b`. Sort descending
/// (`v.sort_by(|x, y| compare(x, y).reverse())`) to put the winner at
/// position 0.
///
/// ```
/// # #[cfg(feature = "chain")] {
/// use std::cmp::Ordering;
/// use disrobe_core::chain::{compare, DetectVerdict};
/// let high: DetectVerdict = DetectVerdict::new(
///     "p.high", "t", "obfuscator-wrapper", 0.95, 10, vec![], "".into());
/// let low: DetectVerdict = DetectVerdict::new(
///     "p.low",  "t", "obfuscator-wrapper", 0.60, 10, vec![], "".into());
/// assert_eq!(compare(&high, &low), Ordering::Greater);
/// # }
/// ```
#[must_use]
pub fn compare(a: &DetectVerdict, b: &DetectVerdict) -> Ordering {
    let by_band: Ordering = a.band.cmp(&b.band);
    if by_band != Ordering::Equal {
        return by_band;
    }
    let by_conf: Ordering = a
        .confidence
        .partial_cmp(&b.confidence)
        .unwrap_or(Ordering::Equal);
    if by_conf != Ordering::Equal {
        return by_conf;
    }
    let by_spec: Ordering = b.specificity.cmp(&a.specificity);
    if by_spec != Ordering::Equal {
        return by_spec;
    }
    let by_family: Ordering = family_precedence(b.family).cmp(&family_precedence(a.family));
    if by_family != Ordering::Equal {
        return by_family;
    }
    b.pass_id.cmp(a.pass_id)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::float_cmp)]
mod tests {
    use super::*;

    fn mk(
        pass_id: &'static str,
        family: &'static str,
        confidence: f32,
        specificity: u16,
    ) -> DetectVerdict {
        DetectVerdict::new(
            pass_id,
            "tag",
            family,
            confidence,
            specificity,
            vec![],
            String::new(),
        )
    }

    #[test]
    fn band_dominates_over_confidence() {
        let high_low_conf: DetectVerdict = mk("a", FAMILY_OBFUSCATOR_WRAPPER, 0.91, 10);
        let med_high_conf: DetectVerdict = mk("b", FAMILY_OBFUSCATOR_WRAPPER, 0.89, 10);
        assert_eq!(compare(&high_low_conf, &med_high_conf), Ordering::Greater);
    }

    #[test]
    fn higher_confidence_wins_within_band() {
        let a: DetectVerdict = mk("a", FAMILY_OBFUSCATOR_WRAPPER, 0.95, 10);
        let b: DetectVerdict = mk("b", FAMILY_OBFUSCATOR_WRAPPER, 0.92, 10);
        assert_eq!(compare(&a, &b), Ordering::Greater);
    }

    #[test]
    fn lower_specificity_wins_at_confidence_tie() {
        let pyarmor: DetectVerdict = mk("pyarmor.unpack", FAMILY_OBFUSCATOR_WRAPPER, 0.95, 10);
        let pyc: DetectVerdict = mk("py.decompile", FAMILY_OBFUSCATOR_WRAPPER, 0.95, 50);
        assert_eq!(compare(&pyarmor, &pyc), Ordering::Greater);
    }

    #[test]
    fn family_breaks_specificity_tie() {
        let wrapper: DetectVerdict = mk("zzz", FAMILY_OBFUSCATOR_WRAPPER, 0.95, 30);
        let bytecode: DetectVerdict = mk("aaa", FAMILY_INTERPRETER_BYTECODE, 0.95, 30);
        assert_eq!(compare(&wrapper, &bytecode), Ordering::Greater);
    }

    #[test]
    fn lex_pass_id_breaks_full_tie() {
        let a: DetectVerdict = mk("aaa", FAMILY_OBFUSCATOR_WRAPPER, 0.95, 10);
        let b: DetectVerdict = mk("bbb", FAMILY_OBFUSCATOR_WRAPPER, 0.95, 10);
        assert_eq!(compare(&a, &b), Ordering::Greater);
    }

    #[test]
    fn equal_verdicts_compare_equal() {
        let a: DetectVerdict = mk("same", FAMILY_OBFUSCATOR_WRAPPER, 0.95, 10);
        let b: DetectVerdict = mk("same", FAMILY_OBFUSCATOR_WRAPPER, 0.95, 10);
        assert_eq!(compare(&a, &b), Ordering::Equal);
    }

    #[test]
    fn family_table_known_ranks() {
        assert_eq!(family_precedence(FAMILY_OBFUSCATOR_WRAPPER), 10);
        assert_eq!(family_precedence(FAMILY_PACKER_ARCHIVE), 20);
        assert_eq!(family_precedence(FAMILY_INTERPRETER_BYTECODE), 30);
        assert_eq!(family_precedence(FAMILY_SOURCE), 40);
        assert_eq!(family_precedence(FAMILY_CONTAINER), 50);
        assert_eq!(family_precedence(FAMILY_NATIVE_FORMAT), 60);
        assert_eq!(family_precedence(FAMILY_UNKNOWN), 100);
        assert_eq!(family_precedence("never-heard-of-it"), 200);
    }

    #[test]
    fn sort_picks_winner_at_position_zero() {
        let mut v: Vec<DetectVerdict> = vec![
            mk("c", FAMILY_INTERPRETER_BYTECODE, 0.80, 50),
            mk("a", FAMILY_OBFUSCATOR_WRAPPER, 0.95, 10),
            mk("b", FAMILY_PACKER_ARCHIVE, 0.90, 20),
        ];
        v.sort_by(|x: &DetectVerdict, y: &DetectVerdict| compare(x, y).reverse());
        assert_eq!(v[0].pass_id, "a");
        assert_eq!(v[1].pass_id, "b");
        assert_eq!(v[2].pass_id, "c");
    }
}
