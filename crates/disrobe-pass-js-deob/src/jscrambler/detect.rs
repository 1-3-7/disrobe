use std::collections::BTreeSet;

use regex::Regex;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum JscramblerTier {
    Free,
    Paid,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum JscramblerTransform {
    BooleanToAnything,
    CharToTernaryOperator,
    CommaOperatorUnfolding,
    ControlFlowFlattening,
    DeadCodeInjection,
    DotToBracketNotation,
    DuplicateLiteralsRemoval,
    ExtendPredicates,
    FunctionOutlining,
    FunctionReordering,
    GlobalVariableIndirection,
    IdentifiersRenaming,
    NumberToString,
    ObjectPropertiesSparsing,
    PropertyKeysObfuscation,
    PropertyKeysReordering,
    RegexObfuscation,
    StringConcealing,
    StringEncoding,
    VariableGrouping,
    VariableMasking,
    AssertionsRemoval,
    ConstantFolding,
    DeadCodeElimination,
    DebugCodeElimination,
    WhitespaceRemoval,
    AntiDebugging,
    AntiMonkeyPatching,
    AntiTampering,
    DeadObjects,
    SelfDefending,
    SelfHealing,
    BrowserLock,
    DateLock,
    DomainLock,
    OsLock,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum CodeLockKind {
    Browser,
    Date,
    Domain,
    Os,
}

#[derive(Debug, Clone, Serialize)]
pub struct JscramblerDetection {
    pub tier: JscramblerTier,
    pub matched: bool,
    pub confidence: f32,
    pub a0_hex_ident_count: usize,
    pub integrity_loop_count: usize,
    pub has_jscrambler_banner: bool,
    pub markers: Vec<String>,
    pub detected_transforms: BTreeSet<JscramblerTransform>,
    pub code_locks: BTreeSet<CodeLockKind>,
}

const HEAD_SCAN_BYTES: usize = 128 * 1024;
const FREE_TIER_IDENT_DENSITY_FLOOR: usize = 5;

#[must_use]
pub fn detect_free_tier(source: &str) -> JscramblerDetection {
    detect_full(source)
}

#[must_use]
pub fn detect_full(source: &str) -> JscramblerDetection {
    let head: &str = &source[..source.len().min(HEAD_SCAN_BYTES)];
    let banner: bool = head.contains("jscrambler") || head.contains("Jscrambler");
    let a0_hex_ident_count: usize = count_a0_hex_idents(head);
    let integrity_loop_count: usize = count_integrity_loops(head);

    let mut markers: Vec<String> = Vec::new();
    if banner {
        markers.push("jscrambler-banner".to_owned());
    }
    if a0_hex_ident_count >= FREE_TIER_IDENT_DENSITY_FLOOR {
        markers.push(format!("a0-hex-ident-density:{a0_hex_ident_count}"));
    }
    if integrity_loop_count > 0 {
        markers.push(format!("integrity-loop:{integrity_loop_count}"));
    }

    let dense_idents: bool = a0_hex_ident_count >= FREE_TIER_IDENT_DENSITY_FLOOR;
    let has_integrity: bool = integrity_loop_count > 0;
    let matched: bool = dense_idents && (has_integrity || banner);
    let tier: JscramblerTier = if matched {
        JscramblerTier::Free
    } else if banner {
        JscramblerTier::Paid
    } else {
        JscramblerTier::Unknown
    };
    let confidence: f32 = if matched {
        let base: f32 = 0.6;
        let banner_bonus: f32 = if banner { 0.15 } else { 0.0 };
        let integrity_bonus: f32 = if has_integrity { 0.15 } else { 0.0 };
        (base + banner_bonus + integrity_bonus).min(0.97)
    } else if banner {
        0.5
    } else {
        0.0
    };

    let detected_transforms: BTreeSet<JscramblerTransform> = scan_transforms(source);
    let code_locks: BTreeSet<CodeLockKind> = scan_code_locks(&detected_transforms);
    for t in &detected_transforms {
        markers.push(format!("transform:{t:?}"));
    }

    JscramblerDetection {
        tier,
        matched,
        confidence,
        a0_hex_ident_count,
        integrity_loop_count,
        has_jscrambler_banner: banner,
        markers,
        detected_transforms,
        code_locks,
    }
}

fn count_a0_hex_idents(text: &str) -> usize {
    let Ok(re): core::result::Result<Regex, regex::Error> =
        Regex::new(r"\ba\d{1,2}_0x[0-9a-fA-F]{4,6}\b")
    else {
        return 0;
    };
    re.find_iter(text).count()
}

fn count_integrity_loops(text: &str) -> usize {
    let mut total: usize = 0;
    for pattern in [
        r"while\s*\(\s*!!\[\]\s*\)\s*\{",
        r"while\s*\(\s*!\[\]\s*\)\s*\{",
        r"for\s*\(\s*;;\s*\)\s*\{",
        r"while\s*\(\s*true\s*\)\s*\{",
    ] {
        if let Ok(re) = Regex::new(pattern) {
            total += re.find_iter(text).count();
        }
    }
    total
}

fn scan_transforms(source: &str) -> BTreeSet<JscramblerTransform> {
    use super::dispatch_detect;
    let candidates: [JscramblerTransform; 36] = [
        JscramblerTransform::BooleanToAnything,
        JscramblerTransform::CharToTernaryOperator,
        JscramblerTransform::CommaOperatorUnfolding,
        JscramblerTransform::ControlFlowFlattening,
        JscramblerTransform::DeadCodeInjection,
        JscramblerTransform::DotToBracketNotation,
        JscramblerTransform::DuplicateLiteralsRemoval,
        JscramblerTransform::ExtendPredicates,
        JscramblerTransform::FunctionOutlining,
        JscramblerTransform::FunctionReordering,
        JscramblerTransform::GlobalVariableIndirection,
        JscramblerTransform::IdentifiersRenaming,
        JscramblerTransform::NumberToString,
        JscramblerTransform::ObjectPropertiesSparsing,
        JscramblerTransform::PropertyKeysObfuscation,
        JscramblerTransform::PropertyKeysReordering,
        JscramblerTransform::RegexObfuscation,
        JscramblerTransform::StringConcealing,
        JscramblerTransform::StringEncoding,
        JscramblerTransform::VariableGrouping,
        JscramblerTransform::VariableMasking,
        JscramblerTransform::AssertionsRemoval,
        JscramblerTransform::ConstantFolding,
        JscramblerTransform::DeadCodeElimination,
        JscramblerTransform::DebugCodeElimination,
        JscramblerTransform::WhitespaceRemoval,
        JscramblerTransform::AntiDebugging,
        JscramblerTransform::AntiMonkeyPatching,
        JscramblerTransform::AntiTampering,
        JscramblerTransform::DeadObjects,
        JscramblerTransform::SelfDefending,
        JscramblerTransform::SelfHealing,
        JscramblerTransform::BrowserLock,
        JscramblerTransform::DateLock,
        JscramblerTransform::DomainLock,
        JscramblerTransform::OsLock,
    ];
    let mut out: BTreeSet<JscramblerTransform> = BTreeSet::new();
    for t in candidates {
        if dispatch_detect(t, source) > 0 {
            out.insert(t);
        }
    }
    out
}

fn scan_code_locks(transforms: &BTreeSet<JscramblerTransform>) -> BTreeSet<CodeLockKind> {
    let mut out: BTreeSet<CodeLockKind> = BTreeSet::new();
    if transforms.contains(&JscramblerTransform::BrowserLock) {
        out.insert(CodeLockKind::Browser);
    }
    if transforms.contains(&JscramblerTransform::DateLock) {
        out.insert(CodeLockKind::Date);
    }
    if transforms.contains(&JscramblerTransform::DomainLock) {
        out.insert(CodeLockKind::Domain);
    }
    if transforms.contains(&JscramblerTransform::OsLock) {
        out.insert(CodeLockKind::Os);
    }
    out
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn detects_free_tier_via_a0_idents_and_integrity_loop() {
        let src: &str = "
            var a0_0xabcd = 1;
            var a0_0xbeef = 2;
            var a1_0xfeed = 3;
            var a0_0xdead = 4;
            var a2_0xc0de = 5;
            (function () { while (!![]) { var x = 1; } }());
        ";
        let det: JscramblerDetection = detect_free_tier(src);
        assert!(
            det.matched,
            "expected matched; got idents={} loops={} banner={}",
            det.a0_hex_ident_count, det.integrity_loop_count, det.has_jscrambler_banner
        );
        assert_eq!(det.tier, JscramblerTier::Free);
        assert!(det.a0_hex_ident_count >= 5);
        assert!(det.integrity_loop_count >= 1);
    }

    #[test]
    fn paid_tier_when_only_banner() {
        let src: &str = "/* Jscrambler License */ const x = 1;";
        let det: JscramblerDetection = detect_free_tier(src);
        assert_eq!(det.tier, JscramblerTier::Paid);
        assert!(det.has_jscrambler_banner);
        assert!(!det.matched);
    }

    #[test]
    fn unknown_for_clean_source() {
        let src: &str = "const x = 1; function f(): number { return x + 1; }";
        let det: JscramblerDetection = detect_free_tier(src);
        assert_eq!(det.tier, JscramblerTier::Unknown);
        assert!(!det.matched);
    }

    #[test]
    fn detect_full_finds_transforms() {
        let src: &str = "var alias = console; alias.log('x'); if (![]) { y(); }";
        let det: JscramblerDetection = detect_full(src);
        assert!(
            det.detected_transforms
                .contains(&JscramblerTransform::BooleanToAnything)
        );
        assert!(
            det.detected_transforms
                .contains(&JscramblerTransform::VariableMasking)
        );
    }

    #[test]
    fn detect_full_finds_browser_lock() {
        let src: &str = "if (navigator.userAgent.indexOf('Chrome') !== -1) { run(); }";
        let det: JscramblerDetection = detect_full(src);
        assert!(det.code_locks.contains(&CodeLockKind::Browser));
    }
}
