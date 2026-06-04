use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::abc::AbcFile;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
pub enum ObfuscationSignal {
    StringEncryption,
    NameMangling,
    ControlFlowFlattening,
    DeadCodeInsertion,
    NumericLiteralBloat,
    RegisterShuffle,
    StringPoolRebuildCandidate,
}

/// A commercial AS3 obfuscator/packer fingerprinted from ABC artefacts.
///
/// Identified by vendor marker strings, decrypt-stub method names, or
/// characteristic constant-pool shapes. Detection is best-effort and never
/// destructive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
pub enum KnownTool {
    SecureSwf,
    DoSwf,
    Kindi,
    Irrfuscator,
    Swflock,
    GenericStringEncryptor,
}

impl KnownTool {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::SecureSwf => "secureSWF",
            Self::DoSwf => "DoSWF",
            Self::Kindi => "Kindi",
            Self::Irrfuscator => "Irrfuscator",
            Self::Swflock => "swfLock",
            Self::GenericStringEncryptor => "generic-string-encryptor",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ConfidenceScore(pub u8);

impl ConfidenceScore {
    pub const LOW: Self = Self(25);
    pub const MEDIUM: Self = Self(60);
    pub const HIGH: Self = Self(85);
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObfuscationReport {
    pub signals: BTreeMap<ObfuscationSignal, ConfidenceScore>,
    pub printable_string_ratio_percent: u8,
    pub identifier_mangle_ratio_percent: u8,
    pub control_flow_jump_density_percent: u8,
    pub register_shuffle_density_percent: u8,
    pub string_pool_rebuild_percent: u8,
    pub tools: Vec<KnownTool>,
}

fn printable_string_ratio(abc: &AbcFile) -> u8 {
    let total: usize = abc.cpool.strings.iter().filter(|s| !s.is_empty()).count();
    if total == 0 {
        return 100;
    }
    let printable: usize = abc
        .cpool
        .strings
        .iter()
        .filter(|s: &&String| !s.is_empty())
        .filter(|s: &&String| {
            s.chars()
                .all(|c: char| c.is_ascii_graphic() || c == ' ' || c == '\t')
        })
        .count();
    let pct: u64 = (printable as u64 * 100) / total as u64;
    pct.min(100) as u8
}

fn identifier_mangle_ratio(abc: &AbcFile) -> u8 {
    let mut total: usize = 0;
    let mut mangled: usize = 0;
    for inst in &abc.instances {
        if let Ok(rendered) = abc.cpool.render_multiname(inst.name_index) {
            total += 1;
            if is_mangled_identifier(&rendered) {
                mangled += 1;
            }
        }
    }
    for tr in abc.instances.iter().flat_map(|i| &i.traits) {
        if let Ok(name) = abc.cpool.string_at(tr.name_index) {
            total += 1;
            if is_mangled_identifier(name) {
                mangled += 1;
            }
        }
    }
    if total == 0 {
        return 0;
    }
    ((mangled as u64 * 100) / total as u64).min(100) as u8
}

fn is_mangled_identifier(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    if name.len() <= 2 && name.chars().all(|c: char| c.is_ascii_alphabetic()) {
        return true;
    }
    let non_ascii: usize = name.chars().filter(|c: &char| !c.is_ascii()).count();
    if non_ascii > 0 && (non_ascii * 100 / name.chars().count()) > 30 {
        return true;
    }
    let suspicious_prefix: bool = name
        .chars()
        .next()
        .is_some_and(|c: char| matches!(c, '_' | '$' | '\u{200B}' | '\u{200C}' | '\u{200D}'));
    if suspicious_prefix && name.len() > 6 {
        return true;
    }
    let hex_run: usize = name
        .chars()
        .filter(|c: &char| c.is_ascii_hexdigit())
        .count();
    if name.len() >= 8 && hex_run == name.len() {
        return true;
    }
    false
}

const JUMP_OPCODES: &[u8] = &[
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x0C, 0x0D, 0x0E, 0x0F, 0x1B,
];

fn control_flow_jump_density(abc: &AbcFile) -> u8 {
    let mut total: u64 = 0;
    let mut jumps: u64 = 0;
    for body in &abc.method_bodies {
        total += body.code.len() as u64;
        jumps += body
            .code
            .iter()
            .filter(|b: &&u8| JUMP_OPCODES.contains(*b))
            .count() as u64;
    }
    if total == 0 {
        return 0;
    }
    ((jumps * 1000) / total).min(100) as u8
}

const STACK_SHUFFLE_OPCODES: &[u8] = &[0x29, 0x2A, 0x2B];

/// Density of stack-shuffle opcodes (`pop`/`dup`/`swap`), per mille capped at
/// 100.
///
/// Register/stack-shuffle obfuscators inflate these to defeat naive stack
/// tracking; ordinary compiler output keeps them sparse.
fn register_shuffle_density(abc: &AbcFile) -> u8 {
    let mut total: u64 = 0;
    let mut shuffles: u64 = 0;
    for body in &abc.method_bodies {
        total += body.code.len() as u64;
        shuffles += body
            .code
            .iter()
            .filter(|b: &&u8| STACK_SHUFFLE_OPCODES.contains(*b))
            .count() as u64;
    }
    if total == 0 {
        return 0;
    }
    ((shuffles * 1000) / total).min(100) as u8
}

/// Fraction of pool strings that look like an encrypted/rebuilt blob: empty of
/// identifier characters yet present, i.e. control-byte or high-entropy noise
/// a string-pool-rebuild pass would have to decrypt before names resolve.
fn string_pool_rebuild_ratio(abc: &AbcFile) -> u8 {
    let strings: &[String] = &abc.cpool.strings;
    let total: usize = strings.iter().filter(|s| !s.is_empty()).count();
    if total == 0 {
        return 0;
    }
    let suspicious: usize = strings
        .iter()
        .filter(|s: &&String| !s.is_empty())
        .filter(|s: &&String| looks_like_encrypted_blob(s))
        .count();
    ((suspicious as u64 * 100) / total as u64).min(100) as u8
}

fn looks_like_encrypted_blob(s: &str) -> bool {
    let len: usize = s.chars().count();
    let control_or_high: usize = s
        .chars()
        .filter(|c: &char| c.is_control() || !c.is_ascii())
        .count();
    if control_or_high == 0 {
        return false;
    }
    len >= 4 && control_or_high * 100 / len >= 40
}

const TOOL_MARKERS: &[(&str, KnownTool)] = &[
    ("secureSWF", KnownTool::SecureSwf),
    ("SecureSWF", KnownTool::SecureSwf),
    ("DoSWF", KnownTool::DoSwf),
    ("doSwf", KnownTool::DoSwf),
    ("__doswf__", KnownTool::DoSwf),
    ("Kindi", KnownTool::Kindi),
    ("kindi", KnownTool::Kindi),
    ("Irrfuscator", KnownTool::Irrfuscator),
    ("irrfuscator", KnownTool::Irrfuscator),
    ("swfLock", KnownTool::Swflock),
    ("swflock", KnownTool::Swflock),
];

/// Scan the constant-pool strings for known commercial-obfuscator vendor
/// markers, plus a generic-string-encryptor inference when the pool is heavily
/// encrypted yet a decrypt-stub-shaped method name is present.
fn fingerprint_tools(abc: &AbcFile, pool_rebuild_pct: u8) -> Vec<KnownTool> {
    let mut found: Vec<KnownTool> = Vec::new();
    for s in &abc.cpool.strings {
        for (marker, tool) in TOOL_MARKERS {
            if s.contains(marker) && !found.contains(tool) {
                found.push(*tool);
            }
        }
    }
    if found.is_empty() && pool_rebuild_pct >= 50 && has_decrypt_stub_name(abc) {
        found.push(KnownTool::GenericStringEncryptor);
    }
    found.sort_unstable();
    found
}

const DECRYPT_STUB_NEEDLES: &[&str] = &["decrypt", "decode", "unscramble", "deobf", "xor"];

fn has_decrypt_stub_name(abc: &AbcFile) -> bool {
    abc.cpool.strings.iter().any(|s: &String| {
        let lower: String = s.to_ascii_lowercase();
        DECRYPT_STUB_NEEDLES
            .iter()
            .any(|needle: &&str| lower.contains(needle))
    })
}

#[must_use]
pub fn analyze(abc: &AbcFile) -> ObfuscationReport {
    let printable_pct: u8 = printable_string_ratio(abc);
    let mangle_pct: u8 = identifier_mangle_ratio(abc);
    let jump_density: u8 = control_flow_jump_density(abc);
    let shuffle_density: u8 = register_shuffle_density(abc);
    let pool_rebuild_pct: u8 = string_pool_rebuild_ratio(abc);
    let tools: Vec<KnownTool> = fingerprint_tools(abc, pool_rebuild_pct);

    let mut signals: BTreeMap<ObfuscationSignal, ConfidenceScore> = BTreeMap::new();
    if printable_pct < 40 {
        signals.insert(ObfuscationSignal::StringEncryption, ConfidenceScore::HIGH);
    } else if printable_pct < 70 {
        signals.insert(ObfuscationSignal::StringEncryption, ConfidenceScore::MEDIUM);
    }
    if mangle_pct >= 60 {
        signals.insert(ObfuscationSignal::NameMangling, ConfidenceScore::HIGH);
    } else if mangle_pct >= 30 {
        signals.insert(ObfuscationSignal::NameMangling, ConfidenceScore::MEDIUM);
    }
    if jump_density >= 15 {
        signals.insert(
            ObfuscationSignal::ControlFlowFlattening,
            ConfidenceScore::HIGH,
        );
    } else if jump_density >= 8 {
        signals.insert(
            ObfuscationSignal::ControlFlowFlattening,
            ConfidenceScore::MEDIUM,
        );
    }
    if shuffle_density >= 20 {
        signals.insert(ObfuscationSignal::RegisterShuffle, ConfidenceScore::HIGH);
    } else if shuffle_density >= 10 {
        signals.insert(ObfuscationSignal::RegisterShuffle, ConfidenceScore::MEDIUM);
    }
    if pool_rebuild_pct >= 50 {
        signals.insert(
            ObfuscationSignal::StringPoolRebuildCandidate,
            ConfidenceScore::HIGH,
        );
    } else if pool_rebuild_pct >= 25 {
        signals.insert(
            ObfuscationSignal::StringPoolRebuildCandidate,
            ConfidenceScore::MEDIUM,
        );
    }
    if !tools.is_empty() {
        signals.insert(ObfuscationSignal::StringEncryption, ConfidenceScore::HIGH);
    }
    ObfuscationReport {
        signals,
        printable_string_ratio_percent: printable_pct,
        identifier_mangle_ratio_percent: mangle_pct,
        control_flow_jump_density_percent: jump_density,
        register_shuffle_density_percent: shuffle_density,
        string_pool_rebuild_percent: pool_rebuild_pct,
        tools,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn detects_short_identifier_as_mangled() {
        assert!(is_mangled_identifier("a"));
        assert!(is_mangled_identifier("ab"));
        assert!(!is_mangled_identifier("init"));
    }

    #[test]
    fn detects_hex_identifier_as_mangled() {
        assert!(is_mangled_identifier("abcdef01"));
        assert!(!is_mangled_identifier("notHex_"));
    }

    fn abc_with(strings: Vec<String>, bodies: Vec<Vec<u8>>) -> AbcFile {
        use crate::abc::{ConstantPool, MethodBody};
        let cpool: ConstantPool = ConstantPool {
            strings,
            ..ConstantPool::default()
        };
        let method_bodies: Vec<MethodBody> = bodies
            .into_iter()
            .enumerate()
            .map(|(i, code): (usize, Vec<u8>)| MethodBody {
                method: i as u32,
                max_stack: 8,
                local_count: 4,
                init_scope_depth: 0,
                max_scope_depth: 1,
                code,
                exceptions: Vec::new(),
                traits: Vec::new(),
            })
            .collect();
        AbcFile {
            minor: 16,
            major: 46,
            cpool,
            methods: Vec::new(),
            metadata_count: 0,
            instances: Vec::new(),
            classes: Vec::new(),
            scripts: Vec::new(),
            method_bodies,
        }
    }

    #[test]
    fn fingerprints_secureswf_marker() {
        let abc: AbcFile = abc_with(
            vec![String::new(), "protected by secureSWF v4".to_owned()],
            vec![],
        );
        let report: ObfuscationReport = analyze(&abc);
        assert!(report.tools.contains(&KnownTool::SecureSwf));
    }

    #[test]
    fn fingerprints_doswf_marker() {
        let abc: AbcFile = abc_with(vec![String::new(), "__doswf__".to_owned()], vec![]);
        let report: ObfuscationReport = analyze(&abc);
        assert!(report.tools.contains(&KnownTool::DoSwf));
    }

    #[test]
    fn register_shuffle_density_flags_swap_heavy_body() {
        let shuffle_heavy: Vec<u8> = vec![0x2A, 0x2B, 0x29, 0x2A, 0x2B, 0x29, 0x2A, 0x2B];
        let abc: AbcFile = abc_with(vec![String::new()], vec![shuffle_heavy]);
        let report: ObfuscationReport = analyze(&abc);
        assert!(report.register_shuffle_density_percent >= 20);
        assert_eq!(
            report.signals.get(&ObfuscationSignal::RegisterShuffle),
            Some(&ConfidenceScore::HIGH)
        );
    }

    #[test]
    fn clean_body_has_no_register_shuffle_signal() {
        let clean: Vec<u8> = vec![0xD0, 0x30, 0x60, 0x01, 0x46, 0x02, 0x00, 0x47];
        let abc: AbcFile = abc_with(vec![String::new(), "init".to_owned()], vec![clean]);
        let report: ObfuscationReport = analyze(&abc);
        assert!(
            !report
                .signals
                .contains_key(&ObfuscationSignal::RegisterShuffle)
        );
    }

    #[test]
    fn encrypted_pool_triggers_rebuild_candidate_and_generic_tool() {
        let blob: String = "\u{1}\u{2}\u{3}\u{4}\u{5}\u{6}".to_owned();
        let abc: AbcFile = abc_with(
            vec![
                String::new(),
                blob.clone(),
                blob.clone(),
                blob,
                "stringDecrypt".to_owned(),
            ],
            vec![],
        );
        let report: ObfuscationReport = analyze(&abc);
        assert!(report.register_shuffle_density_percent == 0);
        assert!(report.string_pool_rebuild_percent >= 50);
        assert_eq!(
            report
                .signals
                .get(&ObfuscationSignal::StringPoolRebuildCandidate),
            Some(&ConfidenceScore::HIGH)
        );
        assert!(report.tools.contains(&KnownTool::GenericStringEncryptor));
    }

    #[test]
    fn printable_pool_is_not_a_rebuild_candidate() {
        let abc: AbcFile = abc_with(
            vec![
                String::new(),
                "Greeter".to_owned(),
                "trace".to_owned(),
                "Hello, World".to_owned(),
                "==".to_owned(),
            ],
            vec![],
        );
        let report: ObfuscationReport = analyze(&abc);
        assert!(
            !report
                .signals
                .contains_key(&ObfuscationSignal::StringPoolRebuildCandidate),
            "clean punctuation/text pool must not look rebuilt"
        );
        assert!(report.tools.is_empty());
    }
}
