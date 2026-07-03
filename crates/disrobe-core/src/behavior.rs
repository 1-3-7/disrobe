use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::anti_analysis_sigs::{STRING_SIGS, SigClass, StringSig};
use crate::ioc::{self, Indicator, IocKind};
use crate::strings::{self, ExtractedString, Options};

pub const BEHAVIOR_SCHEMA: &str = "disrobe.behavior/v0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    Network,
    Filesystem,
    ProcessExec,
    RegistryPersistence,
    Crypto,
    AntiAnalysis,
    DynamicCode,
}

impl Category {
    #[inline]
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Network => "network",
            Self::Filesystem => "filesystem",
            Self::ProcessExec => "process_exec",
            Self::RegistryPersistence => "registry_persistence",
            Self::Crypto => "crypto",
            Self::AntiAnalysis => "anti_analysis",
            Self::DynamicCode => "dynamic_code",
        }
    }

    #[inline]
    #[must_use]
    pub const fn describe(self) -> &'static str {
        match self {
            Self::Network => "network communication",
            Self::Filesystem => "filesystem access",
            Self::ProcessExec => "process / command execution",
            Self::RegistryPersistence => "registry & persistence",
            Self::Crypto => "cryptographic operations",
            Self::AntiAnalysis => "anti-analysis / anti-debug",
            Self::DynamicCode => "dynamic code / loader",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    pub signal: String,
    pub source: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attack_id: Option<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CategoryFinding {
    pub category: Category,
    pub description: &'static str,
    pub evidence: Vec<Evidence>,
    pub attack_ids: Vec<&'static str>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorReport {
    pub schema: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    pub byte_len: usize,
    pub categories: Vec<CategoryFinding>,
    pub attack_ids: Vec<&'static str>,
}

#[derive(Debug, Clone, Copy)]
struct ApiRule {
    needle: &'static str,
    category: Category,
    attack_id: Option<&'static str>,
}

static API_RULES: &[ApiRule] = &[
    ApiRule {
        needle: "wsastartup",
        category: Category::Network,
        attack_id: Some("T1095"),
    },
    ApiRule {
        needle: "connect",
        category: Category::Network,
        attack_id: Some("T1071"),
    },
    ApiRule {
        needle: "socket",
        category: Category::Network,
        attack_id: Some("T1095"),
    },
    ApiRule {
        needle: "send",
        category: Category::Network,
        attack_id: None,
    },
    ApiRule {
        needle: "recv",
        category: Category::Network,
        attack_id: None,
    },
    ApiRule {
        needle: "internetopen",
        category: Category::Network,
        attack_id: Some("T1071.001"),
    },
    ApiRule {
        needle: "internetconnect",
        category: Category::Network,
        attack_id: Some("T1071.001"),
    },
    ApiRule {
        needle: "httpsendrequest",
        category: Category::Network,
        attack_id: Some("T1071.001"),
    },
    ApiRule {
        needle: "winhttp",
        category: Category::Network,
        attack_id: Some("T1071.001"),
    },
    ApiRule {
        needle: "urldownloadtofile",
        category: Category::Network,
        attack_id: Some("T1105"),
    },
    ApiRule {
        needle: "gethostbyname",
        category: Category::Network,
        attack_id: Some("T1071"),
    },
    ApiRule {
        needle: "getaddrinfo",
        category: Category::Network,
        attack_id: Some("T1071"),
    },
    ApiRule {
        needle: "createfile",
        category: Category::Filesystem,
        attack_id: None,
    },
    ApiRule {
        needle: "writefile",
        category: Category::Filesystem,
        attack_id: Some("T1105"),
    },
    ApiRule {
        needle: "readfile",
        category: Category::Filesystem,
        attack_id: None,
    },
    ApiRule {
        needle: "deletefile",
        category: Category::Filesystem,
        attack_id: Some("T1070.004"),
    },
    ApiRule {
        needle: "movefile",
        category: Category::Filesystem,
        attack_id: None,
    },
    ApiRule {
        needle: "findfirstfile",
        category: Category::Filesystem,
        attack_id: Some("T1083"),
    },
    ApiRule {
        needle: "fopen",
        category: Category::Filesystem,
        attack_id: None,
    },
    ApiRule {
        needle: "unlink",
        category: Category::Filesystem,
        attack_id: Some("T1070.004"),
    },
    ApiRule {
        needle: "createprocess",
        category: Category::ProcessExec,
        attack_id: Some("T1106"),
    },
    ApiRule {
        needle: "shellexecute",
        category: Category::ProcessExec,
        attack_id: Some("T1059"),
    },
    ApiRule {
        needle: "winexec",
        category: Category::ProcessExec,
        attack_id: Some("T1106"),
    },
    ApiRule {
        needle: "system",
        category: Category::ProcessExec,
        attack_id: Some("T1059"),
    },
    ApiRule {
        needle: "execve",
        category: Category::ProcessExec,
        attack_id: Some("T1059.004"),
    },
    ApiRule {
        needle: "fork",
        category: Category::ProcessExec,
        attack_id: None,
    },
    ApiRule {
        needle: "popen",
        category: Category::ProcessExec,
        attack_id: Some("T1059"),
    },
    ApiRule {
        needle: "createremotethread",
        category: Category::ProcessExec,
        attack_id: Some("T1055"),
    },
    ApiRule {
        needle: "openprocess",
        category: Category::ProcessExec,
        attack_id: Some("T1055"),
    },
    ApiRule {
        needle: "writeprocessmemory",
        category: Category::ProcessExec,
        attack_id: Some("T1055"),
    },
    ApiRule {
        needle: "regopenkey",
        category: Category::RegistryPersistence,
        attack_id: Some("T1112"),
    },
    ApiRule {
        needle: "regsetvalue",
        category: Category::RegistryPersistence,
        attack_id: Some("T1112"),
    },
    ApiRule {
        needle: "regcreatekey",
        category: Category::RegistryPersistence,
        attack_id: Some("T1112"),
    },
    ApiRule {
        needle: "regdeletekey",
        category: Category::RegistryPersistence,
        attack_id: Some("T1112"),
    },
    ApiRule {
        needle: "currentversion\\run",
        category: Category::RegistryPersistence,
        attack_id: Some("T1547.001"),
    },
    ApiRule {
        needle: "schtasks",
        category: Category::RegistryPersistence,
        attack_id: Some("T1053.005"),
    },
    ApiRule {
        needle: "createservice",
        category: Category::RegistryPersistence,
        attack_id: Some("T1543.003"),
    },
    ApiRule {
        needle: "cryptacquirecontext",
        category: Category::Crypto,
        attack_id: Some("T1486"),
    },
    ApiRule {
        needle: "cryptencrypt",
        category: Category::Crypto,
        attack_id: Some("T1486"),
    },
    ApiRule {
        needle: "cryptdecrypt",
        category: Category::Crypto,
        attack_id: None,
    },
    ApiRule {
        needle: "cryptgenkey",
        category: Category::Crypto,
        attack_id: None,
    },
    ApiRule {
        needle: "bcryptencrypt",
        category: Category::Crypto,
        attack_id: Some("T1486"),
    },
    ApiRule {
        needle: "sleep",
        category: Category::AntiAnalysis,
        attack_id: Some("T1497.003"),
    },
    ApiRule {
        needle: "isprocessorfeaturepresent",
        category: Category::AntiAnalysis,
        attack_id: None,
    },
    ApiRule {
        needle: "loadlibrary",
        category: Category::DynamicCode,
        attack_id: Some("T1129"),
    },
    ApiRule {
        needle: "getprocaddress",
        category: Category::DynamicCode,
        attack_id: Some("T1129"),
    },
    ApiRule {
        needle: "virtualalloc",
        category: Category::DynamicCode,
        attack_id: Some("T1055"),
    },
    ApiRule {
        needle: "virtualprotect",
        category: Category::DynamicCode,
        attack_id: Some("T1055"),
    },
    ApiRule {
        needle: "mmap",
        category: Category::DynamicCode,
        attack_id: None,
    },
    ApiRule {
        needle: "mprotect",
        category: Category::DynamicCode,
        attack_id: None,
    },
    ApiRule {
        needle: "dlopen",
        category: Category::DynamicCode,
        attack_id: Some("T1129"),
    },
    ApiRule {
        needle: "dlsym",
        category: Category::DynamicCode,
        attack_id: Some("T1129"),
    },
];

const fn ioc_category(kind: IocKind) -> Option<(Category, Option<&'static str>)> {
    match kind {
        IocKind::Url | IocKind::Domain | IocKind::Ipv4 | IocKind::Ipv6 => {
            Some((Category::Network, Some("T1071")))
        }
        IocKind::WindowsPath | IocKind::UnixPath | IocKind::PdbPath => {
            Some((Category::Filesystem, None))
        }
        IocKind::RegistryKey => Some((Category::RegistryPersistence, Some("T1112"))),
        IocKind::CryptoConstant => Some((Category::Crypto, None)),
        IocKind::Email
        | IocKind::BitcoinAddress
        | IocKind::EthereumAddress
        | IocKind::MoneroAddress
        | IocKind::LitecoinAddress
        | IocKind::TronAddress
        | IocKind::CreditCard
        | IocKind::MacAddress
        | IocKind::Uuid => None,
    }
}

#[derive(Default)]
struct Accumulator {
    by_category: BTreeMap<Category, Vec<Evidence>>,
}

impl Accumulator {
    fn add(
        &mut self,
        category: Category,
        signal: String,
        source: &'static str,
        attack_id: Option<&'static str>,
    ) {
        let bucket: &mut Vec<Evidence> = self.by_category.entry(category).or_default();
        if bucket
            .iter()
            .any(|e: &Evidence| e.signal == signal && e.source == source)
        {
            return;
        }
        bucket.push(Evidence {
            signal,
            source,
            attack_id,
        });
    }
}

fn match_api_tokens(tokens: &[String], source: &'static str, acc: &mut Accumulator) {
    for token in tokens {
        let lower: String = token.to_ascii_lowercase();
        for rule in API_RULES {
            if token_matches(&lower, rule.needle) {
                acc.add(rule.category, token.clone(), source, rule.attack_id);
            }
        }
    }
}

const fn sig_class_attack_id(class: SigClass) -> &'static str {
    match class {
        SigClass::AntiDebug | SigClass::AntiAttach => "T1622",
        SigClass::AntiVm
        | SigClass::Sandbox
        | SigClass::Hypervisor
        | SigClass::VmMacOui
        | SigClass::AntiTool
        | SigClass::ResourceFloor => "T1497.001",
        SigClass::Interaction => "T1497.002",
        SigClass::AntiDump => "T1027.005",
        SigClass::Timing => "T1497.003",
    }
}

fn match_shared_anti_analysis_sigs(tokens: &[String], source: &'static str, acc: &mut Accumulator) {
    for token in tokens {
        let lower: String = token.to_ascii_lowercase();
        for sig in STRING_SIGS {
            if shared_sig_matches(&lower, sig) {
                acc.add(
                    Category::AntiAnalysis,
                    token.clone(),
                    source,
                    Some(sig_class_attack_id(sig.class)),
                );
            }
        }
    }
}

fn shared_sig_matches(lower: &str, sig: &StringSig) -> bool {
    if sig.word_bounded {
        is_word_bounded(lower, sig.needle)
    } else {
        lower.contains(sig.needle)
    }
}

fn token_matches(haystack_lower: &str, needle: &str) -> bool {
    if needle.contains('\\') || needle.len() <= 4 {
        haystack_lower.contains(needle) && is_word_bounded(haystack_lower, needle)
    } else {
        haystack_lower.contains(needle)
    }
}

fn is_word_bounded(haystack: &str, needle: &str) -> bool {
    let bytes: &[u8] = haystack.as_bytes();
    let nlen: usize = needle.len();
    let mut from: usize = 0;
    while let Some(rel) = haystack[from..].find(needle) {
        let at: usize = from + rel;
        let before_ok: bool = at == 0 || !is_ident_byte(bytes[at - 1]);
        let after_idx: usize = at + nlen;
        let after_ok: bool = after_idx >= bytes.len() || !is_ident_byte(bytes[after_idx]);
        if before_ok && after_ok {
            return true;
        }
        from = at + 1;
    }
    false
}

#[inline]
const fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

#[must_use]
pub fn analyze(bytes: &[u8], imports: &[String]) -> BehaviorReport {
    analyze_with_uri(bytes, imports, None)
}

#[must_use]
pub fn analyze_with_uri(bytes: &[u8], imports: &[String], uri: Option<&str>) -> BehaviorReport {
    let mut acc: Accumulator = Accumulator::default();

    match_api_tokens(imports, "import", &mut acc);
    match_shared_anti_analysis_sigs(imports, "import", &mut acc);

    let extracted: Vec<ExtractedString> = strings::extract(
        bytes,
        Options {
            min_len: 4,
            decode: true,
        },
    );
    let string_tokens: Vec<String> = extracted
        .into_iter()
        .map(|s: ExtractedString| s.value)
        .collect();
    match_api_tokens(&string_tokens, "string", &mut acc);
    match_shared_anti_analysis_sigs(&string_tokens, "string", &mut acc);

    let indicators: Vec<Indicator> = ioc::extract(bytes);
    for ind in &indicators {
        if let Some((category, attack)) = ioc_category(ind.kind) {
            acc.add(
                category,
                format!("{}:{}", ind.kind.label(), ind.value),
                "ioc",
                attack,
            );
        }
    }

    finalize(acc, bytes.len(), uri)
}

fn finalize(acc: Accumulator, byte_len: usize, uri: Option<&str>) -> BehaviorReport {
    let mut categories: Vec<CategoryFinding> = Vec::new();
    let mut all_attack: Vec<&'static str> = Vec::new();
    for (category, evidence) in acc.by_category {
        let mut attack_ids: Vec<&'static str> = evidence
            .iter()
            .filter_map(|e: &Evidence| e.attack_id)
            .collect();
        attack_ids.sort_unstable();
        attack_ids.dedup();
        for id in &attack_ids {
            if !all_attack.contains(id) {
                all_attack.push(id);
            }
        }
        categories.push(CategoryFinding {
            category,
            description: category.describe(),
            evidence,
            attack_ids,
        });
    }
    all_attack.sort_unstable();
    BehaviorReport {
        schema: BEHAVIOR_SCHEMA,
        uri: uri.map(str::to_owned),
        byte_len,
        categories,
        attack_ids: all_attack,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn category(report: &BehaviorReport, cat: Category) -> Option<&CategoryFinding> {
        report
            .categories
            .iter()
            .find(|c: &&CategoryFinding| c.category == cat)
    }

    #[test]
    fn imports_drive_network_and_process_categories() {
        let imports: Vec<String> = vec![
            "kernel32.dll!CreateProcessA".to_owned(),
            "ws2_32.dll!WSAStartup".to_owned(),
            "ws2_32.dll!connect".to_owned(),
        ];
        let report: BehaviorReport = analyze(b"", &imports);
        assert!(category(&report, Category::Network).is_some(), "{report:?}");
        assert!(
            category(&report, Category::ProcessExec).is_some(),
            "{report:?}"
        );
    }

    #[test]
    fn anti_debug_import_tagged_with_attack_id() {
        let imports: Vec<String> = vec!["kernel32.dll!IsDebuggerPresent".to_owned()];
        let report: BehaviorReport = analyze(b"", &imports);
        let anti: &CategoryFinding =
            category(&report, Category::AntiAnalysis).expect("anti-analysis present");
        assert!(anti.attack_ids.contains(&"T1622"), "{anti:?}");
        assert!(report.attack_ids.contains(&"T1622"));
    }

    #[test]
    fn registry_persistence_from_string_signal() {
        let report: BehaviorReport = analyze(
            b"Software\\Microsoft\\Windows\\CurrentVersion\\Run value",
            &[],
        );
        let reg: &CategoryFinding =
            category(&report, Category::RegistryPersistence).expect("registry persistence present");
        assert!(reg.attack_ids.contains(&"T1547.001"), "{reg:?}");
    }

    #[test]
    fn network_ioc_drives_network_category() {
        let report: BehaviorReport = analyze(b"beacon to http://c2.example.com/gate.php", &[]);
        let net: &CategoryFinding = category(&report, Category::Network).expect("network present");
        assert!(
            net.evidence.iter().any(|e: &Evidence| e.source == "ioc"),
            "{net:?}"
        );
        assert!(net.attack_ids.contains(&"T1071"));
    }

    #[test]
    fn crypto_constant_drives_crypto_category() {
        let mut input: Vec<u8> = b"prefix".to_vec();
        input.extend_from_slice(b"expand 32-byte k");
        let report: BehaviorReport = analyze(&input, &[]);
        assert!(category(&report, Category::Crypto).is_some(), "{report:?}");
    }

    #[test]
    fn dynamic_code_from_loader_imports() {
        let imports: Vec<String> = vec![
            "kernel32.dll!LoadLibraryA".to_owned(),
            "kernel32.dll!GetProcAddress".to_owned(),
            "kernel32.dll!VirtualProtect".to_owned(),
        ];
        let report: BehaviorReport = analyze(b"", &imports);
        let dynamic: &CategoryFinding =
            category(&report, Category::DynamicCode).expect("dynamic code present");
        assert!(dynamic.attack_ids.contains(&"T1129"), "{dynamic:?}");
    }

    #[test]
    fn short_token_requires_word_boundary() {
        let report: BehaviorReport = analyze(b"reconnaissance subsystem", &[]);
        assert!(
            category(&report, Category::Network).is_none(),
            "substring 'recv'/'connect' should not match inside a word: {report:?}"
        );
    }

    #[test]
    fn clean_input_yields_no_categories() {
        let report: BehaviorReport = analyze(b"the quick brown fox", &[]);
        assert!(report.categories.is_empty(), "{report:?}");
        assert!(report.attack_ids.is_empty());
    }

    #[test]
    fn report_serializes_with_schema() {
        let report: BehaviorReport = analyze_with_uri(b"http://x.example.com/", &[], Some("a.bin"));
        let value: serde_json::Value = serde_json::to_value(&report).expect("serialize");
        assert_eq!(value["schema"], serde_json::json!(BEHAVIOR_SCHEMA));
        assert_eq!(value["uri"], serde_json::json!("a.bin"));
        let back: Vec<&str> = value["attack_ids"]
            .as_array()
            .expect("attack_ids array")
            .iter()
            .map(|v: &serde_json::Value| v.as_str().expect("str"))
            .collect();
        assert_eq!(back, report.attack_ids);
    }
}
