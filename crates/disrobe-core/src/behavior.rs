use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::anti_analysis::{self, AntiAnalysisFinding, AntiAnalysisReport, Technique};
use crate::anti_analysis_sigs::{STRING_SIGS, SignalCorroboration, StringSig};
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NameFamily {
    Exact,
    Win32,
}

#[derive(Debug, Clone, Copy)]
struct ApiRule {
    name: &'static str,
    family: NameFamily,
    category: Category,
}

const WIN32_SUFFIXES: [&str; 5] = ["a", "w", "ex", "exa", "exw"];

const fn api(name: &'static str, family: NameFamily, category: Category) -> ApiRule {
    ApiRule {
        name,
        family,
        category,
    }
}

static API_RULES: &[ApiRule] = &[
    api("wsastartup", NameFamily::Exact, Category::Network),
    api("connect", NameFamily::Exact, Category::Network),
    api("socket", NameFamily::Exact, Category::Network),
    api("send", NameFamily::Exact, Category::Network),
    api("recv", NameFamily::Exact, Category::Network),
    api("sendto", NameFamily::Exact, Category::Network),
    api("recvfrom", NameFamily::Exact, Category::Network),
    api("internetopen", NameFamily::Win32, Category::Network),
    api("internetopenurl", NameFamily::Win32, Category::Network),
    api("internetconnect", NameFamily::Win32, Category::Network),
    api("httpsendrequest", NameFamily::Win32, Category::Network),
    api("winhttpopen", NameFamily::Exact, Category::Network),
    api("winhttpconnect", NameFamily::Exact, Category::Network),
    api("winhttpopenrequest", NameFamily::Exact, Category::Network),
    api("winhttpsendrequest", NameFamily::Exact, Category::Network),
    api("urldownloadtofile", NameFamily::Win32, Category::Network),
    api("gethostbyname", NameFamily::Exact, Category::Network),
    api("getaddrinfo", NameFamily::Win32, Category::Network),
    api("createfile", NameFamily::Win32, Category::Filesystem),
    api("writefile", NameFamily::Win32, Category::Filesystem),
    api("readfile", NameFamily::Win32, Category::Filesystem),
    api("deletefile", NameFamily::Win32, Category::Filesystem),
    api("movefile", NameFamily::Win32, Category::Filesystem),
    api("findfirstfile", NameFamily::Win32, Category::Filesystem),
    api("fopen", NameFamily::Exact, Category::Filesystem),
    api("unlink", NameFamily::Exact, Category::Filesystem),
    api("createprocess", NameFamily::Win32, Category::ProcessExec),
    api("shellexecute", NameFamily::Win32, Category::ProcessExec),
    api("winexec", NameFamily::Exact, Category::ProcessExec),
    api("system", NameFamily::Exact, Category::ProcessExec),
    api("execve", NameFamily::Exact, Category::ProcessExec),
    api("fork", NameFamily::Exact, Category::ProcessExec),
    api("popen", NameFamily::Exact, Category::ProcessExec),
    api(
        "createremotethread",
        NameFamily::Win32,
        Category::ProcessExec,
    ),
    api("openprocess", NameFamily::Exact, Category::ProcessExec),
    api(
        "writeprocessmemory",
        NameFamily::Exact,
        Category::ProcessExec,
    ),
    api(
        "regopenkey",
        NameFamily::Win32,
        Category::RegistryPersistence,
    ),
    api(
        "regsetvalue",
        NameFamily::Win32,
        Category::RegistryPersistence,
    ),
    api(
        "regcreatekey",
        NameFamily::Win32,
        Category::RegistryPersistence,
    ),
    api(
        "regdeletekey",
        NameFamily::Win32,
        Category::RegistryPersistence,
    ),
    api(
        "createservice",
        NameFamily::Win32,
        Category::RegistryPersistence,
    ),
    api("cryptacquirecontext", NameFamily::Win32, Category::Crypto),
    api("cryptencrypt", NameFamily::Exact, Category::Crypto),
    api("cryptdecrypt", NameFamily::Exact, Category::Crypto),
    api("cryptgenkey", NameFamily::Exact, Category::Crypto),
    api("bcryptencrypt", NameFamily::Exact, Category::Crypto),
    api("loadlibrary", NameFamily::Win32, Category::DynamicCode),
    api("getprocaddress", NameFamily::Exact, Category::DynamicCode),
    api("virtualalloc", NameFamily::Win32, Category::DynamicCode),
    api("virtualprotect", NameFamily::Win32, Category::DynamicCode),
    api("mmap", NameFamily::Exact, Category::DynamicCode),
    api("mprotect", NameFamily::Exact, Category::DynamicCode),
    api("dlopen", NameFamily::Exact, Category::DynamicCode),
    api("dlsym", NameFamily::Exact, Category::DynamicCode),
];

#[derive(Debug, Clone, Copy)]
struct TechniqueRule {
    attack_id: &'static str,
    requires: &'static [&'static [&'static str]],
}

static TECHNIQUE_RULES: &[TechniqueRule] = &[
    TechniqueRule {
        attack_id: "T1055",
        requires: &[&["writeprocessmemory"], &["createremotethread"]],
    },
    TechniqueRule {
        attack_id: "T1105",
        requires: &[&["urldownloadtofile"]],
    },
    TechniqueRule {
        attack_id: "T1112",
        requires: &[&["regsetvalue", "regcreatekey", "regdeletekey"]],
    },
    TechniqueRule {
        attack_id: "T1543.003",
        requires: &[&["createservice"]],
    },
];

#[derive(Debug, Clone, Copy)]
struct StringRule {
    needle: &'static str,
    category: Category,
    attack_id: &'static str,
}

static STRING_RULES: &[StringRule] = &[
    StringRule {
        needle: "currentversion\\run",
        category: Category::RegistryPersistence,
        attack_id: "T1547.001",
    },
    StringRule {
        needle: "currentversion\\runonce",
        category: Category::RegistryPersistence,
        attack_id: "T1547.001",
    },
    StringRule {
        needle: "schtasks",
        category: Category::RegistryPersistence,
        attack_id: "T1053.005",
    },
];

const fn ioc_category(kind: IocKind) -> Option<Category> {
    match kind {
        IocKind::Url | IocKind::Domain | IocKind::Ipv4 | IocKind::Ipv6 => Some(Category::Network),
        IocKind::WindowsPath | IocKind::UnixPath | IocKind::PdbPath => Some(Category::Filesystem),
        IocKind::RegistryKey => Some(Category::RegistryPersistence),
        IocKind::CryptoConstant => Some(Category::Crypto),
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

const fn verdict_attack_id(technique: Technique) -> Option<&'static str> {
    match technique {
        Technique::AntiDebug | Technique::AntiAttach => Some("T1622"),
        Technique::AntiVm | Technique::AntiSandbox | Technique::AntiTool => Some("T1497.001"),
        Technique::TimingEvasion => Some("T1497.003"),
        Technique::AntiDump
        | Technique::AntiDisassembly
        | Technique::OpaquePredicate
        | Technique::ControlFlowFlattening
        | Technique::StringEncryption
        | Technique::Packing
        | Technique::Rasp
        | Technique::VmVirtualization => None,
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

struct ApiMatch {
    rule: &'static ApiRule,
    token: String,
    source: &'static str,
}

fn match_api_tokens(tokens: &[String], source: &'static str, matches: &mut Vec<ApiMatch>) {
    for token in tokens {
        let lower: String = token.to_ascii_lowercase();
        let Some(name): Option<&str> = api_name(&lower) else {
            continue;
        };
        for rule in API_RULES {
            if api_name_matches(name, rule) {
                matches.push(ApiMatch {
                    rule,
                    token: token.clone(),
                    source,
                });
            }
        }
    }
}

fn api_name(token_lower: &str) -> Option<&str> {
    let tail: &str = token_lower.rsplit('!').next().unwrap_or(token_lower);
    let name: &str = tail.trim_start_matches('_');
    let name: &str = name
        .split_once('@')
        .map_or(name, |(head, _): (&str, &str)| head);
    (!name.is_empty() && name.bytes().all(is_ident_byte)).then_some(name)
}

fn api_name_matches(name: &str, rule: &ApiRule) -> bool {
    let Some(rest): Option<&str> = name.strip_prefix(rule.name) else {
        return false;
    };
    match rule.family {
        NameFamily::Exact => rest.is_empty(),
        NameFamily::Win32 => rest.is_empty() || WIN32_SUFFIXES.contains(&rest),
    }
}

fn technique_for(name: &str, matched: &BTreeSet<&'static str>) -> Option<&'static str> {
    TECHNIQUE_RULES
        .iter()
        .find(|rule: &&TechniqueRule| {
            rule.requires
                .iter()
                .any(|group: &&[&str]| group.contains(&name))
                && rule.requires.iter().all(|group: &&[&str]| {
                    group
                        .iter()
                        .any(|required: &&str| matched.contains(required))
                })
        })
        .map(|rule: &TechniqueRule| rule.attack_id)
}

fn add_api_matches(matches: &[ApiMatch], acc: &mut Accumulator) {
    let matched: BTreeSet<&'static str> = matches.iter().map(|m: &ApiMatch| m.rule.name).collect();
    for m in matches {
        acc.add(
            m.rule.category,
            m.token.clone(),
            m.source,
            technique_for(m.rule.name, &matched),
        );
    }
}

fn match_string_rules(tokens: &[String], acc: &mut Accumulator) {
    for token in tokens {
        let lower: String = token.to_ascii_lowercase();
        for rule in STRING_RULES {
            if is_word_bounded(&lower, rule.needle) {
                acc.add(rule.category, token.clone(), "string", Some(rule.attack_id));
            }
        }
    }
}

fn match_anti_analysis_names(tokens: &[String], source: &'static str, acc: &mut Accumulator) {
    for token in tokens {
        let lower: String = token.to_ascii_lowercase();
        let named: bool = STRING_SIGS.iter().any(|sig: &StringSig| {
            sig.corroboration != SignalCorroboration::ContextOnly && shared_sig_matches(&lower, sig)
        });
        if named {
            acc.add(Category::AntiAnalysis, token.clone(), source, None);
        }
    }
}

fn add_anti_analysis_verdicts(anti: &AntiAnalysisReport, acc: &mut Accumulator) {
    for finding in anti
        .findings
        .iter()
        .filter(|f: &&AntiAnalysisFinding| f.detected)
    {
        acc.add(
            Category::AntiAnalysis,
            format!(
                "{} verdict [{}]",
                finding.technique.label(),
                finding.confidence.label()
            ),
            "anti_analysis",
            verdict_attack_id(finding.technique),
        );
    }
}

fn shared_sig_matches(lower: &str, sig: &StringSig) -> bool {
    if sig.word_bounded {
        is_word_bounded(lower, sig.needle)
    } else {
        lower.contains(sig.needle)
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
    let anti: AntiAnalysisReport = anti_analysis::scan(bytes, uri);
    analyze_with_anti_analysis(bytes, imports, uri, &anti)
}

#[must_use]
pub fn analyze_with_anti_analysis(
    bytes: &[u8],
    imports: &[String],
    uri: Option<&str>,
    anti: &AntiAnalysisReport,
) -> BehaviorReport {
    let mut acc: Accumulator = Accumulator::default();

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

    let mut api_matches: Vec<ApiMatch> = Vec::new();
    match_api_tokens(imports, "import", &mut api_matches);
    match_api_tokens(&string_tokens, "string", &mut api_matches);
    add_api_matches(&api_matches, &mut acc);

    match_string_rules(&string_tokens, &mut acc);
    match_anti_analysis_names(imports, "import", &mut acc);
    match_anti_analysis_names(&string_tokens, "string", &mut acc);
    add_anti_analysis_verdicts(anti, &mut acc);

    let indicators: Vec<Indicator> = ioc::extract(bytes);
    for ind in &indicators {
        if let Some(category) = ioc_category(ind.kind) {
            acc.add(
                category,
                format!("{}:{}", ind.kind.label(), ind.value),
                "ioc",
                None,
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
    fn anti_debug_verdict_tagged_with_attack_id() {
        let imports: Vec<String> = vec!["kernel32.dll!IsDebuggerPresent".to_owned()];
        let report: BehaviorReport = analyze(
            b"MZ\x90\x00\x00IsDebuggerPresent\x00CheckRemoteDebuggerPresent\x00",
            &imports,
        );
        let anti: &CategoryFinding =
            category(&report, Category::AntiAnalysis).expect("anti-analysis present");
        assert!(anti.attack_ids.contains(&"T1622"), "{anti:?}");
        assert!(
            anti.evidence
                .iter()
                .any(|e: &Evidence| e.source == "anti_analysis" && e.attack_id == Some("T1622")),
            "{anti:?}"
        );
        assert!(report.attack_ids.contains(&"T1622"));
    }

    #[test]
    fn lone_runtime_anti_debug_import_claims_no_technique() {
        let imports: Vec<String> = vec!["kernel32.dll!IsDebuggerPresent".to_owned()];
        let report: BehaviorReport = analyze(b"", &imports);
        let anti: &CategoryFinding =
            category(&report, Category::AntiAnalysis).expect("anti-analysis capability present");
        assert!(anti.attack_ids.is_empty(), "{anti:?}");
        assert!(report.attack_ids.is_empty(), "{report:?}");
    }

    #[test]
    fn runtime_imports_every_program_links_claim_no_technique() {
        let imports: Vec<String> = [
            "WriteFile",
            "CreateProcessW",
            "FindFirstFileExW",
            "DeleteFileW",
            "GetProcAddress",
            "LoadLibraryExW",
            "Sleep",
            "QueryPerformanceCounter",
            "IsDebuggerPresent",
            "GetThreadContext",
            "SystemTimeToTzSpecificLocalTime",
        ]
        .into_iter()
        .map(|name: &str| format!("kernel32.dll!{name}"))
        .collect();
        let report: BehaviorReport = analyze(
            b"\x00ConnectEx\x00SocketType\x00sleepWhen\x00writeFileCallback\x00\
              *godebugs.Info\x00runtime.link *runtime._defer\x00",
            &imports,
        );
        assert!(
            report.attack_ids.is_empty(),
            "imports every runtime links and symbol names are capabilities, not techniques: \
             {report:?}"
        );
        for absent in [Category::Network, Category::ProcessExec] {
            let finding: Option<&CategoryFinding> = category(&report, absent);
            assert!(
                finding.is_none_or(|f: &CategoryFinding| f
                    .evidence
                    .iter()
                    .all(|e: &Evidence| e.signal.contains("CreateProcessW"))),
                "{absent:?} must come only from an api of its own name family: {finding:?}"
            );
        }
        assert!(category(&report, Category::DynamicCode).is_some());
    }

    #[test]
    fn specific_api_techniques_keep_their_ids() {
        for (import, id) in [
            ("advapi32.dll!CreateServiceW", "T1543.003"),
            ("urlmon.dll!URLDownloadToFileW", "T1105"),
            ("advapi32.dll!RegSetValueExW", "T1112"),
        ] {
            let report: BehaviorReport = analyze(b"", &[import.to_owned()]);
            assert_eq!(report.attack_ids, vec![id], "{import}: {report:?}");
        }
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
        assert!(
            net.attack_ids.is_empty(),
            "an embedded url shows network capability, not command-and-control use: {net:?}"
        );
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
        assert_eq!(dynamic.evidence.len(), 3, "{dynamic:?}");
        assert!(
            dynamic.attack_ids.is_empty(),
            "every msvc program imports these loader apis, so they show the capability and claim \
             no shared-module technique: {dynamic:?}"
        );
    }

    #[test]
    fn runtime_imports_and_free_text_are_not_process_injection() {
        let imports: Vec<String> = vec![
            "kernel32.dll!VirtualAlloc".to_owned(),
            "kernel32.dll!VirtualProtect".to_owned(),
            "kernel32.dll!OpenProcess".to_owned(),
        ];
        let report: BehaviorReport = analyze(
            b"help: call WriteProcessMemory and CreateRemoteThread to inject code",
            &imports,
        );
        assert!(
            !report.attack_ids.contains(&"T1055"),
            "allocation imports every runtime links and prose that names injection APIs are not \
             T1055: {report:?}"
        );
        let injector: BehaviorReport = analyze(
            b"",
            &[
                "kernel32.dll!WriteProcessMemory".to_owned(),
                "kernel32.dll!CreateRemoteThread".to_owned(),
            ],
        );
        assert!(injector.attack_ids.contains(&"T1055"), "{injector:?}");
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
