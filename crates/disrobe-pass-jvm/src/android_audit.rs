use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::dalvik::{DalvikInsn, decode_method};
use crate::dex::{CodeItem, DexFile, FieldId, MethodId, parse as parse_dex, parse_code_items};
use crate::error::Result;
use crate::jar::{ApkExtract, extract_apk};

const MAX_AUDIT_FINDINGS: usize = 65_536;
const MAX_METHOD_LITERALS: usize = 4_096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AuditCategory {
    WeakCrypto,
    InsecureStorage,
    TransportSecurity,
    WebView,
    Logging,
    DangerousApi,
    Privacy,
    AntiAnalysis,
}

impl AuditCategory {
    #[inline]
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::WeakCrypto => "weak_crypto",
            Self::InsecureStorage => "insecure_storage",
            Self::TransportSecurity => "transport_security",
            Self::WebView => "webview",
            Self::Logging => "logging",
            Self::DangerousApi => "dangerous_api",
            Self::Privacy => "privacy",
            Self::AntiAnalysis => "anti_analysis",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AuditSeverity {
    Info,
    Low,
    Medium,
    High,
}

impl AuditSeverity {
    #[inline]
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AuditFinding {
    pub class: String,
    pub method: String,
    pub descriptor: String,
    pub pc: u32,
    pub rule_id: String,
    pub category: AuditCategory,
    pub severity: AuditSeverity,
    pub evidence: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AndroidAuditReport {
    pub dex_files: usize,
    pub methods_scanned: usize,
    pub findings: Vec<AuditFinding>,
    pub truncated: bool,
}

#[derive(Debug, Clone, Copy)]
struct Rule {
    id: &'static str,
    category: AuditCategory,
    severity: AuditSeverity,
}

const fn rule(id: &'static str, category: AuditCategory, severity: AuditSeverity) -> Rule {
    Rule {
        id,
        category,
        severity,
    }
}

const CRYPTO_WEAK_CIPHER: Rule = rule(
    "DR-APK-CRYPTO-WEAK-CIPHER",
    AuditCategory::WeakCrypto,
    AuditSeverity::High,
);
const CRYPTO_ECB: Rule = rule(
    "DR-APK-CRYPTO-ECB",
    AuditCategory::WeakCrypto,
    AuditSeverity::High,
);
const CRYPTO_RSA_NO_OAEP: Rule = rule(
    "DR-APK-CRYPTO-RSA-NO-OAEP",
    AuditCategory::WeakCrypto,
    AuditSeverity::Medium,
);
const CRYPTO_WEAK_HASH: Rule = rule(
    "DR-APK-CRYPTO-WEAK-HASH",
    AuditCategory::WeakCrypto,
    AuditSeverity::Medium,
);
const CRYPTO_SEEDED_RANDOM: Rule = rule(
    "DR-APK-CRYPTO-SEEDED-RANDOM",
    AuditCategory::WeakCrypto,
    AuditSeverity::Medium,
);
const CRYPTO_INSECURE_RANDOM: Rule = rule(
    "DR-APK-CRYPTO-INSECURE-RANDOM",
    AuditCategory::WeakCrypto,
    AuditSeverity::Medium,
);
const CRYPTO_HARDCODED_KEY: Rule = rule(
    "DR-APK-CRYPTO-HARDCODED-KEY",
    AuditCategory::WeakCrypto,
    AuditSeverity::High,
);
const CRYPTO_STATIC_IV: Rule = rule(
    "DR-APK-CRYPTO-STATIC-IV",
    AuditCategory::WeakCrypto,
    AuditSeverity::Medium,
);
const STORAGE_WORLD_ACCESSIBLE: Rule = rule(
    "DR-APK-STORAGE-WORLD-ACCESSIBLE",
    AuditCategory::InsecureStorage,
    AuditSeverity::High,
);
const STORAGE_EXTERNAL: Rule = rule(
    "DR-APK-STORAGE-EXTERNAL",
    AuditCategory::InsecureStorage,
    AuditSeverity::Low,
);
const STORAGE_SDCARD_PATH: Rule = rule(
    "DR-APK-STORAGE-SDCARD-PATH",
    AuditCategory::InsecureStorage,
    AuditSeverity::Medium,
);
const STORAGE_TEMP_FILE: Rule = rule(
    "DR-APK-STORAGE-TEMP-FILE",
    AuditCategory::InsecureStorage,
    AuditSeverity::Low,
);
const SQL_DYNAMIC_QUERY: Rule = rule(
    "DR-APK-SQL-DYNAMIC-QUERY",
    AuditCategory::InsecureStorage,
    AuditSeverity::Medium,
);
const SSL_TRUST_ALL: Rule = rule(
    "DR-APK-SSL-TRUST-ALL",
    AuditCategory::TransportSecurity,
    AuditSeverity::High,
);
const SSL_HOSTNAME_ALLOW_ALL: Rule = rule(
    "DR-APK-SSL-HOSTNAME-ALLOW-ALL",
    AuditCategory::TransportSecurity,
    AuditSeverity::High,
);
const SSL_WEBVIEW_IGNORE_ERROR: Rule = rule(
    "DR-APK-SSL-WEBVIEW-IGNORE-ERROR",
    AuditCategory::TransportSecurity,
    AuditSeverity::High,
);
const SSL_WEAK_PROTOCOL: Rule = rule(
    "DR-APK-SSL-WEAK-PROTOCOL",
    AuditCategory::TransportSecurity,
    AuditSeverity::Medium,
);
const WEBVIEW_JAVASCRIPT: Rule = rule(
    "DR-APK-WEBVIEW-JAVASCRIPT",
    AuditCategory::WebView,
    AuditSeverity::Info,
);
const WEBVIEW_FILE_ACCESS: Rule = rule(
    "DR-APK-WEBVIEW-FILE-ACCESS",
    AuditCategory::WebView,
    AuditSeverity::Medium,
);
const WEBVIEW_MIXED_CONTENT: Rule = rule(
    "DR-APK-WEBVIEW-MIXED-CONTENT",
    AuditCategory::WebView,
    AuditSeverity::Medium,
);
const WEBVIEW_SAVE_PASSWORD: Rule = rule(
    "DR-APK-WEBVIEW-SAVE-PASSWORD",
    AuditCategory::WebView,
    AuditSeverity::Low,
);
const WEBVIEW_JS_INTERFACE: Rule = rule(
    "DR-APK-WEBVIEW-JS-INTERFACE",
    AuditCategory::WebView,
    AuditSeverity::Medium,
);
const WEBVIEW_DEBUGGING: Rule = rule(
    "DR-APK-WEBVIEW-DEBUGGING",
    AuditCategory::WebView,
    AuditSeverity::Low,
);
const LOG_SENSITIVE: Rule = rule(
    "DR-APK-LOG-SENSITIVE",
    AuditCategory::Logging,
    AuditSeverity::Medium,
);
const LOG_CALL: Rule = rule(
    "DR-APK-LOG-CALL",
    AuditCategory::Logging,
    AuditSeverity::Info,
);
const EXEC_COMMAND: Rule = rule(
    "DR-APK-EXEC-COMMAND",
    AuditCategory::DangerousApi,
    AuditSeverity::Medium,
);
const ROOT_SU_COMMAND: Rule = rule(
    "DR-APK-ROOT-SU-COMMAND",
    AuditCategory::AntiAnalysis,
    AuditSeverity::Medium,
);
const ROOT_DETECTION: Rule = rule(
    "DR-APK-ROOT-DETECTION",
    AuditCategory::AntiAnalysis,
    AuditSeverity::Info,
);
const EMULATOR_CHECK: Rule = rule(
    "DR-APK-EMULATOR-CHECK",
    AuditCategory::AntiAnalysis,
    AuditSeverity::Info,
);
const SIGNATURE_CHECK: Rule = rule(
    "DR-APK-SIGNATURE-CHECK",
    AuditCategory::AntiAnalysis,
    AuditSeverity::Info,
);
const FRIDA_CHECK: Rule = rule(
    "DR-APK-FRIDA-CHECK",
    AuditCategory::AntiAnalysis,
    AuditSeverity::Info,
);
const PLAY_INTEGRITY: Rule = rule(
    "DR-APK-PLAY-INTEGRITY",
    AuditCategory::AntiAnalysis,
    AuditSeverity::Info,
);
const SAFETYNET_ATTEST: Rule = rule(
    "DR-APK-SAFETYNET-ATTEST",
    AuditCategory::AntiAnalysis,
    AuditSeverity::Info,
);
const DEBUGGER_CHECK: Rule = rule(
    "DR-APK-DEBUGGER-CHECK",
    AuditCategory::AntiAnalysis,
    AuditSeverity::Info,
);
const DYNAMIC_CODE_LOADING: Rule = rule(
    "DR-APK-DYNAMIC-CODE-LOADING",
    AuditCategory::DangerousApi,
    AuditSeverity::Medium,
);
const NATIVE_LOAD_PATH: Rule = rule(
    "DR-APK-NATIVE-LOAD-PATH",
    AuditCategory::DangerousApi,
    AuditSeverity::Low,
);
const REFLECTION: Rule = rule(
    "DR-APK-REFLECTION",
    AuditCategory::DangerousApi,
    AuditSeverity::Info,
);
const DEVICE_IDENTIFIER: Rule = rule(
    "DR-APK-DEVICE-IDENTIFIER",
    AuditCategory::Privacy,
    AuditSeverity::Medium,
);
const SMS_SEND: Rule = rule(
    "DR-APK-SMS-SEND",
    AuditCategory::Privacy,
    AuditSeverity::Medium,
);
const CLIPBOARD_READ: Rule = rule(
    "DR-APK-CLIPBOARD-READ",
    AuditCategory::Privacy,
    AuditSeverity::Low,
);
const AUDIO_CAPTURE: Rule = rule(
    "DR-APK-AUDIO-CAPTURE",
    AuditCategory::Privacy,
    AuditSeverity::Low,
);
const CAMERA_CAPTURE: Rule = rule(
    "DR-APK-CAMERA-CAPTURE",
    AuditCategory::Privacy,
    AuditSeverity::Low,
);
const LOCATION_ACCESS: Rule = rule(
    "DR-APK-LOCATION-ACCESS",
    AuditCategory::Privacy,
    AuditSeverity::Low,
);
const INSTALLED_APPS: Rule = rule(
    "DR-APK-INSTALLED-APPS",
    AuditCategory::Privacy,
    AuditSeverity::Low,
);

const WEAK_CIPHERS: &[&str] = &[
    "DES",
    "DESEDE",
    "TRIPLEDES",
    "3DES",
    "RC2",
    "RC4",
    "ARC4",
    "ARCFOUR",
    "BLOWFISH",
];
const WEAK_HASHES: &[&str] = &["MD2", "MD4", "MD5", "SHA", "SHA1", "SHA-1"];
const WEAK_PROTOCOLS: &[&str] = &["SSL", "SSLV2", "SSLV3", "TLSV1", "TLSV1.1"];
const SDCARD_PREFIXES: &[&str] = &[
    "/sdcard",
    "/mnt/sdcard",
    "/storage/emulated",
    "/storage/sdcard",
];
const ROOT_INDICATORS: &[&str] = &[
    "/system/xbin/su",
    "/system/bin/su",
    "/sbin/su",
    "/su/bin/su",
    "/system/app/Superuser.apk",
    "eu.chainfire.supersu",
    "com.noshufou.android.su",
    "com.topjohnwu.magisk",
    "com.koushikdutta.superuser",
    "test-keys",
];
const FRIDA_INDICATORS: &[&str] = &[
    "frida-agent",
    "frida-server",
    "re.frida.server",
    "/data/local/tmp/re.frida.server",
    "gum-js-loop",
    "linjector",
    "LIBFRIDA",
    "frida-gadget",
];
const GET_SIGNATURES: i64 = 0x40;
const GET_SIGNING_CERTIFICATES: i64 = 0x0800_0000;
const EMULATOR_INDICATORS: &[&str] = &[
    "goldfish",
    "ranchu",
    "generic",
    "generic_x86",
    "sdk_gphone",
    "google_sdk",
    "Genymotion",
    "vbox86",
    "Android SDK built for x86",
];
const SENSITIVE_WORDS: &[&str] = &[
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "apikey",
    "api_key",
    "credential",
    "privatekey",
    "private_key",
    "ssn",
];

#[derive(Debug, Clone, PartialEq, Eq)]
enum Value {
    Str(String),
    Lit(i64),
    Derived(String),
    Field(String),
}

pub fn audit_android_bytes(bytes: &[u8]) -> Result<AndroidAuditReport> {
    if bytes.len() >= 8 && &bytes[..4] == b"dex\n" && bytes[7] == 0 {
        let dex: DexFile = parse_dex(bytes)?;
        let mut report: AndroidAuditReport = AndroidAuditReport {
            dex_files: 1,
            ..AndroidAuditReport::default()
        };
        audit_dex_into(&dex, bytes, &mut report);
        finish(&mut report);
        return Ok(report);
    }
    if bytes.len() >= 4 && bytes[..4] == [0x50, 0x4B, 0x03, 0x04] {
        return audit_apk(bytes);
    }
    Ok(AndroidAuditReport::default())
}

pub fn audit_apk(bytes: &[u8]) -> Result<AndroidAuditReport> {
    let extract: ApkExtract = extract_apk(bytes)?;
    let mut report: AndroidAuditReport = AndroidAuditReport::default();
    for raw in extract.dex_files.values() {
        let dex: DexFile = parse_dex(raw)?;
        report.dex_files = report.dex_files.saturating_add(1);
        audit_dex_into(&dex, raw, &mut report);
    }
    finish(&mut report);
    Ok(report)
}

fn finish(report: &mut AndroidAuditReport) {
    report.findings.sort();
    report.findings.dedup();
}

pub(crate) fn audit_dex_into(dex: &DexFile, bytes: &[u8], report: &mut AndroidAuditReport) {
    let code = parse_code_items(dex, bytes);
    for item in code.decoded() {
        report.methods_scanned = report.methods_scanned.saturating_add(1);
        let mut sink: Sink<'_> = Sink {
            item,
            findings: &mut report.findings,
            truncated: &mut report.truncated,
        };
        audit_method(dex, item, &mut sink);
    }
}

struct Sink<'a> {
    item: &'a CodeItem,
    findings: &'a mut Vec<AuditFinding>,
    truncated: &'a mut bool,
}

impl Sink<'_> {
    fn push(&mut self, pc: u32, rule: Rule, evidence: String) {
        if self.findings.len() >= MAX_AUDIT_FINDINGS {
            *self.truncated = true;
            return;
        }
        self.findings.push(AuditFinding {
            class: self.item.class.clone(),
            method: self.item.method_name.clone(),
            descriptor: self.item.method_descriptor.clone(),
            pc,
            rule_id: rule.id.to_owned(),
            category: rule.category,
            severity: rule.severity,
            evidence,
        });
    }
}

fn callee<'a>(dex: &'a DexFile, insn: &DalvikInsn) -> Option<&'a MethodId> {
    if !matches!(insn.op, 0x6E..=0x72 | 0x74..=0x78) {
        return None;
    }
    insn.index
        .and_then(|index: u32| dex.method_ids.get(usize::try_from(index).ok()?))
}

fn static_field<'a>(dex: &'a DexFile, insn: &DalvikInsn) -> Option<&'a FieldId> {
    if !matches!(insn.op, 0x60..=0x66) {
        return None;
    }
    insn.index
        .and_then(|index: u32| dex.field_ids.get(usize::try_from(index).ok()?))
}

fn const_string<'a>(dex: &'a DexFile, insn: &DalvikInsn) -> Option<&'a str> {
    if !matches!(insn.op, 0x1A | 0x1B) {
        return None;
    }
    insn.index
        .and_then(|index: u32| dex.strings.get(usize::try_from(index).ok()?))
        .map(String::as_str)
}

const fn writes_first_register(op: u8) -> bool {
    !matches!(
        op,
        0x00 | 0x0E..=0x11
            | 0x1D..=0x1F
            | 0x24..=0x3D
            | 0x4B..=0x51
            | 0x59..=0x5F
            | 0x67..=0x6D
            | 0x6E..=0x78
    )
}

fn audit_method(dex: &DexFile, item: &CodeItem, sink: &mut Sink<'_>) {
    let insns: Vec<DalvikInsn> = decode_method(&item.insns);
    if let Some((shape, evidence)) = method_shape_rule(item, &insns) {
        sink.push(0, shape, evidence);
    }
    let touches_crypto: bool = insns.iter().any(|insn: &DalvikInsn| {
        callee(dex, insn).is_some_and(|m: &MethodId| m.class.starts_with("Ljavax/crypto/"))
    });
    let reads_build: bool = insns.iter().any(|insn: &DalvikInsn| {
        static_field(dex, insn).is_some_and(|f: &FieldId| f.class == "Landroid/os/Build;")
    });
    let mut regs: BTreeMap<u16, Value> = BTreeMap::new();
    let mut pending: Option<Value> = None;
    let mut literals: Vec<String> = Vec::new();
    for insn in &insns {
        if matches!(insn.op, 0x6E..=0x72 | 0x74..=0x78) {
            pending = None;
            if let Some(method) = callee(dex, insn) {
                let is_static: bool = matches!(insn.op, 0x71 | 0x77);
                let skip: usize = usize::from(!is_static);
                let receiver: Option<&Value> = if is_static {
                    None
                } else {
                    insn.regs.first().and_then(|r: &u16| regs.get(r))
                };
                let params: Vec<Option<&Value>> = insn
                    .regs
                    .iter()
                    .skip(skip)
                    .map(|r: &u16| regs.get(r))
                    .collect();
                call_rules(method, &params, touches_crypto, &literals, insn.pc, sink);
                pending = derived_result(method, receiver);
            }
            continue;
        }
        let Some(&dest) = insn.regs.first() else {
            continue;
        };
        match insn.op {
            0x01..=0x09 => {
                let copied: Option<Value> = insn
                    .regs
                    .get(1)
                    .and_then(|src: &u16| regs.get(src).cloned());
                match copied {
                    Some(value) => {
                        regs.insert(dest, value);
                    }
                    None => {
                        regs.remove(&dest);
                    }
                }
            }
            0x0A..=0x0C => match pending.take() {
                Some(value) => {
                    regs.insert(dest, value);
                }
                None => {
                    regs.remove(&dest);
                }
            },
            0x12..=0x19 => match insn.literal {
                Some(literal) => {
                    regs.insert(dest, Value::Lit(literal));
                }
                None => {
                    regs.remove(&dest);
                }
            },
            0x1A | 0x1B => match const_string(dex, insn) {
                Some(text) => {
                    string_rules(text, reads_build, insn.pc, sink);
                    if literals.len() < MAX_METHOD_LITERALS {
                        literals.push(text.to_owned());
                    }
                    regs.insert(dest, Value::Str(text.to_owned()));
                }
                None => {
                    regs.remove(&dest);
                }
            },
            0x60..=0x66 => match static_field(dex, insn) {
                Some(field) => {
                    let name: String = format!("{}->{}", field.class, field.name);
                    field_rules(&name, insn.pc, sink);
                    regs.insert(dest, Value::Field(name));
                }
                None => {
                    regs.remove(&dest);
                }
            },
            op if writes_first_register(op) => {
                regs.remove(&dest);
            }
            _ => {}
        }
    }
}

fn derived_result(method: &MethodId, receiver: Option<&Value>) -> Option<Value> {
    match receiver {
        Some(Value::Str(text))
            if method.class == "Ljava/lang/String;"
                && matches!(method.name.as_str(), "getBytes" | "toCharArray") =>
        {
            Some(Value::Derived(text.clone()))
        }
        _ => None,
    }
}

fn effective(insns: &[DalvikInsn]) -> Vec<&DalvikInsn> {
    insns
        .iter()
        .filter(|insn: &&DalvikInsn| insn.op != 0x00)
        .collect()
}

fn method_shape_rule(item: &CodeItem, insns: &[DalvikInsn]) -> Option<(Rule, String)> {
    let body: Vec<&DalvikInsn> = effective(insns);
    let name: &str = item.method_name.as_str();
    let descriptor: &str = item.method_descriptor.as_str();
    match (name, descriptor) {
        (
            "checkServerTrusted" | "checkClientTrusted",
            "([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V",
        ) => (body.len() == 1 && body[0].op == 0x0E).then(|| {
            (
                SSL_TRUST_ALL,
                format!("X509TrustManager.{name} accepts every certificate chain"),
            )
        }),
        ("getAcceptedIssuers", "()[Ljava/security/cert/X509Certificate;") => {
            let returns_null: bool = body.len() == 2
                && body[0].op == 0x12
                && body[0].literal == Some(0)
                && body[1].op == 0x11
                && body[1].regs.first() == body[0].regs.first();
            returns_null.then(|| {
                (
                    SSL_TRUST_ALL,
                    "X509TrustManager.getAcceptedIssuers returns null".to_owned(),
                )
            })
        }
        ("verify", "(Ljava/lang/String;Ljavax/net/ssl/SSLSession;)Z") => {
            let returns_true: bool = body.len() == 2
                && body[0].op == 0x12
                && body[0].literal == Some(1)
                && body[1].op == 0x0F
                && body[1].regs.first() == body[0].regs.first();
            returns_true.then(|| {
                (
                    SSL_HOSTNAME_ALLOW_ALL,
                    "HostnameVerifier.verify returns true for every host".to_owned(),
                )
            })
        }
        _ => None,
    }
}

fn string_rules(text: &str, reads_build: bool, pc: u32, sink: &mut Sink<'_>) {
    if ROOT_INDICATORS.contains(&text) {
        sink.push(
            pc,
            ROOT_DETECTION,
            format!("root indicator literal {text:?}"),
        );
    }
    if FRIDA_INDICATORS.contains(&text) {
        sink.push(pc, FRIDA_CHECK, format!("Frida indicator literal {text:?}"));
    }
    if reads_build && EMULATOR_INDICATORS.contains(&text) {
        sink.push(
            pc,
            EMULATOR_CHECK,
            format!("Build property compared against emulator literal {text:?}"),
        );
    }
}

fn field_rules(field: &str, pc: u32, sink: &mut Sink<'_>) {
    match field {
        "Lorg/apache/http/conn/ssl/SSLSocketFactory;->ALLOW_ALL_HOSTNAME_VERIFIER" => {
            sink.push(pc, SSL_HOSTNAME_ALLOW_ALL, format!("reads {field}"));
        }
        "Landroid/os/Build;->SERIAL" => {
            sink.push(pc, DEVICE_IDENTIFIER, format!("reads {field}"));
        }
        _ => {}
    }
}

fn str_param<'a>(params: &[Option<&'a Value>], n: usize) -> Option<&'a str> {
    match params.get(n).copied().flatten() {
        Some(Value::Str(text)) => Some(text.as_str()),
        _ => None,
    }
}

fn lit_param(params: &[Option<&Value>], n: usize) -> Option<i64> {
    match params.get(n).copied().flatten() {
        Some(Value::Lit(value)) => Some(*value),
        _ => None,
    }
}

fn derived_param<'a>(params: &[Option<&'a Value>], n: usize) -> Option<&'a str> {
    match params.get(n).copied().flatten() {
        Some(Value::Derived(text)) => Some(text.as_str()),
        _ => None,
    }
}

fn seed_param(params: &[Option<&Value>], n: usize) -> Option<String> {
    match params.get(n).copied().flatten() {
        Some(Value::Lit(value)) => Some(value.to_string()),
        Some(Value::Derived(text)) => Some(format!("{text:?}")),
        _ => None,
    }
}

fn cipher_rule(transformation: &str) -> Option<(Rule, String)> {
    let upper: String = transformation.to_ascii_uppercase();
    let mut parts = upper.split('/');
    let algorithm: &str = parts.next().unwrap_or("");
    let mode: Option<&str> = parts.next();
    let evidence: String = format!("Cipher.getInstance({transformation:?})");
    if WEAK_CIPHERS.contains(&algorithm) {
        return Some((CRYPTO_WEAK_CIPHER, evidence));
    }
    if algorithm == "RSA" {
        return (!upper.contains("OAEP")).then_some((CRYPTO_RSA_NO_OAEP, evidence));
    }
    if mode == Some("ECB") || (mode.is_none() && algorithm == "AES") {
        return Some((CRYPTO_ECB, evidence));
    }
    None
}

fn is_su_command(text: &str) -> bool {
    let trimmed: &str = text.trim();
    trimmed == "su"
        || trimmed.starts_with("su ")
        || trimmed.ends_with("/su")
        || trimmed.contains("/su ")
}

fn sensitive_literal<'a>(params: &[Option<&'a Value>], literals: &'a [String]) -> Option<&'a str> {
    let in_params = params
        .iter()
        .copied()
        .filter_map(|value: Option<&Value>| match value {
            Some(Value::Str(text)) => Some(text.as_str()),
            _ => None,
        });
    in_params
        .chain(literals.iter().map(String::as_str))
        .find(|text: &&str| {
            let lower: String = text.to_ascii_lowercase();
            SENSITIVE_WORDS
                .iter()
                .any(|word: &&str| lower.contains(word))
        })
}

fn call_rules(
    method: &MethodId,
    params: &[Option<&Value>],
    touches_crypto: bool,
    literals: &[String],
    pc: u32,
    sink: &mut Sink<'_>,
) {
    let class: &str = method.class.as_str();
    let name: &str = method.name.as_str();
    let site: String = format!("{class}->{name}");
    let hit: Option<(Rule, String)> = match (class, name) {
        ("Ljavax/crypto/Cipher;", "getInstance") => str_param(params, 0).and_then(cipher_rule),
        ("Ljava/security/MessageDigest;", "getInstance") => str_param(params, 0)
            .filter(|algorithm: &&str| {
                WEAK_HASHES.contains(&algorithm.to_ascii_uppercase().as_str())
            })
            .map(|algorithm: &str| {
                (
                    CRYPTO_WEAK_HASH,
                    format!("MessageDigest.getInstance({algorithm:?})"),
                )
            }),
        ("Ljava/security/SecureRandom;", "setSeed" | "<init>") => {
            seed_param(params, 0).map(|seed: String| {
                (
                    CRYPTO_SEEDED_RANDOM,
                    format!("SecureRandom seeded with constant {seed}"),
                )
            })
        }
        ("Ljava/util/Random;", "<init>") => touches_crypto.then(|| {
            (
                CRYPTO_INSECURE_RANDOM,
                "java.util.Random constructed in a method that uses javax.crypto".to_owned(),
            )
        }),
        ("Ljavax/crypto/spec/SecretKeySpec;" | "Ljavax/crypto/spec/PBEKeySpec;", "<init>") => {
            derived_param(params, 0).map(|key: &str| {
                (
                    CRYPTO_HARDCODED_KEY,
                    format!("{site} built from literal {key:?}"),
                )
            })
        }
        ("Ljavax/crypto/spec/IvParameterSpec;", "<init>") => {
            derived_param(params, 0).map(|iv: &str| {
                (
                    CRYPTO_STATIC_IV,
                    format!("IvParameterSpec built from literal {iv:?}"),
                )
            })
        }
        ("Ljavax/net/ssl/SSLContext;", "getInstance") => str_param(params, 0)
            .filter(|protocol: &&str| {
                WEAK_PROTOCOLS.contains(&protocol.to_ascii_uppercase().as_str())
            })
            .map(|protocol: &str| {
                (
                    SSL_WEAK_PROTOCOL,
                    format!("SSLContext.getInstance({protocol:?})"),
                )
            }),
        ("Landroid/webkit/SslErrorHandler;", "proceed") => Some((
            SSL_WEBVIEW_IGNORE_ERROR,
            "SslErrorHandler.proceed continues past a certificate error".to_owned(),
        )),
        ("Lorg/apache/http/conn/ssl/AllowAllHostnameVerifier;", "<init>") => {
            Some((SSL_HOSTNAME_ALLOW_ALL, format!("constructs {class}")))
        }
        (
            "Landroid/os/Environment;",
            "getExternalStorageDirectory" | "getExternalStoragePublicDirectory",
        ) => Some((STORAGE_EXTERNAL, site)),
        (
            _,
            "getExternalFilesDir"
            | "getExternalCacheDir"
            | "getExternalFilesDirs"
            | "getExternalMediaDirs",
        ) if method.proto.return_type.starts_with("Ljava/io/File;")
            || method.proto.return_type == "[Ljava/io/File;" =>
        {
            Some((STORAGE_EXTERNAL, site))
        }
        (
            "Ljava/io/File;"
            | "Ljava/io/FileOutputStream;"
            | "Ljava/io/FileInputStream;"
            | "Ljava/io/RandomAccessFile;",
            "<init>",
        ) => str_param(params, 0)
            .filter(|path: &&str| {
                SDCARD_PREFIXES
                    .iter()
                    .any(|prefix: &&str| path.starts_with(prefix))
            })
            .map(|path: &str| (STORAGE_SDCARD_PATH, format!("{site} opens {path:?}"))),
        ("Ljava/io/File;", "createTempFile") => Some((STORAGE_TEMP_FILE, site)),
        (_, "openFileOutput" | "getSharedPreferences" | "openOrCreateDatabase" | "getDir")
            if method.proto.parameters.first().map(String::as_str)
                == Some("Ljava/lang/String;")
                && method.proto.parameters.get(1).map(String::as_str) == Some("I") =>
        {
            lit_param(params, 1)
                .filter(|mode: &i64| mode & 0x3 != 0)
                .map(|mode: i64| {
                    (
                        STORAGE_WORLD_ACCESSIBLE,
                        format!("{site} with mode {mode:#x}"),
                    )
                })
        }
        ("Landroid/database/sqlite/SQLiteDatabase;", "execSQL" | "rawQuery") => {
            params.first().copied().flatten().is_none().then(|| {
                (
                    SQL_DYNAMIC_QUERY,
                    format!("{site} with a non-literal statement"),
                )
            })
        }
        (settings, "setJavaScriptEnabled") if settings.ends_with("WebSettings;") => {
            (lit_param(params, 0) == Some(1)).then(|| (WEBVIEW_JAVASCRIPT, format!("{site}(true)")))
        }
        (
            settings,
            "setAllowFileAccess"
            | "setAllowFileAccessFromFileURLs"
            | "setAllowUniversalAccessFromFileURLs"
            | "setAllowContentAccess",
        ) if settings.ends_with("WebSettings;") => (lit_param(params, 0) == Some(1))
            .then(|| (WEBVIEW_FILE_ACCESS, format!("{site}(true)"))),
        (settings, "setMixedContentMode") if settings.ends_with("WebSettings;") => {
            (lit_param(params, 0) == Some(0)).then(|| {
                (
                    WEBVIEW_MIXED_CONTENT,
                    format!("{site}(MIXED_CONTENT_ALWAYS_ALLOW)"),
                )
            })
        }
        (settings, "setSavePassword") if settings.ends_with("WebSettings;") => {
            (lit_param(params, 0) == Some(1))
                .then(|| (WEBVIEW_SAVE_PASSWORD, format!("{site}(true)")))
        }
        ("Landroid/webkit/WebView;", "addJavascriptInterface") => Some((
            WEBVIEW_JS_INTERFACE,
            match str_param(params, 1) {
                Some(bridge) => format!("{site} exposes {bridge:?}"),
                None => site,
            },
        )),
        ("Landroid/webkit/WebView;", "setWebContentsDebuggingEnabled") => {
            (lit_param(params, 0) == Some(1)).then(|| (WEBVIEW_DEBUGGING, format!("{site}(true)")))
        }
        ("Landroid/util/Log;", "v" | "d" | "i" | "w" | "e" | "wtf" | "println") => {
            Some(match sensitive_literal(params, literals) {
                Some(literal) => (LOG_SENSITIVE, format!("{site} with literal {literal:?}")),
                None => (LOG_CALL, site),
            })
        }
        ("Ljava/lang/Runtime;", "exec") | ("Ljava/lang/ProcessBuilder;", "<init>") => {
            let su: Option<&str> =
                params
                    .iter()
                    .copied()
                    .find_map(|value: Option<&Value>| match value {
                        Some(Value::Str(text)) if is_su_command(text) => Some(text.as_str()),
                        _ => None,
                    });
            Some(match su {
                Some(command) => (ROOT_SU_COMMAND, format!("{site} runs {command:?}")),
                None => (EXEC_COMMAND, site),
            })
        }
        (
            "Ldalvik/system/DexClassLoader;"
            | "Ldalvik/system/PathClassLoader;"
            | "Ldalvik/system/InMemoryDexClassLoader;"
            | "Ldalvik/system/BaseDexClassLoader;",
            "<init>",
        ) => Some((DYNAMIC_CODE_LOADING, format!("constructs {class}"))),
        ("Ljava/lang/System;" | "Ljava/lang/Runtime;", "load") => Some((NATIVE_LOAD_PATH, site)),
        ("Ljava/lang/reflect/Method;", "invoke") => Some((REFLECTION, site)),
        ("Landroid/os/Debug;", "isDebuggerConnected" | "waitingForDebugger") => {
            Some((DEBUGGER_CHECK, site))
        }
        ("Landroid/content/pm/PackageManager;", "getPackageInfo") => lit_param(params, 1)
            .filter(|flags: &i64| flags & (GET_SIGNATURES | GET_SIGNING_CERTIFICATES) != 0)
            .map(|flags: i64| {
                (
                    SIGNATURE_CHECK,
                    format!("{site} with flags {flags:#x} reads the signing certificates"),
                )
            }),
        ("Lcom/google/android/play/core/integrity/IntegrityManager;", "requestIntegrityToken") => {
            Some((PLAY_INTEGRITY, site))
        }
        ("Lcom/google/android/gms/safetynet/SafetyNetClient;", "attest") => {
            Some((SAFETYNET_ATTEST, site))
        }
        (
            "Landroid/telephony/TelephonyManager;",
            "getDeviceId" | "getImei" | "getMeid" | "getSubscriberId" | "getSimSerialNumber"
            | "getLine1Number",
        ) => Some((DEVICE_IDENTIFIER, site)),
        ("Landroid/provider/Settings$Secure;", "getString") => (str_param(params, 1)
            == Some("android_id"))
        .then(|| (DEVICE_IDENTIFIER, format!("{site}(android_id)"))),
        ("Landroid/telephony/SmsManager;", send) if send.starts_with("send") => {
            Some((SMS_SEND, site))
        }
        ("Landroid/content/ClipboardManager;", "getPrimaryClip" | "getText") => {
            Some((CLIPBOARD_READ, site))
        }
        ("Landroid/media/MediaRecorder;", "setAudioSource")
        | ("Landroid/media/AudioRecord;", "<init>") => Some((AUDIO_CAPTURE, site)),
        ("Landroid/hardware/Camera;", "open")
        | ("Landroid/hardware/camera2/CameraManager;", "openCamera") => {
            Some((CAMERA_CAPTURE, site))
        }
        (
            "Landroid/location/LocationManager;",
            "getLastKnownLocation" | "requestLocationUpdates",
        ) => Some((LOCATION_ACCESS, site)),
        (
            "Landroid/content/pm/PackageManager;",
            "getInstalledPackages" | "getInstalledApplications",
        ) => Some((INSTALLED_APPS, site)),
        _ => None,
    };
    if let Some((matched, evidence)) = hit {
        sink.push(pc, matched, evidence);
    }
}
