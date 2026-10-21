use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::android_audit::{AndroidAuditReport, AuditFinding, audit_dex_into};
use crate::apk_sig::{ApkSignatureReport, SchemeReport};
use crate::classfile::{self, ClassFile};
use crate::dalvik_pack_recover::{PackageRecoveryReport, SchemeCandidate, recover_packed_dex};
use crate::dex::{DexFile, DexHeader, parse as parse_dex, parse_header};
use crate::jar::{ApkExtract, JarExtract, extract_apk};
use crate::obfuscators::{Detection, Protector, detect_all};
use crate::rasp::{RaspReport, RaspSignal, detect_in_apk};

const DEX_MAGIC: &[u8; 4] = b"dex\n";
const CLASS_MAGIC: [u8; 4] = [0xCA, 0xFE, 0xBA, 0xBE];
const ZIP_LOCAL_HEADER: [u8; 4] = [0x50, 0x4B, 0x03, 0x04];
const MAP_ENTRY_BYTES: usize = 12;
const MAX_MAP_ENTRIES: usize = 64;
const MAX_IDENTITY_HITS: usize = 4_096;
const MAX_CLASSES_FINGERPRINTED: usize = 65_536;
const MINIFIED_NAME_RATIO_PERCENT: u64 = 50;
const MINIFIED_MIN_CLASSES: usize = 2;
const D8_DATA_ORDER: [u16; 4] = [0x2001, 0x2003, 0x1001, 0x2002];
const MAP_LIST_ITEM: u16 = 0x1000;
const DEXLIB_DATA_ORDER: [u16; 2] = [0x2002, 0x1001];
const CODE_ITEM: u16 = 0x2001;
const CLASS_DATA_ITEM: u16 = 0x2000;
const OBFUSCAPK_HELPERS: [&str; 3] = [
    "Lcom/decryptstringmanager/DecryptString;",
    "Lcom/apireflectionmanager/ApiReflection;",
    "Lcom/apireflectionmanager/AdvancedApiReflection;",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AndroidIdentityKind {
    Format,
    Compiler,
    Obfuscator,
    Protector,
    Packer,
    AntiAnalysis,
    Signature,
}

impl AndroidIdentityKind {
    #[inline]
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Format => "format",
            Self::Compiler => "compiler",
            Self::Obfuscator => "obfuscator",
            Self::Protector => "protector",
            Self::Packer => "packer",
            Self::AntiAnalysis => "anti-analysis",
            Self::Signature => "signature",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AndroidIdentityHit {
    pub kind: AndroidIdentityKind,
    pub name: String,
    pub detail: String,
    pub confidence: u8,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AndroidIdentity {
    pub format: String,
    pub dex_files: usize,
    pub class_files: usize,
    pub hits: Vec<AndroidIdentityHit>,
    pub truncated: bool,
}

impl AndroidIdentity {
    fn push(&mut self, kind: AndroidIdentityKind, name: String, detail: String, confidence: u8) {
        if self.hits.len() >= MAX_IDENTITY_HITS {
            self.truncated = true;
            return;
        }
        self.hits.push(AndroidIdentityHit {
            kind,
            name,
            detail,
            confidence,
        });
    }
}

#[must_use]
pub fn identify_android(bytes: &[u8], path_hint: Option<&str>) -> Option<AndroidIdentity> {
    if bytes.len() >= 8 && &bytes[..4] == DEX_MAGIC && bytes[7] == 0 {
        let mut identity: AndroidIdentity = AndroidIdentity {
            format: "dex".to_owned(),
            ..AndroidIdentity::default()
        };
        identify_dex(bytes, "classes.dex", &mut identity);
        finish(&mut identity);
        return Some(identity);
    }
    if bytes.len() >= 8 && bytes[..4] == CLASS_MAGIC {
        let mut identity: AndroidIdentity = AndroidIdentity {
            format: "class".to_owned(),
            ..AndroidIdentity::default()
        };
        if let Ok(class) = classfile::parse(bytes) {
            identify_classes(&[("<input>".to_owned(), class)], &mut identity);
        }
        finish(&mut identity);
        return Some(identity);
    }
    if bytes.len() >= 4 && bytes[..4] == ZIP_LOCAL_HEADER {
        let apk: ApkExtract = extract_apk(bytes).ok()?;
        let has_manifest: bool = apk.manifest_bytes.is_some();
        let has_dex: bool = !apk.dex_files.is_empty();
        let has_classes: bool = !apk.jar.classes.is_empty();
        if !has_manifest && !has_dex && !has_classes {
            return None;
        }
        let looks_apk: bool = has_manifest
            || path_hint.is_some_and(|p: &str| p.to_ascii_lowercase().ends_with(".apk"));
        let mut identity: AndroidIdentity = AndroidIdentity {
            format: if looks_apk { "apk" } else { "jar" }.to_owned(),
            ..AndroidIdentity::default()
        };
        for (name, dex) in &apk.dex_files {
            identify_dex(dex, name, &mut identity);
        }
        identify_jar(&apk.jar, &mut identity);
        if looks_apk {
            identify_apk(bytes, &mut identity);
        }
        finish(&mut identity);
        return Some(identity);
    }
    None
}

fn finish(identity: &mut AndroidIdentity) {
    identity.hits.sort();
    identity.hits.dedup();
}

fn identify_dex(bytes: &[u8], name: &str, identity: &mut AndroidIdentity) {
    identity.dex_files = identity.dex_files.saturating_add(1);
    let Ok(header) = parse_header(bytes) else {
        identity.push(
            AndroidIdentityKind::Format,
            "malformed dex".to_owned(),
            format!("{name}: the header does not parse"),
            100,
        );
        return;
    };
    identity.push(
        AndroidIdentityKind::Format,
        format!("dex {}", &String::from_utf8_lossy(&bytes[4..7])),
        format!(
            "{name}: {} bytes, {}",
            bytes.len(),
            header.version.android_marketing()
        ),
        100,
    );
    match data_item_order(bytes, &header) {
        Some(order)
            if order.starts_with(&D8_DATA_ORDER) && order.last() == Some(&MAP_LIST_ITEM) =>
        {
            identity.push(
                AndroidIdentityKind::Compiler,
                "d8/r8".to_owned(),
                format!(
                    "{name}: data section written code items, debug info, type lists, string data first and the map list last, the layout the d8 and r8 writers produce"
                ),
                85,
            );
        }
        Some(order)
            if order.starts_with(&DEXLIB_DATA_ORDER)
                && order.last() == Some(&MAP_LIST_ITEM)
                && order.iter().position(|item: &u16| *item == CODE_ITEM)
                    < order.iter().position(|item: &u16| *item == CLASS_DATA_ITEM) =>
        {
            identity.push(
                AndroidIdentityKind::Compiler,
                "dexlib 2.x".to_owned(),
                format!(
                    "{name}: data section written string data and type lists first, code items before class data and the map list last, the layout the smali and apktool writer produces"
                ),
                80,
            );
        }
        Some(order) => {
            identity.push(
                AndroidIdentityKind::Compiler,
                "unknown dex writer".to_owned(),
                format!(
                    "{name}: data item order {} does not match the d8/r8 layout",
                    order
                        .iter()
                        .map(|item: &u16| format!("{item:#06x}"))
                        .collect::<Vec<String>>()
                        .join(",")
                ),
                40,
            );
        }
        None => {}
    }
    let Ok(dex) = parse_dex(bytes) else {
        return;
    };
    if let Some((minified, total)) = minified_class_names(&dex) {
        identity.push(
            AndroidIdentityKind::Obfuscator,
            "ProGuard/R8 renaming".to_owned(),
            format!("{name}: {minified} of {total} classes carry names of at most two characters"),
            70,
        );
    }
    let helpers: Vec<&str> = OBFUSCAPK_HELPERS
        .iter()
        .copied()
        .filter(|helper: &&str| dex.class_descriptors.iter().any(|c: &String| c == helper))
        .collect();
    if !helpers.is_empty() {
        identity.push(
            AndroidIdentityKind::Obfuscator,
            "Obfuscapk".to_owned(),
            format!(
                "{name}: the Obfuscapk helper classes {} are defined in this dex",
                helpers.join(", ")
            ),
            95,
        );
    }
    let mut audit: AndroidAuditReport = AndroidAuditReport::default();
    audit_dex_into(&dex, bytes, &mut audit);
    anti_analysis_hits(&audit, name, identity);
}

fn data_item_order(bytes: &[u8], header: &DexHeader) -> Option<Vec<u16>> {
    let map_off: usize = usize::try_from(header.map_off).ok()?;
    let count: usize = usize::try_from(u32::from_le_bytes(
        bytes
            .get(map_off..map_off.checked_add(4)?)?
            .try_into()
            .ok()?,
    ))
    .ok()?;
    let count: usize = count.min(MAX_MAP_ENTRIES);
    let mut order: Vec<u16> = Vec::with_capacity(count);
    for index in 0..count {
        let at: usize = map_off
            .checked_add(4)?
            .checked_add(index.checked_mul(MAP_ENTRY_BYTES)?)?;
        let item_type: u16 =
            u16::from_le_bytes(bytes.get(at..at.checked_add(2)?)?.try_into().ok()?);
        if item_type > 0x1000 || item_type == MAP_LIST_ITEM {
            order.push(item_type);
        }
    }
    Some(order)
}

fn simple_name(descriptor: &str) -> &str {
    let body: &str = descriptor
        .strip_prefix('L')
        .and_then(|d: &str| d.strip_suffix(';'))
        .unwrap_or(descriptor);
    body.rsplit('/').next().unwrap_or(body)
}

fn minified_class_names(dex: &DexFile) -> Option<(usize, usize)> {
    let mut total: usize = 0;
    let mut minified: usize = 0;
    for descriptor in dex.class_descriptors.iter().take(MAX_CLASSES_FINGERPRINTED) {
        if descriptor.contains('$') {
            continue;
        }
        let name: &str = simple_name(descriptor);
        if name.is_empty() {
            continue;
        }
        total += 1;
        if name.chars().count() <= 2 && name.chars().all(|c: char| c.is_ascii_alphabetic()) {
            minified += 1;
        }
    }
    let ratio: u64 =
        u64::try_from(minified).ok()?.saturating_mul(100) / u64::try_from(total.max(1)).ok()?;
    (total >= MINIFIED_MIN_CLASSES && ratio >= MINIFIED_NAME_RATIO_PERCENT)
        .then_some((minified, total))
}

fn anti_analysis_hits(audit: &AndroidAuditReport, name: &str, identity: &mut AndroidIdentity) {
    let mut by_rule: BTreeMap<&str, (usize, &AuditFinding)> = BTreeMap::new();
    for finding in &audit.findings {
        let label: Option<&str> = match finding.rule_id.as_str() {
            "DR-APK-DEBUGGER-CHECK" => Some("debugger check"),
            "DR-APK-EMULATOR-CHECK" => Some("emulator check"),
            "DR-APK-ROOT-DETECTION" | "DR-APK-ROOT-SU-COMMAND" => Some("root check"),
            "DR-APK-DYNAMIC-CODE-LOADING" => Some("dynamic code loading"),
            "DR-APK-FRIDA-CHECK" => Some("instrumentation check"),
            "DR-APK-SIGNATURE-CHECK" => Some("signature check"),
            "DR-APK-PLAY-INTEGRITY" | "DR-APK-SAFETYNET-ATTEST" => Some("attestation call"),
            _ => None,
        };
        if let Some(label) = label {
            let slot: &mut (usize, &AuditFinding) = by_rule.entry(label).or_insert((0, finding));
            slot.0 = slot.0.saturating_add(1);
        }
    }
    for (label, (count, first)) in by_rule {
        identity.push(
            AndroidIdentityKind::AntiAnalysis,
            label.to_owned(),
            format!(
                "{name}: {count} site{} ({} {}->{} {})",
                if count == 1 { "" } else { "s" },
                first.rule_id,
                first.class,
                first.method,
                first.evidence
            ),
            90,
        );
    }
}

fn identify_jar(jar: &JarExtract, identity: &mut AndroidIdentity) {
    let mut classes: Vec<(String, ClassFile)> = Vec::new();
    for (name, bytes) in jar.classes.iter().take(MAX_CLASSES_FINGERPRINTED) {
        if let Ok(class) = classfile::parse(bytes) {
            classes.push((name.clone(), class));
        }
    }
    identify_classes(&classes, identity);
}

fn identify_classes(classes: &[(String, ClassFile)], identity: &mut AndroidIdentity) {
    identity.class_files = identity.class_files.saturating_add(classes.len());
    let mut by_protector: BTreeMap<Protector, (usize, u8, String)> = BTreeMap::new();
    for (name, class) in classes {
        for detection in detect_all(class) {
            let Detection {
                protector,
                confidence,
                evidence,
            } = detection;
            let slot: &mut (usize, u8, String) = by_protector
                .entry(protector)
                .or_insert_with(|| (0, 0, String::new()));
            slot.0 = slot.0.saturating_add(1);
            if confidence > slot.1 {
                slot.1 = confidence;
                slot.2 = format!("{name}: {}", evidence.join("; "));
            }
        }
    }
    for (protector, (count, confidence, detail)) in by_protector {
        identity.push(
            AndroidIdentityKind::Obfuscator,
            protector.name().to_owned(),
            format!(
                "{count} class{} matched; strongest {detail}",
                if count == 1 { "" } else { "es" }
            ),
            confidence,
        );
    }
}

fn identify_apk(bytes: &[u8], identity: &mut AndroidIdentity) {
    if let Ok(signatures) = crate::apk_sig::verify(bytes) {
        signature_hits(&signatures, identity);
    }
    if let Ok(rasp) = detect_in_apk(bytes) {
        rasp_hits(&rasp, identity);
    }
    let packing: PackageRecoveryReport = recover_packed_dex(bytes);
    for candidate in &packing.candidates {
        let SchemeCandidate { kind, confidence } = candidate;
        identity.push(
            AndroidIdentityKind::Packer,
            "stub-loader dex packer".to_owned(),
            kind.label().to_owned(),
            *confidence,
        );
    }
}

fn signature_hits(signatures: &ApkSignatureReport, identity: &mut AndroidIdentity) {
    if signatures.v1_present {
        identity.push(
            AndroidIdentityKind::Signature,
            "v1 (JAR signing)".to_owned(),
            format!(
                "{} signed entr{}",
                signatures.v1_entries.len(),
                if signatures.v1_entries.len() == 1 {
                    "y"
                } else {
                    "ies"
                }
            ),
            100,
        );
    }
    for scheme in &signatures.schemes {
        let SchemeReport {
            scheme,
            signer_count,
            integrity_verified,
            ..
        } = scheme;
        identity.push(
            AndroidIdentityKind::Signature,
            scheme.label().to_owned(),
            format!(
                "{signer_count} signer{}, integrity {}",
                if *signer_count == 1 { "" } else { "s" },
                if *integrity_verified {
                    "verified"
                } else {
                    "not verified"
                }
            ),
            100,
        );
    }
}

fn rasp_hits(rasp: &RaspReport, identity: &mut AndroidIdentity) {
    for signal in &rasp.signals {
        let RaspSignal {
            vendor,
            confidence,
            evidence,
        } = signal;
        identity.push(
            AndroidIdentityKind::Protector,
            vendor.name().to_owned(),
            evidence.join("; "),
            *confidence,
        );
    }
}
