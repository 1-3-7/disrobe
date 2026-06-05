use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::classfile::{ClassFile, ConstantPoolEntry};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Protector {
    ProguardR8,
    ZelixKlassMaster,
    Allatori,
    Stringer,
    DashO,
    DexGuard,
    YGuard,
    SkidSuite2,
    Jbco,
}

impl Protector {
    #[inline]
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::ProguardR8 => "ProGuard/R8",
            Self::ZelixKlassMaster => "Zelix KlassMaster",
            Self::Allatori => "Allatori",
            Self::Stringer => "Stringer",
            Self::DashO => "DashO",
            Self::DexGuard => "DexGuard",
            Self::YGuard => "yGuard",
            Self::SkidSuite2 => "SkidSuite2",
            Self::Jbco => "JBCO",
        }
    }

    #[inline]
    #[must_use]
    pub const fn requires_authorization(self) -> bool {
        matches!(self, Self::DexGuard)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Detection {
    pub protector: Protector,
    pub confidence: u8,
    pub evidence: Vec<String>,
}

#[must_use]
pub fn detect_all(cf: &ClassFile) -> Vec<Detection> {
    let strings: BTreeMap<u16, String> = cf.collect_strings();
    let mut out: Vec<Detection> = Vec::new();
    if let Some(d) = detect_proguard_r8(cf, &strings) {
        out.push(d);
    }
    if let Some(d) = detect_zelix(cf, &strings) {
        out.push(d);
    }
    if let Some(d) = detect_allatori(cf, &strings) {
        out.push(d);
    }
    if let Some(d) = detect_stringer(cf, &strings) {
        out.push(d);
    }
    if let Some(d) = detect_dasho(cf, &strings) {
        out.push(d);
    }
    if let Some(d) = detect_yguard(cf, &strings) {
        out.push(d);
    }
    if let Some(d) = detect_skidsuite2(cf, &strings) {
        out.push(d);
    }
    if let Some(d) = detect_jbco(cf, &strings) {
        out.push(d);
    }
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UpstreamStatus {
    Active,
    Archived,
    Dead,
}

#[must_use]
pub const fn upstream_status(protector: Protector) -> UpstreamStatus {
    match protector {
        Protector::ProguardR8
        | Protector::Allatori
        | Protector::DexGuard
        | Protector::ZelixKlassMaster => UpstreamStatus::Active,
        Protector::Stringer | Protector::DashO => UpstreamStatus::Archived,
        Protector::YGuard | Protector::SkidSuite2 | Protector::Jbco => UpstreamStatus::Dead,
    }
}

fn class_name_from_cp(cf: &ClassFile, idx: u16) -> Option<String> {
    let i: usize = usize::from(idx);
    if i == 0 || i >= cf.constant_pool.len() {
        return None;
    }
    if let ConstantPoolEntry::Class { name_index } = cf.constant_pool[i] {
        cf.utf8_at(name_index).ok().map(str::to_string)
    } else {
        None
    }
}

fn detect_proguard_r8(cf: &ClassFile, strings: &BTreeMap<u16, String>) -> Option<Detection> {
    let mut evidence: Vec<String> = Vec::new();
    let mut score: u8 = 0;
    if let Some(name) = class_name_from_cp(cf, cf.this_class) {
        let leaf: &str = name.rsplit('/').next().unwrap_or(&name);
        if leaf.len() <= 3 && leaf.chars().all(|c| c.is_ascii_lowercase()) {
            score = score.saturating_add(30);
            evidence.push(format!("short class name '{leaf}'"));
        }
    }
    let short_methods: usize = cf
        .methods
        .iter()
        .filter(|m| {
            cf.utf8_at(m.name_index)
                .map(|n| n.len() <= 2 && n.chars().all(|c| c.is_ascii_lowercase()))
                .unwrap_or(false)
        })
        .count();
    if short_methods >= 2 {
        score = score.saturating_add(30);
        evidence.push(format!("{short_methods} short-mangled methods"));
    }
    for s in strings.values() {
        if s.contains("proguard") || s.contains("ProGuard") || s.contains("r8.jar") {
            score = score.saturating_add(40);
            evidence.push(format!("string literal matches: '{s}'"));
            break;
        }
    }
    if score >= 30 {
        Some(Detection {
            protector: Protector::ProguardR8,
            confidence: score.min(100),
            evidence,
        })
    } else {
        None
    }
}

fn detect_zelix(cf: &ClassFile, strings: &BTreeMap<u16, String>) -> Option<Detection> {
    let mut evidence: Vec<String> = Vec::new();
    let mut score: u8 = 0;
    for s in strings.values() {
        let lower: String = s.to_ascii_lowercase();
        if lower.contains("zkm") || lower.contains("zelix") || lower.contains("klassmaster") {
            score = score.saturating_add(60);
            evidence.push(format!("zkm marker string: '{s}'"));
        }
    }
    let stringbuilder_loops: usize = cf
        .methods
        .iter()
        .filter(|m| {
            m.attributes.iter().any(|a| {
                cf.utf8_at(a.name_index)
                    .map(|n| n == "Code")
                    .unwrap_or(false)
            }) && cf
                .utf8_at(m.name_index)
                .map(|n| n.contains("decrypt") || n.contains("decode"))
                .unwrap_or(false)
        })
        .count();
    if stringbuilder_loops > 0 {
        score = score.saturating_add(20);
        evidence.push(format!(
            "{stringbuilder_loops} methods named like decryption stubs"
        ));
    }
    let large_string_pool: bool = strings
        .values()
        .filter(|s| {
            s.len() > 32
                && s.chars()
                    .all(|c| !c.is_ascii_alphanumeric() || c.is_ascii_alphanumeric())
        })
        .count()
        >= 3;
    if large_string_pool {
        score = score.saturating_add(15);
        evidence.push("dense string pool consistent with ZKM encryption".into());
    }
    if score >= 30 {
        Some(Detection {
            protector: Protector::ZelixKlassMaster,
            confidence: score.min(100),
            evidence,
        })
    } else {
        None
    }
}

fn detect_allatori(cf: &ClassFile, strings: &BTreeMap<u16, String>) -> Option<Detection> {
    let mut evidence: Vec<String> = Vec::new();
    let mut score: u8 = 0;
    for s in strings.values() {
        let lower: String = s.to_ascii_lowercase();
        if lower.contains("allatori") || lower.contains("smardec") {
            score = score.saturating_add(70);
            evidence.push(format!("allatori marker string: '{s}'"));
        }
    }
    let watermark_field: bool = cf.fields.iter().any(|f| {
        cf.utf8_at(f.name_index)
            .map(|n| n.starts_with("AllatoriWM") || n == "ALLATORI_WATERMARK")
            .unwrap_or(false)
    });
    if watermark_field {
        score = score.saturating_add(30);
        evidence.push("field named like Allatori watermark".into());
    }
    if score >= 30 {
        Some(Detection {
            protector: Protector::Allatori,
            confidence: score.min(100),
            evidence,
        })
    } else {
        None
    }
}

fn detect_stringer(cf: &ClassFile, strings: &BTreeMap<u16, String>) -> Option<Detection> {
    let mut evidence: Vec<String> = Vec::new();
    let mut score: u8 = 0;
    for s in strings.values() {
        if s.contains("Stringer") || s.contains("Licel") {
            score = score.saturating_add(60);
            evidence.push(format!("stringer marker: '{s}'"));
        }
    }
    let stringer_methods: usize = cf
        .methods
        .iter()
        .filter(|m| {
            cf.utf8_at(m.name_index)
                .map(|n| n.starts_with("\u{0}") || n.starts_with("ↁ") || n == "ⁱ")
                .unwrap_or(false)
        })
        .count();
    if stringer_methods > 0 {
        score = score.saturating_add(25);
        evidence.push(format!("{stringer_methods} unicode-trickery method names"));
    }
    if score >= 30 {
        Some(Detection {
            protector: Protector::Stringer,
            confidence: score.min(100),
            evidence,
        })
    } else {
        None
    }
}

fn detect_dasho(cf: &ClassFile, strings: &BTreeMap<u16, String>) -> Option<Detection> {
    let mut evidence: Vec<String> = Vec::new();
    let mut score: u8 = 0;
    for s in strings.values() {
        let lower: String = s.to_ascii_lowercase();
        if lower.contains("dasho") || lower.contains("preemptive") {
            score = score.saturating_add(70);
            evidence.push(format!("dasho marker: '{s}'"));
        }
    }
    let _ = cf;
    if score >= 30 {
        Some(Detection {
            protector: Protector::DashO,
            confidence: score.min(100),
            evidence,
        })
    } else {
        None
    }
}

fn detect_yguard(_cf: &ClassFile, strings: &BTreeMap<u16, String>) -> Option<Detection> {
    let mut evidence: Vec<String> = Vec::new();
    let mut score: u8 = 0;
    for s in strings.values() {
        if s.contains("yGuard") || s.contains("yworks") {
            score = score.saturating_add(80);
            evidence.push(format!("yguard marker: '{s}'"));
        }
    }
    if score >= 30 {
        Some(Detection {
            protector: Protector::YGuard,
            confidence: score.min(100),
            evidence,
        })
    } else {
        None
    }
}

fn detect_skidsuite2(cf: &ClassFile, strings: &BTreeMap<u16, String>) -> Option<Detection> {
    let mut evidence: Vec<String> = Vec::new();
    let mut score: u8 = 0;
    for s in strings.values() {
        let lower: String = s.to_ascii_lowercase();
        if lower.contains("skidsuite")
            || lower.contains("me.lpk")
            || lower.contains("lpk/skidsuite")
        {
            score = score.saturating_add(70);
            evidence.push(format!("SkidSuite2 marker: '{s}'"));
        }
    }
    if let Some(name) = class_name_from_cp(cf, cf.this_class)
        && (name.contains("lpk/skidsuite") || name.contains("me/lpk"))
    {
        score = score.saturating_add(50);
        evidence.push(format!("SkidSuite2 class prefix: '{name}'"));
    }
    if score >= 50 {
        Some(Detection {
            protector: Protector::SkidSuite2,
            confidence: score.min(100),
            evidence,
        })
    } else {
        None
    }
}

fn detect_jbco(cf: &ClassFile, strings: &BTreeMap<u16, String>) -> Option<Detection> {
    let mut evidence: Vec<String> = Vec::new();
    let mut score: u8 = 0;
    for s in strings.values() {
        let lower: String = s.to_ascii_lowercase();
        if lower.contains("jbco") || lower.contains("soot.jbco") || s.contains("ca.mcgill.sable") {
            score = score.saturating_add(70);
            evidence.push(format!("JBCO marker: '{s}'"));
        }
    }
    let jsr_ret_methods: usize = cf
        .methods
        .iter()
        .filter(|m| {
            m.attributes.iter().any(|attr| {
                cf.utf8_at(attr.name_index)
                    .map(|n| n == "Code")
                    .unwrap_or(false)
                    && crate::bytecode::parse_code_attribute(&attr.info)
                        .ok()
                        .and_then(|c| crate::bytecode::disassemble(&c.code).ok())
                        .map(|insns: Vec<crate::bytecode::Instruction>| {
                            insns.iter().any(|i| matches!(i.opcode, 0xA8 | 0xC9 | 0xA9))
                        })
                        .unwrap_or(false)
            })
        })
        .count();
    if jsr_ret_methods >= 2 {
        score = score.saturating_add(35);
        evidence.push(format!(
            "{jsr_ret_methods} methods use JBCO-style jsr/ret control flow"
        ));
    }
    if score >= 50 {
        Some(Detection {
            protector: Protector::Jbco,
            confidence: score.min(100),
            evidence,
        })
    } else {
        None
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StringStrip {
    pub stripped_count: usize,
    pub recovered: BTreeMap<u16, String>,
    pub residual_encrypted: usize,
}

#[must_use]
pub fn strip_encrypted_strings(cf: &ClassFile, protector: Protector) -> StringStrip {
    let strings: BTreeMap<u16, String> = cf.collect_strings();
    let mut recovered: BTreeMap<u16, String> = BTreeMap::new();
    let mut residual: usize = 0;
    for (idx, value) in &strings {
        let looks_encrypted: bool = is_likely_encrypted_string(value, protector);
        if looks_encrypted {
            residual += 1;
        } else {
            recovered.insert(*idx, value.clone());
        }
    }
    StringStrip {
        stripped_count: strings.len().saturating_sub(residual),
        recovered,
        residual_encrypted: residual,
    }
}

fn is_likely_encrypted_string(s: &str, protector: Protector) -> bool {
    if s.is_empty() {
        return false;
    }
    let non_printable: usize = s
        .chars()
        .filter(|c| !c.is_ascii_graphic() && !c.is_whitespace())
        .count();
    let ratio: f64 = non_printable as f64 / s.chars().count().max(1) as f64;
    match protector {
        Protector::ZelixKlassMaster
        | Protector::Allatori
        | Protector::Stringer
        | Protector::DashO
        | Protector::DexGuard => ratio > 0.5 && s.chars().count() >= 4,
        _ => false,
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatermarkFinding {
    pub fields: Vec<String>,
    pub strings: Vec<String>,
}

#[must_use]
pub fn detect_allatori_watermarks(cf: &ClassFile) -> WatermarkFinding {
    let mut finding: WatermarkFinding = WatermarkFinding::default();
    for f in &cf.fields {
        if let Ok(name) = cf.utf8_at(f.name_index)
            && (name.starts_with("AllatoriWM") || name == "ALLATORI_WATERMARK")
        {
            finding.fields.push(name.to_string());
        }
    }
    for s in cf.collect_strings().values() {
        if s.starts_with("AllatoriWatermark:") || s.starts_with("WM:") {
            finding.strings.push(s.clone());
        }
    }
    finding
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CffUndoStats {
    pub flattened_methods: usize,
    pub recovered_branches: usize,
}

#[must_use]
pub fn undo_control_flow(cf: &ClassFile) -> CffUndoStats {
    let mut stats: CffUndoStats = CffUndoStats::default();
    for m in &cf.methods {
        for attr in &m.attributes {
            let Ok(name): Result<&str, crate::error::Error> = cf.utf8_at(attr.name_index) else {
                continue;
            };
            if name != "Code" {
                continue;
            }
            let Ok(parsed): Result<crate::bytecode::CodeAttribute, crate::error::Error> =
                crate::bytecode::parse_code_attribute(&attr.info)
            else {
                continue;
            };
            let Ok(insns): Result<Vec<crate::bytecode::Instruction>, crate::error::Error> =
                crate::bytecode::disassemble(&parsed.code)
            else {
                continue;
            };
            let mut goto_count: usize = 0;
            let mut switch_count: usize = 0;
            for insn in &insns {
                match insn.opcode {
                    0xA7 | 0xC8 => goto_count += 1,
                    0xAA | 0xAB => switch_count += 1,
                    _ => {}
                }
            }
            if goto_count + switch_count > 8 {
                stats.flattened_methods += 1;
                stats.recovered_branches += goto_count;
            }
        }
    }
    stats
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use crate::classfile::{Attribute, ClassFile, ConstantPoolEntry, FieldInfo, MethodInfo};

    use super::*;

    fn empty_class() -> ClassFile {
        ClassFile {
            minor_version: 0,
            major_version: 52,
            constant_pool: vec![ConstantPoolEntry::Placeholder],
            access_flags: 0,
            this_class: 0,
            super_class: 0,
            interfaces: Vec::new(),
            fields: Vec::new(),
            methods: Vec::new(),
            attributes: Vec::new(),
        }
    }

    #[test]
    fn detect_returns_empty_for_clean_class() {
        let cf: ClassFile = empty_class();
        let d: Vec<Detection> = detect_all(&cf);
        assert!(d.is_empty());
    }

    #[test]
    fn allatori_watermark_fields_detected() {
        let mut cf: ClassFile = empty_class();
        cf.constant_pool
            .push(ConstantPoolEntry::Utf8("AllatoriWM_x".into()));
        cf.fields.push(FieldInfo {
            access_flags: 0,
            name_index: 1,
            descriptor_index: 1,
            attributes: Vec::new(),
        });
        let f: WatermarkFinding = detect_allatori_watermarks(&cf);
        assert_eq!(f.fields.len(), 1);
    }

    #[test]
    fn cff_stats_zero_for_no_methods() {
        let cf: ClassFile = empty_class();
        let s: CffUndoStats = undo_control_flow(&cf);
        assert_eq!(s.flattened_methods, 0);
    }

    #[test]
    fn cff_detects_goto_heavy_method() {
        let mut cf: ClassFile = empty_class();
        cf.constant_pool
            .push(ConstantPoolEntry::Utf8("Code".into()));
        let mut code_body: Vec<u8> = Vec::new();
        for _ in 0..10 {
            code_body.push(0xA7);
            code_body.extend_from_slice(&[0x00, 0x03]);
        }
        let mut info: Vec<u8> = Vec::new();
        info.extend_from_slice(&0u16.to_be_bytes());
        info.extend_from_slice(&0u16.to_be_bytes());
        info.extend_from_slice(&(code_body.len() as u32).to_be_bytes());
        info.extend_from_slice(&code_body);
        info.extend_from_slice(&0u16.to_be_bytes());
        cf.methods.push(MethodInfo {
            access_flags: 0,
            name_index: 0,
            descriptor_index: 0,
            attributes: vec![Attribute {
                name_index: 1,
                info,
            }],
        });
        let s: CffUndoStats = undo_control_flow(&cf);
        assert_eq!(s.flattened_methods, 1);
    }
}
