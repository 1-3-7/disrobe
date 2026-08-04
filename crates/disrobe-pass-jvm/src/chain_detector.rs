#![cfg(feature = "chain")]
#![allow(clippy::module_name_repetitions)]
use disrobe_core::Artifact;
use disrobe_core::Rung;
use disrobe_core::chain::detection::TERMINAL_HINT;
use disrobe_core::chain::{
    CatalogEntry, ChildArtifact, ChildHandle, DetectContext, DetectVerdict, Detector,
    DetectorOutput, FAMILY_INTERPRETER_BYTECODE, ObfuscatorCatalog, OutputKind, Pass,
    SupportQuality,
};
use disrobe_core::error::{CoreError, Result as CoreResult};
use disrobe_core::pass::PassId;

use crate::classfile::{CLASS_MAGIC, ClassFile, JavaVersion, parse as parse_classfile};
use crate::dalvik_decompile::{DecompiledDex, decompile_dex};
use crate::dalvik_dexguard::{DalvikCffReport, unflatten_dex_methods};
use crate::dalvik_strdec::{DexStringRecovery, DexStringRecoveryReport, recover_report};
use crate::decompile::{DecompiledClass, decompile_class};
use crate::dex::{
    CodeItem, CodeItemsReport, DEX_MAGIC_PREFIX, DexFile, parse as parse_dex, parse_code_items,
};
use crate::obfuscators::Protector;
use crate::protectors::{
    PeelStatus, PeeledClass, ProtectorPeelReport, detect_family as detect_protector_family,
    peel_and_decompile,
};

pub const PASS_ID: PassId = "jvm.classify";

const TAG_CLASSFILE: &str = "jvm-classfile";
const TAG_DEX: &str = "android-dex";
const TAG_JAR: &str = "jar-zip";
const TAG_APK: &str = "android-apk";
const ZIP_LOCAL_HEADER: &[u8; 4] = b"PK\x03\x04";

#[derive(Debug)]
pub struct JvmDetector;

impl Detector for JvmDetector {
    #[inline]
    fn id(&self) -> PassId {
        PASS_ID
    }

    fn detect(&self, ctx: &DetectContext<'_>) -> Option<DetectVerdict> {
        let bytes: &[u8] = ctx.bytes;
        if bytes.len() >= 8 && reads_class_magic(bytes) {
            return Some(verdict_classfile(bytes));
        }
        if bytes.len() >= 8 && &bytes[..4] == DEX_MAGIC_PREFIX.as_slice() && bytes[7] == 0 {
            return Some(verdict_dex(bytes));
        }
        if bytes.len() >= 4 && &bytes[..4] == ZIP_LOCAL_HEADER.as_slice() {
            return Some(verdict_zip(ctx.path_hint));
        }
        None
    }
}

#[derive(Debug)]
pub struct JvmPass;

impl Pass for JvmPass {
    #[inline]
    fn meta(&self) -> disrobe_core::chain::PassMeta {
        META
    }
    #[inline]
    fn id(&self) -> PassId {
        PASS_ID
    }

    #[inline]
    fn detector(&self) -> &'static dyn Detector {
        &JvmDetector
    }

    #[inline]
    fn output_kind(&self, _output: &Artifact) -> OutputKind {
        OutputKind::Mixed {
            children: Vec::new(),
        }
    }

    fn run(&self, artifact: &Artifact) -> CoreResult<Artifact> {
        let bytes: &[u8] = artifact.envelope.as_slice();
        let ctx: DetectContext<'_> = DetectContext {
            bytes,
            path_hint: None,
            parent_hint: None,
            depth: 0,
        };
        let verdict: DetectVerdict = Detector::detect(&JvmDetector, &ctx).ok_or_else(|| {
            CoreError::PassFailure(
                "DR-JVM-0902: jvm.classify: input does not match classfile/dex/jar signatures"
                    .to_string(),
            )
        })?;
        decompile_for(verdict.format_tag, bytes, artifact.root_hash)
    }

    fn extract_children(&self, input: &Artifact) -> CoreResult<Vec<ChildArtifact>> {
        let bytes: &[u8] = input.envelope.as_slice();
        let ctx: DetectContext<'_> = DetectContext {
            bytes,
            path_hint: None,
            parent_hint: None,
            depth: 0,
        };
        let Some(verdict): Option<DetectVerdict> = Detector::detect(&JvmDetector, &ctx) else {
            return Ok(Vec::new());
        };
        match verdict.format_tag {
            TAG_CLASSFILE => classfile_children(bytes),
            TAG_DEX => dex_children(bytes),
            _ => Ok(Vec::new()),
        }
    }
}

pub const META: disrobe_core::chain::PassMeta = disrobe_core::chain::PassMeta::new(
    PASS_ID,
    disrobe_core::chain::Ecosystem::Jvm,
    disrobe_core::chain::SupportQuality::Full,
    disrobe_core::chain::Determinism::Deterministic,
    disrobe_core::chain::SafetyClass::Static,
);

pub static JVM_PASS: JvmPass = JvmPass;

fn decompile_for(format_tag: &str, bytes: &[u8], root_hash: [u8; 32]) -> CoreResult<Artifact> {
    match format_tag {
        TAG_CLASSFILE => decompile_classfile(bytes, root_hash),
        TAG_DEX => decompile_dex_artifact(bytes, root_hash),
        TAG_JAR | TAG_APK => Ok(Artifact::new(
            Rung::Disasm,
            archive_note(format_tag).into_bytes(),
            root_hash,
        )),
        other => Err(CoreError::PassFailure(format!(
            "DR-JVM-0906: jvm.classify: unknown format tag {other}"
        ))),
    }
}

fn decompile_classfile(bytes: &[u8], root_hash: [u8; 32]) -> CoreResult<Artifact> {
    let cf: ClassFile = parse_classfile(bytes).map_err(|e: crate::error::Error| {
        CoreError::PassFailure(format!("DR-JVM-0907: classfile parse: {e}"))
    })?;
    let source: String = match crate::protectors::peel_and_decompile(&cf) {
        Some(peeled) => peeled.source,
        None => {
            let decompiled: DecompiledClass = decompile_class(&cf);
            decompiled.source
        }
    };
    if source.trim().is_empty() {
        return Err(CoreError::PassFailure(
            "DR-JVM-0910: jvm.classify: classfile decompiler produced empty source".to_string(),
        ));
    }
    Ok(Artifact::new(Rung::Surface, source.into_bytes(), root_hash))
}

fn decompile_dex_artifact(bytes: &[u8], root_hash: [u8; 32]) -> CoreResult<Artifact> {
    let dex: DexFile = parse_dex(bytes).map_err(|e: crate::error::Error| {
        CoreError::PassFailure(format!("DR-JVM-0908: dex parse: {e}"))
    })?;
    let decompiled: DecompiledDex = decompile_dex(&dex, bytes);
    if decompiled.source.trim().is_empty() {
        return Err(CoreError::PassFailure(
            "DR-JVM-0911: jvm.classify: dex decompiler produced empty source".to_string(),
        ));
    }
    Ok(Artifact::new(
        Rung::Surface,
        decompiled.source.into_bytes(),
        root_hash,
    ))
}

fn terminal_child(relative_path: String, bytes: Vec<u8>) -> ChildArtifact {
    ChildArtifact {
        handle: ChildHandle {
            artifact_index: 0,
            relative_path,
            hint: Some(TERMINAL_HINT.to_string()),
        },
        bytes,
    }
}

fn reindex(children: &mut [ChildArtifact]) {
    for (index, child) in children.iter_mut().enumerate() {
        child.handle.artifact_index = u32::try_from(index).unwrap_or(u32::MAX);
    }
}

fn classfile_children(bytes: &[u8]) -> CoreResult<Vec<ChildArtifact>> {
    let cf: ClassFile = parse_classfile(bytes).map_err(|e: crate::error::Error| {
        CoreError::PassFailure(format!("DR-JVM-0907: classfile parse: {e}"))
    })?;
    let mut children: Vec<ChildArtifact> = Vec::new();

    let this_class: String = cf
        .this_class_name()
        .map_or_else(|_| "Unknown".to_owned(), str::to_owned);
    let stem: String = sanitize_component(&this_class);

    let peeled: Option<PeeledClass> = detect_protector_family(&cf)
        .is_some()
        .then(|| peel_and_decompile(&cf))
        .flatten();
    let (source, fully_lifted_methods, fallback_methods, decode_error_count): (
        String,
        usize,
        usize,
        usize,
    ) = match &peeled {
        Some(p) => (
            p.source.clone(),
            p.fully_lifted_methods,
            p.fallback_methods,
            p.decode_error_count,
        ),
        None => {
            let decompiled: DecompiledClass = decompile_class(&cf);
            (
                decompiled.source,
                decompiled.fully_lifted_methods,
                decompiled.fallback_methods,
                decompiled.decode_error_count,
            )
        }
    };
    if !source.trim().is_empty() {
        children.push(terminal_child(format!("{stem}.java"), source.into_bytes()));
    }

    if let Some(p) = &peeled
        && let Ok(json) = serde_json::to_vec_pretty(&peel_sidecar(&p.report))
    {
        children.push(terminal_child("jvm-peel.json".to_string(), json));
    }

    let manifest_json: Result<Vec<u8>, serde_json::Error> =
        serde_json::to_vec_pretty(&classfile_manifest(
            &cf,
            &this_class,
            fully_lifted_methods,
            fallback_methods,
            decode_error_count,
        ));
    if let Ok(json) = manifest_json {
        children.push(terminal_child("jvm-manifest.json".to_string(), json));
    }

    reindex(&mut children);
    Ok(children)
}

fn dex_children(bytes: &[u8]) -> CoreResult<Vec<ChildArtifact>> {
    let dex: DexFile = parse_dex(bytes).map_err(|e: crate::error::Error| {
        CoreError::PassFailure(format!("DR-JVM-0908: dex parse: {e}"))
    })?;
    let decompiled: DecompiledDex = decompile_dex(&dex, bytes);
    let recovery: DexStringRecoveryReport = recover_report(&dex, bytes);
    let code_report: CodeItemsReport = parse_code_items(&dex, bytes);
    let code_scan_complete: bool = code_report.is_fully_decoded();
    let decode_error_count: usize = code_report.error_count();
    let items: Vec<CodeItem> = code_report.into_partial_decoded();
    let (cff, _per_method): (DalvikCffReport, _) = unflatten_dex_methods(&items);
    let mut children: Vec<ChildArtifact> = Vec::new();

    if !decompiled.source.trim().is_empty() {
        children.push(terminal_child(
            "classes.java".to_string(),
            decompiled.source.into_bytes(),
        ));
    }

    if (!recovery.recoveries.is_empty() || !recovery.code_scan_complete)
        && let Ok(json) = serde_json::to_vec_pretty(&dex_reflection_sidecar(&recovery))
    {
        children.push(terminal_child(
            "jvm-reflection-strings.json".to_string(),
            json,
        ));
    }

    let manifest_json: Result<Vec<u8>, serde_json::Error> = serde_json::to_vec_pretty(
        &dex_manifest(&dex, &cff, code_scan_complete, decode_error_count),
    );
    if let Ok(json) = manifest_json {
        children.push(terminal_child("jvm-manifest.json".to_string(), json));
    }

    reindex(&mut children);
    Ok(children)
}

const fn peel_status_label(status: PeelStatus) -> &'static str {
    match status {
        PeelStatus::StubRecovered => "stub-recovered",
        PeelStatus::CipherRecovered => "cipher-recovered",
        PeelStatus::DetectOnly => "detect-only",
    }
}

fn runtime_key_walled(report: &ProtectorPeelReport) -> bool {
    report.status == PeelStatus::DetectOnly
        && report.notes.iter().any(|n: &String| {
            n.contains("runtime")
                || n.contains("stack-trace")
                || n.contains("self-tamper checksum")
                || n.contains("run time")
        })
}

fn peel_sidecar(report: &ProtectorPeelReport) -> serde_json::Value {
    serde_json::json!({
        "schema": "disrobe.jvm.protector-peel/v1",
        "family": report.family.name(),
        "status": peel_status_label(report.status),
        "strings_recovered": report.strings_recovered.len(),
        "strings_residual": report.strings_residual,
        "cff_methods_unflattened": report.cff_methods_unflattened,
        "cff_branches_recovered": report.cff_branches_recovered,
        "runtime_key_walled": runtime_key_walled(report),
        "report": report,
    })
}

fn classfile_manifest(
    cf: &ClassFile,
    this_class: &str,
    fully_lifted_methods: usize,
    fallback_methods: usize,
    decode_error_count: usize,
) -> serde_json::Value {
    let java_version: Option<&'static str> = cf.version().map(|v: JavaVersion| v.marketing_name());
    serde_json::json!({
        "schema": "disrobe.jvm.classify/v1",
        "format": "classfile",
        "this_class": this_class,
        "major_version": cf.major_version,
        "minor_version": cf.minor_version,
        "java_version": java_version,
        "field_count": cf.fields.len(),
        "method_count": cf.methods.len(),
        "fully_lifted_methods": fully_lifted_methods,
        "fallback_methods": fallback_methods,
        "code_scan_complete": decode_error_count == 0,
        "decode_error_count": decode_error_count,
        "constant_pool_size": cf.constant_pool.len(),
    })
}

fn dex_reflection_sidecar(report: &DexStringRecoveryReport) -> serde_json::Value {
    let recovered_total: usize = report
        .recoveries
        .iter()
        .map(|r: &DexStringRecovery| r.recovered.len())
        .sum();
    let reflective_total: usize = report
        .recoveries
        .iter()
        .map(|r: &DexStringRecovery| r.reflective_call_sites.len())
        .sum();
    let runtime_key_walled: bool = report
        .recoveries
        .iter()
        .any(|r: &DexStringRecovery| r.runtime_key_wall);
    serde_json::json!({
        "schema": "disrobe.jvm.reflection-strings/v1",
        "family": "DexGuard",
        "strings_recovered": recovered_total,
        "reflection_call_sites_resolved": reflective_total,
        "runtime_key_walled": runtime_key_walled,
        "code_scan_complete": report.code_scan_complete,
        "decode_error_count": report.decode_error_count,
        "classes": report.recoveries,
    })
}

fn dex_manifest(
    dex: &DexFile,
    cff: &DalvikCffReport,
    code_scan_complete: bool,
    decode_error_count: usize,
) -> serde_json::Value {
    serde_json::json!({
        "schema": "disrobe.jvm.classify/v1",
        "format": "dex",
        "dex_version": format!("{:?}", dex.header.version),
        "android_marketing": dex.header.version.android_marketing(),
        "string_count": dex.strings.len(),
        "class_count": dex.class_descriptors.len(),
        "type_name_count": dex.type_names.len(),
        "method_count": dex.method_ids.len(),
        "field_count": dex.field_ids.len(),
        "code_scan_complete": code_scan_complete,
        "decode_error_count": decode_error_count,
        "cff_methods_scanned": cff.methods_scanned,
        "cff_flattened_methods": cff.flattened_methods,
        "cff_methods_unflattened": cff.methods_unflattened,
        "cff_dispatchers_resolved": cff.dispatchers_resolved,
        "cff_edges_redirected": cff.edges_redirected,
        "cff_dead_branches_folded": cff.dead_branches_folded,
        "cff_dispatcher_blocks_pruned": cff.dispatcher_blocks_pruned,
        "cff_residual_dispatcher_edges": cff.residual_dispatcher_edges,
    })
}

fn sanitize_component(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c: char| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();
    let trimmed: &str = cleaned.trim_matches(['.', '/', '\\', ' ']);
    if trimmed.is_empty() {
        "Unknown".to_owned()
    } else {
        trimmed.to_owned()
    }
}

fn archive_note(tag: &str) -> String {
    format!(
        "// disrobe jvm: {tag} container surfaced; per-entry .class/.dex are extracted and \
         decompiled by the container chain stage\n"
    )
}

fn reads_class_magic(bytes: &[u8]) -> bool {
    let magic: u32 = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    magic == CLASS_MAGIC
}

fn verdict_classfile(bytes: &[u8]) -> DetectVerdict {
    let major: u16 = u16::from_be_bytes([bytes[6], bytes[7]]);
    DetectVerdict::new(
        PASS_ID,
        TAG_CLASSFILE,
        FAMILY_INTERPRETER_BYTECODE,
        0.97,
        25,
        vec!["CAFEBABE"],
        format!("classfile major={major}"),
    )
}

fn verdict_dex(bytes: &[u8]) -> DetectVerdict {
    let version: [u8; 3] = [bytes[4], bytes[5], bytes[6]];
    let label: String = std::str::from_utf8(&version)
        .map(|s: &str| s.to_string())
        .unwrap_or_else(|_| "???".to_string());
    DetectVerdict::new(
        PASS_ID,
        TAG_DEX,
        FAMILY_INTERPRETER_BYTECODE,
        0.96,
        25,
        vec!["dex-magic-dex\\n"],
        format!("dex version={label}"),
    )
}

fn verdict_zip(path_hint: Option<&str>) -> DetectVerdict {
    let looks_apk: bool = path_hint
        .map(|p: &str| p.to_lowercase().ends_with(".apk"))
        .unwrap_or(false);
    let tag: &'static str = if looks_apk { TAG_APK } else { TAG_JAR };
    DetectVerdict::new(
        PASS_ID,
        tag,
        FAMILY_INTERPRETER_BYTECODE,
        if looks_apk { 0.78 } else { 0.62 },
        25,
        vec!["zip-PK"],
        format!("zip container (jar/apk) hint={path_hint:?}"),
    )
}

#[derive(Debug)]
enum JvmCatalogKey {
    Protector(Protector),
    DalvikBlackObfuscator,
}

#[derive(Debug)]
pub struct JvmCatalogEntry {
    key: JvmCatalogKey,
    id: &'static str,
    display_name: &'static str,
    aliases: &'static [&'static str],
    quality: SupportQuality,
}

impl CatalogEntry for JvmCatalogEntry {
    #[inline]
    fn id(&self) -> &'static str {
        self.id
    }
    #[inline]
    fn display_name(&self) -> &'static str {
        self.display_name
    }
    #[inline]
    fn aliases(&self) -> &'static [&'static str] {
        self.aliases
    }
    #[inline]
    fn support_quality(&self) -> SupportQuality {
        self.quality
    }
}

const CATALOG_COUNT: usize = 10;

static CATALOG: [JvmCatalogEntry; CATALOG_COUNT] = [
    JvmCatalogEntry {
        key: JvmCatalogKey::Protector(Protector::ZelixKlassMaster),
        id: "jvm-zkm",
        display_name: "Zelix KlassMaster",
        aliases: &["zelix", "zkm", "klassmaster"],
        quality: SupportQuality::Full,
    },
    JvmCatalogEntry {
        key: JvmCatalogKey::Protector(Protector::Allatori),
        id: "jvm-allatori",
        display_name: "Allatori",
        aliases: &["allatori"],
        quality: SupportQuality::Full,
    },
    JvmCatalogEntry {
        key: JvmCatalogKey::Protector(Protector::Stringer),
        id: "jvm-stringer",
        display_name: "Stringer",
        aliases: &["stringer"],
        quality: SupportQuality::Full,
    },
    JvmCatalogEntry {
        key: JvmCatalogKey::Protector(Protector::DashO),
        id: "jvm-dasho",
        display_name: "DashO",
        aliases: &["dasho", "preemptive"],
        quality: SupportQuality::Full,
    },
    JvmCatalogEntry {
        key: JvmCatalogKey::Protector(Protector::DexGuard),
        id: "jvm-dexguard",
        display_name: "DexGuard",
        aliases: &["dexguard"],
        quality: SupportQuality::Full,
    },
    JvmCatalogEntry {
        key: JvmCatalogKey::DalvikBlackObfuscator,
        id: "jvm-blackobfuscator",
        display_name: "BlackObfuscator",
        aliases: &["blackobfuscator", "blackobf"],
        quality: SupportQuality::Full,
    },
    JvmCatalogEntry {
        key: JvmCatalogKey::Protector(Protector::ProguardR8),
        id: "jvm-proguard",
        display_name: "ProGuard / R8",
        aliases: &["proguard", "r8"],
        quality: SupportQuality::Partial,
    },
    JvmCatalogEntry {
        key: JvmCatalogKey::Protector(Protector::YGuard),
        id: "jvm-yguard",
        display_name: "yGuard",
        aliases: &["yguard"],
        quality: SupportQuality::Partial,
    },
    JvmCatalogEntry {
        key: JvmCatalogKey::Protector(Protector::SkidSuite2),
        id: "jvm-skidsuite2",
        display_name: "SkidSuite2",
        aliases: &["skidsuite", "skidsuite2", "skidfuscator"],
        quality: SupportQuality::Partial,
    },
    JvmCatalogEntry {
        key: JvmCatalogKey::Protector(Protector::Jbco),
        id: "jvm-jbco",
        display_name: "JBCO",
        aliases: &["jbco", "soot"],
        quality: SupportQuality::Partial,
    },
];

fn catalog_id_for_protector(protector: Protector) -> Option<&'static str> {
    CATALOG
        .iter()
        .find(|e: &&JvmCatalogEntry| matches!(e.key, JvmCatalogKey::Protector(p) if p == protector))
        .map(|e: &JvmCatalogEntry| e.id)
}

impl ObfuscatorCatalog for JvmDetector {
    #[inline]
    fn pass_id(&self) -> PassId {
        PASS_ID
    }

    fn catalog(&self) -> Vec<&'static dyn CatalogEntry> {
        CATALOG
            .iter()
            .map(|e: &'static JvmCatalogEntry| e as &'static dyn CatalogEntry)
            .collect()
    }

    fn detect(&self, ctx: &DetectContext<'_>) -> Option<DetectorOutput> {
        let bytes: &[u8] = ctx.bytes;
        if bytes.len() < 8 || !reads_class_magic(bytes) {
            return None;
        }
        let cf: ClassFile = parse_classfile(bytes).ok()?;
        let detections: Vec<crate::obfuscators::Detection> = crate::obfuscators::detect_all(&cf);
        let best: &crate::obfuscators::Detection = detections
            .iter()
            .max_by_key(|d: &&crate::obfuscators::Detection| d.confidence)?;
        let entry_id: &'static str = catalog_id_for_protector(best.protector)?;
        let confidence: f32 = (f32::from(best.confidence) / 100.0_f32).clamp(0.4_f32, 0.99_f32);
        let markers: Vec<String> = detections
            .iter()
            .filter_map(|d: &crate::obfuscators::Detection| {
                catalog_id_for_protector(d.protector).map(str::to_owned)
            })
            .collect();
        Some(DetectorOutput::new(entry_id, confidence, markers))
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use disrobe_core::Rung;

    fn ctx<'a>(bytes: &'a [u8], path: Option<&'a str>) -> DetectContext<'a> {
        DetectContext {
            bytes,
            path_hint: path,
            parent_hint: None,
            depth: 0,
        }
    }

    #[test]
    fn detector_id_is_stable() {
        assert_eq!(JvmDetector.id(), PASS_ID);
    }

    #[test]
    fn detect_classfile_magic() {
        let mut bytes: Vec<u8> = Vec::with_capacity(16);
        bytes.extend_from_slice(&CLASS_MAGIC.to_be_bytes());
        bytes.extend_from_slice(&[0u8, 0u8, 0u8, 65u8]);
        let v: DetectVerdict =
            Detector::detect(&JvmDetector, &ctx(&bytes, None)).expect("must detect");
        assert_eq!(v.format_tag, TAG_CLASSFILE);
    }

    #[test]
    fn detect_dex_magic() {
        let mut bytes: Vec<u8> = Vec::with_capacity(16);
        bytes.extend_from_slice(b"dex\n035\x00");
        bytes.extend(std::iter::repeat_n(0u8, 8));
        let v: DetectVerdict =
            Detector::detect(&JvmDetector, &ctx(&bytes, None)).expect("must detect");
        assert_eq!(v.format_tag, TAG_DEX);
    }

    #[test]
    fn detect_jar_zip_default() {
        let bytes: Vec<u8> = vec![b'P', b'K', 0x03, 0x04, 0u8, 0u8];
        let v: DetectVerdict =
            Detector::detect(&JvmDetector, &ctx(&bytes, None)).expect("must detect");
        assert_eq!(v.format_tag, TAG_JAR);
    }

    #[test]
    fn detect_apk_from_path_hint() {
        let bytes: Vec<u8> = vec![b'P', b'K', 0x03, 0x04, 0u8, 0u8];
        let v: DetectVerdict = Detector::detect(&JvmDetector, &ctx(&bytes, Some("/tmp/Hello.apk")))
            .expect("must detect");
        assert_eq!(v.format_tag, TAG_APK);
    }

    #[test]
    fn detect_misses_random_bytes() {
        let bytes: Vec<u8> = vec![0u8; 8];
        assert!(Detector::detect(&JvmDetector, &ctx(&bytes, None)).is_none());
    }

    #[test]
    fn pass_output_kind_is_mixed_so_extract_children_runs() {
        let a: Artifact = Artifact::new(Rung::Raw, vec![], [0u8; 32]);
        assert!(
            JVM_PASS.output_kind(&a).is_mixed(),
            "the pass must declare Mixed so the chain runner invokes extract_children and the \
             dedicated classify sidecars reach auto"
        );
    }

    #[test]
    fn pass_run_surfaces_jar_archive_note() {
        let bytes: Vec<u8> = vec![b'P', b'K', 0x03, 0x04, 0u8, 0u8, 0u8, 0u8];
        let a: Artifact = Artifact::new(Rung::Raw, bytes, [0u8; 32]);
        let out: Artifact = JVM_PASS.run(&a).expect("extract must succeed");
        assert_eq!(out.rung, Rung::Disasm);
        assert!(!out.envelope.is_empty());
        let s: &str = std::str::from_utf8(&out.envelope).expect("utf8 text");
        assert!(s.contains("jar-zip"), "got: {s}");
        assert!(s.contains("container surfaced"), "got: {s}");
    }

    #[test]
    fn pass_run_rejects_unknown_bytes() {
        let a: Artifact = Artifact::new(Rung::Raw, vec![0u8; 64], [0u8; 32]);
        let err: CoreError = JVM_PASS.run(&a).expect_err("must reject");
        assert!(format!("{err}").contains("DR-JVM-0902"));
    }

    #[test]
    fn chain_pass_peels_protected_classfile_strings() {
        const ZKM: &[u8] = include_bytes!("../../../corpus/jvm/zkmshape/StaticTableCrypt.class");
        let a: Artifact = Artifact::new(Rung::Raw, ZKM.to_vec(), [0u8; 32]);
        let out: Artifact = JVM_PASS.run(&a).expect("protected classfile decompiles");
        let src: &str = std::str::from_utf8(&out.envelope).expect("utf8 source");
        for want in [
            "jdbc:mysql://10.0.0.5:3306/billing",
            "X-Internal-Auth: 9f8e7d6c",
        ] {
            assert!(
                src.contains(want),
                "the chain pass must peel the protector and surface {want:?} in the decompiled \
                 source so `disrobe auto` defeats it; got:\n{src}"
            );
        }
    }

    #[test]
    fn chain_pass_peels_dexguard_dex_strings() {
        const DG: &[u8] = include_bytes!("../../../corpus/jvm/dexguard/DexGuardReflectStrings.dex");
        let a: Artifact = Artifact::new(Rung::Raw, DG.to_vec(), [0u8; 32]);
        let out: Artifact = JVM_PASS.run(&a).expect("dexguard dex decompiles");
        let src: &str = std::str::from_utf8(&out.envelope).expect("utf8 source");
        assert!(
            src.contains("https://api.example.com/v1/auth")
                && src.contains("com.disrobe.sample.Secret"),
            "the chain dex pass must surface the reflection-invoked decrypt plaintext; got:\n{src}"
        );
    }

    fn child<'a>(children: &'a [ChildArtifact], path: &str) -> &'a ChildArtifact {
        children
            .iter()
            .find(|c: &&ChildArtifact| c.handle.relative_path == path)
            .unwrap_or_else(|| panic!("missing sidecar child {path:?} in extract_children output"))
    }

    fn parse_child(children: &[ChildArtifact], path: &str) -> serde_json::Value {
        serde_json::from_slice(&child(children, path).bytes).expect("sidecar child is valid JSON")
    }

    #[test]
    fn dex_manifest_preserves_partial_code_failure() {
        let (_, bytes): (DexFile, Vec<u8>) = crate::dex::partial_code_failure_fixture();
        let children: Vec<ChildArtifact> = dex_children(&bytes).expect("DEX children");
        let manifest: serde_json::Value = parse_child(&children, "jvm-manifest.json");
        assert_eq!(manifest["code_scan_complete"], false);
        assert_eq!(manifest["decode_error_count"], 1);
        let recovery: serde_json::Value = parse_child(&children, "jvm-reflection-strings.json");
        assert_eq!(recovery["code_scan_complete"], false);
        assert_eq!(recovery["decode_error_count"], 1);
    }

    #[test]
    fn classfile_manifest_preserves_partial_code_failure() {
        let class: ClassFile = ClassFile {
            minor_version: 0,
            major_version: 52,
            constant_pool: vec![
                crate::classfile::ConstantPoolEntry::Placeholder,
                crate::classfile::ConstantPoolEntry::Utf8("DecodeStates".to_owned()),
                crate::classfile::ConstantPoolEntry::Class { name_index: 1 },
                crate::classfile::ConstantPoolEntry::Utf8("java/lang/Object".to_owned()),
                crate::classfile::ConstantPoolEntry::Class { name_index: 3 },
                crate::classfile::ConstantPoolEntry::Utf8("body".to_owned()),
                crate::classfile::ConstantPoolEntry::Utf8("()V".to_owned()),
                crate::classfile::ConstantPoolEntry::Utf8("Code".to_owned()),
            ],
            access_flags: crate::decompile::ACC_PUBLIC,
            this_class: 2,
            super_class: 4,
            interfaces: Vec::new(),
            fields: Vec::new(),
            methods: vec![crate::classfile::MethodInfo {
                access_flags: crate::decompile::ACC_PUBLIC | crate::decompile::ACC_STATIC,
                name_index: 5,
                descriptor_index: 6,
                attributes: vec![crate::classfile::Attribute {
                    name_index: 7,
                    info: vec![0; 7],
                }],
            }],
            attributes: Vec::new(),
        };
        let decompiled: DecompiledClass = decompile_class(&class);
        let manifest: serde_json::Value = classfile_manifest(
            &class,
            "DecodeStates",
            decompiled.fully_lifted_methods,
            decompiled.fallback_methods,
            decompiled.decode_error_count,
        );
        assert_eq!(manifest["code_scan_complete"], false);
        assert_eq!(manifest["decode_error_count"], 1);
        assert_eq!(manifest["fully_lifted_methods"], 0);
        assert_eq!(manifest["fallback_methods"], 1);
    }

    #[test]
    fn classfile_manifest_separates_semantic_fallbacks_from_decode_errors() {
        let class: ClassFile = ClassFile {
            minor_version: 0,
            major_version: 52,
            constant_pool: vec![
                crate::classfile::ConstantPoolEntry::Placeholder,
                crate::classfile::ConstantPoolEntry::Utf8("Fallback".to_owned()),
                crate::classfile::ConstantPoolEntry::Class { name_index: 1 },
            ],
            access_flags: crate::decompile::ACC_PUBLIC,
            this_class: 2,
            super_class: 0,
            interfaces: Vec::new(),
            fields: Vec::new(),
            methods: Vec::new(),
            attributes: Vec::new(),
        };
        let manifest: serde_json::Value = classfile_manifest(&class, "Fallback", 0, 1, 0);
        assert_eq!(manifest["fallback_methods"], 1);
        assert_eq!(manifest["code_scan_complete"], true);
        assert_eq!(manifest["decode_error_count"], 0);
    }

    #[test]
    fn extract_children_emits_classfile_peel_sidecar_for_real_sample() {
        const ZKM: &[u8] = include_bytes!("../../../corpus/jvm/zkmshape/StaticTableCrypt.class");
        let a: Artifact = Artifact::new(Rung::Raw, ZKM.to_vec(), [0u8; 32]);
        let children: Vec<ChildArtifact> = JVM_PASS
            .extract_children(&a)
            .expect("extract_children runs");

        for c in &children {
            assert_eq!(
                c.handle.hint.as_deref(),
                Some(TERMINAL_HINT),
                "classify sidecars are already-recovered terminal artifacts, not re-chained inputs"
            );
        }

        let peel: serde_json::Value = parse_child(&children, "jvm-peel.json");
        assert_eq!(peel["schema"], "disrobe.jvm.protector-peel/v1");
        assert!(
            peel["family"].is_string() && peel["status"].is_string(),
            "the peel sidecar must carry family + status the dedicated command writes"
        );
        assert!(
            peel["strings_recovered"].as_u64().unwrap_or(0) > 0,
            "the real ZKM sample recovers strings; auto must record the count, got:\n{peel}"
        );
        assert!(peel["strings_residual"].is_number());
        assert!(peel["cff_methods_unflattened"].is_number());
        assert!(peel["runtime_key_walled"].is_boolean());

        let manifest: serde_json::Value = parse_child(&children, "jvm-manifest.json");
        assert_eq!(manifest["format"], "classfile");
        assert!(manifest["this_class"].is_string());
        assert!(manifest["method_count"].as_u64().is_some());
        assert!(
            manifest["java_version"].is_string(),
            "the manifest sidecar must carry the marketing java_version the legacy analyze() \
             report also exposed; got:\n{manifest}"
        );

        let java: &ChildArtifact = children
            .iter()
            .find(|c: &&ChildArtifact| c.handle.relative_path.ends_with(".java"))
            .expect("the recovered decompiled source must also be surfaced as a child");
        let src: &str = std::str::from_utf8(&java.bytes).expect("utf8 java source");
        assert!(
            src.contains("jdbc:mysql://10.0.0.5:3306/billing"),
            "the surfaced source child must contain the peeled plaintext"
        );
    }

    #[test]
    fn extract_children_emits_dex_reflection_sidecar_for_real_sample() {
        const DG: &[u8] = include_bytes!("../../../corpus/jvm/dexguard/DexGuardReflectStrings.dex");
        let a: Artifact = Artifact::new(Rung::Raw, DG.to_vec(), [0u8; 32]);
        let children: Vec<ChildArtifact> = JVM_PASS
            .extract_children(&a)
            .expect("extract_children runs");

        let refl: serde_json::Value = parse_child(&children, "jvm-reflection-strings.json");
        assert_eq!(refl["schema"], "disrobe.jvm.reflection-strings/v1");
        assert!(
            refl["strings_recovered"].as_u64().unwrap_or(0) > 0,
            "the dex reflection sidecar must record recovered plaintext count, got:\n{refl}"
        );
        assert!(refl["runtime_key_walled"].is_boolean());

        let manifest: serde_json::Value = parse_child(&children, "jvm-manifest.json");
        assert_eq!(manifest["format"], "dex");
        assert!(manifest["class_count"].as_u64().is_some());
        assert!(
            manifest["method_count"].is_number() && manifest["field_count"].is_number(),
            "the dex manifest sidecar must carry the method/field counts the legacy analyze() \
             report also exposed; got:\n{manifest}"
        );
        assert!(
            manifest["cff_methods_scanned"].is_number(),
            "the dex manifest sidecar must carry the DexGuard control-flow-unflatten stats the \
             legacy analyze() report's dex_protector_peel.cff also exposed; got:\n{manifest}"
        );
    }

    fn published_bar(heading_needle: &str, label: &str) -> serde_json::Value {
        let path: std::path::PathBuf = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("xtask")
            .join("data")
            .join("recovery.json");
        let raw: String = std::fs::read_to_string(&path)
            .unwrap_or_else(|e: std::io::Error| panic!("read {}: {e}", path.display()));
        let doc: serde_json::Value = serde_json::from_str(&raw)
            .unwrap_or_else(|e: serde_json::Error| panic!("parse {}: {e}", path.display()));
        let mut found: Vec<serde_json::Value> = Vec::new();
        for group in doc["groups"].as_array().expect("groups array") {
            let heading_matches: bool = group["heading"]
                .as_str()
                .is_some_and(|h: &str| h.contains(heading_needle));
            if !heading_matches {
                continue;
            }
            for bar in group["bars"].as_array().unwrap_or(&Vec::new()) {
                if bar["label"].as_str() == Some(label) {
                    found.push(bar.clone());
                }
            }
        }
        assert_eq!(
            found.len(),
            1,
            "xtask/data/recovery.json must carry exactly one bar labelled `{label}` under a \
             heading containing `{heading_needle}`, found {}",
            found.len()
        );
        found.remove(0)
    }

    #[test]
    fn published_jvm_android_roster_count_matches_this_catalog() {
        const BAR: &str = "JVM / Android families";
        let bar: serde_json::Value = published_bar("Detection and routing rosters", BAR);
        let count: u64 = bar["value"]
            .as_u64()
            .expect("the JVM / Android families bar must carry a roster count");
        let entries: Vec<&'static dyn CatalogEntry> = ObfuscatorCatalog::catalog(&JvmDetector);
        assert_eq!(
            usize::try_from(count).expect("roster count fits usize"),
            entries.len(),
            "xtask/data/recovery.json publishes {count} addressed JVM and Android families in its \
             routing roster and every document renders that number, but this catalog carries {}",
            entries.len()
        );
        let protector_entries: usize = entries
            .iter()
            .filter(|e: &&&'static dyn CatalogEntry| e.id() != "jvm-blackobfuscator")
            .count();
        assert_eq!(
            protector_entries,
            entries.len() - 1,
            "the tenth family is the DEX deflattening path, which is not a Protector variant; if \
             that stops holding the published split needs re-deriving"
        );
    }

    #[test]
    fn catalog_lists_known_jvm_families() {
        let entries: Vec<&'static dyn CatalogEntry> = ObfuscatorCatalog::catalog(&JvmDetector);
        assert_eq!(entries.len(), CATALOG_COUNT);
        let ids: Vec<&'static str> = entries.iter().map(|e| e.id()).collect();
        for want in [
            "jvm-proguard",
            "jvm-allatori",
            "jvm-zkm",
            "jvm-dexguard",
            "jvm-blackobfuscator",
        ] {
            assert!(
                ids.contains(&want),
                "jvm catalog missing {want}, got {ids:?}"
            );
        }
        let mut sorted: Vec<&'static str> = ids.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), CATALOG_COUNT, "catalog ids must be unique");
    }

    #[test]
    fn catalog_quality_is_honest() {
        let entries: Vec<&'static dyn CatalogEntry> = ObfuscatorCatalog::catalog(&JvmDetector);
        let find = |id: &str| -> SupportQuality {
            entries
                .iter()
                .find(|e: &&&dyn CatalogEntry| e.id() == id)
                .expect("entry present")
                .support_quality()
        };
        assert_eq!(find("jvm-zkm"), SupportQuality::Full);
        assert_eq!(find("jvm-allatori"), SupportQuality::Full);
        assert_eq!(find("jvm-blackobfuscator"), SupportQuality::Full);
        assert_eq!(find("jvm-proguard"), SupportQuality::Partial);
        assert_eq!(find("jvm-yguard"), SupportQuality::Partial);
    }

    #[test]
    fn catalog_detect_fires_on_real_protected_classfile() {
        const ZKM: &[u8] = include_bytes!("../../../corpus/jvm/zkmshape/StaticTableCrypt.class");
        let out: DetectorOutput = ObfuscatorCatalog::detect(&JvmDetector, &ctx(ZKM, None))
            .expect("a real protected classfile must be catalog-detected");
        assert!(out.confidence > 0.0);
        let entry_ids: Vec<&'static str> = ObfuscatorCatalog::catalog(&JvmDetector)
            .into_iter()
            .map(|e: &dyn CatalogEntry| e.id())
            .collect();
        assert!(
            entry_ids.contains(&out.entry_id),
            "detected id {} must be in the catalog",
            out.entry_id
        );
    }

    #[test]
    fn catalog_detect_misses_non_classfile() {
        let bytes: Vec<u8> = vec![0u8; 64];
        assert!(ObfuscatorCatalog::detect(&JvmDetector, &ctx(&bytes, None)).is_none());
    }

    #[test]
    fn extract_children_indices_are_dense_and_unique() {
        const ZKM: &[u8] = include_bytes!("../../../corpus/jvm/zkmshape/StaticTableCrypt.class");
        let a: Artifact = Artifact::new(Rung::Raw, ZKM.to_vec(), [0u8; 32]);
        let children: Vec<ChildArtifact> = JVM_PASS
            .extract_children(&a)
            .expect("extract_children runs");
        for (i, c) in children.iter().enumerate() {
            assert_eq!(c.handle.artifact_index as usize, i, "indices must be dense");
        }
    }
}
