use serde::{Deserialize, Serialize};

use disrobe_core::{
    Artifact, Capability, CoreError, LegacyPass, PassId, Result as CoreResult, Rung,
};

use crate::apk_resources::{ApkResourceReport, analyze_apk};
use crate::arsc::{RES_TABLE_TYPE, ResourceTable, parse_arsc};
use crate::classfile::{CLASS_MAGIC, ClassFile, parse as parse_classfile};
use crate::dalvik_dexguard::{DalvikCffReport, unflatten_dex_methods};
use crate::dalvik_strdec::{
    DexStringRecovery, recover as recover_dex_strings,
    recover_with_native_keys as recover_dex_strings_with_native_keys,
};
use crate::dex::{CodeItem, DEX_MAGIC_PREFIX, DexFile, parse as parse_dex, parse_code_items};
use crate::jar::{JIMAGE_MAGIC, JMOD_MAGIC, Jimage, JmodExtract, extract_jmod, parse_jimage};
use crate::oat::{ODEX_MAGIC, OdexFile, parse_oat, parse_odex};
use crate::protectors::{ProtectorPeelReport, peel_classfile};

const ZIP_LOCAL_FILE_MAGIC: [u8; 4] = [0x50, 0x4b, 0x03, 0x04];

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct JvmPass;

impl JvmPass {
    #[inline]
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct JvmSummary {
    pub kind: String,
    pub major_version: u16,
    pub minor_version: u16,
    pub java_version: Option<String>,
    pub constant_pool_len: usize,
    pub method_count: usize,
    pub field_count: usize,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub apk_resources: Option<ApkResourceReport>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub protector_peel: Option<ProtectorPeelReport>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub dex_protector_peel: Option<DexProtectorPeel>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DexProtectorPeel {
    pub strings_recovered: usize,
    pub runtime_key_walled_classes: usize,
    pub cff: DalvikCffReport,
    pub recovery: Vec<DexStringRecovery>,
}

#[must_use]
fn peel_apk_dex_protectors(apk_bytes: &[u8]) -> Option<DexProtectorPeel> {
    let extract: crate::jar::ApkExtract = crate::jar::extract_apk(apk_bytes).ok()?;
    let native_libs: Vec<(&str, &[u8])> = extract
        .native_libs
        .iter()
        .map(|(path, raw): (&String, &Vec<u8>)| (path.as_str(), raw.as_slice()))
        .collect();
    let mut merged: Option<DexProtectorPeel> = None;
    for (path, bytes) in &extract.dex_files {
        let leaf: &str = path.rsplit('/').next().unwrap_or(path);
        if !(leaf.starts_with("classes") && leaf.ends_with(".dex")) {
            continue;
        }
        let Ok(dex): Result<DexFile, _> = parse_dex(bytes) else {
            continue;
        };
        let Some(part): Option<DexProtectorPeel> =
            peel_dex_protectors_with_native_libs(&dex, bytes, &native_libs)
        else {
            continue;
        };
        match merged.as_mut() {
            Some(acc) => merge_dex_peel(acc, part),
            None => merged = Some(part),
        }
    }
    merged
}

fn merge_dex_peel(acc: &mut DexProtectorPeel, part: DexProtectorPeel) {
    acc.strings_recovered += part.strings_recovered;
    acc.runtime_key_walled_classes += part.runtime_key_walled_classes;
    acc.cff.methods_scanned += part.cff.methods_scanned;
    acc.cff.flattened_methods += part.cff.flattened_methods;
    acc.cff.methods_unflattened += part.cff.methods_unflattened;
    acc.cff.dispatchers_resolved += part.cff.dispatchers_resolved;
    acc.cff.edges_redirected += part.cff.edges_redirected;
    acc.cff.dead_branches_folded += part.cff.dead_branches_folded;
    acc.cff.dispatcher_blocks_pruned += part.cff.dispatcher_blocks_pruned;
    acc.cff.residual_dispatcher_edges += part.cff.residual_dispatcher_edges;
    acc.cff.unhandled_shapes.extend(part.cff.unhandled_shapes);
    acc.recovery.extend(part.recovery);
}

#[must_use]
fn peel_dex_protectors(dex: &DexFile, bytes: &[u8]) -> Option<DexProtectorPeel> {
    peel_dex_protectors_with_native_libs(dex, bytes, &[])
}

#[must_use]
fn peel_dex_protectors_with_native_libs(
    dex: &DexFile,
    bytes: &[u8],
    native_libs: &[(&str, &[u8])],
) -> Option<DexProtectorPeel> {
    let native_keys: Vec<crate::dalvik_strdec::NativeIntKey> =
        crate::jni::extract_static_int_keys(dex, bytes, native_libs);
    let recovery: Vec<DexStringRecovery> = if native_keys.is_empty() {
        recover_dex_strings(dex, bytes)
    } else {
        recover_dex_strings_with_native_keys(dex, bytes, &native_keys)
    };
    let items: Vec<CodeItem> = parse_code_items(dex, bytes);
    let (cff, _per_method): (DalvikCffReport, _) = unflatten_dex_methods(&items);
    let strings_recovered: usize = recovery
        .iter()
        .map(|r: &DexStringRecovery| r.recovered.len())
        .sum();
    let runtime_key_walled_classes: usize = recovery
        .iter()
        .filter(|r: &&DexStringRecovery| r.runtime_key_wall)
        .count();
    if strings_recovered == 0 && cff.flattened_methods == 0 && runtime_key_walled_classes == 0 {
        return None;
    }
    Some(DexProtectorPeel {
        strings_recovered,
        runtime_key_walled_classes,
        cff,
        recovery,
    })
}

pub fn analyze(bytes: &[u8]) -> crate::error::Result<JvmSummary> {
    crate::debug::dbg_section("jvm analyze");
    crate::debug::dbg_kv("input-len", || bytes.len().to_string());
    crate::debug::dbg_hex("input-magic", bytes, 8);
    let first4: [u8; 4] = match bytes.first_chunk::<4>() {
        Some(chunk) => *chunk,
        None => {
            crate::debug::dbg_kv("classify", || "truncated: fewer than 4 bytes".to_owned());
            return Err(crate::error::Error::BadMagic(0));
        }
    };
    if first4 == ZIP_LOCAL_FILE_MAGIC {
        crate::debug::dbg_kv("classify", || {
            "apk/jar (PK\\x03\\x04 zip local header)".to_owned()
        });
        let report: ApkResourceReport = analyze_apk(bytes)?;
        crate::debug::dbg_kv("apk", || {
            format!(
                "package={:?} resource_entries={} certificates={} packages={}",
                report.package,
                report.resource_entry_count,
                report.certificates.len(),
                report.package_count
            )
        });
        let dex_protector_peel: Option<DexProtectorPeel> = peel_apk_dex_protectors(bytes);
        crate::debug::dbg_kv("apk-dex-peel", || match &dex_protector_peel {
            Some(peel) => format!(
                "strings_recovered={} runtime_key_walled={} flattened_methods={}",
                peel.strings_recovered, peel.runtime_key_walled_classes, peel.cff.flattened_methods
            ),
            None => "none".to_owned(),
        });
        return Ok(JvmSummary {
            kind: "apk".to_owned(),
            java_version: report.package.clone(),
            constant_pool_len: report.resource_entry_count,
            method_count: report.certificates.len(),
            field_count: report.package_count,
            apk_resources: Some(report),
            dex_protector_peel,
            ..Default::default()
        });
    }
    if first4 == CLASS_MAGIC.to_be_bytes() {
        crate::debug::dbg_kv("classify", || "classfile (0xCAFEBABE)".to_owned());
        let cf: ClassFile = parse_classfile(bytes)?;
        crate::debug::dbg_kv("classfile", || {
            format!(
                "version={}.{} ({:?}) cp_len={} methods={} fields={}",
                cf.major_version,
                cf.minor_version,
                cf.version()
                    .map(|v: crate::classfile::JavaVersion| v.marketing_name()),
                cf.constant_pool.len(),
                cf.methods.len(),
                cf.fields.len()
            )
        });
        let protector_peel: Option<ProtectorPeelReport> = peel_classfile(&cf);
        crate::debug::dbg_kv("protector-peel", || match &protector_peel {
            Some(peel) => format!(
                "family={} status={:?} strings_recovered={} cff_unflattened={}",
                peel.family.name(),
                peel.status,
                peel.strings_recovered.len(),
                peel.cff_methods_unflattened
            ),
            None => "no protector detected".to_owned(),
        });
        return Ok(JvmSummary {
            kind: "classfile".to_owned(),
            major_version: cf.major_version,
            minor_version: cf.minor_version,
            java_version: cf
                .version()
                .map(|v: crate::classfile::JavaVersion| v.marketing_name().to_owned()),
            constant_pool_len: cf.constant_pool.len(),
            method_count: cf.methods.len(),
            field_count: cf.fields.len(),
            apk_resources: None,
            protector_peel,
            dex_protector_peel: None,
        });
    }
    if first4 == DEX_MAGIC_PREFIX {
        crate::debug::dbg_kv("classify", || "dex (Android dalvik)".to_owned());
        let dex: DexFile = parse_dex(bytes)?;
        crate::debug::dbg_kv("dex", || {
            format!(
                "version={} strings={} methods={} fields={} types={}",
                dex.header.version.android_marketing(),
                dex.strings.len(),
                dex.method_ids.len(),
                dex.field_ids.len(),
                dex.type_names.len()
            )
        });
        let dex_protector_peel: Option<DexProtectorPeel> = peel_dex_protectors(&dex, bytes);
        crate::debug::dbg_kv("dex-peel", || match &dex_protector_peel {
            Some(peel) => format!(
                "strings_recovered={} runtime_key_walled={} flattened={} unflattened={}",
                peel.strings_recovered,
                peel.runtime_key_walled_classes,
                peel.cff.flattened_methods,
                peel.cff.methods_unflattened
            ),
            None => "none".to_owned(),
        });
        return Ok(JvmSummary {
            kind: "dex".to_owned(),
            major_version: 0,
            minor_version: 0,
            java_version: Some(dex.header.version.android_marketing().to_owned()),
            constant_pool_len: dex.strings.len(),
            method_count: dex.method_ids.len(),
            field_count: dex.field_ids.len(),
            apk_resources: None,
            protector_peel: None,
            dex_protector_peel,
        });
    }
    if first4 == ODEX_MAGIC {
        crate::debug::dbg_kv("classify", || "odex (optimized dex)".to_owned());
        let odex: OdexFile = parse_odex(bytes)?;
        crate::debug::dbg_kv("odex", || {
            format!(
                "version={} strings={} methods={}",
                odex.dex.header.version.android_marketing(),
                odex.dex.strings.len(),
                odex.dex.method_ids.len()
            )
        });
        return Ok(JvmSummary {
            kind: "odex".to_owned(),
            major_version: 0,
            minor_version: 0,
            java_version: Some(odex.dex.header.version.android_marketing().to_owned()),
            constant_pool_len: odex.dex.strings.len(),
            method_count: odex.dex.method_ids.len(),
            field_count: odex.dex.field_ids.len(),
            apk_resources: None,
            protector_peel: None,
            dex_protector_peel: None,
        });
    }
    if u16::from_le_bytes([first4[0], first4[1]]) == RES_TABLE_TYPE {
        crate::debug::dbg_kv("classify", || {
            "arsc (Android resources.arsc table)".to_owned()
        });
        let table: ResourceTable = parse_arsc(bytes)?;
        crate::debug::dbg_kv("arsc", || {
            format!(
                "global_strings={} entries={} packages={}",
                table.global_strings.strings.len(),
                table.entry_count(),
                table.package_count
            )
        });
        return Ok(JvmSummary {
            kind: "arsc".to_owned(),
            major_version: 0,
            minor_version: 0,
            java_version: None,
            constant_pool_len: table.global_strings.strings.len(),
            method_count: table.entry_count(),
            field_count: table.package_count as usize,
            apk_resources: None,
            protector_peel: None,
            dex_protector_peel: None,
        });
    }
    if first4 == [0x7F, b'E', b'L', b'F']
        && let Ok(oat) = parse_oat(bytes)
    {
        crate::debug::dbg_kv("classify", || "oat (ELF-wrapped ART oat)".to_owned());
        crate::debug::dbg_kv("oat", || {
            format!(
                "dex_locations={} dex_file_count={} kv_store={}",
                oat.dex_locations.len(),
                oat.header.dex_file_count,
                oat.header.key_value_store.len()
            )
        });
        return Ok(JvmSummary {
            kind: "oat".to_owned(),
            major_version: 0,
            minor_version: 0,
            java_version: None,
            constant_pool_len: oat.dex_locations.len(),
            method_count: oat.header.dex_file_count as usize,
            field_count: oat.header.key_value_store.len(),
            apk_resources: None,
            protector_peel: None,
            dex_protector_peel: None,
        });
    }
    if first4 == JMOD_MAGIC {
        crate::debug::dbg_kv("classify", || "jmod (Java module archive)".to_owned());
        let jmod: JmodExtract = extract_jmod(bytes)?;
        crate::debug::dbg_kv("jmod", || {
            format!(
                "classes={} native_libs={} resources={}",
                jmod.classes.len(),
                jmod.native_libs.len(),
                jmod.resources.len()
            )
        });
        return Ok(JvmSummary {
            kind: "jmod".to_owned(),
            major_version: 0,
            minor_version: 0,
            java_version: None,
            constant_pool_len: jmod.classes.len(),
            method_count: jmod.native_libs.len(),
            field_count: jmod.resources.len(),
            apk_resources: None,
            protector_peel: None,
            dex_protector_peel: None,
        });
    }
    if first4 == JIMAGE_MAGIC.to_le_bytes() || first4 == JIMAGE_MAGIC.to_be_bytes() {
        crate::debug::dbg_kv("classify", || "jimage (modules runtime image)".to_owned());
        let img: Jimage = parse_jimage(bytes)?;
        crate::debug::dbg_kv("jimage", || {
            format!(
                "version={}.{} resources={}",
                img.header.version_major,
                img.header.version_minor,
                img.resources.len()
            )
        });
        return Ok(JvmSummary {
            kind: "jimage".to_owned(),
            major_version: img.header.version_major,
            minor_version: img.header.version_minor,
            java_version: None,
            constant_pool_len: img.resources.len(),
            method_count: 0,
            field_count: 0,
            apk_resources: None,
            protector_peel: None,
            dex_protector_peel: None,
        });
    }
    crate::debug::dbg_kv("classify", || {
        format!("unrecognized magic {:#010x}", u32::from_be_bytes(first4))
    });
    Err(crate::error::Error::BadMagic(u32::from_be_bytes(first4)))
}

impl LegacyPass for JvmPass {
    const CONSUMES: &'static [Rung] = &[Rung::Raw];
    const EMITS: &'static [Rung] = &[Rung::Disasm];
    const REQUIRES: &'static [fn() -> Capability] = &[];
    const PRODUCES: &'static [fn() -> Capability] = &[
        || Capability::produces("jvm.classfile", 1),
        || Capability::produces("jvm.dex", 1),
        || Capability::produces("jvm.axml", 1),
        || Capability::produces("android.apk.resources", 1),
        || Capability::produces("android.apk.certificate", 1),
        || Capability::produces("jvm.proguard.mapping", 1),
        || Capability::produces("jvm.jmod", 1),
        || Capability::produces("jvm.jimage", 1),
        || Capability::produces("jvm.oat", 1),
        || Capability::produces("jvm.odex", 1),
        || Capability::produces("android.arsc", 1),
    ];

    fn id(&self) -> PassId {
        "jvm.deob"
    }

    fn run(&self, artifact: &Artifact) -> CoreResult<Artifact> {
        let bytes: &[u8] = artifact.envelope.as_slice();
        let summary: JvmSummary = analyze(bytes)
            .map_err(|e: crate::error::Error| CoreError::PassFailure(format!("{e}")))?;
        let payload: Vec<u8> = serde_json::to_vec(&summary)
            .map_err(|e: serde_json::Error| CoreError::PassFailure(format!("DR-JVM-SER: {e}")))?;
        let mut next: Artifact = Artifact::new(Rung::Disasm, payload, artifact.root_hash);
        for emitter in <Self as LegacyPass>::PRODUCES {
            next.add_capability(emitter());
        }
        Ok(next)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use disrobe_core::PassMetadata;

    fn minimal_classfile(major: u16) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&CLASS_MAGIC.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.extend_from_slice(&major.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf
    }

    #[test]
    fn pass_metadata_advertises_capabilities() {
        let p: JvmPass = JvmPass::new();
        assert_eq!(PassMetadata::id(&p), "jvm.deob");
        assert_eq!(p.consumes(), &[Rung::Raw]);
        assert_eq!(p.emits(), &[Rung::Disasm]);
        assert_eq!(p.produced_capabilities().len(), 11);
    }

    #[test]
    fn jvm_pass_run_on_classfile_emits_summary() {
        let envelope: Vec<u8> = minimal_classfile(52);
        let input: Artifact = Artifact::new(Rung::Raw, envelope, [0u8; 32]);
        let out: Artifact = JvmPass::new().run(&input).expect("classfile parses");
        assert_eq!(out.rung, Rung::Disasm);
        assert!(!out.capabilities.is_empty());
        let summary: JvmSummary =
            serde_json::from_slice(&out.envelope).expect("payload is a JvmSummary");
        assert_eq!(summary.kind, "classfile");
        assert_eq!(summary.major_version, 52);
        assert_eq!(summary.java_version.as_deref(), Some("Java SE 8"));
    }

    #[test]
    fn jvm_pass_run_on_garbage_returns_pass_failure() {
        let input: Artifact = Artifact::new(Rung::Raw, vec![0u8; 64], [0u8; 32]);
        let err: CoreError = JvmPass::new().run(&input).expect_err("garbage should fail");
        let text: String = format!("{err}");
        assert!(text.contains("DR-JVM"), "got: {text}");
    }
}
