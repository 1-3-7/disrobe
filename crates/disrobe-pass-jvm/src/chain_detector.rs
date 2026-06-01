#![cfg(feature = "chain")]
#![allow(clippy::module_name_repetitions)]

use serde::Serialize;

use disrobe_core::Artifact;
use disrobe_core::Rung;
use disrobe_core::chain::{
    DetectContext, DetectVerdict, Detector, FAMILY_INTERPRETER_BYTECODE, OutputKind, Pass,
};
use disrobe_core::error::{CoreError, Result as CoreResult};
use disrobe_core::pass::PassId;
use disrobe_core::provenance::Language;

use crate::classfile::{CLASS_MAGIC, ClassFile, JavaVersion, parse as parse_classfile};
use crate::dex::{DEX_MAGIC_PREFIX, DexFile, DexVersion, parse as parse_dex};
use crate::smali::{SmaliEmission, emit as emit_smali};

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
    fn id(&self) -> PassId {
        PASS_ID
    }

    #[inline]
    fn detector(&self) -> &'static dyn Detector {
        &JvmDetector
    }

    #[inline]
    fn output_kind(&self, _output: &Artifact) -> OutputKind {
        OutputKind::Source {
            language: Language::Java,
            formatted: true,
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
        let verdict: DetectVerdict = JvmDetector.detect(&ctx).ok_or_else(|| {
            CoreError::PassFailure(
                "DR-JVM-0902: jvm.classify: input does not match classfile/dex/jar signatures"
                    .to_string(),
            )
        })?;
        let extracted: JvmExtract = extract_for(verdict.format_tag, bytes)?;
        let payload: Vec<u8> =
            serde_json::to_vec_pretty(&extracted).map_err(|e: serde_json::Error| {
                CoreError::PassFailure(format!("DR-JVM-0905: serialize jvm extract: {e}"))
            })?;
        Ok(Artifact::new(Rung::Disasm, payload, artifact.root_hash))
    }
}

pub static JVM_PASS: JvmPass = JvmPass;

#[derive(Debug, Clone, Serialize)]
pub struct JvmExtract {
    pub format_tag: String,
    pub kind: JvmExtractKind,
    pub classfile: Option<JvmClassfileSummary>,
    pub dex: Option<JvmDexSummary>,
    pub archive: Option<JvmArchiveSummary>,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum JvmExtractKind {
    Classfile,
    Dex,
    JarOrApk,
}

#[derive(Debug, Clone, Serialize)]
pub struct JvmClassfileSummary {
    pub this_class: String,
    pub super_class: String,
    pub major_version: u16,
    pub minor_version: u16,
    pub java_version: Option<JavaVersion>,
    pub interface_count: usize,
    pub field_count: usize,
    pub method_count: usize,
    pub constant_pool_size: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct JvmDexSummary {
    pub version: DexVersion,
    pub class_count: usize,
    pub string_count: usize,
    pub type_name_count: usize,
    pub smali_class_count: usize,
    pub smali_text: String,
    pub smali_lossy_notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct JvmArchiveSummary {
    pub note: &'static str,
}

fn extract_for(format_tag: &str, bytes: &[u8]) -> CoreResult<JvmExtract> {
    match format_tag {
        TAG_CLASSFILE => extract_classfile(bytes),
        TAG_DEX => extract_dex(bytes),
        TAG_JAR | TAG_APK => Ok(extract_archive_placeholder(format_tag)),
        other => Err(CoreError::PassFailure(format!(
            "DR-JVM-0906: jvm.classify: unknown format tag {other}"
        ))),
    }
}

fn extract_classfile(bytes: &[u8]) -> CoreResult<JvmExtract> {
    let cf: ClassFile = parse_classfile(bytes).map_err(|e: crate::error::Error| {
        CoreError::PassFailure(format!("DR-JVM-0907: classfile parse: {e}"))
    })?;
    let this_class: String = cf
        .this_class_name()
        .map_or_else(|_| "?".to_owned(), str::to_owned);
    let super_class: String = if cf.super_class == 0 {
        "java/lang/Object".to_owned()
    } else {
        cf.class_name(cf.super_class)
            .map_or_else(|_| "?".to_owned(), str::to_owned)
    };
    let summary: JvmClassfileSummary = JvmClassfileSummary {
        this_class,
        super_class,
        major_version: cf.major_version,
        minor_version: cf.minor_version,
        java_version: cf.version(),
        interface_count: cf.interfaces.len(),
        field_count: cf.fields.len(),
        method_count: cf.methods.len(),
        constant_pool_size: cf.constant_pool.len(),
    };
    Ok(JvmExtract {
        format_tag: TAG_CLASSFILE.to_owned(),
        kind: JvmExtractKind::Classfile,
        classfile: Some(summary),
        dex: None,
        archive: None,
    })
}

fn extract_dex(bytes: &[u8]) -> CoreResult<JvmExtract> {
    let dex: DexFile = parse_dex(bytes).map_err(|e: crate::error::Error| {
        CoreError::PassFailure(format!("DR-JVM-0908: dex parse: {e}"))
    })?;
    let smali: SmaliEmission = emit_smali(&dex).map_err(|e: crate::error::Error| {
        CoreError::PassFailure(format!("DR-JVM-0909: smali emit: {e}"))
    })?;
    let summary: JvmDexSummary = JvmDexSummary {
        version: dex.header.version,
        class_count: dex.class_descriptors.len(),
        string_count: dex.strings.len(),
        type_name_count: dex.type_names.len(),
        smali_class_count: smali.class_count,
        smali_text: smali.text,
        smali_lossy_notes: smali.lossy_notes,
    };
    Ok(JvmExtract {
        format_tag: TAG_DEX.to_owned(),
        kind: JvmExtractKind::Dex,
        classfile: None,
        dex: Some(summary),
        archive: None,
    })
}

fn extract_archive_placeholder(tag: &str) -> JvmExtract {
    JvmExtract {
        format_tag: tag.to_owned(),
        kind: JvmExtractKind::JarOrApk,
        classfile: None,
        dex: None,
        archive: Some(JvmArchiveSummary {
            note: "container surfaced for downstream entry-by-entry extraction",
        }),
    }
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
        let v: DetectVerdict = JvmDetector.detect(&ctx(&bytes, None)).expect("must detect");
        assert_eq!(v.format_tag, TAG_CLASSFILE);
    }

    #[test]
    fn detect_dex_magic() {
        let mut bytes: Vec<u8> = Vec::with_capacity(16);
        bytes.extend_from_slice(b"dex\n035\x00");
        bytes.extend(std::iter::repeat_n(0u8, 8));
        let v: DetectVerdict = JvmDetector.detect(&ctx(&bytes, None)).expect("must detect");
        assert_eq!(v.format_tag, TAG_DEX);
    }

    #[test]
    fn detect_jar_zip_default() {
        let bytes: Vec<u8> = vec![b'P', b'K', 0x03, 0x04, 0u8, 0u8];
        let v: DetectVerdict = JvmDetector.detect(&ctx(&bytes, None)).expect("must detect");
        assert_eq!(v.format_tag, TAG_JAR);
    }

    #[test]
    fn detect_apk_from_path_hint() {
        let bytes: Vec<u8> = vec![b'P', b'K', 0x03, 0x04, 0u8, 0u8];
        let v: DetectVerdict = JvmDetector
            .detect(&ctx(&bytes, Some("/tmp/Hello.apk")))
            .expect("must detect");
        assert_eq!(v.format_tag, TAG_APK);
    }

    #[test]
    fn detect_misses_random_bytes() {
        let bytes: Vec<u8> = vec![0u8; 8];
        assert!(JvmDetector.detect(&ctx(&bytes, None)).is_none());
    }

    #[test]
    fn pass_output_kind_is_java_source() {
        let a: Artifact = Artifact::new(Rung::Raw, vec![], [0u8; 32]);
        match JVM_PASS.output_kind(&a) {
            OutputKind::Source {
                language,
                formatted,
            } => {
                assert_eq!(language, Language::Java);
                assert!(formatted);
            }
            _ => panic!("expected Source"),
        }
    }

    #[test]
    fn pass_run_extracts_jar_archive_placeholder() {
        let bytes: Vec<u8> = vec![b'P', b'K', 0x03, 0x04, 0u8, 0u8, 0u8, 0u8];
        let a: Artifact = Artifact::new(Rung::Raw, bytes, [0u8; 32]);
        let out: Artifact = JVM_PASS.run(&a).expect("extract must succeed");
        assert_eq!(out.rung, Rung::Disasm);
        assert!(!out.envelope.is_empty());
        let s: &str = std::str::from_utf8(&out.envelope).expect("utf8 json");
        assert!(s.contains("jar-zip"));
        assert!(s.contains("jar-or-apk"));
    }

    #[test]
    fn pass_run_rejects_unknown_bytes() {
        let a: Artifact = Artifact::new(Rung::Raw, vec![0u8; 64], [0u8; 32]);
        let err: CoreError = JVM_PASS.run(&a).expect_err("must reject");
        assert!(format!("{err}").contains("DR-JVM-0902"));
    }
}
