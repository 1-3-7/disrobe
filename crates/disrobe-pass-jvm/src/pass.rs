use serde::{Deserialize, Serialize};

use disrobe_core::{
    Artifact, Capability, CoreError, LegacyPass, PassId, Result as CoreResult, Rung,
};

use crate::classfile::{CLASS_MAGIC, ClassFile, parse as parse_classfile};
use crate::dex::{DEX_MAGIC_PREFIX, DexFile, parse as parse_dex};
use crate::jar::{JIMAGE_MAGIC, JMOD_MAGIC, Jimage, JmodExtract, extract_jmod, parse_jimage};

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct JvmPass;

impl JvmPass {
    #[inline]
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JvmSummary {
    pub kind: String,
    pub major_version: u16,
    pub minor_version: u16,
    pub java_version: Option<String>,
    pub constant_pool_len: usize,
    pub method_count: usize,
    pub field_count: usize,
}

pub fn analyze(bytes: &[u8]) -> crate::error::Result<JvmSummary> {
    let first4: [u8; 4] = match bytes.first_chunk::<4>() {
        Some(chunk) => *chunk,
        None => return Err(crate::error::Error::BadMagic(0)),
    };
    if first4 == CLASS_MAGIC.to_be_bytes() {
        let cf: ClassFile = parse_classfile(bytes)?;
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
        });
    }
    if first4 == DEX_MAGIC_PREFIX {
        let dex: DexFile = parse_dex(bytes)?;
        return Ok(JvmSummary {
            kind: "dex".to_owned(),
            major_version: 0,
            minor_version: 0,
            java_version: Some(dex.header.version.android_marketing().to_owned()),
            constant_pool_len: dex.strings.len(),
            method_count: dex.method_ids.len(),
            field_count: dex.field_ids.len(),
        });
    }
    if first4 == JMOD_MAGIC {
        let jmod: JmodExtract = extract_jmod(bytes)?;
        return Ok(JvmSummary {
            kind: "jmod".to_owned(),
            major_version: 0,
            minor_version: 0,
            java_version: None,
            constant_pool_len: jmod.classes.len(),
            method_count: jmod.native_libs.len(),
            field_count: jmod.resources.len(),
        });
    }
    if first4 == JIMAGE_MAGIC.to_le_bytes() || first4 == JIMAGE_MAGIC.to_be_bytes() {
        let img: Jimage = parse_jimage(bytes)?;
        return Ok(JvmSummary {
            kind: "jimage".to_owned(),
            major_version: img.header.version_major,
            minor_version: img.header.version_minor,
            java_version: None,
            constant_pool_len: img.resources.len(),
            method_count: 0,
            field_count: 0,
        });
    }
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
        || Capability::produces("jvm.proguard.mapping", 1),
        || Capability::produces("jvm.jmod", 1),
        || Capability::produces("jvm.jimage", 1),
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
        assert_eq!(p.produced_capabilities().len(), 6);
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
