use disrobe_core::{Artifact, Capability, LegacyPass, PassId, Result as CoreResult, Rung};

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct JvmPass;

impl JvmPass {
    #[inline]
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
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
    ];

    fn id(&self) -> PassId {
        "jvm.deob"
    }

    fn run(&self, artifact: &Artifact) -> CoreResult<Artifact> {
        let mut next: Artifact = artifact.clone();
        next.rung = Rung::Disasm;
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

    #[test]
    fn pass_metadata_advertises_capabilities() {
        let p: JvmPass = JvmPass::new();
        assert_eq!(PassMetadata::id(&p), "jvm.deob");
        assert_eq!(p.consumes(), &[Rung::Raw]);
        assert_eq!(p.emits(), &[Rung::Disasm]);
        assert_eq!(p.produced_capabilities().len(), 4);
    }

    #[test]
    fn pass_run_promotes_rung() {
        let input: Artifact = Artifact::new(Rung::Raw, vec![], [0u8; 32]);
        let out: Artifact = JvmPass::new().run(&input).expect("ok");
        assert_eq!(out.rung, Rung::Disasm);
        assert!(!out.capabilities.is_empty());
    }
}
