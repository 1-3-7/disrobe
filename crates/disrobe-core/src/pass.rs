use std::fmt::Debug;

#[cfg(feature = "chain")]
use crate::artifact::Artifact;
#[cfg(feature = "chain")]
use crate::chain::detection::{ChildArtifact, OutputKind};
#[cfg(feature = "chain")]
use crate::chain::detector::Detector;
#[cfg(feature = "chain")]
use crate::error::Result as CoreResult;

use crate::artifact::Artifact as LegacyArtifact;
use crate::capability::Capability;
use crate::error::Result as LegacyResult;
use crate::rung::Rung;

pub type PassId = &'static str;

#[cfg(feature = "chain")]
pub trait Pass: Debug + Send + Sync {
    fn id(&self) -> PassId;
    fn detector(&self) -> &'static dyn Detector;
    fn output_kind(&self, output: &Artifact) -> OutputKind;
    fn run(&self, artifact: &Artifact) -> CoreResult<Artifact>;

    fn run_with_path(&self, artifact: &Artifact, _path_hint: Option<&str>) -> CoreResult<Artifact> {
        self.run(artifact)
    }

    fn extract_children(&self, _input: &Artifact) -> CoreResult<Vec<ChildArtifact>> {
        Ok(Vec::new())
    }
}

pub trait LegacyPass: Debug + Send + Sync {
    const CONSUMES: &'static [Rung];
    const EMITS: &'static [Rung];
    const REQUIRES: &'static [fn() -> Capability];
    const PRODUCES: &'static [fn() -> Capability];

    fn id(&self) -> PassId;

    fn run(&self, artifact: &LegacyArtifact) -> LegacyResult<LegacyArtifact>;
}

pub trait PassMetadata {
    fn consumes(&self) -> &'static [Rung];
    fn emits(&self) -> &'static [Rung];
    fn required_capabilities(&self) -> Vec<Capability>;
    fn produced_capabilities(&self) -> Vec<Capability>;
    fn id(&self) -> PassId;
}

impl<P: LegacyPass> PassMetadata for P {
    #[inline]
    fn consumes(&self) -> &'static [Rung] {
        P::CONSUMES
    }

    #[inline]
    fn emits(&self) -> &'static [Rung] {
        P::EMITS
    }

    #[inline]
    fn required_capabilities(&self) -> Vec<Capability> {
        P::REQUIRES.iter().map(|f| f()).collect()
    }

    #[inline]
    fn produced_capabilities(&self) -> Vec<Capability> {
        P::PRODUCES.iter().map(|f| f()).collect()
    }

    #[inline]
    fn id(&self) -> PassId {
        <P as LegacyPass>::id(self)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct DummyPass;

    impl LegacyPass for DummyPass {
        const CONSUMES: &'static [Rung] = &[Rung::Raw];
        const EMITS: &'static [Rung] = &[Rung::Disasm];
        const REQUIRES: &'static [fn() -> Capability] = &[];
        const PRODUCES: &'static [fn() -> Capability] =
            &[|| Capability::produces("disasm.core", 1)];

        fn id(&self) -> PassId {
            "test.dummy"
        }

        fn run(&self, artifact: &LegacyArtifact) -> LegacyResult<LegacyArtifact> {
            let mut next: LegacyArtifact = artifact.clone();
            next.rung = Rung::Disasm;
            for emitter in <Self as LegacyPass>::PRODUCES {
                next.add_capability(emitter());
            }
            Ok(next)
        }
    }

    #[test]
    fn metadata_reflects_associated_consts() {
        let p: DummyPass = DummyPass;
        assert_eq!(PassMetadata::id(&p), "test.dummy");
        assert_eq!(p.consumes(), &[Rung::Raw]);
        assert_eq!(p.emits(), &[Rung::Disasm]);
        assert!(p.required_capabilities().is_empty());
        assert_eq!(p.produced_capabilities().len(), 1);
    }
}
