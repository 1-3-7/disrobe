use disrobe_core::{
    Artifact, Capability, CoreError, LegacyPass, PassId, Result as CoreResult, Rung,
};

use crate::debug::{dbg_kv, dbg_line, dbg_section};
use crate::detect::{Detection, Family, detect};
use crate::peel::{PeelResult, peel};

#[derive(Debug, Default, Clone, Copy)]
pub struct PyDeobLegacyPass;

impl PyDeobLegacyPass {
    pub const ID: PassId = "py.deob.legacy";

    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl LegacyPass for PyDeobLegacyPass {
    const CONSUMES: &'static [Rung] = &[Rung::Raw];
    const EMITS: &'static [Rung] = &[Rung::Surface];
    const REQUIRES: &'static [fn() -> Capability] = &[];
    const PRODUCES: &'static [fn() -> Capability] =
        &[|| Capability::produces("py.deob.surface", 1)];

    fn id(&self) -> PassId {
        Self::ID
    }

    fn run(&self, artifact: &Artifact) -> CoreResult<Artifact> {
        dbg_section("py.deob");
        let bytes: &[u8] = artifact.envelope.as_slice();
        dbg_kv("input_len", || bytes.len().to_string());
        let detection: Detection = detect(bytes);
        dbg_kv("family", || format!("{:?}", detection.family));
        if detection.family == Family::Unknown {
            dbg_line(|| "no known obfuscation family matched".to_owned());
            return Err(CoreError::PassFailure(
                "DR-PYDEOB-0001: source does not match any known obfuscation family".to_string(),
            ));
        }
        let peeled: PeelResult = peel(bytes).map_err(|e: crate::error::Error| {
            dbg_line(|| format!("peel failed: {e}"));
            CoreError::PassFailure(format!("{e}"))
        })?;
        dbg_kv("recovered_len", || peeled.final_source.len().to_string());
        let mut next: Artifact = Artifact::new(
            Rung::Surface,
            peeled.final_source.into_bytes(),
            artifact.root_hash,
        );
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
    fn py_deob_legacy_metadata_advertises_capabilities() {
        let p: PyDeobLegacyPass = PyDeobLegacyPass::new();
        assert_eq!(PassMetadata::id(&p), "py.deob.legacy");
        assert_eq!(p.consumes(), &[Rung::Raw]);
        assert_eq!(p.emits(), &[Rung::Surface]);
        assert_eq!(p.produced_capabilities().len(), 1);
    }

    #[test]
    fn py_deob_legacy_run_peels_known_family() {
        let source: &[u8] = b"# BlankOBF v2\nexec(__import__('base64').b64decode(b''))\n";
        let input: Artifact = Artifact::new(Rung::Raw, source.to_vec(), [0u8; 32]);
        let detection: Detection = detect(source);
        assert_ne!(detection.family, Family::Unknown);
        let out: Artifact = PyDeobLegacyPass::new()
            .run(&input)
            .expect("known obfuscation family must peel");
        assert_eq!(out.rung, Rung::Surface);
        assert!(
            out.has_capability(&Capability::produces("py.deob.surface", 1)),
            "expected py.deob.surface capability"
        );
    }

    #[test]
    fn py_deob_legacy_run_on_clean_source_returns_pass_failure() {
        let source: &[u8] = b"def foo():\n    return 1\n";
        let input: Artifact = Artifact::new(Rung::Raw, source.to_vec(), [0u8; 32]);
        let err: CoreError = PyDeobLegacyPass::new()
            .run(&input)
            .expect_err("clean source has no known family");
        let text: String = format!("{err}");
        assert!(text.contains("DR-PYDEOB"), "got: {text}");
    }
}
