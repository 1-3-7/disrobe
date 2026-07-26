use std::fmt::Debug;

use crate::artifact::Artifact;
use crate::chain::detection::{ChildArtifact, OutputKind};
use crate::chain::detector::Detector;
use crate::error::Result as CoreResult;

pub type PassId = &'static str;

#[derive(Debug, Clone, Copy, Default)]
pub struct PassContext<'a> {
    pub path_hint: Option<&'a str>,
    pub i_have_authorization: bool,
}

impl<'a> PassContext<'a> {
    #[must_use]
    pub const fn with_path_hint(path_hint: Option<&'a str>) -> Self {
        Self {
            path_hint,
            i_have_authorization: false,
        }
    }
}

pub trait Pass: Debug + Send + Sync {
    fn id(&self) -> PassId;
    fn detector(&self) -> &'static dyn Detector;
    fn output_kind(&self, output: &Artifact) -> OutputKind;
    fn run(&self, artifact: &Artifact) -> CoreResult<Artifact>;

    fn run_with_path(&self, artifact: &Artifact, _path_hint: Option<&str>) -> CoreResult<Artifact> {
        self.run(artifact)
    }

    fn run_with_context(
        &self,
        artifact: &Artifact,
        context: PassContext<'_>,
    ) -> CoreResult<Artifact> {
        self.run_with_path(artifact, context.path_hint)
    }

    fn extract_children(&self, _input: &Artifact) -> CoreResult<Vec<ChildArtifact>> {
        Ok(Vec::new())
    }

    fn extract_children_with_context(
        &self,
        input: &Artifact,
        _context: PassContext<'_>,
    ) -> CoreResult<Vec<ChildArtifact>> {
        self.extract_children(input)
    }
}
