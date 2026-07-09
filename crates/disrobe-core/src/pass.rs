use std::fmt::Debug;

use crate::artifact::Artifact;
use crate::chain::detection::{ChildArtifact, OutputKind};
use crate::chain::detector::Detector;
use crate::error::Result as CoreResult;

pub type PassId = &'static str;

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
