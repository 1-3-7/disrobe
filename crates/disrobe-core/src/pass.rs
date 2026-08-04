use std::fmt::Debug;

use serde::Serialize;

use crate::artifact::Artifact;
use crate::chain::detection::{ChildArtifact, OutputKind};
use crate::chain::detector::Detector;
use crate::chain::ecosystem::{Ecosystem, ecosystem_for};
use crate::chain::obfuscator_catalog::SupportQuality;
use crate::error::Result as CoreResult;

pub type PassId = &'static str;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Determinism {
    Deterministic,
    EnvironmentSensitive,
}

impl Determinism {
    #[inline]
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Deterministic => "deterministic",
            Self::EnvironmentSensitive => "environment-sensitive",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SafetyClass {
    Static,
    GatedDynamic,
}

impl SafetyClass {
    #[inline]
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Static => "static",
            Self::GatedDynamic => "gated-dynamic",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct PassMeta {
    pub id: PassId,
    pub ecosystem: Ecosystem,
    pub support: SupportQuality,
    pub determinism: Determinism,
    pub safety: SafetyClass,
}

impl PassMeta {
    #[inline]
    #[must_use]
    pub const fn new(
        id: PassId,
        ecosystem: Ecosystem,
        support: SupportQuality,
        determinism: Determinism,
        safety: SafetyClass,
    ) -> Self {
        Self {
            id,
            ecosystem,
            support,
            determinism,
            safety,
        }
    }
}

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

    fn meta(&self) -> PassMeta {
        PassMeta::new(
            self.id(),
            ecosystem_for(self.id()),
            SupportQuality::DetectOnly,
            Determinism::Deterministic,
            SafetyClass::Static,
        )
    }

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
