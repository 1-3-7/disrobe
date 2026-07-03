use disrobe_llm_metadata::{Category, LlmMetadataEmitter, MetadataCapability};
use disrobe_nir::NirModule;
use serde_json::Value as Json;

use crate::capability::{CapabilitySummary, capability_summary};
use crate::cfg::cfg_summary;
use crate::dfg::dfg_summary;

const PASS: &str = "disrobe-irsummary";

pub const METADATA_CAPABILITY: MetadataCapability =
    MetadataCapability::new(PASS, crate::VERSION, &[Category::Cfg, Category::Dfg]);

#[derive(Debug, Clone)]
pub struct IrSummaryEmitter<'a> {
    module: &'a NirModule,
}

impl<'a> IrSummaryEmitter<'a> {
    #[must_use]
    pub const fn new(module: &'a NirModule) -> Self {
        Self { module }
    }

    #[must_use]
    pub fn capabilities(&self) -> CapabilitySummary {
        capability_summary(self.module)
    }
}

impl LlmMetadataEmitter for IrSummaryEmitter<'_> {
    fn metadata_capability(&self) -> MetadataCapability {
        METADATA_CAPABILITY
    }

    fn emit_cfg(&self) -> Option<Json> {
        Some(cfg_summary(self.module).to_json())
    }

    fn emit_dfg(&self) -> Option<Json> {
        Some(dfg_summary(self.module).to_json())
    }
}
