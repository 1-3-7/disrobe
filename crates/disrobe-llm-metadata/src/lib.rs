#![forbid(unsafe_code)]
#![deny(unreachable_pub)]
pub mod annotation;
pub mod bundle;
pub mod capability;
pub mod category;
pub mod envelope;
pub mod error;
pub mod markdown;
pub mod pack;
pub mod selection;
pub mod shape;
pub mod trait_def;
pub mod usage_inference;

pub use annotation::{ANNOTATION_SCHEMA, AnnotationError, AnnotationFile, SymbolAnnotation};
pub use bundle::{
    BundleBuilder, InputDescriptor, PipelineStep, ToolDescriptor, envelope_map, serialize,
    write_briefs_to_dir, write_bundle_to_path,
};
pub use capability::MetadataCapability;
pub use category::Category;
pub use envelope::PerPassEnvelope;
pub use error::LlmMetadataError;
pub use markdown::{render_agents_md, render_skill_md};
pub use pack::Pack;
pub use selection::{MetadataFormat, MetadataSelection, SelectionBuilder};
pub use trait_def::LlmMetadataEmitter;
pub use usage_inference::{
    FunctionUsage, InferredType, UsageInferenceEngine, UsageObservation, VariableUsage,
};

pub const SCHEMA: &str = "disrobe.metadata.llm.v1";
pub const SCHEMA_VERSION: &str = "1.0.0";
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
