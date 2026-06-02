//! Disrobe LLM metadata envelope, selection builder, capability matrix, and
//! per-pass emitter trait for the `disrobe --llm` bundle (`disrobe.metadata.llm.v1`).
//!
//! Phase 1 of the LLM-metadata rollout. This crate is a *leaf* dependency: it
//! introduces zero coupling to any pass crate. Pass crates depend on it (not
//! the other way around) so they can opt into emitting any subset of the 18
//! categories defined by the schema at
//! [`schemas/disrobe-metadata-llm-v1.json`](../../../schemas/disrobe-metadata-llm-v1.json).
//!
//! Public surface:
//!
//! - [`Category`] - the 18-variant enum of metadata categories
//! - [`Pack`] - the 4 pre-bundled packs (`Pack1`..`Pack4`) plus [`Pack::expand`]
//! - [`MetadataSelection`] + [`SelectionBuilder`] - the value-object resolver
//! - [`MetadataCapability`] - const-friendly "what this pass can emit"
//! - [`PerPassEnvelope`] - wire-shape wrapper for every category payload
//! - [`LlmMetadataEmitter`] - the trait every pass implements (Phase 2)
//! - [`LlmMetadataError`] - failure modes for emission
//!
//! All collections are `BTreeMap` / `BTreeSet` for determinism. No wall-clock,
//! no environment reads, no I/O - pure types + transformations.

#![forbid(unsafe_code)]

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

pub const SCHEMA: &str = "disrobe.metadata.llm.v1";
pub const SCHEMA_VERSION: &str = "1.0.0";
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
