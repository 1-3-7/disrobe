use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use disrobe_llm_metadata::{
    Category, MetadataSelection, PerPassEnvelope, PipelineStep, SelectionBuilder, envelope_map,
};
use disrobe_nir::NirModule;
use serde_json::Value as Json;

use crate::cli::llm::make_step;

const OWNED_CATEGORIES: [Category; 2] = [Category::Cfg, Category::Dfg];

#[cfg(feature = "irsummary")]
const MIR_UNREACHABLE: &str =
    "the input never reached the Mir rung, so no control-flow or data-flow summary exists for it";

fn owned_selection(selection: &MetadataSelection) -> Option<MetadataSelection> {
    let resolved: BTreeSet<Category> = selection.resolved();
    let owned: Vec<Category> = OWNED_CATEGORIES
        .into_iter()
        .filter(|category: &Category| resolved.contains(category))
        .collect();
    if owned.is_empty() {
        return None;
    }
    Some(
        SelectionBuilder::new()
            .categories(owned)
            .format(selection.format)
            .build(),
    )
}

pub(crate) fn unavailable(
    selection: &MetadataSelection,
    reason: &str,
) -> Option<(PipelineStep, Json)> {
    let narrowed: MetadataSelection = owned_selection(selection)?;
    let (pass, version): (&'static str, &'static str) = reporting_pass();
    let mut entries: BTreeMap<&'static str, PerPassEnvelope> = BTreeMap::new();
    for category in narrowed.resolved() {
        entries.insert(
            category.label(),
            PerPassEnvelope::not_applicable(pass, version, reason),
        );
    }
    Some((
        make_step(pass, version, "raw", "raw", 0.0_f64),
        envelope_map(entries),
    ))
}

#[cfg(feature = "irsummary")]
pub(crate) fn summarize(
    selection: &MetadataSelection,
    module: &NirModule,
) -> Option<(PipelineStep, Json)> {
    use disrobe_irsummary::{IrSummaryEmitter, METADATA_CAPABILITY};
    use disrobe_llm_metadata::LlmMetadataEmitter;

    let narrowed: MetadataSelection = owned_selection(selection)?;
    let started: std::time::Instant = std::time::Instant::now();
    let emitter: IrSummaryEmitter<'_> = IrSummaryEmitter::new(module);
    let envelopes: Json = emitter.emit_metadata(&narrowed);
    let duration_ms: f64 = started.elapsed().as_secs_f64() * 1000.0_f64;
    Some((
        make_step(
            METADATA_CAPABILITY.pass,
            METADATA_CAPABILITY.pass_version,
            "mir",
            "mir",
            duration_ms,
        ),
        envelopes,
    ))
}

#[cfg(not(feature = "irsummary"))]
pub(crate) fn summarize(
    selection: &MetadataSelection,
    _module: &NirModule,
) -> Option<(PipelineStep, Json)> {
    unavailable(selection, BUILD_WITHOUT_IR_SUMMARY)
}

#[cfg(feature = "irsummary")]
pub(crate) fn pass_for_bytes(
    selection: &MetadataSelection,
    input: &Path,
    bytes: &[u8],
) -> Option<(PipelineStep, Json)> {
    let _: MetadataSelection = owned_selection(selection)?;
    match crate::cli::nir_source::lift_module_from_bytes(input, bytes) {
        Ok(module) => summarize(selection, &module),
        Err(e) => unavailable(selection, &format!("{MIR_UNREACHABLE}: {e}")),
    }
}

#[cfg(not(feature = "irsummary"))]
pub(crate) fn pass_for_bytes(
    selection: &MetadataSelection,
    _input: &Path,
    _bytes: &[u8],
) -> Option<(PipelineStep, Json)> {
    unavailable(selection, BUILD_WITHOUT_IR_SUMMARY)
}

#[cfg(feature = "irsummary")]
const fn reporting_pass() -> (&'static str, &'static str) {
    (
        disrobe_irsummary::METADATA_CAPABILITY.pass,
        disrobe_irsummary::METADATA_CAPABILITY.pass_version,
    )
}

#[cfg(not(feature = "irsummary"))]
const BUILD_WITHOUT_IR_SUMMARY: &str = "this build was compiled without the irsummary feature, so no pass in it can produce a control-flow or data-flow summary";

#[cfg(not(feature = "irsummary"))]
const fn reporting_pass() -> (&'static str, &'static str) {
    (env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"))
}
