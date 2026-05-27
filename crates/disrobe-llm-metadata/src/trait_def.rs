use std::collections::BTreeMap;

use serde_json::Value as Json;

use crate::capability::MetadataCapability;
use crate::category::Category;
use crate::envelope::PerPassEnvelope;
use crate::selection::MetadataSelection;

/// The trait every pass crate that wants to participate in `--llm` emission
/// implements on its primary pass-output struct.
///
/// All 18 `emit_*` methods default to `None`. A pass only overrides what it can
/// genuinely produce. The blanket [`Self::emit_metadata`] walks the resolved
/// selection, calls the right method per category, and wraps each result in a
/// [`PerPassEnvelope`] — when a category is requested but the pass cannot
/// produce it, the envelope carries `applicable: false` with a reason so the
/// downstream LLM can reason about gaps rather than silently get nothing.
pub trait LlmMetadataEmitter {
    fn metadata_capability(&self) -> MetadataCapability;

    fn emit_ast(&self) -> Option<Json> {
        None
    }
    fn emit_disasm(&self) -> Option<Json> {
        None
    }
    fn emit_cfg(&self) -> Option<Json> {
        None
    }
    fn emit_dfg(&self) -> Option<Json> {
        None
    }
    fn emit_symbols(&self) -> Option<Json> {
        None
    }
    fn emit_strings(&self) -> Option<Json> {
        None
    }
    fn emit_types(&self) -> Option<Json> {
        None
    }
    fn emit_imports(&self) -> Option<Json> {
        None
    }
    fn emit_constants(&self) -> Option<Json> {
        None
    }
    fn emit_signatures(&self) -> Option<Json> {
        None
    }
    fn emit_provenance(&self) -> Option<Json> {
        None
    }
    fn emit_roundtrip_verdict(&self) -> Option<Json> {
        None
    }
    fn emit_source_map(&self) -> Option<Json> {
        None
    }
    fn emit_manifest(&self) -> Option<Json> {
        None
    }
    fn emit_decryption_keys(&self) -> Option<Json> {
        None
    }
    fn emit_confidence(&self) -> Option<Json> {
        None
    }
    fn emit_opcode_coverage(&self) -> Option<Json> {
        None
    }
    fn emit_pii_map(&self) -> Option<Json> {
        None
    }

    /// Build a `category-label -> PerPassEnvelope` map for every category in
    /// the resolved selection. Always deterministic (`BTreeMap` + sorted iteration).
    fn emit_metadata(&self, sel: &MetadataSelection) -> Json {
        let cap: MetadataCapability = self.metadata_capability();
        let mut out: BTreeMap<&'static str, PerPassEnvelope> = BTreeMap::new();
        for c in sel.resolved() {
            let value: Option<Json> = match c {
                Category::Ast => self.emit_ast(),
                Category::Disasm => self.emit_disasm(),
                Category::Cfg => self.emit_cfg(),
                Category::Dfg => self.emit_dfg(),
                Category::Symbols => self.emit_symbols(),
                Category::Strings => self.emit_strings(),
                Category::Types => self.emit_types(),
                Category::Imports => self.emit_imports(),
                Category::Constants => self.emit_constants(),
                Category::Signatures => self.emit_signatures(),
                Category::Provenance => self.emit_provenance(),
                Category::RoundtripVerdict => self.emit_roundtrip_verdict(),
                Category::SourceMap => self.emit_source_map(),
                Category::Manifest => self.emit_manifest(),
                Category::DecryptionKeys => self.emit_decryption_keys(),
                Category::Confidence => self.emit_confidence(),
                Category::OpcodeCoverage => self.emit_opcode_coverage(),
                Category::PiiMap => self.emit_pii_map(),
            };
            let envelope: PerPassEnvelope = value.map_or_else(
                || {
                    PerPassEnvelope::not_applicable(
                        cap.pass,
                        cap.pass_version,
                        format!("pass `{}` does not produce `{}`", cap.pass, c.label()),
                    )
                },
                |v: Json| PerPassEnvelope::applicable(cap.pass, cap.pass_version, v),
            );
            out.insert(c.label(), envelope);
        }
        serde_json::to_value(&out).unwrap_or(Json::Null)
    }
}
