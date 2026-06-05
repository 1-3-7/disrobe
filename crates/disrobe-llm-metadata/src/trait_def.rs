use std::collections::BTreeMap;

use serde_json::Value as Json;

use crate::capability::MetadataCapability;
use crate::category::Category;
use crate::envelope::PerPassEnvelope;
use crate::selection::MetadataSelection;

/// The trait a pass implements on its output struct to participate in `--llm` emission.
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

    /// Build a `category-label -> PerPassEnvelope` map for every selected category.
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
