mod closure_advanced;
mod corpus;
mod dts_reverse;
mod flow_infer;
mod preset_env_undo;
mod sourcemap_emit;
mod terser_restore;
mod type_recover;

use serde::Serialize;

pub use closure_advanced::{ClosureAdvancedReport, undo_closure_advanced};
pub use corpus::{DtsCorpus, DtsModule, DtsSymbol, DtsSymbolKind};
pub use dts_reverse::{DtsReverseResult, reverse_declarations};
pub use flow_infer::{InferredType, TypeFlowReport, analyze as analyze_flow};
pub use preset_env_undo::{PresetEnvUndoResult, undo_preset_env};
pub use sourcemap_emit::{SourceMapEmitResult, emit_ts_with_source_map};
pub use terser_restore::{MangledCandidate, TerserRestoreReport, restore_terser_mangled};
pub use type_recover::{TypeRecoveryResult, recover_types};

#[derive(Debug, Clone, Default, Serialize)]
pub struct TypeScriptEmitStats {
    pub annotations_emitted: usize,
    pub symbols_matched_via_corpus: usize,
    pub symbols_inferred_via_flow: usize,
    pub unknown_symbols: usize,
}
