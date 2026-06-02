mod ast_scrambler;
mod ast_shape;
mod calculator;
mod dispatcher;
mod flatten;
mod integrity;
mod lock;
mod moved_declarations;
mod opaque;
mod packing;
mod rgf;
mod scanner;
mod shuffle;
mod string_compression;
mod string_encoding;
mod variable_masking;

use serde::Serialize;

pub use ast_scrambler::{AstScramblerResult, reverse_ast_scrambler};
pub use ast_shape::{
    CalculatorShape, DispatcherShape, RgfShape, detect_calculator_shapes, detect_dispatcher_shapes,
    detect_rgf_shapes,
};
pub use calculator::{CalculatorReversalResult, reverse_calculator};
pub use dispatcher::{DispatcherReversalResult, reverse_dispatcher};
pub use flatten::{FlattenReversalResult, reverse_flatten};
pub use integrity::{IntegrityReversalResult, strip_integrity};
pub use lock::{LockReversalResult, strip_locks};
pub use moved_declarations::{MovedDeclReversalResult, reverse_moved_declarations};
pub use opaque::{
    OpaqueReversalResult, PredicateValue, recognize_predicate, reverse_opaque_predicates,
};
pub use packing::{PackingReversalResult, reverse_packing};
pub use rgf::{RgfReversalResult, reverse_rgf};
pub use shuffle::{ShuffleReversalResult, reverse_shuffle};
pub use string_compression::{StringCompressionResult, reverse_string_compression};
pub use string_encoding::{StringEncodingResult, reverse_string_encoding};
pub use variable_masking::{VariableMaskingResult, reverse_variable_masking};

#[derive(Debug, Clone, Default)]
pub struct DeobOptions {
    pub run_dispatcher: bool,
    pub run_calculator: bool,
    pub run_rgf: bool,
    pub run_opaque: bool,
    pub run_flatten: bool,
    pub run_variable_masking: bool,
    pub run_string_encoding: bool,
    pub run_string_compression: bool,
    pub run_shuffle: bool,
    pub run_ast_scrambler: bool,
    pub run_moved_declarations: bool,
    pub run_packing: bool,
    pub run_lock: bool,
    pub run_integrity: bool,
}

impl DeobOptions {
    #[must_use]
    pub const fn all() -> Self {
        Self {
            run_dispatcher: true,
            run_calculator: true,
            run_rgf: true,
            run_opaque: true,
            run_flatten: true,
            run_variable_masking: true,
            run_string_encoding: true,
            run_string_compression: true,
            run_shuffle: true,
            run_ast_scrambler: true,
            run_moved_declarations: true,
            run_packing: true,
            run_lock: true,
            run_integrity: true,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct DeobOutput {
    pub source: String,
    pub dispatcher_calls_inlined: usize,
    pub calculator_calls_inlined: usize,
    pub rgf_calls_inlined: usize,
    pub opaque_predicates_folded: usize,
    pub flatten_dispatches_collapsed: usize,
    pub variable_masking_proxies_eliminated: usize,
    pub string_literals_decoded: usize,
    pub string_compression_blocks_reversed: usize,
    pub shuffle_blocks_reordered: usize,
    pub ast_rotations_folded: usize,
    pub moved_decls_normalized: usize,
    pub packed_blocks_expanded: usize,
    pub lock_guards_stripped: usize,
    pub integrity_loops_stripped: usize,
}

#[must_use]
pub fn deobfuscate_all(source: &str, opts: &DeobOptions) -> DeobOutput {
    let mut current: String = source.to_owned();
    let mut out: DeobOutput = DeobOutput {
        source: String::new(),
        dispatcher_calls_inlined: 0,
        calculator_calls_inlined: 0,
        rgf_calls_inlined: 0,
        opaque_predicates_folded: 0,
        flatten_dispatches_collapsed: 0,
        variable_masking_proxies_eliminated: 0,
        string_literals_decoded: 0,
        string_compression_blocks_reversed: 0,
        shuffle_blocks_reordered: 0,
        ast_rotations_folded: 0,
        moved_decls_normalized: 0,
        packed_blocks_expanded: 0,
        lock_guards_stripped: 0,
        integrity_loops_stripped: 0,
    };

    if opts.run_packing {
        let r: PackingReversalResult = reverse_packing(&current);
        out.packed_blocks_expanded += r.blocks_expanded;
        current = r.rewritten_source;
    }
    if opts.run_string_compression {
        let r: StringCompressionResult = reverse_string_compression(&current);
        out.string_compression_blocks_reversed += r.blocks_reversed;
        current = r.rewritten_source;
    }
    if opts.run_string_encoding {
        let r: StringEncodingResult = reverse_string_encoding(&current);
        out.string_literals_decoded += r.literals_decoded;
        current = r.rewritten_source;
    }
    if opts.run_dispatcher {
        let r: DispatcherReversalResult = reverse_dispatcher(&current);
        out.dispatcher_calls_inlined += r.call_sites_inlined;
        current = r.rewritten_source;
    }
    if opts.run_calculator {
        let r: CalculatorReversalResult = reverse_calculator(&current);
        out.calculator_calls_inlined += r.call_sites_inlined;
        current = r.rewritten_source;
    }
    if opts.run_rgf {
        let r: RgfReversalResult = reverse_rgf(&current);
        out.rgf_calls_inlined += r.call_sites_inlined;
        current = r.rewritten_source;
    }
    if opts.run_flatten {
        let r: FlattenReversalResult = reverse_flatten(&current);
        out.flatten_dispatches_collapsed += r.dispatches_collapsed;
        current = r.rewritten_source;
    }
    if opts.run_variable_masking {
        let r: VariableMaskingResult = reverse_variable_masking(&current);
        out.variable_masking_proxies_eliminated += r.proxies_eliminated;
        current = r.rewritten_source;
    }
    if opts.run_shuffle {
        let r: ShuffleReversalResult = reverse_shuffle(&current);
        out.shuffle_blocks_reordered += r.blocks_reordered;
        current = r.rewritten_source;
    }
    if opts.run_ast_scrambler {
        let r: AstScramblerResult = reverse_ast_scrambler(&current);
        out.ast_rotations_folded += r.rotations_folded;
        current = r.rewritten_source;
    }
    if opts.run_moved_declarations {
        let r: MovedDeclReversalResult = reverse_moved_declarations(&current);
        out.moved_decls_normalized += r.decls_normalized;
        current = r.rewritten_source;
    }
    if opts.run_opaque {
        let r: OpaqueReversalResult = reverse_opaque_predicates(&current);
        out.opaque_predicates_folded += r.predicates_folded;
        current = r.rewritten_source;
    }
    if opts.run_lock {
        let r: LockReversalResult = strip_locks(&current);
        out.lock_guards_stripped += r.guards_stripped;
        current = r.rewritten_source;
    }
    if opts.run_integrity {
        let r: IntegrityReversalResult = strip_integrity(&current);
        out.integrity_loops_stripped += r.loops_stripped;
        current = r.rewritten_source;
    }

    out.source = current;
    out
}
