mod algebraic_opaque;
mod ast_scrambler;
mod ast_shape;
mod calculator;
mod cff_vm;
mod dead_code;
mod dispatcher;
mod flatten;
mod integrity;
mod integrity_self_check;
mod lock;
mod moved_declarations;
mod opaque;
mod packing;
mod rgf;
mod rgf_eval;
mod scanner;
mod shuffle;
mod state_sum;
mod string_compression;
mod string_conceal;
mod string_encoding;
mod variable_masking;

use serde::Serialize;

pub use ast_scrambler::{AstScramblerResult, reverse_ast_scrambler};
pub use ast_shape::{
    CalculatorShape, DispatcherShape, RgfShape, detect_calculator_shapes, detect_dispatcher_shapes,
    detect_rgf_shapes,
};
pub use calculator::{CalculatorReversalResult, reverse_calculator};
pub use dead_code::{DeadCodeReversalResult, reverse_dead_code};
pub use dispatcher::{DispatcherReversalResult, reverse_dispatcher};
pub use flatten::{FlattenReversalResult, reverse_flatten};
pub use integrity::{IntegrityReversalResult, strip_integrity};
pub use integrity_self_check::{IntegritySelfCheckResult, strip_integrity_self_check};
pub use lock::{LockReversalResult, strip_locks};
pub use moved_declarations::{MovedDeclReversalResult, reverse_moved_declarations};
pub use opaque::{
    OpaqueReversalResult, PredicateValue, recognize_predicate, reverse_opaque_predicates,
};
pub use packing::{PackingReversalResult, reverse_packing};
pub use rgf::{RgfReversalResult, reverse_rgf};
pub use rgf_eval::{RgfEvalReversalResult, reverse_rgf_eval};
pub use shuffle::{ShuffleReversalResult, reverse_shuffle};
pub use state_sum::{StateSumReversalResult, reverse_state_sum};
pub use string_compression::{StringCompressionResult, reverse_string_compression};
pub use string_conceal::{StringConcealResult, reverse_string_conceal};
pub use string_encoding::{StringEncodingResult, reverse_string_encoding};
pub use variable_masking::{VariableMaskingResult, reverse_variable_masking};

#[derive(Debug, Clone, Default)]
pub struct DeobOptions {
    pub run_dispatcher: bool,
    pub run_calculator: bool,
    pub run_rgf: bool,
    pub run_rgf_eval: bool,
    pub run_opaque: bool,
    pub run_flatten: bool,
    pub run_state_sum: bool,
    pub run_variable_masking: bool,
    pub run_string_encoding: bool,
    pub run_string_compression: bool,
    pub run_string_conceal: bool,
    pub run_shuffle: bool,
    pub run_ast_scrambler: bool,
    pub run_moved_declarations: bool,
    pub run_packing: bool,
    pub run_lock: bool,
    pub run_integrity: bool,
    pub run_dead_code: bool,
    pub run_integrity_self_check: bool,
}

impl DeobOptions {
    #[must_use]
    pub const fn all() -> Self {
        Self {
            run_dispatcher: true,
            run_calculator: true,
            run_rgf: true,
            run_rgf_eval: true,
            run_opaque: true,
            run_flatten: true,
            run_state_sum: true,
            run_variable_masking: true,
            run_string_encoding: true,
            run_string_compression: true,
            run_string_conceal: true,
            run_shuffle: true,
            run_ast_scrambler: true,
            run_moved_declarations: true,
            run_packing: true,
            run_lock: true,
            run_integrity: true,
            run_dead_code: true,
            run_integrity_self_check: true,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct DeobOutput {
    pub source: String,
    pub dispatcher_calls_inlined: usize,
    pub calculator_calls_inlined: usize,
    pub rgf_calls_inlined: usize,
    pub rgf_eval_wrappers_inlined: usize,
    pub rgf_eval_runtime_walls: usize,
    pub opaque_predicates_folded: usize,
    pub flatten_dispatches_collapsed: usize,
    pub state_sum_machines_linearized: usize,
    pub state_sum_blocks_recovered: usize,
    pub cff_generators_devirtualized: usize,
    pub variable_masking_proxies_eliminated: usize,
    pub string_literals_decoded: usize,
    pub string_compression_blocks_reversed: usize,
    pub string_conceal_call_sites_decoded: usize,
    pub string_conceal_runtime_keyed: bool,
    pub shuffle_blocks_reordered: usize,
    pub ast_rotations_folded: usize,
    pub moved_decls_normalized: usize,
    pub packed_blocks_expanded: usize,
    pub lock_guards_stripped: usize,
    pub integrity_loops_stripped: usize,
    pub dead_code_branches_removed: usize,
    pub dead_code_functions_removed: usize,
    pub integrity_self_checks_unwrapped: usize,
}

#[must_use]
pub fn deobfuscate_all(source: &str, opts: &DeobOptions) -> DeobOutput {
    let mut current: String = source.to_owned();
    crate::debug::dbg_section("jsconfuser deobfuscate_all");
    crate::debug::dbg_kv("input-bytes", || source.len().to_string());
    let mut out: DeobOutput = DeobOutput {
        source: String::new(),
        dispatcher_calls_inlined: 0,
        calculator_calls_inlined: 0,
        rgf_calls_inlined: 0,
        rgf_eval_wrappers_inlined: 0,
        rgf_eval_runtime_walls: 0,
        opaque_predicates_folded: 0,
        flatten_dispatches_collapsed: 0,
        state_sum_machines_linearized: 0,
        state_sum_blocks_recovered: 0,
        cff_generators_devirtualized: 0,
        variable_masking_proxies_eliminated: 0,
        string_literals_decoded: 0,
        string_compression_blocks_reversed: 0,
        string_conceal_call_sites_decoded: 0,
        string_conceal_runtime_keyed: false,
        shuffle_blocks_reordered: 0,
        ast_rotations_folded: 0,
        moved_decls_normalized: 0,
        packed_blocks_expanded: 0,
        lock_guards_stripped: 0,
        integrity_loops_stripped: 0,
        dead_code_branches_removed: 0,
        dead_code_functions_removed: 0,
        integrity_self_checks_unwrapped: 0,
    };

    if opts.run_dead_code {
        let r: DeadCodeReversalResult = reverse_dead_code(&current);
        out.dead_code_branches_removed += r.branches_removed;
        out.dead_code_functions_removed += r.dead_functions_removed;
        if crate::debug::dbg_enabled() && (r.branches_removed > 0 || r.dead_functions_removed > 0) {
            crate::debug::dbg_kv("dead-code", || {
                format!(
                    "branches={} functions={}",
                    r.branches_removed, r.dead_functions_removed
                )
            });
        }
        current = r.rewritten_source;
    }
    if opts.run_packing {
        let r: PackingReversalResult = reverse_packing(&current);
        out.packed_blocks_expanded += r.blocks_expanded;
        if r.blocks_expanded > 0 {
            crate::debug::dbg_kv("packing-blocks-expanded", || r.blocks_expanded.to_string());
        }
        current = r.rewritten_source;
    }
    if opts.run_string_conceal {
        let r: StringConcealResult = reverse_string_conceal(&current);
        out.string_conceal_call_sites_decoded += r.call_sites_decoded;
        out.string_conceal_runtime_keyed = out.string_conceal_runtime_keyed || r.runtime_keyed;
        if crate::debug::dbg_enabled() && (r.call_sites_decoded > 0 || r.runtime_keyed) {
            crate::debug::dbg_kv("string-conceal", || {
                format!(
                    "call-sites={} runtime-keyed={}",
                    r.call_sites_decoded, r.runtime_keyed
                )
            });
        }
        current = r.rewritten_source;
    }
    if opts.run_string_compression {
        let r: StringCompressionResult = reverse_string_compression(&current);
        out.string_compression_blocks_reversed += r.blocks_reversed;
        if r.blocks_reversed > 0 {
            crate::debug::dbg_kv("string-compression-blocks-reversed", || {
                r.blocks_reversed.to_string()
            });
        }
        current = r.rewritten_source;
    }
    if opts.run_string_encoding {
        let r: StringEncodingResult = reverse_string_encoding(&current);
        out.string_literals_decoded += r.literals_decoded;
        if r.literals_decoded > 0 {
            crate::debug::dbg_kv("string-literals-decoded", || r.literals_decoded.to_string());
        }
        current = r.rewritten_source;
    }
    if opts.run_dispatcher {
        let r: DispatcherReversalResult = reverse_dispatcher(&current);
        out.dispatcher_calls_inlined += r.call_sites_inlined;
        if r.call_sites_inlined > 0 {
            crate::debug::dbg_kv("dispatcher-calls-inlined", || {
                r.call_sites_inlined.to_string()
            });
        }
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
    if opts.run_rgf_eval {
        let r: RgfEvalReversalResult = reverse_rgf_eval(&current);
        out.rgf_eval_wrappers_inlined += r.wrappers_inlined;
        out.rgf_eval_runtime_walls += r.runtime_payload_walls;
        if crate::debug::dbg_enabled() && (r.wrappers_inlined > 0 || r.runtime_payload_walls > 0) {
            crate::debug::dbg_kv("rgf-eval", || {
                format!(
                    "wrappers-inlined={} runtime-walls={}",
                    r.wrappers_inlined, r.runtime_payload_walls
                )
            });
        }
        current = r.rewritten_source;
    }
    if opts.run_state_sum {
        let vm: cff_vm::CffVmResult = cff_vm::devirtualize_cff(&current);
        if vm.generators_devirtualized > 0 {
            out.cff_generators_devirtualized += vm.generators_devirtualized;
            crate::debug::dbg_kv("cff-generators-devirtualized", || {
                vm.generators_devirtualized.to_string()
            });
            current = vm.rewritten_source;
        } else {
            let r: StateSumReversalResult = reverse_state_sum(&current);
            out.state_sum_machines_linearized += r.machines_linearized;
            out.state_sum_blocks_recovered += r.blocks_recovered;
            if crate::debug::dbg_enabled() && r.machines_linearized > 0 {
                crate::debug::dbg_kv("state-sum", || {
                    format!(
                        "machines-linearized={} blocks-recovered={}",
                        r.machines_linearized, r.blocks_recovered
                    )
                });
            }
            current = r.rewritten_source;
        }
    }
    if opts.run_flatten {
        let r: FlattenReversalResult = reverse_flatten(&current);
        out.flatten_dispatches_collapsed += r.dispatches_collapsed;
        if r.dispatches_collapsed > 0 {
            crate::debug::dbg_kv("flatten-dispatches-collapsed", || {
                r.dispatches_collapsed.to_string()
            });
        }
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
    if opts.run_integrity_self_check {
        let r: IntegritySelfCheckResult = strip_integrity_self_check(&current);
        out.integrity_self_checks_unwrapped += r.wrappers_unwrapped;
        current = r.rewritten_source;
    }

    out.source = current;
    crate::debug::dbg_kv("output-bytes", || out.source.len().to_string());
    out
}
