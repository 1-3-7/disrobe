mod arithmetic;
mod control_flow;
mod globals;
mod peepholes;
mod protection;
mod string_split;

use serde::Serialize;

const MAX_FIX_POINT_PASSES: usize = 8;

#[derive(Debug, Clone, Default, Serialize)]
pub struct UnminifyStats {
    pub bool_shorthand_reversed: usize,
    pub void_undefined_reversed: usize,
    pub double_not_reversed: usize,
    pub merged_string_concat: usize,
    pub string_split_literals_merged: usize,
    pub arithmetic_folded: usize,
    pub function_call_reversed: usize,
    pub globals_call_sites: usize,
    pub globals_evaluated: usize,
    pub globals_failed: usize,
    pub if_true_inlined: usize,
    pub if_false_eliminated: usize,
    pub debugger_loops_removed: usize,
    pub set_interval_watchdogs_removed: usize,
    pub function_debugger_removed: usize,
    pub self_defending_iifes_removed: usize,
    pub control_flow_blocks_unflattened: usize,
    pub control_flow_cases_inlined: usize,
}

pub fn unminify(source: &str) -> (String, UnminifyStats) {
    let mut out: String = source.to_owned();
    let mut stats: UnminifyStats = UnminifyStats::default();
    let mut last_len: usize = out.len();
    for _ in 0..MAX_FIX_POINT_PASSES {
        let (next, n): (String, usize) = peepholes::reverse_bool_shorthand(&out);
        out = next;
        stats.bool_shorthand_reversed += n;

        let (next, n): (String, usize) = peepholes::reverse_void_undefined(&out);
        out = next;
        stats.void_undefined_reversed += n;

        let (next, n): (String, usize) = peepholes::reverse_double_not(&out);
        out = next;
        stats.double_not_reversed += n;

        let (next, n): (String, usize) = peepholes::merge_string_concat(&out);
        out = next;
        stats.merged_string_concat += n;

        let (next, split_stats): (String, string_split::StringSplitStats) =
            string_split::fold_string_concat(&out);
        out = next;
        stats.string_split_literals_merged += split_stats.literals_merged;

        let (next, n): (String, usize) = arithmetic::fold_binary(&out);
        out = next;
        stats.arithmetic_folded += n;

        let (next, n): (String, usize) = arithmetic::reverse_function_call(&out);
        out = next;
        stats.function_call_reversed += n;

        let (next, globals_stats): (String, globals::GlobalsEvalStats) =
            globals::evaluate_globals(&out);
        out = next;
        stats.globals_call_sites += globals_stats.call_sites;
        stats.globals_evaluated += globals_stats.evaluated;
        stats.globals_failed += globals_stats.failed;

        let (next, prot_stats): (String, protection::ProtectionStripStats) =
            protection::strip_protection(&out);
        out = next;
        stats.if_true_inlined += prot_stats.if_true_inlined;
        stats.if_false_eliminated += prot_stats.if_false_eliminated;
        stats.debugger_loops_removed += prot_stats.debugger_loops_removed;
        stats.set_interval_watchdogs_removed += prot_stats.set_interval_watchdogs_removed;
        stats.function_debugger_removed += prot_stats.function_debugger_removed;
        stats.self_defending_iifes_removed += prot_stats.self_defending_iifes_removed;

        let (next, cf_stats): (String, control_flow::UnflattenStats) =
            control_flow::unflatten(&out);
        out = next;
        stats.control_flow_blocks_unflattened += cf_stats.blocks_unflattened;
        stats.control_flow_cases_inlined += cf_stats.cases_inlined;

        if out.len() == last_len {
            break;
        }
        last_len = out.len();
    }
    (out, stats)
}
