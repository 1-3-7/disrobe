mod arithmetic;
mod ast;
mod control_flow;
mod globals;
mod protection;
mod self_defending;
mod string_split;

pub use ast::{AstPipeline, AstRuleId, AstUnminifyStats, try_unminify_ast, unminify_ast};
pub(crate) use ast::{
    PresetEnvExpressionRestore, has_preset_env_async_protection,
    requires_preset_env_async_quarantine, restore_preset_env_expressions,
};

use serde::Serialize;

const MAX_FIX_POINT_PASSES: usize = 8;

#[derive(Debug, Clone, Default, Serialize)]
pub struct UnminifyStats {
    pub literals_normalized: usize,
    pub members_dotted: usize,
    pub string_split_literals_merged: usize,
    pub arithmetic_folded: usize,
    pub radix_literals_decimalized: usize,
    pub globals_call_sites: usize,
    pub globals_evaluated: usize,
    pub globals_failed: usize,
    pub if_true_inlined: usize,
    pub if_false_eliminated: usize,
    pub debugger_loops_removed: usize,
    pub set_interval_watchdogs_removed: usize,
    pub function_debugger_removed: usize,
    pub self_defending_iifes_removed: usize,
    pub self_defending_checkers_removed: usize,
    pub self_defending_wrappers_removed: usize,
    pub debug_protection_ratchets_removed: usize,
    pub debug_ratchet_functions_removed: usize,
    pub discarded_constructor_calls_removed: usize,
    pub control_flow_blocks_unflattened: usize,
    pub control_flow_cases_inlined: usize,
}

#[must_use]
pub fn unminify(source: &str) -> (String, UnminifyStats) {
    let mut out: String = source.to_owned();
    let mut stats: UnminifyStats = UnminifyStats::default();
    let mut last_len: usize = out.len();
    let normalize: AstPipeline = AstPipeline::only(&[
        AstRuleId::BracketToDot,
        AstRuleId::OptionalChaining,
        AstRuleId::NullishCoalescing,
        AstRuleId::LiteralNormalize,
    ]);
    for _ in 0..MAX_FIX_POINT_PASSES {
        let (next, normalized): (String, AstUnminifyStats) = normalize.run(&out);
        out = next;
        stats.literals_normalized += normalized.boolean_shorthands_normalized
            + normalized.void_undefineds_normalized
            + normalized.double_not_coercions_normalized
            + normalized.string_concats_folded;
        stats.members_dotted += normalized.bracket_accesses_dotted;
        stats.arithmetic_folded += normalized.numeric_constants_folded;

        let (next, split_stats): (String, string_split::StringSplitStats) =
            string_split::fold_string_concat(&out);
        out = next;
        stats.string_split_literals_merged += split_stats.literals_merged;

        let (next, n): (String, usize) = arithmetic::fold_binary(&out);
        out = next;
        stats.arithmetic_folded += n;

        let (next, n): (String, usize) = arithmetic::decimalize_radix_literals(&out);
        out = next;
        stats.radix_literals_decimalized += n;

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

        let (next, sd_stats): (String, self_defending::SelfDefendingStats) =
            self_defending::strip_self_defending(&out);
        out = next;
        stats.self_defending_checkers_removed += sd_stats.checker_blocks;
        stats.self_defending_wrappers_removed += sd_stats.once_wrappers;
        stats.debug_protection_ratchets_removed += sd_stats.debug_ratchets;
        stats.debug_ratchet_functions_removed += sd_stats.ratchet_functions;
        stats.discarded_constructor_calls_removed += sd_stats.discarded_constructor_calls;

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
