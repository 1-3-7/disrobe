use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::hash_map::DefaultHasher;

use serde::Serialize;

use crate::error::Result;
use crate::jsconfuser::{
    DispatcherReversalResult, FlattenReversalResult, OpaqueReversalResult, PackingReversalResult,
    reverse_dispatcher, reverse_flatten, reverse_opaque_predicates, reverse_packing,
};
use crate::jsobfu::{JsObfuRewriteStats, rewrite_bracket_access};
use crate::rename::{RenameStats, rename_hex_idents};
use crate::string_array::{StringArrayRecovery, recover as recover_string_array};
use crate::unminify::{UnminifyStats, unminify};

use super::control_flow_object::{ControlFlowObjectResult, merge_control_flow_objects};
use super::control_flow_switch::{ControlFlowSwitchResult, unflatten_control_flow_switch};
use super::controls::ObfControl;
use super::normalize_strings::{NormalizeStringsResult, normalize_escaped_strings};
use super::presets::Preset;
use super::scope_proxy::{ScopeProxyResult, merge_scope_proxies};

#[derive(Debug, Clone, Default)]
pub struct Options {
    pub controls: BTreeSet<ObfControl>,
    pub max_passes: u32,
}

impl Options {
    #[must_use]
    pub fn all() -> Self {
        Self {
            controls: ObfControl::ALL
                .iter()
                .copied()
                .collect::<BTreeSet<ObfControl>>(),
            max_passes: DEFAULT_PASSES,
        }
    }

    #[must_use]
    pub fn for_preset(preset: Preset) -> Self {
        Self {
            controls: preset.controls(),
            max_passes: DEFAULT_PASSES,
        }
    }
}

pub const DEFAULT_PASSES: u32 = 4;

pub const MAX_PASS_CEILING: u32 = 32;

#[derive(Debug, Clone, Default, Serialize)]
pub struct Output {
    pub source: String,
    pub passes_run: u32,
    pub hit_pass_ceiling: bool,
    pub controls_applied: BTreeSet<ObfControl>,
    pub per_control_stats: BTreeMap<&'static str, u64>,
    pub idents_renamed: usize,
    pub string_array_call_sites_inlined: usize,
    pub string_array_rotation_count: u32,
    pub bracket_accesses_rewritten: usize,
    pub dispatcher_call_sites_inlined: usize,
    pub flatten_dispatches_collapsed: usize,
    pub control_flow_objects_merged: usize,
    pub scope_proxy_objects_merged: usize,
    pub control_flow_switches_unflattened: usize,
    pub string_literals_normalized: usize,
    pub opaque_predicates_folded: usize,
    pub packed_blocks_expanded: usize,
    pub unminify_stats: UnminifyStats,
}

const fn effective_passes(requested: u32) -> u32 {
    let floored: u32 = if requested < 1 { 1 } else { requested };
    if floored > MAX_PASS_CEILING {
        MAX_PASS_CEILING
    } else {
        floored
    }
}

pub fn deobfuscate(source: &str, opts: &Options) -> Result<Output> {
    let requested: u32 = opts.max_passes.max(1);
    let passes: u32 = effective_passes(requested);
    let mut current: String = source.to_owned();
    let mut out: Output = Output::default();
    let mut last_len: usize = current.len();
    let mut seen: BTreeSet<u64> = BTreeSet::new();
    seen.insert(fingerprint(&current));
    let mut converged: bool = false;

    for pass in 0..passes {
        out.passes_run = pass + 1;
        current = run_statements(current, opts, &mut out)?;
        current = run_strings(current, opts, &mut out);
        current = run_control_flow(current, opts, &mut out);
        current = run_statements(current, opts, &mut out)?;
        current = run_predicates(current, opts, &mut out);
        current = run_objects(current, opts, &mut out);
        current = run_unminify_block(current, opts, &mut out);
        current = run_identifiers(current, opts, &mut out);

        if current.len() == last_len {
            converged = true;
            break;
        }
        last_len = current.len();
        if !seen.insert(fingerprint(&current)) {
            crate::debug::dbg_line(|| {
                format!(
                    "obfuscator.io rewrite oscillation at pass {}; bailing out with best-effort progress",
                    pass + 1
                )
            });
            converged = true;
            break;
        }
    }

    if !converged && requested > passes {
        out.hit_pass_ceiling = true;
        crate::debug::dbg_line(|| {
            format!(
                "obfuscator.io pass ceiling {MAX_PASS_CEILING} reached (requested {requested}); returning best-effort progress"
            )
        });
    }

    out.source = current;
    Ok(out)
}

fn fingerprint(source: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher: DefaultHasher = DefaultHasher::new();
    source.hash(&mut hasher);
    hasher.finish()
}

fn run_statements(mut current: String, opts: &Options, out: &mut Output) -> Result<String> {
    if !opts.controls.contains(&ObfControl::Statements) {
        return Ok(current);
    }
    let maybe_rec: Option<StringArrayRecovery> = recover_string_array(&current)?;
    let Some(rec): Option<StringArrayRecovery> = maybe_rec else {
        return Ok(current);
    };
    out.string_array_call_sites_inlined += rec.call_sites_inlined;
    out.string_array_rotation_count = out
        .string_array_rotation_count
        .saturating_add(rec.rotation_count);
    out.controls_applied.insert(ObfControl::Statements);
    bump(
        &mut out.per_control_stats,
        "statements",
        usize_to_u64(rec.call_sites_inlined),
    );
    current = rec.rewritten_source;
    Ok(current)
}

fn run_strings(mut current: String, opts: &Options, out: &mut Output) -> String {
    if !opts.controls.contains(&ObfControl::Strings) {
        return current;
    }
    let packing: PackingReversalResult = reverse_packing(&current);
    if packing.blocks_expanded > 0 {
        out.packed_blocks_expanded += packing.blocks_expanded;
        out.controls_applied.insert(ObfControl::Strings);
        bump(
            &mut out.per_control_stats,
            "strings",
            usize_to_u64(packing.blocks_expanded),
        );
        current = packing.rewritten_source;
    }
    let normalized: NormalizeStringsResult = normalize_escaped_strings(&current);
    if normalized.literals_normalized > 0 {
        out.string_literals_normalized += normalized.literals_normalized;
        out.controls_applied.insert(ObfControl::Strings);
        bump(
            &mut out.per_control_stats,
            "strings",
            usize_to_u64(normalized.literals_normalized),
        );
        current = normalized.rewritten_source;
    }
    current
}

fn run_control_flow(mut current: String, opts: &Options, out: &mut Output) -> String {
    let wants_cfo: bool = opts.controls.contains(&ObfControl::Objects)
        || opts.controls.contains(&ObfControl::ControlFlowFlattening);
    if wants_cfo {
        let cfo: ControlFlowObjectResult = merge_control_flow_objects(&current);
        if cfo.objects_merged > 0 {
            out.control_flow_objects_merged += cfo.objects_merged;
            out.controls_applied.insert(ObfControl::Objects);
            bump(
                &mut out.per_control_stats,
                "objects",
                usize_to_u64(cfo.call_sites_inlined),
            );
            current = cfo.rewritten_source;
        }
        let scoped: ScopeProxyResult = merge_scope_proxies(&current);
        if scoped.objects_merged > 0 {
            out.control_flow_objects_merged += scoped.objects_merged;
            out.scope_proxy_objects_merged += scoped.objects_merged;
            out.controls_applied.insert(ObfControl::Objects);
            bump(
                &mut out.per_control_stats,
                "objects",
                usize_to_u64(scoped.call_sites_inlined),
            );
            current = scoped.rewritten_source;
        }
    }
    if !opts.controls.contains(&ObfControl::ControlFlowFlattening) {
        return current;
    }
    let switch: ControlFlowSwitchResult = unflatten_control_flow_switch(&current);
    if switch.switches_unflattened > 0 {
        out.control_flow_switches_unflattened += switch.switches_unflattened;
        out.controls_applied
            .insert(ObfControl::ControlFlowFlattening);
        bump(
            &mut out.per_control_stats,
            "controlFlowFlattening",
            usize_to_u64(switch.switches_unflattened),
        );
        current = switch.rewritten_source;
    }
    let flatten: FlattenReversalResult = reverse_flatten(&current);
    if flatten.dispatches_collapsed > 0 {
        out.flatten_dispatches_collapsed += flatten.dispatches_collapsed;
        out.controls_applied
            .insert(ObfControl::ControlFlowFlattening);
        bump(
            &mut out.per_control_stats,
            "controlFlowFlattening",
            usize_to_u64(flatten.dispatches_collapsed),
        );
        current = flatten.rewritten_source;
    }
    let dispatcher: DispatcherReversalResult = reverse_dispatcher(&current);
    if dispatcher.call_sites_inlined > 0 {
        out.dispatcher_call_sites_inlined += dispatcher.call_sites_inlined;
        out.controls_applied
            .insert(ObfControl::ControlFlowFlattening);
        bump(
            &mut out.per_control_stats,
            "controlFlowFlattening",
            usize_to_u64(dispatcher.call_sites_inlined),
        );
        current = dispatcher.rewritten_source;
    }
    current
}

fn run_predicates(mut current: String, opts: &Options, out: &mut Output) -> String {
    if !opts.controls.contains(&ObfControl::Predicates) {
        return current;
    }
    let opaque: OpaqueReversalResult = reverse_opaque_predicates(&current);
    if opaque.predicates_folded == 0 {
        return current;
    }
    out.opaque_predicates_folded += opaque.predicates_folded;
    out.controls_applied.insert(ObfControl::Predicates);
    bump(
        &mut out.per_control_stats,
        "predicates",
        usize_to_u64(opaque.predicates_folded),
    );
    current = opaque.rewritten_source;
    current
}

fn run_objects(mut current: String, opts: &Options, out: &mut Output) -> String {
    if !opts.controls.contains(&ObfControl::Objects) {
        return current;
    }
    let (next, stats): (String, JsObfuRewriteStats) = rewrite_bracket_access(&current);
    let total: usize = stats.bracket_to_dot_rewrites + stats.array_join_folded;
    if total == 0 {
        return current;
    }
    out.bracket_accesses_rewritten += total;
    out.controls_applied.insert(ObfControl::Objects);
    bump(&mut out.per_control_stats, "objects", usize_to_u64(total));
    current = next;
    current
}

fn run_unminify_block(mut current: String, opts: &Options, out: &mut Output) -> String {
    if !has_minification_like_work(&opts.controls) {
        return current;
    }
    let (next, stats): (String, UnminifyStats) = unminify(&current);
    let delta: u64 = unminify_delta(&stats).saturating_sub(unminify_delta(&out.unminify_stats));
    if delta == 0 {
        return current;
    }
    if opts.controls.contains(&ObfControl::Booleans) {
        out.controls_applied.insert(ObfControl::Booleans);
    }
    if opts.controls.contains(&ObfControl::Numbers) {
        out.controls_applied.insert(ObfControl::Numbers);
    }
    if opts.controls.contains(&ObfControl::Minification) {
        out.controls_applied.insert(ObfControl::Minification);
    }
    bump_unminify(&mut out.per_control_stats, &opts.controls, delta);
    current = next;
    out.unminify_stats = stats;
    current
}

fn run_identifiers(mut current: String, opts: &Options, out: &mut Output) -> String {
    if !opts.controls.contains(&ObfControl::Identifiers) {
        return current;
    }
    let (next, stats): (String, RenameStats) = rename_hex_idents(&current);
    if stats.idents_renamed == 0 {
        return current;
    }
    out.idents_renamed += stats.idents_renamed;
    out.controls_applied.insert(ObfControl::Identifiers);
    bump(
        &mut out.per_control_stats,
        "identifiers",
        usize_to_u64(stats.idents_renamed),
    );
    current = next;
    current
}

fn has_minification_like_work(controls: &BTreeSet<ObfControl>) -> bool {
    controls.contains(&ObfControl::Booleans)
        || controls.contains(&ObfControl::Numbers)
        || controls.contains(&ObfControl::Minification)
}

const fn unminify_delta(s: &UnminifyStats) -> u64 {
    let total: usize = s.bool_shorthand_reversed
        + s.void_undefined_reversed
        + s.double_not_reversed
        + s.member_access_dotted
        + s.merged_string_concat
        + s.string_split_literals_merged
        + s.arithmetic_folded
        + s.radix_literals_decimalized
        + s.function_call_reversed
        + s.globals_call_sites
        + s.if_true_inlined
        + s.if_false_eliminated
        + s.debugger_loops_removed
        + s.set_interval_watchdogs_removed
        + s.function_debugger_removed
        + s.self_defending_iifes_removed
        + s.self_defending_checkers_removed
        + s.self_defending_wrappers_removed
        + s.debug_protection_ratchets_removed
        + s.control_flow_blocks_unflattened;
    total as u64
}

fn usize_to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn bump(map: &mut BTreeMap<&'static str, u64>, key: &'static str, delta: u64) {
    let entry: &mut u64 = map.entry(key).or_insert(0);
    *entry = entry.saturating_add(delta);
}

fn bump_unminify(
    map: &mut BTreeMap<&'static str, u64>,
    controls: &BTreeSet<ObfControl>,
    delta: u64,
) {
    if controls.contains(&ObfControl::Booleans) {
        bump(map, "booleans", delta);
    }
    if controls.contains(&ObfControl::Numbers) {
        bump(map, "numbers", delta);
    }
    if controls.contains(&ObfControl::Minification) {
        bump(map, "minification", delta);
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn options_for_preset_low_is_subset_of_high() {
        let low: Options = Options::for_preset(Preset::Low);
        let high: Options = Options::for_preset(Preset::High);
        assert!(low.controls.is_subset(&high.controls));
    }

    #[test]
    fn effective_passes_is_clamped_to_ceiling() {
        assert_eq!(effective_passes(0), 1);
        assert_eq!(effective_passes(1), 1);
        assert_eq!(effective_passes(4), 4);
        assert_eq!(effective_passes(MAX_PASS_CEILING), MAX_PASS_CEILING);
        assert_eq!(effective_passes(MAX_PASS_CEILING + 1), MAX_PASS_CEILING);
        assert_eq!(effective_passes(u32::MAX), MAX_PASS_CEILING);
    }

    #[test]
    fn fingerprint_is_deterministic_and_discriminating() {
        assert_eq!(fingerprint("var a = 1;"), fingerprint("var a = 1;"));
        assert_ne!(fingerprint("var a = 1;"), fingerprint("var a = 2;"));
    }

    #[test]
    fn hostile_max_passes_is_bounded_and_terminates() {
        let src: &str = "var _0xa = ['x'];\nconsole.log(_0xa[0]);";
        let opts: Options = Options {
            controls: ObfControl::ALL
                .iter()
                .copied()
                .collect::<BTreeSet<ObfControl>>(),
            max_passes: u32::MAX,
        };
        let out: Output =
            deobfuscate(src, &opts).expect("hostile max_passes must not hang or error");
        assert!(
            out.passes_run <= MAX_PASS_CEILING,
            "pipeline must be bounded by the pass ceiling; ran {} passes",
            out.passes_run
        );
    }

    #[test]
    fn deobfuscate_passes_through_clean_source() {
        let src: &str = "function add(a, b) { return a + b; }";
        let opts: Options = Options::all();
        let out: Output = deobfuscate(src, &opts).expect("clean source must succeed");
        assert!(out.source.contains("add"));
        assert!(out.passes_run >= 1);
    }

    #[test]
    fn deobfuscate_reduces_minimal_obfuscator_io_sample() {
        let src: &str = r"
var _0xa = ['hello', 'world'];
(function(_0xb, _0xc){
  var _0xd = function(_0xe){
    while(--_0xe){
      _0xb.push(_0xb.shift());
    }
  };
  _0xd(_0xc);
}(_0xa, 0x1));
var _0xf = function(_0x1) { return _0xa[_0x1]; };
console.log(_0xf(0) + ' ' + _0xf(1));
";
        let opts: Options = Options::for_preset(Preset::Low);
        let out: Output = deobfuscate(src, &opts).expect("ok");
        assert!(
            out.source.len() < src.len() || out.controls_applied.contains(&ObfControl::Statements),
            "expected reduction or statements applied; got\n{}",
            out.source
        );
    }
}
