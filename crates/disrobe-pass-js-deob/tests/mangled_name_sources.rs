#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::sync::Arc;

use disrobe_pass_js_deob::{
    ContextNameSource, CorpusNameSource, HeuristicNameSource, MangledNameContext,
    MangledNameRegistry, MangledRestoreStats, MangledScopeKey, MangledSuggestion,
    MangledSymbolRole, NameSource,
};

#[test]
fn corpus_source_resolves_well_known_minified_idents() {
    let src: CorpusNameSource = CorpusNameSource::well_known_minified();
    let ctx: MangledNameContext =
        MangledNameContext::new("e", MangledSymbolRole::Parameter, MangledScopeKey(0));
    let s: MangledSuggestion = src.suggest(MangledScopeKey(0), &ctx).expect("got");
    assert_eq!(s.name, "event");
}

#[test]
fn heuristic_source_falls_back_to_role_pool() {
    let src: HeuristicNameSource = HeuristicNameSource::new();
    let ctx: MangledNameContext =
        MangledNameContext::new("zz", MangledSymbolRole::Function, MangledScopeKey(0));
    let s: MangledSuggestion = src.suggest(MangledScopeKey(0), &ctx).expect("got");
    assert!(!s.name.is_empty());
}

#[test]
fn context_source_picks_up_nearby_string() {
    let src: ContextNameSource = ContextNameSource::new();
    let mut ctx: MangledNameContext =
        MangledNameContext::new("a", MangledSymbolRole::Function, MangledScopeKey(0));
    ctx.nearby_strings.insert("on-click".to_owned());
    let s: MangledSuggestion = src.suggest(MangledScopeKey(0), &ctx).expect("got");
    assert_eq!(s.name, "onClick");
}

#[test]
fn registry_layers_sources_and_picks_highest_confidence() {
    let reg: MangledNameRegistry = MangledNameRegistry::new()
        .with_source(Arc::new(HeuristicNameSource::new()))
        .with_source(Arc::new(CorpusNameSource::well_known_minified()))
        .with_source(Arc::new(ContextNameSource::new()));
    let mut ctx: MangledNameContext =
        MangledNameContext::new("e", MangledSymbolRole::Function, MangledScopeKey(0));
    ctx.nearby_strings.insert("handle-event".to_owned());
    let s: MangledSuggestion = reg.best_suggestion(MangledScopeKey(0), &ctx).expect("got");
    assert_eq!(s.name, "handleEvent", "context > corpus > heuristic");
}

#[test]
fn registry_restore_emits_collision_safe_plan() {
    let mut reg: MangledNameRegistry =
        MangledNameRegistry::new().with_source(Arc::new(CorpusNameSource::well_known_minified()));
    let mut contexts: BTreeMap<String, MangledNameContext> = BTreeMap::new();
    contexts.insert(
        "e".into(),
        MangledNameContext::new("e", MangledSymbolRole::Parameter, MangledScopeKey(0)),
    );
    contexts.insert(
        "e_other".into(),
        MangledNameContext::new("e", MangledSymbolRole::Parameter, MangledScopeKey(0)),
    );
    let (plan, stats): (BTreeMap<String, String>, MangledRestoreStats) = reg.restore(&contexts);
    assert_eq!(plan.get("e").map(String::as_str), Some("event"));
    assert_eq!(plan.get("e_other").map(String::as_str), Some("event_2"));
    assert_eq!(stats.conflicts_resolved, 1);
}
