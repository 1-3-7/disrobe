use std::collections::{BTreeMap, BTreeSet};

use super::{Confidence, Context, NameSource, ScopeKey, Suggestion};

#[derive(Debug, Clone)]
pub struct HeuristicNameSource {
    member_keywords: BTreeMap<&'static str, (&'static str, Confidence)>,
}

impl Default for HeuristicNameSource {
    fn default() -> Self {
        let mut member_keywords: BTreeMap<&'static str, (&'static str, Confidence)> =
            BTreeMap::new();
        member_keywords.insert("push", ("list", Confidence::MEDIUM));
        member_keywords.insert("slice", ("source", Confidence::LOW));
        member_keywords.insert("then", ("promise", Confidence::HIGH));
        member_keywords.insert("catch", ("promise", Confidence::HIGH));
        member_keywords.insert("finally", ("promise", Confidence::HIGH));
        member_keywords.insert("addEventListener", ("target", Confidence::HIGH));
        member_keywords.insert("removeEventListener", ("target", Confidence::HIGH));
        member_keywords.insert("dispatchEvent", ("target", Confidence::HIGH));
        member_keywords.insert("querySelector", ("root", Confidence::HIGH));
        member_keywords.insert("querySelectorAll", ("root", Confidence::HIGH));
        member_keywords.insert("appendChild", ("parent", Confidence::HIGH));
        member_keywords.insert("removeChild", ("parent", Confidence::HIGH));
        member_keywords.insert("createElement", ("doc", Confidence::HIGH));
        member_keywords.insert("getElementById", ("doc", Confidence::HIGH));
        member_keywords.insert("setState", ("component", Confidence::HIGH));
        member_keywords.insert("forceUpdate", ("component", Confidence::HIGH));
        member_keywords.insert("getReader", ("stream", Confidence::HIGH));
        member_keywords.insert("getWriter", ("stream", Confidence::HIGH));
        member_keywords.insert("getContext", ("canvas", Confidence::HIGH));
        member_keywords.insert("getBoundingClientRect", ("element", Confidence::HIGH));
        member_keywords.insert("toISOString", ("date", Confidence::HIGH));
        member_keywords.insert("getTime", ("date", Confidence::HIGH));
        member_keywords.insert("pop", ("stack", Confidence::MEDIUM));
        member_keywords.insert("shift", ("queue", Confidence::MEDIUM));
        member_keywords.insert("dispatch", ("store", Confidence::MEDIUM));
        member_keywords.insert("subscribe", ("store", Confidence::MEDIUM));
        member_keywords.insert("pipe", ("stream", Confidence::MEDIUM));
        member_keywords.insert("render", ("component", Confidence::MEDIUM));
        member_keywords.insert("write", ("writer", Confidence::MEDIUM));
        member_keywords.insert("read", ("reader", Confidence::MEDIUM));
        member_keywords.insert("length", ("list", Confidence::LOW));
        Self { member_keywords }
    }
}

impl HeuristicNameSource {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn lookup_member_hint(&self, context: &Context) -> Option<(&'static str, Confidence)> {
        if context.called_as_predicate {
            return Some(("predicate", Confidence::MEDIUM));
        }
        if context.member_accesses.contains("push")
            && context.member_accesses.contains("join")
            && context
                .member_call_literals
                .get("join")
                .is_some_and(|literals: &BTreeSet<String>| literals.contains("&"))
        {
            return Some(("query", Confidence::MEDIUM));
        }
        if context.indexed_elements_called
            && context.member_accesses.contains("push")
            && context.member_accesses.contains("indexOf")
            && context.member_accesses.contains("splice")
        {
            return Some(("listeners", Confidence::MEDIUM));
        }
        let mut tally: BTreeMap<&'static str, (Confidence, usize)> = BTreeMap::new();
        for member in &context.member_accesses {
            if let Some(&(name, conf)) = self.member_keywords.get(member.as_str()) {
                let slot: &mut (Confidence, usize) = tally.entry(name).or_insert((conf, 0));
                slot.0 = slot.0.max(conf);
                slot.1 += 1;
            }
        }
        let (name, (conf, hits)): (&&'static str, &(Confidence, usize)) = tally.iter().max_by_key(
            |(_, (conf, hits)): &(&&'static str, &(Confidence, usize))| (conf.0, *hits),
        )?;
        let effective: Confidence = if *hits >= 2 && *conf < Confidence::HIGH {
            Confidence(
                conf.0
                    .saturating_add(AGREEMENT_BONUS)
                    .min(Confidence::HIGH.0.saturating_sub(1)),
            )
        } else {
            *conf
        };
        Some((name, effective))
    }
}

const AGREEMENT_BONUS: u8 = 15;

impl NameSource for HeuristicNameSource {
    fn suggest(&self, _scope: ScopeKey, context: &Context) -> Option<Suggestion> {
        if let Some((hint, confidence)) = self.lookup_member_hint(context) {
            return Some(Suggestion {
                name: hint.to_owned(),
                confidence,
                source_label: self.label(),
            });
        }
        None
    }

    fn label(&self) -> &'static str {
        "heuristic"
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::mangled_names::{ScopeKey, SymbolRole};

    #[test]
    fn a_binding_with_no_matching_evidence_gets_no_suggestion() {
        let src: HeuristicNameSource = HeuristicNameSource::new();
        let ctx: Context = Context::new("a", SymbolRole::Function, ScopeKey(0));
        assert!(
            src.suggest(ScopeKey(0), &ctx).is_none(),
            "nothing about this binding is known, so naming it would be invention"
        );
    }

    #[test]
    fn a_verb_any_object_can_define_does_not_claim_the_top_band() {
        let src: HeuristicNameSource = HeuristicNameSource::new();
        let mut ctx: Context = Context::new("a", SymbolRole::Variable, ScopeKey(0));
        ctx.member_accesses.insert("push".to_owned());
        let s: Suggestion = src.suggest(ScopeKey(0), &ctx).expect("push resolves");
        assert!(
            s.confidence < Confidence::HIGH,
            "any object can define `push`, so it infers a type at best and must not outrank \
             evidence that read the program; got {:?}",
            s.confidence
        );
    }

    #[test]
    fn two_agreeing_generic_verbs_still_do_not_reach_the_top_band() {
        let src: HeuristicNameSource = HeuristicNameSource::new();
        let mut ctx: Context = Context::new("a", SymbolRole::Variable, ScopeKey(0));
        ctx.member_accesses.insert("push".to_owned());
        ctx.member_accesses.insert("length".to_owned());
        let s: Suggestion = src.suggest(ScopeKey(0), &ctx).expect("both resolve");
        assert!(
            s.confidence < Confidence::HIGH,
            "`push` and `length` are the same signal said twice, not two independent \
             observations, so their agreement must not manufacture top-band confidence; got {:?}",
            s.confidence
        );
    }

    #[test]
    fn agreement_still_counts_for_something() {
        let src: HeuristicNameSource = HeuristicNameSource::new();
        let mut one: Context = Context::new("a", SymbolRole::Variable, ScopeKey(0));
        one.member_accesses.insert("push".to_owned());
        let mut two: Context = Context::new("a", SymbolRole::Variable, ScopeKey(0));
        two.member_accesses.insert("push".to_owned());
        two.member_accesses.insert("length".to_owned());
        let single: Suggestion = src.suggest(ScopeKey(0), &one).expect("one resolves");
        let agreeing: Suggestion = src.suggest(ScopeKey(0), &two).expect("two resolve");
        assert!(
            agreeing.confidence > single.confidence,
            "corroboration should raise confidence even when it cannot reach the top band"
        );
    }

    #[test]
    fn a_narrow_api_receiver_keeps_the_top_band() {
        let src: HeuristicNameSource = HeuristicNameSource::new();
        let mut ctx: Context = Context::new("a", SymbolRole::Variable, ScopeKey(0));
        ctx.member_accesses.insert("querySelector".to_owned());
        let s: Suggestion = src.suggest(ScopeKey(0), &ctx).expect("resolves");
        assert_eq!(
            s.confidence,
            Confidence::HIGH,
            "`querySelector` names a specific API, so the receiver really is a DOM root"
        );
    }

    #[test]
    fn suggests_promise_for_then_caller() {
        let src: HeuristicNameSource = HeuristicNameSource::new();
        let mut ctx: Context = Context::new("a", SymbolRole::Variable, ScopeKey(0));
        ctx.member_accesses.insert("then".to_owned());
        let s: Suggestion = src.suggest(ScopeKey(0), &ctx).expect("got suggestion");
        assert_eq!(s.name, "promise");
        assert_eq!(s.confidence, Confidence::HIGH);
    }

    #[test]
    fn a_slice_receiver_is_a_low_confidence_source() {
        let src: HeuristicNameSource = HeuristicNameSource::new();
        let mut ctx: Context = Context::new("a", SymbolRole::Parameter, ScopeKey(0));
        ctx.member_accesses.insert("length".to_owned());
        ctx.member_accesses.insert("slice".to_owned());
        let s: Suggestion = src.suggest(ScopeKey(0), &ctx).expect("slice resolves");
        assert_eq!(s.name, "source");
        assert_eq!(s.confidence, Confidence::LOW);
    }

    #[test]
    fn a_direct_condition_call_is_a_medium_confidence_predicate() {
        let src: HeuristicNameSource = HeuristicNameSource::new();
        let mut ctx: Context = Context::new("a", SymbolRole::Parameter, ScopeKey(0));
        ctx.called_as_predicate = true;
        let s: Suggestion = src.suggest(ScopeKey(0), &ctx).expect("predicate resolves");
        assert_eq!(s.name, "predicate");
        assert_eq!(s.confidence, Confidence::MEDIUM);
    }

    #[test]
    fn ampersand_joined_pushes_are_medium_confidence_query_components() {
        let src: HeuristicNameSource = HeuristicNameSource::new();
        let mut ctx: Context = Context::new("a", SymbolRole::Variable, ScopeKey(0));
        ctx.member_accesses.insert("join".to_owned());
        ctx.member_accesses.insert("push".to_owned());
        ctx.member_call_literals
            .entry("join".to_owned())
            .or_default()
            .insert("&".to_owned());
        let s: Suggestion = src.suggest(ScopeKey(0), &ctx).expect("query resolves");
        assert_eq!(s.name, "query");
        assert_eq!(s.confidence, Confidence::MEDIUM);
    }

    #[test]
    fn other_or_unknown_join_delimiters_remain_lists() {
        let src: HeuristicNameSource = HeuristicNameSource::new();
        for delimiter in [Some(","), None] {
            let mut ctx: Context = Context::new("a", SymbolRole::Variable, ScopeKey(0));
            ctx.member_accesses.insert("join".to_owned());
            ctx.member_accesses.insert("push".to_owned());
            if let Some(delimiter) = delimiter {
                ctx.member_call_literals
                    .entry("join".to_owned())
                    .or_default()
                    .insert(delimiter.to_owned());
            }
            let s: Suggestion = src.suggest(ScopeKey(0), &ctx).expect("list resolves");
            assert_eq!(s.name, "list");
        }
    }

    #[test]
    fn callable_identity_removed_elements_are_medium_confidence_listeners() {
        let src: HeuristicNameSource = HeuristicNameSource::new();
        let mut ctx: Context = Context::new("a", SymbolRole::Variable, ScopeKey(0));
        ctx.indexed_elements_called = true;
        ctx.member_accesses
            .extend(["push", "indexOf", "splice"].into_iter().map(str::to_owned));
        let s: Suggestion = src.suggest(ScopeKey(0), &ctx).expect("listeners resolve");
        assert_eq!(s.name, "listeners");
        assert_eq!(s.confidence, Confidence::MEDIUM);
    }

    #[test]
    fn incomplete_callable_collection_evidence_remains_a_list() {
        let src: HeuristicNameSource = HeuristicNameSource::new();
        for (called, members) in [
            (false, &["push", "indexOf", "splice"][..]),
            (true, &["push", "splice"][..]),
            (true, &["push", "indexOf"][..]),
        ] {
            let mut ctx: Context = Context::new("a", SymbolRole::Variable, ScopeKey(0));
            ctx.indexed_elements_called = called;
            ctx.member_accesses
                .extend(members.iter().copied().map(str::to_owned));
            let s: Suggestion = src.suggest(ScopeKey(0), &ctx).expect("list resolves");
            assert_eq!(s.name, "list");
        }
    }
}
