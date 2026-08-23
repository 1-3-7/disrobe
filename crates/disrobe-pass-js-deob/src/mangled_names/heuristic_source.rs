use std::collections::BTreeMap;

use super::{Confidence, Context, NameSource, ScopeKey, Suggestion};

#[derive(Debug, Clone)]
pub struct HeuristicNameSource {
    member_keywords: BTreeMap<&'static str, (&'static str, Confidence)>,
}

impl Default for HeuristicNameSource {
    fn default() -> Self {
        let mut member_keywords: BTreeMap<&'static str, (&'static str, Confidence)> =
            BTreeMap::new();
        member_keywords.insert("push", ("list", Confidence::HIGH));
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
            Confidence::HIGH
        } else {
            *conf
        };
        Some((name, effective))
    }
}

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
    fn suggests_promise_for_then_caller() {
        let src: HeuristicNameSource = HeuristicNameSource::new();
        let mut ctx: Context = Context::new("a", SymbolRole::Variable, ScopeKey(0));
        ctx.member_accesses.insert("then".to_owned());
        let s: Suggestion = src.suggest(ScopeKey(0), &ctx).expect("got suggestion");
        assert_eq!(s.name, "promise");
        assert_eq!(s.confidence, Confidence::HIGH);
    }
}
