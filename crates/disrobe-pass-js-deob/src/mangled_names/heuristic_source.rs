use std::collections::BTreeMap;

use super::{Confidence, Context, NameSource, ScopeKey, Suggestion, SymbolRole};

#[derive(Debug, Clone)]
pub struct HeuristicNameSource {
    function_pool: Vec<&'static str>,
    variable_pool: Vec<&'static str>,
    parameter_pool: Vec<&'static str>,
    class_pool: Vec<&'static str>,
    member_keywords: BTreeMap<&'static str, (&'static str, Confidence)>,
}

impl Default for HeuristicNameSource {
    fn default() -> Self {
        let function_pool: Vec<&'static str> = vec![
            "init",
            "render",
            "handle",
            "process",
            "format",
            "parse",
            "compute",
            "create",
            "build",
            "load",
            "save",
            "update",
            "execute",
            "dispatch",
            "compile",
            "encode",
            "decode",
            "serialize",
            "deserialize",
            "validate",
        ];
        let variable_pool: Vec<&'static str> = vec![
            "result", "value", "data", "state", "node", "item", "entry", "record", "context",
            "options", "config", "buffer", "offset", "length", "index", "count", "total",
        ];
        let parameter_pool: Vec<&'static str> = vec![
            "value", "input", "options", "config", "context", "node", "ev", "event", "props",
            "state",
        ];
        let class_pool: Vec<&'static str> = vec![
            "Controller",
            "Model",
            "View",
            "Service",
            "Manager",
            "Handler",
            "Builder",
            "Parser",
            "Provider",
        ];
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
        Self {
            function_pool,
            variable_pool,
            parameter_pool,
            class_pool,
            member_keywords,
        }
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

    fn pool_for(&self, role: SymbolRole) -> &[&'static str] {
        match role {
            SymbolRole::Function | SymbolRole::Method => &self.function_pool,
            SymbolRole::Class => &self.class_pool,
            SymbolRole::Variable | SymbolRole::Property => &self.variable_pool,
            SymbolRole::Parameter => &self.parameter_pool,
        }
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
        let pool: &[&'static str] = self.pool_for(context.role);
        let bucket: usize = hash_str(&context.original) % pool.len().max(1);
        let candidate: &str = pool.get(bucket).copied()?;
        Some(Suggestion {
            name: candidate.to_owned(),
            confidence: Confidence::LOW,
            source_label: self.label(),
        })
    }

    fn label(&self) -> &'static str {
        "heuristic"
    }
}

fn hash_str(s: &str) -> usize {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.as_bytes() {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x100_0000_01b3);
    }
    usize::try_from(h & 0x0fff_ffff).unwrap_or(0)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::mangled_names::ScopeKey;

    #[test]
    fn suggests_function_name_from_pool() {
        let src: HeuristicNameSource = HeuristicNameSource::new();
        let ctx: Context = Context::new("a", SymbolRole::Function, ScopeKey(0));
        let s: Suggestion = src.suggest(ScopeKey(0), &ctx).expect("got suggestion");
        assert!(!s.name.is_empty());
        assert_eq!(s.source_label, "heuristic");
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
