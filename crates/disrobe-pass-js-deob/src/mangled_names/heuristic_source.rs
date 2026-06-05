use std::collections::BTreeMap;

use super::{Confidence, Context, NameSource, ScopeKey, Suggestion, SymbolRole};

#[derive(Debug, Clone)]
pub struct HeuristicNameSource {
    function_pool: Vec<&'static str>,
    variable_pool: Vec<&'static str>,
    parameter_pool: Vec<&'static str>,
    class_pool: Vec<&'static str>,
    member_keywords: BTreeMap<&'static str, &'static str>,
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
        let mut member_keywords: BTreeMap<&'static str, &'static str> = BTreeMap::new();
        member_keywords.insert("length", "buffer");
        member_keywords.insert("push", "list");
        member_keywords.insert("pop", "stack");
        member_keywords.insert("shift", "queue");
        member_keywords.insert("then", "promise");
        member_keywords.insert("catch", "promise");
        member_keywords.insert("addEventListener", "target");
        member_keywords.insert("querySelector", "root");
        member_keywords.insert("createElement", "doc");
        member_keywords.insert("getElementById", "doc");
        member_keywords.insert("setState", "component");
        member_keywords.insert("render", "component");
        member_keywords.insert("dispatch", "store");
        member_keywords.insert("subscribe", "store");
        member_keywords.insert("getReader", "stream");
        member_keywords.insert("pipe", "stream");
        member_keywords.insert("write", "writer");
        member_keywords.insert("read", "reader");
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

    fn lookup_member_hint(&self, context: &Context) -> Option<&'static str> {
        for member in &context.member_accesses {
            if let Some(hint) = self.member_keywords.get(member.as_str()) {
                return Some(hint);
            }
        }
        None
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
        if let Some(hint) = self.lookup_member_hint(context) {
            return Some(Suggestion {
                name: hint.to_owned(),
                confidence: Confidence::MEDIUM,
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
        assert_eq!(s.confidence, Confidence::MEDIUM);
    }
}
