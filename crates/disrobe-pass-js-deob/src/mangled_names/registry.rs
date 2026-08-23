use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::sync::Arc;

use super::{Context, NameDecision, NameSource, RestoreStats, ScopeKey, Suggestion};

#[derive(Debug, Clone)]
pub struct NameRegistry {
    sources: Vec<Arc<dyn NameSource>>,
    reserved: BTreeSet<String>,
}

impl Default for NameRegistry {
    fn default() -> Self {
        Self {
            sources: Vec::new(),
            reserved: js_reserved_words(),
        }
    }
}

impl NameRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_source(mut self, source: Arc<dyn NameSource>) -> Self {
        self.sources.push(source);
        self
    }

    pub fn reserve(&mut self, name: impl Into<String>) {
        self.reserved.insert(name.into());
    }

    #[must_use]
    pub fn best_suggestion(&self, scope: ScopeKey, context: &Context) -> Option<Suggestion> {
        let mut best: Option<Suggestion> = None;
        for src in &self.sources {
            if let Some(s) = src.suggest(scope, context)
                && best
                    .as_ref()
                    .is_none_or(|prev: &Suggestion| s.confidence > prev.confidence)
            {
                best = Some(s);
            }
        }
        best
    }

    pub fn restore(
        &mut self,
        contexts: &BTreeMap<String, Context>,
    ) -> (BTreeMap<String, NameDecision>, RestoreStats) {
        let mut plan: BTreeMap<String, NameDecision> = BTreeMap::new();
        let mut stats: RestoreStats = RestoreStats::default();
        let mut by_source: BTreeMap<String, usize> = BTreeMap::new();
        for (original, ctx) in contexts {
            let Some(suggestion): Option<Suggestion> = self.best_suggestion(ctx.scope, ctx) else {
                stats.fallback_to_original += 1;
                continue;
            };
            let resolved: String = self.resolve_collision(&suggestion.name);
            if resolved != suggestion.name {
                stats.conflicts_resolved += 1;
            }
            self.reserved.insert(resolved.clone());
            *by_source
                .entry(suggestion.source_label.to_owned())
                .or_insert(0) += 1;
            plan.insert(
                original.clone(),
                NameDecision {
                    restored: resolved,
                    confidence: suggestion.confidence,
                    tier: suggestion.confidence.tier(),
                    source_label: suggestion.source_label,
                },
            );
            stats.suggestions_made += 1;
        }
        stats.by_source = by_source;
        (plan, stats)
    }

    fn resolve_collision(&self, base: &str) -> String {
        if !self.reserved.contains(base) {
            return base.to_owned();
        }
        let mut counter: u32 = 2;
        loop {
            let candidate: String = format!("{base}_{counter}");
            if !self.reserved.contains(&candidate) {
                return candidate;
            }
            counter = counter.saturating_add(1);
            if counter == u32::MAX {
                return format!("{base}_x");
            }
        }
    }
}

fn js_reserved_words() -> BTreeSet<String> {
    let words: &[&str] = &[
        "arguments",
        "async",
        "await",
        "break",
        "case",
        "catch",
        "class",
        "const",
        "continue",
        "debugger",
        "default",
        "delete",
        "do",
        "else",
        "enum",
        "eval",
        "export",
        "extends",
        "false",
        "finally",
        "for",
        "from",
        "function",
        "if",
        "implements",
        "import",
        "in",
        "instanceof",
        "interface",
        "let",
        "new",
        "null",
        "of",
        "package",
        "private",
        "protected",
        "public",
        "return",
        "static",
        "super",
        "switch",
        "this",
        "throw",
        "true",
        "try",
        "typeof",
        "undefined",
        "var",
        "void",
        "while",
        "with",
        "yield",
    ];
    words.iter().map(|w| (*w).to_owned()).collect()
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::mangled_names::{
        ContextNameSource, CorpusNameSource, HeuristicNameSource, SymbolRole,
    };

    #[test]
    fn registry_combines_sources_and_picks_highest_confidence() {
        let reg: NameRegistry = NameRegistry::new()
            .with_source(Arc::new(HeuristicNameSource::new()))
            .with_source(Arc::new(CorpusNameSource::well_known_minified()))
            .with_source(Arc::new(ContextNameSource::new()));
        let mut ctx: Context = Context::new("e", SymbolRole::Function, ScopeKey(0));
        ctx.nearby_strings.insert("on-click".to_owned());
        let s: Suggestion = reg.best_suggestion(ScopeKey(0), &ctx).expect("got one");
        assert_eq!(s.name, "onClick");
    }

    #[test]
    fn registry_resolves_collisions() {
        let mut reg: NameRegistry =
            NameRegistry::new().with_source(Arc::new(CorpusNameSource::well_known_minified()));
        let mut contexts: BTreeMap<String, Context> = BTreeMap::new();
        contexts.insert(
            "e".into(),
            Context::new("e", SymbolRole::Parameter, ScopeKey(0)),
        );
        contexts.insert(
            "e2".into(),
            Context::new("e", SymbolRole::Parameter, ScopeKey(0)),
        );
        let (plan, stats): (BTreeMap<String, NameDecision>, RestoreStats) = reg.restore(&contexts);
        assert_eq!(
            plan.get("e").map(|d: &NameDecision| d.restored.as_str()),
            Some("event")
        );
        assert_eq!(
            plan.get("e2").map(|d: &NameDecision| d.restored.as_str()),
            Some("event_2")
        );
        assert_eq!(stats.suggestions_made, 2);
        assert_eq!(stats.conflicts_resolved, 1);
    }
}
