use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::{Confidence, Context, NameSource, ScopeKey, Suggestion};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CorpusEntry {
    pub original: String,
    pub restored: String,
    pub min_confidence: u8,
}

#[derive(Debug, Clone, Default)]
pub struct CorpusNameSource {
    entries: BTreeMap<String, CorpusEntry>,
}

impl CorpusNameSource {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_entries(entries: impl IntoIterator<Item = CorpusEntry>) -> Self {
        let mut map: BTreeMap<String, CorpusEntry> = BTreeMap::new();
        for e in entries {
            map.insert(e.original.clone(), e);
        }
        Self { entries: map }
    }

    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        let entries: Vec<CorpusEntry> = serde_json::from_str(json)?;
        Ok(Self::from_entries(entries))
    }

    #[must_use]
    pub fn well_known_minified() -> Self {
        let baseline: &[(&str, &str, u8)] = &[
            ("e", "event", 60),
            ("t", "target", 55),
            ("n", "node", 55),
            ("r", "result", 60),
            ("o", "options", 55),
            ("i", "index", 70),
            ("u", "utils", 50),
            ("a", "args", 55),
            ("s", "state", 60),
            ("c", "context", 60),
            ("p", "props", 65),
            ("d", "data", 65),
            ("f", "fn", 50),
            ("g", "group", 50),
            ("h", "handler", 65),
            ("k", "key", 70),
            ("l", "list", 60),
            ("m", "map", 60),
            ("v", "value", 70),
            ("w", "width", 50),
            ("x", "x", 50),
            ("y", "y", 50),
            ("z", "z", 50),
        ];
        Self::from_entries(baseline.iter().map(|(o, r, c)| CorpusEntry {
            original: (*o).to_owned(),
            restored: (*r).to_owned(),
            min_confidence: *c,
        }))
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl NameSource for CorpusNameSource {
    fn suggest(&self, _scope: ScopeKey, context: &Context) -> Option<Suggestion> {
        let entry: &CorpusEntry = self.entries.get(&context.original)?;
        Some(Suggestion {
            name: entry.restored.clone(),
            confidence: Confidence(entry.min_confidence),
            source_label: self.label(),
        })
    }

    fn label(&self) -> &'static str {
        "corpus"
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::mangled_names::SymbolRole;

    #[test]
    fn well_known_lookup_succeeds() {
        let src: CorpusNameSource = CorpusNameSource::well_known_minified();
        let ctx: Context = Context::new("e", SymbolRole::Parameter, ScopeKey(0));
        let s: Suggestion = src.suggest(ScopeKey(0), &ctx).expect("lookup hits");
        assert_eq!(s.name, "event");
    }

    #[test]
    fn json_round_trip() {
        let json: &str = r#"[{"original":"q","restored":"query","min_confidence":75}]"#;
        let src: CorpusNameSource = CorpusNameSource::from_json(json).expect("parse");
        assert_eq!(src.len(), 1);
        let ctx: Context = Context::new("q", SymbolRole::Variable, ScopeKey(0));
        let s: Suggestion = src.suggest(ScopeKey(0), &ctx).expect("hit");
        assert_eq!(s.name, "query");
    }
}
