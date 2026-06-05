use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DtsSymbol {
    pub name: String,
    pub kind: DtsSymbolKind,
    pub signature: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
pub enum DtsSymbolKind {
    Function,
    Class,
    Interface,
    Type,
    Const,
    Enum,
    Namespace,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DtsModule {
    pub name: String,
    pub symbols: Vec<DtsSymbol>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct DtsCorpus {
    pub modules: BTreeMap<String, DtsModule>,
}

impl DtsCorpus {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    pub fn lookup(&self, module: &str, symbol: &str) -> Option<&DtsSymbol> {
        self.modules
            .get(module)
            .and_then(|m: &DtsModule| m.symbols.iter().find(|s: &&DtsSymbol| s.name == symbol))
    }

    pub fn lookup_global(&self, symbol: &str) -> Option<&DtsSymbol> {
        for m in self.modules.values() {
            if let Some(s) = m.symbols.iter().find(|s: &&DtsSymbol| s.name == symbol) {
                return Some(s);
            }
        }
        None
    }

    #[must_use]
    pub fn well_known() -> Self {
        let mut modules: BTreeMap<String, DtsModule> = BTreeMap::new();
        let lodash: DtsModule = DtsModule {
            name: "lodash".into(),
            symbols: vec![
                DtsSymbol {
                    name: "isString".into(),
                    kind: DtsSymbolKind::Function,
                    signature: "(value: unknown) => value is string".into(),
                },
                DtsSymbol {
                    name: "isArray".into(),
                    kind: DtsSymbolKind::Function,
                    signature: "(value: unknown) => value is unknown[]".into(),
                },
                DtsSymbol {
                    name: "debounce".into(),
                    kind: DtsSymbolKind::Function,
                    signature:
                        "<T extends (...args: never[]) => unknown>(fn: T, wait: number) => T".into(),
                },
                DtsSymbol {
                    name: "throttle".into(),
                    kind: DtsSymbolKind::Function,
                    signature:
                        "<T extends (...args: never[]) => unknown>(fn: T, wait: number) => T".into(),
                },
            ],
        };
        let react: DtsModule = DtsModule {
            name: "react".into(),
            symbols: vec![
                DtsSymbol {
                    name: "useState".into(),
                    kind: DtsSymbolKind::Function,
                    signature: "<S>(initial: S | (() => S)) => [S, (next: S | ((prev: S) => S)) => void]"
                        .into(),
                },
                DtsSymbol {
                    name: "useEffect".into(),
                    kind: DtsSymbolKind::Function,
                    signature: "(effect: () => void | (() => void), deps?: readonly unknown[]) => void"
                        .into(),
                },
                DtsSymbol {
                    name: "useMemo".into(),
                    kind: DtsSymbolKind::Function,
                    signature: "<T>(factory: () => T, deps: readonly unknown[]) => T".into(),
                },
                DtsSymbol {
                    name: "useCallback".into(),
                    kind: DtsSymbolKind::Function,
                    signature: "<T extends (...args: never[]) => unknown>(cb: T, deps: readonly unknown[]) => T"
                        .into(),
                },
            ],
        };
        modules.insert(lodash.name.clone(), lodash);
        modules.insert(react.name.clone(), react);
        Self { modules }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn well_known_has_react_and_lodash() {
        let corpus: DtsCorpus = DtsCorpus::well_known();
        assert!(corpus.lookup("react", "useState").is_some());
        assert!(corpus.lookup("lodash", "isString").is_some());
    }

    #[test]
    fn global_search_finds_anywhere() {
        let corpus: DtsCorpus = DtsCorpus::well_known();
        let s: Option<&DtsSymbol> = corpus.lookup_global("debounce");
        assert!(s.is_some());
    }
}
