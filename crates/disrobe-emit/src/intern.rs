use std::collections::BTreeMap;

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct Symbol(u32);

impl Symbol {
    #[must_use]
    pub const fn index(self) -> u32 {
        self.0
    }
}

#[derive(Clone, Default, Debug)]
pub struct Interner {
    by_name: BTreeMap<Box<str>, Symbol>,
    strings: Vec<Box<str>>,
}

impl Interner {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn intern(&mut self, text: &str) -> Symbol {
        if let Some(&existing) = self.by_name.get(text) {
            return existing;
        }
        let symbol: Symbol = Symbol(self.strings.len() as u32);
        let boxed: Box<str> = Box::from(text);
        self.strings.push(boxed.clone());
        self.by_name.insert(boxed, symbol);
        symbol
    }

    #[must_use]
    pub fn lookup(&self, text: &str) -> Option<Symbol> {
        self.by_name.get(text).copied()
    }

    #[must_use]
    pub fn resolve(&self, symbol: Symbol) -> Option<&str> {
        self.strings.get(symbol.0 as usize).map(Box::as_ref)
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.strings.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.strings.is_empty()
    }
}
