use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::etf::Term;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleDocs {
    pub format: String,
    pub module_doc: Option<String>,
    pub entries: BTreeMap<(String, String, u32), String>,
}

impl ModuleDocs {
    #[must_use]
    pub fn function_doc(&self, name: &str, arity: u32) -> Option<&str> {
        self.entries
            .get(&("function".to_owned(), name.to_owned(), arity))
            .map(String::as_str)
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.module_doc.is_none() && self.entries.is_empty()
    }
}

#[must_use]
pub fn parse(term: &Term) -> Option<ModuleDocs> {
    let tuple: &[Term] = term.as_tuple()?;
    if tuple.len() < 6 || tuple[0].as_atom() != Some("docs_v1") {
        return None;
    }
    let format: String = tuple
        .get(3)
        .and_then(Term::as_str)
        .unwrap_or_else(|| "text/markdown".to_owned());
    let module_doc: Option<String> = doc_text(&tuple[4]);
    let mut entries: BTreeMap<(String, String, u32), String> = BTreeMap::new();
    if let Some(list) = tuple.get(6).and_then(Term::as_list) {
        for item in list {
            capture_entry(item, &mut entries);
        }
    }
    Some(ModuleDocs {
        format,
        module_doc,
        entries,
    })
}

fn capture_entry(item: &Term, out: &mut BTreeMap<(String, String, u32), String>) {
    let Some(tuple): Option<&[Term]> = item.as_tuple() else {
        return;
    };
    if tuple.len() < 4 {
        return;
    }
    let Some(kna): Option<&[Term]> = tuple[0].as_tuple() else {
        return;
    };
    if kna.len() != 3 {
        return;
    }
    let Some(kind): Option<&str> = kna[0].as_atom() else {
        return;
    };
    let Some(name): Option<&str> = kna[1].as_atom() else {
        return;
    };
    let arity: u32 = match &kna[2] {
        Term::SmallInt(v) => u32::from(*v),
        Term::Int(v) => u32::try_from(*v).unwrap_or(0),
        _ => return,
    };
    if let Some(text) = doc_text(&tuple[3]) {
        out.insert((kind.to_owned(), name.to_owned(), arity), text);
    }
}

fn doc_text(term: &Term) -> Option<String> {
    match term {
        Term::Map(map) => map
            .get("en")
            .or_else(|| map.values().next())
            .and_then(Term::as_str),
        Term::Atom(a) if a == "none" || a == "hidden" => None,
        _ => None,
    }
}
