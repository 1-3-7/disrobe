use std::collections::BTreeSet;

use disrobe_py_marshal::{CodeObject, Object};

const MARKER_PREFIX: &str = "__DR_";
const MAX_SCAN_DEPTH: usize = 64;
const MAX_SCANNED_STRINGS: usize = 1 << 16;
const UNNAMED_STEM: &str = "UNNAMED";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeakedMarker {
    pub stem: String,
    pub line: usize,
}

fn token_at(text: &str, at: usize) -> Option<&str> {
    let rest: &str = text.get(at..)?;
    let end: usize = rest
        .char_indices()
        .find(|(_, ch): &(usize, char)| !(ch.is_ascii_alphanumeric() || *ch == '_'))
        .map_or(rest.len(), |(idx, _): (usize, char)| idx);
    rest.get(..end)
}

fn stem_of(token: &str) -> String {
    let trimmed: &str = token
        .strip_prefix(MARKER_PREFIX)
        .unwrap_or(token)
        .trim_matches('_');
    if trimmed.is_empty() {
        UNNAMED_STEM.to_owned()
    } else {
        trimmed.to_owned()
    }
}

fn collect_tokens(text: &str, into: &mut BTreeSet<String>) {
    let mut from: usize = 0;
    while let Some(found) = text
        .get(from..)
        .and_then(|rest: &str| rest.find(MARKER_PREFIX))
    {
        let at: usize = from.saturating_add(found);
        let Some(token): Option<&str> = token_at(text, at) else {
            return;
        };
        from = at.saturating_add(token.len().max(MARKER_PREFIX.len()));
        into.insert(token.to_owned());
    }
}

fn collect_object(object: &Object, depth: usize, budget: &mut usize, into: &mut BTreeSet<String>) {
    if depth > MAX_SCAN_DEPTH || *budget == 0 {
        return;
    }
    match object {
        Object::String { value, .. }
        | Object::Unicode { value, .. }
        | Object::ShortAscii { value, .. } => {
            *budget = budget.saturating_sub(1);
            collect_tokens(value, into);
        }
        Object::Tuple(items)
        | Object::List(items)
        | Object::Set(items)
        | Object::FrozenSet(items) => {
            for item in items {
                collect_object(item, depth.saturating_add(1), budget, into);
            }
        }
        Object::Dict(entries) | Object::FrozenDict(entries) => {
            for (key, value) in entries {
                collect_object(key, depth.saturating_add(1), budget, into);
                collect_object(value, depth.saturating_add(1), budget, into);
            }
        }
        Object::Code(inner) => collect_code(inner, depth.saturating_add(1), budget, into),
        _ => {}
    }
}

fn collect_code(code: &CodeObject, depth: usize, budget: &mut usize, into: &mut BTreeSet<String>) {
    if depth > MAX_SCAN_DEPTH || *budget == 0 {
        return;
    }
    let pools: [&Vec<Object>; 6] = [
        &code.consts,
        &code.names,
        &code.varnames,
        &code.freevars,
        &code.cellvars,
        &code.localsplusnames,
    ];
    for pool in pools {
        for object in pool {
            collect_object(object, depth, budget, into);
        }
    }
    for object in [&code.name, &code.qualname] {
        collect_object(object, depth, budget, into);
    }
}

#[must_use]
pub fn authentic_markers(code: &CodeObject) -> BTreeSet<String> {
    let mut found: BTreeSet<String> = BTreeSet::new();
    let mut budget: usize = MAX_SCANNED_STRINGS;
    collect_code(code, 0, &mut budget, &mut found);
    found
}

fn first_unauthentic<'a>(line: &'a str, authentic: &BTreeSet<String>) -> Option<&'a str> {
    let mut from: usize = 0;
    while let Some(found) = line
        .get(from..)
        .and_then(|rest: &str| rest.find(MARKER_PREFIX))
    {
        let at: usize = from.saturating_add(found);
        let token: &str = token_at(line, at)?;
        if !authentic.contains(token) {
            return Some(token);
        }
        from = at.saturating_add(token.len().max(MARKER_PREFIX.len()));
    }
    None
}

#[must_use]
pub fn carries_a_marker(source: &str) -> bool {
    source.contains(MARKER_PREFIX)
}

#[must_use]
pub fn find_leaked_marker(source: &str, authentic: &BTreeSet<String>) -> Option<LeakedMarker> {
    if !carries_a_marker(source) {
        return None;
    }
    source
        .lines()
        .enumerate()
        .find_map(|(index, line): (usize, &str)| {
            first_unauthentic(line, authentic).map(|token: &str| LeakedMarker {
                stem: stem_of(token),
                line: index.saturating_add(1),
            })
        })
}
