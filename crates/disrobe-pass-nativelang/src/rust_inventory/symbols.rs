use std::collections::BTreeMap;

use disrobe_pass_native::demangle_rust;
use object::read::File as ObjectFile;
use object::{Object as _, ObjectSymbol as _};
use serde::Serialize;

const MAX_SYMBOLS: usize = 1 << 22;
const MAX_SYMBOL_NAME_BYTES: usize = 64 * 1024;
const MAX_SYMBOL_CRATES: usize = 16_384;
const LEGACY_HASH_MARKER: &str = "17h";
const LEGACY_HASH_DIGITS: usize = 16;
const TYPE_PREFIXES: [&str; 6] = ["&", "*const ", "*mut ", "mut ", "dyn ", "const "];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ManglingScheme {
    Legacy,
    V0,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SymbolEvidence {
    pub index: u64,
    pub mangled: String,
    pub demangled: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CrateSymbols {
    pub name: String,
    pub legacy: u64,
    pub v0: u64,
    pub evidence: SymbolEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
pub struct SymbolInventory {
    pub symbol_table: bool,
    pub defined: u64,
    pub legacy: u64,
    pub v0: u64,
    pub unattributed: u64,
    pub crates: Vec<CrateSymbols>,
    pub truncated: bool,
}

pub(super) fn inventory(file: &ObjectFile<'_>) -> SymbolInventory {
    let mut out: SymbolInventory = SymbolInventory::default();
    let mut crates: BTreeMap<String, CrateSymbols> = BTreeMap::new();
    for (position, symbol) in file.symbols().enumerate() {
        if position >= MAX_SYMBOLS {
            out.truncated = true;
            break;
        }
        if symbol.is_undefined() {
            continue;
        }
        out.defined += 1;
        let Ok(name) = symbol.name() else {
            continue;
        };
        if name.len() > MAX_SYMBOL_NAME_BYTES {
            out.truncated = true;
            continue;
        }
        let Some((scheme, mangled)) = mangling(name) else {
            continue;
        };
        let Ok(demangled) = demangle_rust(mangled) else {
            continue;
        };
        match scheme {
            ManglingScheme::Legacy => out.legacy += 1,
            ManglingScheme::V0 => out.v0 += 1,
        }
        let Some(crate_name) = symbol_path_crate(&demangled.demangled) else {
            out.unattributed += 1;
            continue;
        };
        if let Some(entry) = crates.get_mut(crate_name) {
            match scheme {
                ManglingScheme::Legacy => entry.legacy += 1,
                ManglingScheme::V0 => entry.v0 += 1,
            }
            continue;
        }
        if crates.len() >= MAX_SYMBOL_CRATES {
            out.truncated = true;
            continue;
        }
        crates.insert(
            crate_name.to_owned(),
            CrateSymbols {
                name: crate_name.to_owned(),
                legacy: u64::from(scheme == ManglingScheme::Legacy),
                v0: u64::from(scheme == ManglingScheme::V0),
                evidence: SymbolEvidence {
                    index: symbol.index().0 as u64,
                    mangled: name.to_owned(),
                    demangled: demangled.demangled.clone(),
                },
            },
        );
    }
    out.symbol_table = out.defined > 0;
    out.crates = crates.into_values().collect();
    out
}

fn mangling(name: &str) -> Option<(ManglingScheme, &str)> {
    let mangled: &str = if name.starts_with("_ZN") || name.starts_with("_R") {
        name
    } else {
        name.strip_prefix('_')?
    };
    if let Some(rest) = mangled.strip_prefix("_R") {
        return rest
            .bytes()
            .next()
            .filter(|byte: &u8| byte.is_ascii_uppercase() || byte.is_ascii_digit())
            .map(|_| (ManglingScheme::V0, mangled));
    }
    (mangled.starts_with("_ZN") && has_legacy_hash(mangled))
        .then_some((ManglingScheme::Legacy, mangled))
}

fn has_legacy_hash(mangled: &str) -> bool {
    mangled
        .match_indices(LEGACY_HASH_MARKER)
        .any(|(at, _): (usize, &str)| {
            let digits: usize = at + LEGACY_HASH_MARKER.len();
            mangled
                .get(digits..digits + LEGACY_HASH_DIGITS)
                .is_some_and(|hash: &str| {
                    hash.bytes()
                        .all(|byte: u8| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                })
                && mangled.as_bytes().get(digits + LEGACY_HASH_DIGITS) == Some(&b'E')
        })
}

pub fn symbol_path_crate(demangled: &str) -> Option<&str> {
    if demangled.starts_with('<') {
        let close: usize = matching_close(demangled)?;
        let (self_type, trait_path): (&str, Option<&str>) = split_as(&demangled[1..close]);
        return leading_crate(self_type).or_else(|| trait_path.and_then(leading_crate));
    }
    leading_crate(demangled)
}

fn is_arrow(bytes: &[u8], index: usize) -> bool {
    index > 0 && bytes[index - 1] == b'-'
}

fn matching_close(text: &str) -> Option<usize> {
    let bytes: &[u8] = text.as_bytes();
    let mut depth: usize = 0;
    for (index, byte) in bytes.iter().enumerate() {
        match byte {
            b'<' => depth += 1,
            b'>' if !is_arrow(bytes, index) => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(index);
                }
            }
            _ => {}
        }
    }
    None
}

fn split_as(inner: &str) -> (&str, Option<&str>) {
    let bytes: &[u8] = inner.as_bytes();
    let mut depth: usize = 0;
    for (index, byte) in bytes.iter().enumerate() {
        match byte {
            b'<' | b'(' | b'[' => depth += 1,
            b')' | b']' => depth = depth.saturating_sub(1),
            b'>' if !is_arrow(bytes, index) => depth = depth.saturating_sub(1),
            b' ' if depth == 0 && inner[index..].starts_with(" as ") => {
                return (&inner[..index], Some(&inner[index + 4..]));
            }
            _ => {}
        }
    }
    (inner, None)
}

fn leading_crate(path: &str) -> Option<&str> {
    let mut rest: &str = path;
    loop {
        if let Some(stripped) = TYPE_PREFIXES
            .iter()
            .find_map(|prefix: &&str| rest.strip_prefix(*prefix))
        {
            rest = stripped;
            continue;
        }
        if let Some(lifetime) = rest.strip_prefix('\'') {
            let length: usize = lifetime
                .bytes()
                .take_while(|byte: &u8| byte.is_ascii_alphanumeric() || *byte == b'_')
                .count();
            if length > 0
                && let Some(stripped) = lifetime[length..].strip_prefix(' ')
            {
                rest = stripped;
                continue;
            }
        }
        break;
    }
    let length: usize = rest
        .bytes()
        .take_while(|byte: &u8| byte.is_ascii_alphanumeric() || *byte == b'_')
        .count();
    if length == 0 {
        return None;
    }
    let mut after: &str = &rest[length..];
    if let Some(disambiguated) = after.strip_prefix('[')
        && let Some(close) = disambiguated.find(']')
        && disambiguated[..close]
            .bytes()
            .all(|byte: u8| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        after = &disambiguated[close + 1..];
    }
    after.starts_with("::").then(|| &rest[..length])
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn qualified_paths_take_the_self_type_crate_then_the_trait_crate() {
        assert_eq!(
            symbol_path_crate(
                "<regex_automata[1a2b]::meta::Regex as core[3c]::clone::Clone>::clone"
            ),
            Some("regex_automata")
        );
        assert_eq!(
            symbol_path_crate("<&T as core::fmt::Debug>::fmt::h0123456789abcdef"),
            Some("core")
        );
        assert_eq!(
            symbol_path_crate("<&'_ mut dyn anyhow::StdError as core::fmt::Display>::fmt"),
            Some("anyhow")
        );
        assert_eq!(
            symbol_path_crate("<fn() -> u8 as alloc::Run<T>>::run"),
            Some("alloc")
        );
        assert_eq!(symbol_path_crate("<str>::trim_matches::<char>"), None);
        assert_eq!(symbol_path_crate("rust_eh_personality"), None);
        assert_eq!(
            symbol_path_crate("gitdep::weave::h0123456789abcdef"),
            Some("gitdep")
        );
    }

    #[test]
    fn mangled_names_are_rust_only_with_a_v0_tag_or_a_legacy_hash() {
        assert_eq!(
            mangling("__RNvCs1_6gitdep5weave").map(|(scheme, _)| scheme),
            Some(ManglingScheme::V0)
        );
        assert_eq!(
            mangling("_ZN6gitdep5weave17h0123456789abcdefE").map(|(scheme, _)| scheme),
            Some(ManglingScheme::Legacy)
        );
        assert_eq!(mangling("_ZN6gitdep5weaveE"), None);
        assert_eq!(mangling("_Rust"), None);
        assert_eq!(mangling("memcpy"), None);
    }
}
