use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClassMapping {
    pub original_name: String,
    pub obfuscated_name: String,
    pub fields: BTreeMap<String, String>,
    pub methods: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Mapping {
    pub classes: BTreeMap<String, ClassMapping>,
    pub by_original: BTreeMap<String, String>,
}

impl Mapping {
    #[inline]
    #[must_use]
    pub fn lookup_obfuscated_class(&self, obfuscated: &str) -> Option<&ClassMapping> {
        self.classes.get(obfuscated)
    }

    #[inline]
    #[must_use]
    pub fn lookup_original_class(&self, original: &str) -> Option<&str> {
        self.by_original.get(original).map(String::as_str)
    }
}

pub fn parse(text: &str) -> Result<Mapping> {
    let mut mapping: Mapping = Mapping::default();
    let mut current: Option<ClassMapping> = None;
    for (line_no, raw) in text.lines().enumerate() {
        let line: &str = strip_comment(raw);
        if line.is_empty() {
            continue;
        }
        if !line.starts_with(|c: char| c.is_whitespace()) {
            if let Some(cls) = current.take() {
                mapping
                    .by_original
                    .insert(cls.original_name.clone(), cls.obfuscated_name.clone());
                mapping.classes.insert(cls.obfuscated_name.clone(), cls);
            }
            let Some(arrow): Option<usize> = line.find(" -> ") else {
                return Err(Error::BadMapping(
                    line_no + 1,
                    "expected ' -> ' in class header".into(),
                ));
            };
            let original_name: String = line[..arrow].trim().to_string();
            let rest: &str = &line[arrow + 4..];
            let obfuscated: String = rest.trim_end_matches(':').trim().to_string();
            if original_name.is_empty() || obfuscated.is_empty() {
                return Err(Error::BadMapping(
                    line_no + 1,
                    "empty original or obfuscated name".into(),
                ));
            }
            current = Some(ClassMapping {
                original_name,
                obfuscated_name: obfuscated,
                fields: BTreeMap::new(),
                methods: BTreeMap::new(),
            });
            continue;
        }
        let trimmed: &str = line.trim();
        let Some(arrow): Option<usize> = trimmed.find(" -> ") else {
            continue;
        };
        let lhs: &str = trimmed[..arrow].trim();
        let rhs: &str = trimmed[arrow + 4..].trim();
        let Some(cls): Option<&mut ClassMapping> = current.as_mut() else {
            return Err(Error::BadMapping(
                line_no + 1,
                "member line outside class block".into(),
            ));
        };
        if let Some(paren_open) = lhs.find('(') {
            let prefix: &str = &lhs[..paren_open];
            let method_name: String = prefix
                .rsplit(' ')
                .next()
                .map(str::to_string)
                .unwrap_or_default();
            let paren_close: usize = lhs.find(')').unwrap_or(lhs.len());
            let params: &str = &lhs[paren_open + 1..paren_close.min(lhs.len())];
            let signature: String = format!("{method_name}({params})");
            cls.methods.insert(rhs.to_string(), signature);
        } else {
            let field_name: String = lhs
                .rsplit(' ')
                .next()
                .map(str::to_string)
                .unwrap_or_default();
            cls.fields.insert(rhs.to_string(), field_name);
        }
    }
    if let Some(cls) = current.take() {
        mapping
            .by_original
            .insert(cls.original_name.clone(), cls.obfuscated_name.clone());
        mapping.classes.insert(cls.obfuscated_name.clone(), cls);
    }
    Ok(mapping)
}

fn strip_comment(line: &str) -> &str {
    if let Some(hash) = line.find('#') {
        &line[..hash]
    } else {
        line
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnmappedHeuristics {
    pub mapped: BTreeMap<String, String>,
}

pub fn heuristic_recover(obfuscated_names: &[String]) -> UnmappedHeuristics {
    let mut out: UnmappedHeuristics = UnmappedHeuristics::default();
    for name in obfuscated_names {
        if is_proguard_short(name) {
            let recovered: String = synthesize_name(name);
            out.mapped.insert(name.clone(), recovered);
        }
    }
    out
}

fn is_proguard_short(name: &str) -> bool {
    if name.is_empty() || name.len() > 3 {
        return false;
    }
    name.chars().all(|c| c.is_ascii_lowercase())
}

fn synthesize_name(name: &str) -> String {
    let mut out: String = String::with_capacity(name.len() + 4);
    out.push_str("sym_");
    out.push_str(name);
    out
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn parses_simple_class_header() {
        let src: &str = "com.example.Foo -> a.a:\n    int counter -> a\n";
        let m: Mapping = parse(src).expect("parse");
        let cls: &ClassMapping = m.classes.get("a.a").expect("class present");
        assert_eq!(cls.original_name, "com.example.Foo");
        assert_eq!(cls.fields.get("a").map(String::as_str), Some("counter"));
    }

    #[test]
    fn parses_method() {
        let src: &str = "com.example.Foo -> a.a:\n    void run(int) -> b\n";
        let m: Mapping = parse(src).expect("parse");
        let cls: &ClassMapping = m.classes.get("a.a").expect("class");
        assert!(cls.methods.contains_key("b"));
    }

    #[test]
    fn heuristic_recovers_short_names() {
        let names: Vec<String> = vec!["a".into(), "ab".into(), "myLongName".into()];
        let h: UnmappedHeuristics = heuristic_recover(&names);
        assert!(h.mapped.contains_key("a"));
        assert!(h.mapped.contains_key("ab"));
        assert!(!h.mapped.contains_key("myLongName"));
    }

    #[test]
    fn rejects_member_without_class() {
        let src: &str = "    int x -> a\n";
        let err: Error = parse(src).expect_err("orphan");
        assert!(matches!(err, Error::BadMapping(_, _)));
    }

    #[test]
    fn comments_are_stripped() {
        let src: &str = "# header comment\ncom.example.Foo -> a.a:\n";
        let m: Mapping = parse(src).expect("parse");
        assert!(m.classes.contains_key("a.a"));
    }
}
