use std::collections::BTreeMap;

use crate::error::{Error, Result};
use crate::proguard::{ClassMapping, Mapping, MethodMapping, source_params_to_descriptor};

const MAX_LOG_BYTES: usize = 16 * 1024 * 1024;
const MAX_LOG_ENTRIES: usize = 262_144;
const MAX_NESTED_CLASS_DEPTH: usize = 64;
const MAX_ENTITY_BYTES: usize = 16;

struct Tag<'a> {
    name: &'a str,
    attributes: BTreeMap<&'a str, String>,
}

fn decode_entities(raw: &str) -> String {
    if !raw.contains('&') {
        return raw.to_owned();
    }
    let mut out: String = String::with_capacity(raw.len());
    let mut rest: &str = raw;
    while let Some(start) = rest.find('&') {
        out.push_str(&rest[..start]);
        let tail: &str = &rest[start..];
        let decoded: Option<(char, usize)> = tail
            .find(';')
            .filter(|end: &usize| *end <= MAX_ENTITY_BYTES)
            .and_then(|end: usize| entity_char(&tail[1..end]).map(|c: char| (c, end + 1)));
        match decoded {
            Some((c, consumed)) => {
                out.push(c);
                rest = &tail[consumed..];
            }
            None => {
                out.push('&');
                rest = &tail[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

fn entity_char(name: &str) -> Option<char> {
    match name {
        "lt" => Some('<'),
        "gt" => Some('>'),
        "quot" => Some('"'),
        "apos" => Some('\''),
        "amp" => Some('&'),
        _ => {
            let digits: &str = name.strip_prefix('#')?;
            let value: u32 = match digits.strip_prefix(['x', 'X']) {
                Some(hex) => u32::from_str_radix(hex, 16).ok()?,
                None => digits.parse::<u32>().ok()?,
            };
            char::from_u32(value)
        }
    }
}

fn parse_tag(body: &str) -> Option<Tag<'_>> {
    let body: &str = body.trim().trim_end_matches('/').trim();
    let name_end: usize = body.find(|c: char| c.is_whitespace()).unwrap_or(body.len());
    let name: &str = &body[..name_end];
    let mut attributes: BTreeMap<&str, String> = BTreeMap::new();
    let mut rest: &str = body[name_end..].trim_start();
    while !rest.is_empty() {
        let eq: usize = rest.find('=')?;
        let key: &str = rest[..eq].trim();
        let after: &str = rest[eq + 1..].trim_start();
        let quote: char = after.chars().next()?;
        if quote != '"' && quote != '\'' {
            return None;
        }
        let value_body: &str = &after[1..];
        let close: usize = value_body.find(quote)?;
        attributes.insert(key, decode_entities(&value_body[..close]));
        rest = value_body[close + 1..].trim_start();
    }
    Some(Tag { name, attributes })
}

fn tags(text: &str) -> impl Iterator<Item = Tag<'_>> {
    let mut rest: &str = text;
    std::iter::from_fn(move || {
        loop {
            let open: usize = rest.find('<')?;
            let after: &str = &rest[open + 1..];
            if after.starts_with("!--") {
                let end: usize = after.find("-->")?;
                rest = &after[end + 3..];
                continue;
            }
            if after.starts_with('?') || after.starts_with('/') {
                let end: usize = after.find('>')?;
                rest = &after[end + 1..];
                continue;
            }
            let end: usize = after.find('>')?;
            let body: &str = &after[..end];
            rest = &after[end + 1..];
            if let Some(tag) = parse_tag(body) {
                return Some(tag);
            }
        }
    })
}

fn obfuscated_class_name(
    original: &str,
    class_maps: &BTreeMap<String, String>,
    package_maps: &BTreeMap<String, String>,
) -> Result<String> {
    let mut nested: Vec<&str> = Vec::new();
    let mut current: &str = original;
    let mut name: String = loop {
        let mapped: Option<&str> = class_maps.get(current).map(String::as_str);
        if let Some(qualified) = mapped.filter(|mapped: &&str| mapped.contains('.')) {
            break qualified.to_owned();
        }
        if let Some((outer, inner)) = current.rsplit_once('$') {
            if nested.len() == MAX_NESTED_CLASS_DEPTH {
                return Err(Error::BadMapping(
                    0,
                    format!("yGuard class name nests deeper than {MAX_NESTED_CLASS_DEPTH} levels"),
                ));
            }
            nested.push(mapped.unwrap_or(inner));
            current = outer;
            continue;
        }
        break match current.rsplit_once('.') {
            Some((package, simple)) => {
                let package: &str = package_maps.get(package).map_or(package, String::as_str);
                format!("{package}.{}", mapped.unwrap_or(simple))
            }
            None => mapped.unwrap_or(current).to_owned(),
        };
    };
    for segment in nested.iter().rev() {
        name.push('$');
        name.push_str(segment);
    }
    Ok(name)
}

fn method_mapping(source: &str) -> Option<MethodMapping> {
    let paren_open: usize = source.find('(')?;
    let paren_close: usize = source[paren_open..].find(')')? + paren_open;
    let mut prefix: std::str::SplitWhitespace<'_> = source[..paren_open].split_whitespace();
    let return_type: &str = prefix.next()?;
    let name: &str = prefix.next()?;
    let params: &str = source[paren_open + 1..paren_close].trim();
    let param_count: usize = if params.is_empty() {
        0
    } else {
        params.split(',').count()
    };
    Some(MethodMapping {
        original_name: name.to_owned(),
        param_count,
        params: params.to_owned(),
        descriptor_params: source_params_to_descriptor(params),
        return_type: return_type.to_owned(),
        line_ranges: Vec::new(),
    })
}

fn class_entry<'a>(
    classes: &'a mut BTreeMap<String, ClassMapping>,
    original: &str,
    class_maps: &BTreeMap<String, String>,
    package_maps: &BTreeMap<String, String>,
) -> Result<&'a mut ClassMapping> {
    let obfuscated: String = obfuscated_class_name(original, class_maps, package_maps)?;
    Ok(classes
        .entry(obfuscated.clone())
        .or_insert_with(|| ClassMapping {
            original_name: original.to_owned(),
            obfuscated_name: obfuscated,
            fields: BTreeMap::new(),
            field_overloads: BTreeMap::new(),
            methods: BTreeMap::new(),
            line_records: BTreeMap::new(),
        }))
}

pub fn parse_renamelog(text: &str) -> Result<Mapping> {
    if text.len() > MAX_LOG_BYTES {
        return Err(Error::BadMapping(
            0,
            "yGuard rename log exceeds 16 MiB".into(),
        ));
    }
    if !text.contains("<yguard") {
        return Err(Error::BadMapping(
            0,
            "not a yGuard rename log (no <yguard> root)".into(),
        ));
    }
    let mut class_maps: BTreeMap<String, String> = BTreeMap::new();
    let mut package_maps: BTreeMap<String, String> = BTreeMap::new();
    let mut members: Vec<Tag<'_>> = Vec::new();
    let mut entries: usize = 0;
    for tag in tags(text) {
        entries += 1;
        if entries > MAX_LOG_ENTRIES {
            return Err(Error::BadMapping(
                entries,
                "yGuard rename log has too many entries".into(),
            ));
        }
        match tag.name {
            "class" => {
                if let (Some(name), Some(map)) =
                    (tag.attributes.get("name"), tag.attributes.get("map"))
                {
                    class_maps.insert(name.clone(), map.clone());
                }
            }
            "package" => {
                if let (Some(name), Some(map)) =
                    (tag.attributes.get("name"), tag.attributes.get("map"))
                {
                    package_maps.insert(name.clone(), map.clone());
                }
            }
            "field" | "method" if tag.attributes.contains_key("map") => members.push(tag),
            _ => {}
        }
    }
    let mut classes: BTreeMap<String, ClassMapping> = BTreeMap::new();
    for original in class_maps.keys() {
        let _: &mut ClassMapping = class_entry(&mut classes, original, &class_maps, &package_maps)?;
    }
    for (index, tag) in members.iter().enumerate() {
        let (Some(class), Some(name), Some(map)) = (
            tag.attributes.get("class"),
            tag.attributes.get("name"),
            tag.attributes.get("map"),
        ) else {
            continue;
        };
        let entry: &mut ClassMapping =
            class_entry(&mut classes, class, &class_maps, &package_maps)?;
        if tag.name == "field" {
            entry.fields.insert(map.clone(), name.clone());
            continue;
        }
        let Some(method): Option<MethodMapping> = method_mapping(name) else {
            return Err(Error::BadMapping(
                index + 1,
                format!("yGuard method entry {name:?} is not `type name(params)`"),
            ));
        };
        let overloads: &mut Vec<MethodMapping> = entry.methods.entry(map.clone()).or_default();
        if !overloads
            .iter()
            .any(|existing: &MethodMapping| existing.descriptor_params == method.descriptor_params)
        {
            overloads.push(method);
        }
    }
    let mut mapping: Mapping = Mapping::default();
    for (obfuscated, class) in classes {
        mapping
            .by_original
            .insert(class.original_name.clone(), obfuscated.clone());
        mapping.classes.insert(obfuscated, class);
    }
    Ok(mapping)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn numeric_character_references_decode_to_the_obfuscated_name() {
        assert_eq!(decode_entities("&#x00d2;00000"), "\u{d2}00000");
        assert_eq!(decode_entities("&#210;00000"), "\u{d2}00000");
        assert_eq!(decode_entities("&amp;#x41;"), "&#x41;");
        assert_eq!(decode_entities("a&lt;b&gt;&quot;&apos;"), "a<b>\"'");
        assert_eq!(decode_entities("&#x110000;"), "&#x110000;");
        assert_eq!(decode_entities("&#xD800;x"), "&#xD800;x");
        assert_eq!(decode_entities("tail &"), "tail &");
        assert_eq!(decode_entities("&unknown;"), "&unknown;");
    }

    const LOG: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<yguard version="1.5">
<!-- comment with <class name="x" map="y"/> inside -->
<expose>
  <class name="com.example.app.Calculator"/>
</expose>
<map>
  <class name="com.example.app.Calculator$Ledger" map="_A"/>
  <field class="com.example.app.Calculator$Ledger" name="checksum" map="A"/>
  <method class="com.example.app.Calculator$Ledger" name="int size()" map="A"/>
  <method class="com.example.app.Calculator$Ledger" name="void record(int, int)" map="A"/>
  <field class="com.example.app.Calculator" name="ledger" map="C"/>
  <method class="com.example.app.Calculator" name="java.lang.String describe(int)" map="A"/>
  <method class="com.example.app.Calculator" name="java.lang.String banner()" map="A"/>
</map>
</yguard>
"#;

    #[test]
    fn inner_class_rename_is_anchored_on_its_outer() {
        let mapping: Mapping = parse_renamelog(LOG).expect("parse");
        let ledger: &ClassMapping = mapping
            .classes
            .get("com.example.app.Calculator$_A")
            .expect("renamed inner class");
        assert_eq!(ledger.original_name, "com.example.app.Calculator$Ledger");
        assert_eq!(ledger.fields.get("A").map(String::as_str), Some("checksum"));
        let overloads: &Vec<MethodMapping> = ledger.methods.get("A").expect("A overloads");
        assert_eq!(overloads.len(), 2);
        assert!(
            overloads
                .iter()
                .any(|m: &MethodMapping| m.original_name == "record" && m.descriptor_params == "II")
        );
    }

    #[test]
    fn exposed_class_keeps_its_name_but_maps_members() {
        let mapping: Mapping = parse_renamelog(LOG).expect("parse");
        let calculator: &ClassMapping = mapping
            .classes
            .get("com.example.app.Calculator")
            .expect("exposed class");
        assert_eq!(calculator.original_name, "com.example.app.Calculator");
        assert_eq!(
            calculator.fields.get("C").map(String::as_str),
            Some("ledger")
        );
        let overloads: &Vec<MethodMapping> = calculator.methods.get("A").expect("A");
        assert_eq!(overloads.len(), 2);
    }

    #[test]
    fn a_non_yguard_document_is_refused_by_name() {
        let error: Error = parse_renamelog("<mapping/>").expect_err("refused");
        assert!(error.to_string().contains("yGuard"));
    }

    #[test]
    fn a_class_nested_past_the_bound_is_refused_by_name() {
        let name: String = format!("a.C{}", "$I".repeat(200_000));
        let text: String =
            format!("<yguard><map><class name=\"{name}\" map=\"A\"/></map></yguard>");
        let error: Error = parse_renamelog(&text).expect_err("refused");
        assert!(error.to_string().contains("nests deeper than"), "{error}");
    }

    #[test]
    fn a_malformed_method_entry_is_refused() {
        let text: String = LOG.replace("int size()", "size");
        assert!(parse_renamelog(&text).is_err());
    }
}
