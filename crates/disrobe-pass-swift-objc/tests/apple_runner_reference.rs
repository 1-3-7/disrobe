#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use disrobe_pass_swift_objc::keyed_archive::{ArchivedValue, KeyedArchive, decode_keyed_archive};
use disrobe_pass_swift_objc::nib_archive::{
    NibArchive, decode_nib_archive, swift_runtime_class_name,
};

fn corpus(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus/apple")
        .join(relative)
}

fn read(relative: &str) -> Vec<u8> {
    let path: PathBuf = corpus(relative);
    std::fs::read(&path)
        .unwrap_or_else(|error| panic!("apple fixture {} is required: {error}", path.display()))
}

#[derive(Debug)]
struct Element {
    tag: String,
    attributes: BTreeMap<String, String>,
    parent: Option<usize>,
}

fn attributes(text: &str) -> BTreeMap<String, String> {
    let mut out: BTreeMap<String, String> = BTreeMap::new();
    let mut rest: &str = text;
    while let Some(eq) = rest.find("=\"") {
        let key: &str = rest[..eq].trim();
        let after: &str = &rest[eq + 2..];
        let end: usize = after.find('"').expect("closing quote");
        let value: String = after[..end]
            .replace("&quot;", "\"")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&apos;", "'")
            .replace("&amp;", "&");
        out.insert(key.rsplit(' ').next().unwrap().to_owned(), value);
        rest = &after[end + 1..];
    }
    out
}

fn parse_xib(text: &str) -> Vec<Element> {
    let mut elements: Vec<Element> = Vec::new();
    let mut open: Vec<usize> = Vec::new();
    let mut rest: &str = text;
    while let Some(start) = rest.find('<') {
        let end: usize = start + rest[start..].find('>').expect("tag end");
        let tag: &str = &rest[start + 1..end];
        rest = &rest[end + 1..];
        if tag.starts_with('?') || tag.starts_with('!') {
            continue;
        }
        if let Some(name) = tag.strip_prefix('/') {
            let index: usize = open.pop().expect("balanced xib");
            assert_eq!(elements[index].tag, name.trim(), "balanced xib");
            continue;
        }
        let closed: bool = tag.ends_with('/');
        let body: &str = tag.trim_end_matches('/');
        let name: &str = body.split_whitespace().next().unwrap();
        elements.push(Element {
            tag: name.to_owned(),
            attributes: attributes(&body[name.len()..]),
            parent: open.last().copied(),
        });
        if !closed {
            open.push(elements.len() - 1);
        }
    }
    assert!(open.is_empty(), "balanced xib");
    elements
}

fn uikit_class(element: &Element) -> String {
    if element.tag == "placeholder" {
        return "UIProxyObject".to_owned();
    }
    if let Some(custom) = element.attributes.get("customClass") {
        return element.attributes.get("customModule").map_or_else(
            || custom.clone(),
            |module: &String| format!("{module}.{custom}"),
        );
    }
    let mut chars = element.tag.chars();
    let first: char = chars.next().unwrap().to_ascii_uppercase();
    format!("UI{first}{}", chars.as_str())
}

fn owner_of_connections(elements: &[Element], index: usize) -> usize {
    let connections: usize = elements[index]
        .parent
        .expect("connection inside connections");
    assert_eq!(elements[connections].tag, "connections");
    elements[connections]
        .parent
        .expect("connections inside an object")
}

type Connection = (String, String, String, String);

fn xib_connections(elements: &[Element]) -> Vec<Connection> {
    let by_id: BTreeMap<&str, &Element> = elements
        .iter()
        .filter_map(|element: &Element| {
            element
                .attributes
                .get("id")
                .map(|id: &String| (id.as_str(), element))
        })
        .collect();
    let mut out: Vec<Connection> = Vec::new();
    for (index, element) in elements.iter().enumerate() {
        let (kind, label): (&str, &str) = match element.tag.as_str() {
            "outlet" => ("outlet", element.attributes["property"].as_str()),
            "outletCollection" => ("outlet-collection", element.attributes["property"].as_str()),
            "action" => ("action", element.attributes["selector"].as_str()),
            _ => continue,
        };
        let source: &Element = &elements[owner_of_connections(elements, index)];
        let destination: &Element = by_id[element.attributes["destination"].as_str()];
        out.push((
            kind.to_owned(),
            label.to_owned(),
            uikit_class(source),
            uikit_class(destination),
        ));
    }
    out.sort();
    out
}

fn readable(archive: &NibArchive, class: Option<&String>) -> String {
    class.map_or_else(String::new, |name: &String| {
        archive
            .swift_class_names
            .get(name)
            .cloned()
            .unwrap_or_else(|| name.clone())
    })
}

fn nib_connections(archive: &NibArchive) -> Vec<Connection> {
    let mut out: Vec<Connection> = Vec::new();
    for connection in &archive.connections {
        let kind: String = connection.kind.clone();
        let label: String = connection.label.clone().unwrap_or_default();
        let source: String = readable(archive, connection.source_class.as_ref());
        if connection.kind == "outlet-collection" {
            for item in &connection.collected_classes {
                out.push((
                    kind.clone(),
                    label.clone(),
                    source.clone(),
                    readable(archive, Some(item)),
                ));
            }
        } else {
            out.push((
                kind,
                label,
                source,
                readable(archive, connection.destination_class.as_ref()),
            ));
        }
    }
    out.sort();
    out
}

fn grade_nib(name: &str, nib: &[u8]) -> Vec<String> {
    let xib: String = String::from_utf8(read(&format!("src/{name}.xib"))).expect("xib text");
    let elements: Vec<Element> = parse_xib(&xib);
    let mut wrong: Vec<String> = Vec::new();
    let archive: NibArchive = match decode_nib_archive(nib) {
        Ok(archive) => archive,
        Err(error) => return vec![format!("{name}: refused: {error}")],
    };
    let expected: Vec<Connection> = xib_connections(&elements);
    let recovered: Vec<Connection> = nib_connections(&archive);
    if expected != recovered {
        wrong.push(format!(
            "{name}: connections\n  xib {expected:?}\n  nib {recovered:?}"
        ));
    }
    let custom: BTreeSet<String> = elements
        .iter()
        .filter(|element: &&Element| {
            element.tag != "placeholder" && element.attributes.contains_key("customClass")
        })
        .map(uikit_class)
        .collect();
    let recovered_custom: BTreeSet<String> = archive
        .custom_classes
        .iter()
        .map(|name: &String| readable(&archive, Some(name)))
        .collect();
    if custom != recovered_custom {
        wrong.push(format!(
            "{name}: custom classes {custom:?} against {recovered_custom:?}"
        ));
    }
    let strings: BTreeSet<&str> = archive.strings.iter().map(String::as_str).collect();
    for element in &elements {
        for key in ["text", "title", "placeholder", "reuseIdentifier"] {
            if let Some(value) = element.attributes.get(key)
                && !strings.contains(value.as_str())
            {
                wrong.push(format!(
                    "{name}: {} {key} {value:?} is not among the nib strings",
                    element.tag
                ));
            }
        }
    }
    wrong
}

#[test]
fn compiled_nibs_carry_the_connections_classes_and_strings_of_their_xib() {
    let mut wrong: Vec<String> = Vec::new();
    let mut connections: usize = 0;
    for name in ["Controls", "Settings"] {
        let nib: Vec<u8> = read(&format!("runner/{name}.nib"));
        connections += decode_nib_archive(&nib).expect("nib").connections.len();
        wrong.extend(grade_nib(name, &nib));
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    assert!(connections >= 8, "only {connections} connections graded");
}

#[test]
fn a_renamed_outlet_in_a_compiled_nib_is_caught() {
    let mut nib: Vec<u8> = read("runner/Controls.nib");
    let at: usize = nib
        .windows(b"titleLabel".len())
        .position(|window: &[u8]| window == b"titleLabel")
        .expect("outlet name in the nib");
    nib[at] = b'T';
    assert!(
        !grade_nib("Controls", &nib).is_empty(),
        "a renamed outlet went unnoticed"
    );
}

fn field<'a>(value: &'a ArchivedValue, key: &str) -> &'a ArchivedValue {
    match value {
        ArchivedValue::Object { fields, .. } | ArchivedValue::Value { fields, .. } => fields
            .get(key)
            .unwrap_or_else(|| panic!("field {key} missing from {value:?}")),
        other => panic!("{key} looked up on {other:?}"),
    }
}

fn text(value: &ArchivedValue) -> &str {
    match value {
        ArchivedValue::String { value } => value,
        other => panic!("expected a string, found {other:?}"),
    }
}

fn integer(value: &ArchivedValue) -> i128 {
    match value {
        ArchivedValue::Integer { value } => *value,
        other => panic!("expected an integer, found {other:?}"),
    }
}

fn dictionary(value: &ArchivedValue) -> BTreeMap<String, &ArchivedValue> {
    match value {
        ArchivedValue::Dictionary { entries, .. } => entries
            .iter()
            .map(|(key, item): &(ArchivedValue, ArchivedValue)| (text(key).to_owned(), item))
            .collect(),
        other => panic!("expected a dictionary, found {other:?}"),
    }
}

fn items(value: &ArchivedValue) -> &[ArchivedValue] {
    match value {
        ArchivedValue::Array { items, .. } | ArchivedValue::Set { items, .. } => items,
        other => panic!("expected an array or set, found {other:?}"),
    }
}

fn person_summary(person: &ArchivedValue) -> String {
    let tags: Vec<&str> = items(field(person, "tags")).iter().map(text).collect();
    let scores: BTreeMap<String, String> = dictionary(field(person, "scores"))
        .into_iter()
        .map(|(key, value): (String, &ArchivedValue)| {
            let score: f64 = match value {
                ArchivedValue::Real { value } => *value,
                ArchivedValue::Integer { value } => f64::from(i32::try_from(*value).unwrap()),
                other => panic!("score {other:?}"),
            };
            (key, format!("{score}"))
        })
        .collect();
    let born: f64 = match field(person, "born") {
        ArchivedValue::Date {
            seconds_since_2001, ..
        } => *seconds_since_2001,
        other => panic!("born {other:?}"),
    };
    let avatar: &str = match field(person, "avatar") {
        ArchivedValue::Data { hex } => hex,
        other => panic!("avatar {other:?}"),
    };
    let home: &str = match field(person, "home") {
        ArchivedValue::Url {
            base: None,
            relative,
        } => text(relative),
        other => panic!("home {other:?}"),
    };
    let id: &str = match field(person, "id") {
        ArchivedValue::Uuid { value } => value,
        other => panic!("id {other:?}"),
    };
    format!(
        "{} {} {tags:?} {scores:?} {born} {avatar} {home} {}",
        text(field(person, "name")),
        integer(field(person, "age")),
        id.to_ascii_uppercase()
    )
}

fn archive_summary(archive: &KeyedArchive) -> Vec<String> {
    let root: BTreeMap<String, &ArchivedValue> = dictionary(&archive.top["root"]);
    let mut lines: Vec<String> = vec![format!(
        "keys {:?}",
        root.keys().cloned().collect::<Vec<String>>()
    )];
    lines.push(format!("count {}", integer(root["count"])));
    let mut set: Vec<&str> = items(root["set"]).iter().map(text).collect();
    set.sort_unstable();
    lines.push(format!("set {set:?}"));
    lines.push(format!("null {:?}", root["null"]));
    for person in items(root["people"]) {
        lines.push(person_summary(person));
        let friend: &ArchivedValue = field(person, "friend");
        lines.push(match friend {
            ArchivedValue::Object { .. } => format!("friend {}", text(field(friend, "name"))),
            ArchivedValue::BackReference { .. } => "friend back-reference".to_owned(),
            other => format!("friend {other:?}"),
        });
    }
    lines
}

#[test]
fn the_foundation_archive_decodes_to_the_values_the_program_archived() {
    let binary: KeyedArchive =
        decode_keyed_archive(&read("runner/graph.archive")).expect("binary archive");
    let xml: KeyedArchive =
        decode_keyed_archive(&read("runner/graph.archive.xml")).expect("xml archive");
    assert_eq!(binary.archiver, "NSKeyedArchiver");
    assert!(binary.problems.is_empty(), "{:?}", binary.problems);
    let summary: Vec<String> = archive_summary(&binary);
    let expected: Vec<String> = vec![
        r#"keys ["count", "null", "people", "set"]"#.to_owned(),
        "count 2".to_owned(),
        r#"set ["x", "y"]"#.to_owned(),
        "null Null".to_owned(),
        r#"Alice 34 ["admin", "ops"] {"accuracy": "8.25", "speed": "9.5"} 123456789 00010203ff https://example.org/alice 6F9619FF-8B86-D011-B42D-00C04FC964FF"#.to_owned(),
        "friend Bob".to_owned(),
        "Bob 29 [] {} 0  https://example.org/bob 00000000-0000-0000-0000-000000000001".to_owned(),
        "friend Alice".to_owned(),
    ];
    assert_eq!(summary, expected);
    assert_eq!(
        archive_summary(&xml),
        summary,
        "the XML form decodes to the same graph"
    );
}

#[test]
fn swift_runtime_class_names_read_back_their_module_and_nesting() {
    assert_eq!(
        swift_runtime_class_name("_TtC7Fixture16SettingsCellView").as_deref(),
        Some("Fixture.SettingsCellView")
    );
    assert_eq!(
        swift_runtime_class_name("_TtCC7Fixture5Outer5Inner").as_deref(),
        Some("Fixture.Outer.Inner")
    );
    assert_eq!(
        swift_runtime_class_name("_TtCs12_SwiftObject").as_deref(),
        Some("Swift._SwiftObject")
    );
    for refused in [
        "_TtC7Fixture",
        "_TtC7Fixture16Settings",
        "_TtGC7Fixture4Box_",
        "UILabel",
        "_TtC0",
    ] {
        assert_eq!(swift_runtime_class_name(refused), None, "{refused}");
    }
}
