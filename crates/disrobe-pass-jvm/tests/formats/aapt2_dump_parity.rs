#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use disrobe_pass_jvm::{
    ApkResourceReport, AxmlAttribute, AxmlNode, AxmlTree, ManifestComponent, ManifestFacts,
    ResEntryValue, ResourceTable, analyze_apk_resources, parse_arsc, parse_axml,
};

const ANDROID_NS: &str = "http://schemas.android.com/apk/res/android";

fn corpus(rel: &str) -> PathBuf {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.push("corpus");
    p.push("apk");
    p.push(rel);
    p
}

fn read(rel: &str) -> Vec<u8> {
    fs::read(corpus(rel)).unwrap_or_else(|e: std::io::Error| panic!("read {rel}: {e}"))
}

fn read_text(rel: &str) -> String {
    String::from_utf8(read(rel)).expect("utf-8 aapt2 dump")
}

fn entry(apk: &[u8], name: &str) -> Vec<u8> {
    use std::io::{Cursor, Read};
    let mut zip: zip::ZipArchive<Cursor<&[u8]>> =
        zip::ZipArchive::new(Cursor::new(apk)).expect("zip open");
    let mut f: zip::read::ZipFile<'_> = zip.by_name(name).expect("entry present");
    let mut buf: Vec<u8> = Vec::new();
    f.read_to_end(&mut buf).expect("read entry");
    buf
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Element {
    depth: usize,
    name: String,
    attributes: BTreeMap<String, String>,
}

fn aapt2_elements(dump: &str) -> Vec<Element> {
    let mut out: Vec<Element> = Vec::new();
    for line in dump.lines() {
        let indent: usize = line.len() - line.trim_start().len();
        let body: &str = line.trim_start();
        if let Some(rest) = body.strip_prefix("E: ") {
            let name: &str = rest.split(" (line=").next().unwrap_or(rest);
            out.push(Element {
                depth: (indent + 2) / 4,
                name: name.to_owned(),
                attributes: BTreeMap::new(),
            });
        } else if let Some(rest) = body.strip_prefix("A: ") {
            let (key, value): (&str, &str) = rest.split_once('=').expect("attribute has a value");
            let key: String = match key.rsplit_once('(') {
                Some((name, id)) if id.ends_with(')') => name.to_owned(),
                _ => key.to_owned(),
            };
            let value: &str = value.split(" (Raw: ").next().unwrap_or(value);
            let last: &mut Element = out.last_mut().expect("attribute follows an element");
            last.attributes.insert(key, value.to_owned());
        }
    }
    out
}

fn attribute_key(attribute: &AxmlAttribute) -> String {
    attribute.ns.as_deref().map_or_else(
        || attribute.name.clone(),
        |ns: &str| format!("{ns}:{}", attribute.name),
    )
}

fn attribute_value(attribute: &AxmlAttribute) -> String {
    match attribute.value_type {
        0x01 => format!("@0x{:08x}", attribute.typed_value),
        0x02 => format!("?0x{:08x}", attribute.typed_value),
        0x03 => format!("\"{}\"", attribute.raw_value.clone().unwrap_or_default()),
        0x10 => (attribute.typed_value as i32).to_string(),
        0x11 => format!("0x{:x}", attribute.typed_value),
        0x12 => (attribute.typed_value != 0).to_string(),
        other => format!("type{other:#x}:{:#x}", attribute.typed_value),
    }
}

fn disrobe_elements(tree: &AxmlTree) -> Vec<Element> {
    let mut out: Vec<Element> = Vec::new();
    let mut depth: usize = 0;
    for node in &tree.events {
        match node {
            AxmlNode::StartNamespace { .. } => depth += 1,
            AxmlNode::StartElement {
                name, attributes, ..
            } => {
                out.push(Element {
                    depth,
                    name: name.clone(),
                    attributes: attributes
                        .iter()
                        .map(|a: &AxmlAttribute| (attribute_key(a), attribute_value(a)))
                        .collect(),
                });
                depth += 1;
            }
            AxmlNode::EndNamespace { .. } | AxmlNode::EndElement { .. } => depth -= 1,
            AxmlNode::CharData(_) => {}
        }
    }
    out
}

fn assert_manifest_matches_aapt2(fixture: &str) {
    let apk: Vec<u8> = read(&format!("{fixture}.apk"));
    let tree: AxmlTree = parse_axml(&entry(&apk, "AndroidManifest.xml")).expect("axml parses");
    let ours: Vec<Element> = disrobe_elements(&tree);
    let reference: Vec<Element> =
        aapt2_elements(&read_text(&format!("aapt2/{fixture}.manifest.xmltree.txt")));
    assert!(
        !reference.is_empty(),
        "the aapt2 dump names at least one element"
    );
    assert_eq!(
        ours, reference,
        "{fixture}: element tree and typed attributes must equal `aapt2 dump xmltree`"
    );
    assert!(
        reference.iter().any(|e: &Element| e
            .attributes
            .keys()
            .any(|k: &String| k.starts_with(ANDROID_NS))),
        "the reference carries namespaced attributes"
    );
}

#[test]
fn rich_manifest_decodes_equal_to_aapt2_xmltree() {
    assert_manifest_matches_aapt2("fixture-rich");
}

#[test]
fn res_manifest_decodes_equal_to_aapt2_xmltree() {
    assert_manifest_matches_aapt2("fixture-res");
}

#[test]
fn the_xmltree_comparison_turns_red_on_one_changed_attribute() {
    let apk: Vec<u8> = read("fixture-rich.apk");
    let tree: AxmlTree = parse_axml(&entry(&apk, "AndroidManifest.xml")).expect("axml parses");
    let ours: Vec<Element> = disrobe_elements(&tree);
    let dump: String = read_text("aapt2/fixture-rich.manifest.xmltree.txt");
    let mutated: String = dump.replacen(
        "debuggable(0x0101000f)=true",
        "debuggable(0x0101000f)=false",
        1,
    );
    assert_ne!(dump, mutated, "the mutation control changed the reference");
    assert_ne!(ours, aapt2_elements(&mutated));
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ResourceLine {
    id: u32,
    name: String,
    values: BTreeMap<String, String>,
}

fn aapt2_resources(dump: &str) -> Vec<ResourceLine> {
    let mut out: Vec<ResourceLine> = Vec::new();
    for line in dump.lines() {
        let body: &str = line.trim_start();
        if let Some(rest) = body.strip_prefix("resource 0x") {
            let (id, name): (&str, &str) = rest.split_once(' ').expect("resource id and name");
            out.push(ResourceLine {
                id: u32::from_str_radix(id, 16).expect("hex id"),
                name: name.to_owned(),
                values: BTreeMap::new(),
            });
        } else if body.starts_with('(') {
            let (config, value): (&str, &str) = body.split_once(") ").expect("config and value");
            let last: &mut ResourceLine = out.last_mut().expect("value follows a resource");
            last.values
                .insert(config.trim_start_matches('(').to_owned(), value.to_owned());
        }
    }
    out
}

fn canonical_value(value: &str) -> String {
    let trimmed: &str = value.trim();
    if let Some(dimension) = trimmed
        .strip_suffix("dp")
        .or_else(|| trimmed.strip_suffix("sp"))
        .or_else(|| trimmed.strip_suffix("px"))
        .or_else(|| trimmed.strip_suffix("pt"))
        .or_else(|| trimmed.strip_suffix("mm"))
        .or_else(|| trimmed.strip_suffix("in"))
        && let Ok(number) = dimension.parse::<f64>()
    {
        let unit: &str = &trimmed[dimension.len()..];
        return format!("{number:.3}{unit}");
    }
    if let Some(path) = trimmed.strip_prefix("(file) ") {
        return path.split(" type=").next().unwrap_or(path).to_owned();
    }
    if trimmed == "(id)" {
        return "false".to_owned();
    }
    trimmed.trim_matches('"').to_ascii_lowercase()
}

fn disrobe_resources(table: &ResourceTable) -> Vec<ResourceLine> {
    let mut by_id: BTreeMap<u32, ResourceLine> = BTreeMap::new();
    for package in &table.packages {
        for type_config in &package.types {
            let type_name: &str = package
                .type_strings
                .strings
                .get(usize::from(type_config.type_id) - 1)
                .map(String::as_str)
                .expect("type name");
            for entry in &type_config.entries {
                let id: u32 =
                    (package.id << 24) | (u32::from(type_config.type_id) << 16) | entry.entry_id;
                let line: &mut ResourceLine = by_id.entry(id).or_insert_with(|| ResourceLine {
                    id,
                    name: format!("{type_name}/{}", entry.key),
                    values: BTreeMap::new(),
                });
                let value: String = match &entry.value {
                    ResEntryValue::Simple(v) => v.formatted.clone(),
                    ResEntryValue::Bag { items, .. } => format!("(bag {} items)", items.len()),
                };
                line.values.insert(type_config.qualifier.clone(), value);
            }
        }
    }
    by_id.into_values().collect()
}

type CanonicalResource = (u32, String, Vec<(String, String)>);

fn canonical(lines: &[ResourceLine]) -> Vec<CanonicalResource> {
    lines
        .iter()
        .map(|line: &ResourceLine| {
            (
                line.id,
                line.name.clone(),
                line.values
                    .iter()
                    .map(|(config, value): (&String, &String)| {
                        (config.clone(), canonical_value(value))
                    })
                    .collect(),
            )
        })
        .collect()
}

fn assert_resources_match_aapt2(fixture: &str) {
    let apk: Vec<u8> = read(&format!("{fixture}.apk"));
    let table: ResourceTable = parse_arsc(&entry(&apk, "resources.arsc")).expect("arsc parses");
    let ours: Vec<ResourceLine> = disrobe_resources(&table);
    let reference: Vec<ResourceLine> =
        aapt2_resources(&read_text(&format!("aapt2/{fixture}.resources.txt")));
    assert!(
        reference.len() >= 4,
        "the aapt2 dump lists the fixture's resources"
    );
    assert_eq!(
        canonical(&ours),
        canonical(&reference),
        "{fixture}: resource ids, names and per-config values must equal `aapt2 dump resources`\nours: {ours:#?}"
    );
}

#[test]
fn rich_resources_decode_equal_to_aapt2_dump() {
    assert_resources_match_aapt2("fixture-rich");
}

#[test]
fn res_resources_decode_equal_to_aapt2_dump() {
    assert_resources_match_aapt2("fixture-res");
}

#[test]
fn the_resource_comparison_turns_red_on_one_changed_value() {
    let dump: String = read_text("aapt2/fixture-res.resources.txt");
    let mutated: String = dump.replacen("() 5", "() 6", 1);
    assert_ne!(dump, mutated);
    let apk: Vec<u8> = read("fixture-res.apk");
    let table: ResourceTable = parse_arsc(&entry(&apk, "resources.arsc")).expect("arsc parses");
    assert_ne!(
        canonical(&disrobe_resources(&table)),
        canonical(&aapt2_resources(&mutated))
    );
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Badging {
    package: String,
    version_code: i64,
    version_name: String,
    min_sdk: i64,
    target_sdk: i64,
    permissions: Vec<String>,
    debuggable: bool,
    launchable: Vec<String>,
    label: String,
}

fn quoted<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let start: usize = line.find(&format!("{key}='"))? + key.len() + 2;
    let rest: &str = &line[start..];
    rest.split('\'').next()
}

fn aapt2_badging(dump: &str) -> Badging {
    let mut badging: Badging = Badging {
        package: String::new(),
        version_code: 0,
        version_name: String::new(),
        min_sdk: 0,
        target_sdk: 0,
        permissions: Vec::new(),
        debuggable: false,
        launchable: Vec::new(),
        label: String::new(),
    };
    for line in dump.lines() {
        if let Some(rest) = line.strip_prefix("package: ") {
            quoted(rest, "name")
                .expect("package name")
                .clone_into(&mut badging.package);
            badging.version_code = quoted(rest, "versionCode")
                .expect("versionCode")
                .parse()
                .expect("int");
            quoted(rest, "versionName")
                .expect("versionName")
                .clone_into(&mut badging.version_name);
        } else if let Some(rest) = line.strip_prefix("minSdkVersion:'") {
            badging.min_sdk = rest.trim_end_matches('\'').parse().expect("int");
        } else if let Some(rest) = line.strip_prefix("targetSdkVersion:'") {
            badging.target_sdk = rest.trim_end_matches('\'').parse().expect("int");
        } else if let Some(rest) = line.strip_prefix("uses-permission: ") {
            badging
                .permissions
                .push(quoted(rest, "name").expect("permission").to_owned());
        } else if let Some(rest) = line.strip_prefix("uses-implied-permission: ") {
            let implied: &str = quoted(rest, "name").expect("implied permission");
            badging.permissions.retain(|p: &String| p != implied);
        } else if let Some(rest) = line.strip_prefix("application-label:'") {
            rest.trim_end_matches('\'').clone_into(&mut badging.label);
        } else if line == "application-debuggable" {
            badging.debuggable = true;
        } else if let Some(rest) = line.strip_prefix("launchable-activity: ") {
            badging
                .launchable
                .push(quoted(rest, "name").expect("activity").to_owned());
        }
    }
    badging.permissions.sort();
    badging
}

fn disrobe_badging(facts: &ManifestFacts) -> Badging {
    Badging {
        package: facts.package.clone().unwrap_or_default(),
        version_code: facts.version_code.unwrap_or_default(),
        version_name: facts.version_name.clone().unwrap_or_default(),
        min_sdk: facts.min_sdk.unwrap_or_default(),
        target_sdk: facts.target_sdk.unwrap_or_default(),
        permissions: facts.uses_permissions.clone(),
        debuggable: facts.debuggable.unwrap_or(false),
        launchable: facts.launchable_activities.clone(),
        label: facts.application_label.clone().unwrap_or_default(),
    }
}

fn assert_facts_match_badging(fixture: &str) -> ManifestFacts {
    let apk: Vec<u8> = read(&format!("{fixture}.apk"));
    let report: ApkResourceReport = analyze_apk_resources(&apk).expect("apk analysis");
    let facts: ManifestFacts = report.manifest.expect("manifest facts");
    let reference: Badging = aapt2_badging(&read_text(&format!("aapt2/{fixture}.badging.txt")));
    assert!(!reference.package.is_empty());
    assert_eq!(
        disrobe_badging(&facts),
        reference,
        "{fixture}: manifest facts must equal `aapt2 dump badging`"
    );
    facts
}

#[test]
fn rich_manifest_facts_equal_aapt2_badging_and_name_exported_components() {
    let facts: ManifestFacts = assert_facts_match_badging("fixture-rich");
    let components: Vec<(String, String, bool, bool)> = facts
        .components
        .iter()
        .map(|c: &ManifestComponent| {
            (
                c.kind.label().to_owned(),
                c.name.clone(),
                c.effectively_exported,
                c.launchable,
            )
        })
        .collect();
    assert_eq!(
        components,
        vec![
            (
                "activity".to_owned(),
                "com.disrobe.rich.MainActivity".to_owned(),
                true,
                true
            ),
            (
                "service".to_owned(),
                "com.disrobe.rich.SyncService".to_owned(),
                false,
                false
            ),
        ]
    );
    assert_eq!(facts.exported_components, 1);
    assert_eq!(facts.allow_backup, Some(false));
    assert_eq!(facts.debuggable, Some(true));
}

#[test]
fn res_manifest_facts_equal_aapt2_badging() {
    let facts: ManifestFacts = assert_facts_match_badging("fixture-res");
    assert_eq!(facts.components.len(), 1);
    assert_eq!(
        facts.components[0].name,
        "com.disrobe.resfixture.MainActivity"
    );
}

#[test]
fn the_badging_comparison_turns_red_on_one_changed_fact() {
    let apk: Vec<u8> = read("fixture-rich.apk");
    let report: ApkResourceReport = analyze_apk_resources(&apk).expect("apk analysis");
    let facts: ManifestFacts = report.manifest.expect("manifest facts");
    let dump: String = read_text("aapt2/fixture-rich.badging.txt");
    let mutated: String = dump.replacen("targetSdkVersion:'34'", "targetSdkVersion:'33'", 1);
    assert_ne!(dump, mutated);
    assert_ne!(disrobe_badging(&facts), aapt2_badging(&mutated));
}
