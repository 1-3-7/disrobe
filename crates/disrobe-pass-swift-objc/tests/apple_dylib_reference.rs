#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use disrobe_pass_swift_objc::macho::{
    FunctionSymbol, ParsedSlice, Section, Segment, function_symbols, parse_slice,
};
use disrobe_pass_swift_objc::objc::{ObjcClassDump, class_dump};
use disrobe_pass_swift_objc::objc_records::{ObjcInterface, ObjcMethod};

fn runner(name: &str) -> Vec<u8> {
    let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus/apple/runner")
        .join(name);
    std::fs::read(&path)
        .unwrap_or_else(|error| panic!("runner fixture {} is required: {error}", path.display()))
}

fn text(name: &str) -> String {
    String::from_utf8(runner(name)).expect("utf-8 reference")
}

fn hex(value: &str) -> u64 {
    u64::from_str_radix(value.trim_start_matches("0x"), 16).expect("hex")
}

fn nm_symbols(listing: &str, kinds: &[&str]) -> BTreeSet<(u64, String)> {
    listing
        .lines()
        .filter_map(|line: &str| {
            let mut fields = line.splitn(3, ' ');
            let address: &str = fields.next()?;
            let kind: &str = fields.next()?;
            let name: &str = fields.next()?;
            kinds
                .contains(&kind)
                .then(|| (hex(address), name.to_owned()))
        })
        .collect()
}

type MethodKey = (String, char, String);

fn nm_objc_methods(listing: &str) -> BTreeSet<MethodKey> {
    nm_symbols(listing, &["T", "t"])
        .into_iter()
        .filter_map(|(_, name): (u64, String)| {
            let kind: char = name.chars().next()?;
            if !matches!(kind, '-' | '+') {
                return None;
            }
            let body: &str = name.get(1..)?.strip_prefix('[')?.strip_suffix(']')?;
            let (owner, selector): (&str, &str) = body.split_once(' ')?;
            let class: &str = owner.split_once('(').map_or(owner, |(class, _)| class);
            Some((class.to_owned(), kind, selector.to_owned()))
        })
        .collect()
}

const fn method_kind(method: &ObjcMethod) -> char {
    if method.is_class_method { '+' } else { '-' }
}

fn dump_methods(dump: &ObjcClassDump) -> BTreeSet<MethodKey> {
    let mut out: BTreeSet<MethodKey> = BTreeSet::new();
    for interface in &dump.interfaces {
        for method in interface
            .instance_methods
            .iter()
            .chain(&interface.class_methods)
        {
            out.insert((
                interface.name.clone(),
                method_kind(method),
                method.name.clone(),
            ));
        }
    }
    for category in &dump.categories {
        let class: String = category.class_name.clone().unwrap_or_default();
        for method in category
            .instance_methods
            .iter()
            .chain(&category.class_methods)
        {
            out.insert((class.clone(), method_kind(method), method.name.clone()));
        }
    }
    out
}

struct ClassBlock {
    address: u64,
    name: Option<String>,
    superclass_address: u64,
    superclass_symbol: Option<String>,
}

fn otool_superclasses(listing: &str) -> BTreeMap<String, Option<String>> {
    let mut blocks: Vec<ClassBlock> = Vec::new();
    let mut in_classlist: bool = false;
    let mut meta: bool = false;
    for line in listing.lines() {
        if line.starts_with("Contents of ") {
            in_classlist = line.contains("__objc_classlist");
            continue;
        }
        if !in_classlist {
            continue;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        let header: bool = line.len() > 17
            && line.as_bytes()[0].is_ascii_hexdigit()
            && line.as_bytes()[16] == b' '
            && fields.len() >= 2
            && fields[1].starts_with("0x");
        if header {
            blocks.push(ClassBlock {
                address: hex(fields[1]),
                name: None,
                superclass_address: 0,
                superclass_symbol: None,
            });
            meta = false;
        } else if line.trim() == "Meta Class" {
            meta = true;
        } else if !meta && fields.first() == Some(&"superclass") {
            let block: &mut ClassBlock = blocks.last_mut().expect("superclass inside a class");
            block.superclass_address = hex(fields[1]);
            block.superclass_symbol = fields.get(2).map(|symbol: &&str| (*symbol).to_owned());
        } else if !meta && line.starts_with("        name ") {
            let block: &mut ClassBlock = blocks.last_mut().expect("name inside a class");
            if block.name.is_none() {
                block.name = fields.get(2).map(|name: &&str| (*name).to_owned());
            }
        }
    }
    let by_address: BTreeMap<u64, String> = blocks
        .iter()
        .filter_map(|block: &ClassBlock| {
            block.name.clone().map(|name: String| (block.address, name))
        })
        .collect();
    blocks
        .iter()
        .map(|block: &ClassBlock| {
            let expected: Option<String> = block
                .superclass_symbol
                .as_deref()
                .and_then(|symbol: &str| symbol.strip_prefix("_OBJC_CLASS_$_"))
                .map(str::to_owned)
                .or_else(|| by_address.get(&block.superclass_address).cloned());
            (block.name.clone().expect("class name"), expected)
        })
        .collect()
}

struct Dylib {
    slice: Vec<u8>,
    parsed: ParsedSlice,
}

fn dylib(bytes: Vec<u8>) -> Dylib {
    let parsed: ParsedSlice = parse_slice(&bytes).expect("thin arm64 dylib");
    Dylib {
        slice: bytes,
        parsed,
    }
}

fn text_section(parsed: &ParsedSlice) -> (u64, u64) {
    parsed
        .segments
        .iter()
        .flat_map(|segment: &Segment| segment.sections.iter())
        .find(|section: &&Section| section.seg == "__TEXT" && section.name == "__text")
        .map(|section: &Section| (section.addr, section.addr + section.size))
        .expect("__TEXT,__text")
}

#[test]
fn function_symbols_match_nm() {
    let image: Dylib = dylib(runner("Fixture.dylib"));
    let listing: String = text("Fixture.dylib.nm-defined.txt");
    let (start, end): (u64, u64) = text_section(&image.parsed);
    let recovered: BTreeSet<(u64, String)> = function_symbols(&image.slice, &image.parsed)
        .into_iter()
        .map(|symbol: FunctionSymbol| (symbol.address, symbol.name))
        .collect();
    let in_text: BTreeSet<(u64, String)> = recovered
        .iter()
        .filter(|(address, _)| (start..end).contains(address))
        .cloned()
        .collect();
    let expected: BTreeSet<(u64, String)> = nm_symbols(&listing, &["T", "t"]);
    assert_eq!(
        in_text, expected,
        "symbols inside __TEXT,__text against nm's T and t"
    );
    let section_symbols: BTreeSet<(u64, String)> = nm_symbols(&listing, &["S", "s"]);
    let outside: Vec<&(u64, String)> = recovered.difference(&in_text).collect();
    assert!(
        outside
            .iter()
            .all(|symbol| section_symbols.contains(*symbol)),
        "code symbols outside __text that nm does not list as section symbols: {outside:?}"
    );
    assert!(
        expected.len() >= 100,
        "only {} text symbols graded",
        expected.len()
    );
    for name in ["_fx_add", "_fx_public_twice", "-[FXLegacyView refresh:]"] {
        assert!(expected.iter().any(|(_, symbol)| symbol == name), "{name}");
    }
}

#[test]
fn objc_methods_and_superclasses_match_nm_and_otool() {
    let image: Dylib = dylib(runner("Fixture.dylib"));
    let dump: ObjcClassDump = class_dump(&image.slice, &image.parsed);
    let expected_methods: BTreeSet<MethodKey> =
        nm_objc_methods(&text("Fixture.dylib.nm-defined.txt"));
    assert!(
        expected_methods.len() >= 7,
        "nm lists {} objc methods",
        expected_methods.len()
    );
    let missing: Vec<MethodKey> = expected_methods
        .difference(&dump_methods(&dump))
        .cloned()
        .collect();
    assert!(
        missing.is_empty(),
        "objc methods nm names that the class dump lacks: {missing:?}"
    );
    let expected_supers: BTreeMap<String, Option<String>> =
        otool_superclasses(&text("Fixture.dylib.otool-ov.txt"));
    assert_eq!(expected_supers.len(), 5, "{expected_supers:?}");
    let recovered_supers: BTreeMap<String, Option<String>> = dump
        .interfaces
        .iter()
        .map(|interface: &ObjcInterface| (interface.name.clone(), interface.superclass.clone()))
        .collect();
    assert_eq!(recovered_supers, expected_supers);
    assert_eq!(
        expected_supers.get("_TtC7Fixture22SettingsViewController"),
        Some(&Some("UIViewController".to_owned()))
    );
    assert_eq!(
        expected_supers.get("_TtC7Fixture9ValueCell"),
        Some(&Some("_TtC7Fixture8BaseCell".to_owned()))
    );
}

#[test]
fn a_changed_superclass_reference_is_caught() {
    let listing: String = text("Fixture.dylib.otool-ov.txt").replacen(
        "superclass 0x0 _OBJC_CLASS_$_UIViewController",
        "superclass 0x0 _OBJC_CLASS_$_UINavigationController",
        1,
    );
    let image: Dylib = dylib(runner("Fixture.dylib"));
    let dump: ObjcClassDump = class_dump(&image.slice, &image.parsed);
    let recovered: BTreeMap<String, Option<String>> = dump
        .interfaces
        .iter()
        .map(|interface: &ObjcInterface| (interface.name.clone(), interface.superclass.clone()))
        .collect();
    assert_ne!(recovered, otool_superclasses(&listing));
}
