#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::fs;
use std::path::{Path, PathBuf};

use disrobe_pass_swift_objc::demangle;
use disrobe_pass_swift_objc::macho::{self, MachoKind, ParsedSlice};

fn corpus_root() -> PathBuf {
    let manifest_dir: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root: &Path = manifest_dir
        .ancestors()
        .nth(2)
        .expect("workspace root above crate");
    workspace_root
        .join("corpus")
        .join("mobile")
        .join("macho-mac")
}

fn load_fixture(name: &str) -> Option<Vec<u8>> {
    fs::read(corpus_root().join(name)).ok()
}

fn thin_slice(bytes: &[u8]) -> Option<(Vec<u8>, ParsedSlice)> {
    match macho::detect_magic(bytes)? {
        MachoKind::Fat32 | MachoKind::Fat64 => {
            let entries: Vec<macho::FatArchEntry> = macho::walk_fat(bytes).ok()?;
            let entry: &macho::FatArchEntry = entries.first()?;
            let inner: &[u8] = macho::slice_bytes(bytes, entry)?;
            let parsed: ParsedSlice = macho::parse_slice(inner).ok()?;
            Some((inner.to_vec(), parsed))
        }
        _ => {
            let parsed: ParsedSlice = macho::parse_slice(bytes).ok()?;
            Some((bytes.to_vec(), parsed))
        }
    }
}

fn swift_mangled_symbols(slice: &[u8], parsed: &ParsedSlice) -> Vec<String> {
    let mut out: Vec<String> = macho::symbol_names(slice, parsed)
        .into_iter()
        .filter(|s: &String| demangle::looks_like_swift_mangled(s))
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

#[test]
fn swift_hello_symbol_table_demangles_above_threshold() {
    let Some(bytes): Option<Vec<u8>> = load_fixture("SwiftHello.original") else {
        eprintln!("skip: macho-mac/SwiftHello.original fixture absent (LEGAL.md sourcing-gated)");
        return;
    };
    let (slice, parsed): (Vec<u8>, ParsedSlice) = thin_slice(&bytes).expect("thin slice");
    let symbols: Vec<String> = swift_mangled_symbols(&slice, &parsed);

    assert!(
        symbols.len() >= 30,
        "SwiftHello.original LC_SYMTAB must expose 30+ Swift-mangled symbols, got {}",
        symbols.len()
    );

    let demangled: usize = symbols
        .iter()
        .filter(|s: &&String| demangle::demangle(s).is_ok())
        .count();
    let ratio: f64 = demangled as f64 / symbols.len() as f64;
    assert!(
        ratio >= 0.95,
        "demangler must recover >=95% of the binary's own symbols, got {}/{} = {:.1}%",
        demangled,
        symbols.len(),
        ratio * 100.0
    );
}

#[test]
fn swift_hello_demangle_recovers_ground_truth_class_names() {
    let Some(bytes): Option<Vec<u8>> = load_fixture("SwiftHello.original") else {
        eprintln!("skip: macho-mac/SwiftHello.original fixture absent");
        return;
    };
    let (slice, parsed): (Vec<u8>, ParsedSlice) = thin_slice(&bytes).expect("thin slice");
    let symbols: Vec<String> = swift_mangled_symbols(&slice, &parsed);

    let rendered: Vec<String> = symbols
        .iter()
        .filter_map(|s: &String| demangle::demangle(s).ok())
        .collect();
    let joined: String = rendered.join("\n");

    for expected in [
        "SwiftHello.LoginViewController",
        "SwiftHello.AuthenticationService",
    ] {
        assert!(
            joined.contains(expected),
            "demangled symbol table must contain ground-truth class {expected}"
        );
    }
}

#[test]
fn swift_hello_demangle_recovers_entity_kinds_and_descriptors() {
    let Some(bytes): Option<Vec<u8>> = load_fixture("SwiftHello.original") else {
        eprintln!("skip: macho-mac/SwiftHello.original fixture absent");
        return;
    };
    let (slice, parsed): (Vec<u8>, ParsedSlice) = thin_slice(&bytes).expect("thin slice");
    let symbols: Vec<String> = swift_mangled_symbols(&slice, &parsed);
    let rendered: String = symbols
        .iter()
        .filter_map(|s: &String| demangle::demangle(s).ok())
        .collect::<Vec<String>>()
        .join("\n");

    assert!(
        rendered.contains("nominal type descriptor for SwiftHello."),
        "expected a recovered nominal type descriptor entity"
    );
    assert!(
        rendered.contains("type metadata for SwiftHello."),
        "expected a recovered type-metadata entity"
    );
    assert!(
        rendered.contains("field offset for SwiftHello."),
        "expected a recovered field-offset entity carrying a real property name"
    );
    assert!(
        rendered.contains(".__deallocating_deinit"),
        "expected a recovered deallocating destructor entity"
    );
    assert!(
        rendered.contains("(class)"),
        "expected at least one bare nominal class rendered with its kind"
    );
}

#[test]
fn swift_hello_obfuscated_symbol_table_still_demangles_structurally() {
    let Some(bytes): Option<Vec<u8>> = load_fixture("SwiftHello.obfuscated") else {
        eprintln!("skip: macho-mac/SwiftHello.obfuscated fixture absent");
        return;
    };
    let (slice, parsed): (Vec<u8>, ParsedSlice) = thin_slice(&bytes).expect("thin slice");
    let symbols: Vec<String> = swift_mangled_symbols(&slice, &parsed);
    assert!(
        symbols.len() >= 30,
        "obfuscated binary still carries 30+ mangled symbols, got {}",
        symbols.len()
    );
    let demangled: usize = symbols
        .iter()
        .filter(|s: &&String| demangle::demangle(s).is_ok())
        .count();
    let ratio: f64 = demangled as f64 / symbols.len() as f64;
    assert!(
        ratio >= 0.95,
        "demangler structure-recovers obfuscated symbols too: {}/{} = {:.1}%",
        demangled,
        symbols.len(),
        ratio * 100.0
    );
}
