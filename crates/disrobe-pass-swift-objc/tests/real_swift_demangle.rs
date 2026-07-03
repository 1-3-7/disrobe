#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

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

fn driver_arm64_slice() -> Option<(Vec<u8>, ParsedSlice)> {
    let bytes: Vec<u8> = load_fixture("swift-driver")?;
    let entries: Vec<macho::FatArchEntry> = macho::walk_fat(&bytes).ok()?;
    let entry: &macho::FatArchEntry = entries
        .iter()
        .find(|a: &&macho::FatArchEntry| matches!(a.cpu, macho::CpuKind::Arm64))
        .or_else(|| entries.first())?;
    let inner: &[u8] = macho::slice_bytes(&bytes, entry)?;
    let parsed: ParsedSlice = macho::parse_slice(inner).ok()?;
    Some((inner.to_vec(), parsed))
}

fn tuple_shaped(mangled: &str) -> bool {
    mangled.ends_with('t') && mangled.contains('_') && mangled.is_ascii()
}

#[test]
fn swift_driver_enum_payload_tuples_demangle_above_threshold() {
    use disrobe_pass_swift_objc::swift::{self, SwiftClassDump};
    use disrobe_pass_swift_objc::swift_typedump::{NominalKind, SwiftNominalType};

    let Some((slice, parsed)): Option<(Vec<u8>, ParsedSlice)> = driver_arm64_slice() else {
        eprintln!("skip: macho-mac/swift-driver fixture absent or not universal");
        return;
    };
    let dump: SwiftClassDump = swift::class_dump(&slice, &parsed);

    let payloads: Vec<String> = dump
        .type_dump
        .nominal_types
        .iter()
        .filter(|t: &&SwiftNominalType| matches!(t.kind, NominalKind::Enum))
        .flat_map(|t: &SwiftNominalType| t.fields.iter())
        .filter_map(|f| f.mangled_type.clone())
        .filter(|m: &String| tuple_shaped(m))
        .collect();

    assert!(
        payloads.len() >= 15,
        "swift-driver's own __swift5_fieldmd must expose 15+ tuple-shaped enum payloads, got {}",
        payloads.len()
    );

    let demangled: usize = payloads
        .iter()
        .filter(|m: &&String| {
            demangle::demangle_type(m)
                .is_some_and(|d: String| d.starts_with('(') && d.ends_with(')'))
        })
        .count();
    let ratio: f64 = demangled as f64 / payloads.len() as f64;
    assert!(
        ratio >= 0.85,
        "labeled-tuple payload demangling must clear 85% of the binary's own tuple payloads, \
         got {demangled}/{} = {:.1}%",
        payloads.len(),
        ratio * 100.0
    );

    let labeled: bool = payloads
        .iter()
        .any(|m: &String| demangle::demangle_type(m).is_some_and(|d: String| d.contains(": ")));
    assert!(
        labeled,
        "at least one recovered enum payload must carry a Swift tuple element label"
    );
}

#[test]
fn swift_driver_field_types_demangle_at_ceiling() {
    use disrobe_pass_swift_objc::swift::{self, SwiftClassDump};
    use disrobe_pass_swift_objc::swift_typedump::SwiftNominalType;

    let Some((slice, parsed)): Option<(Vec<u8>, ParsedSlice)> = driver_arm64_slice() else {
        eprintln!("skip: macho-mac/swift-driver fixture absent or not universal");
        return;
    };
    let dump: SwiftClassDump = swift::class_dump(&slice, &parsed);

    let field_types: Vec<String> = dump
        .type_dump
        .nominal_types
        .iter()
        .flat_map(|t: &SwiftNominalType| t.fields.iter())
        .filter_map(|f| f.mangled_type.clone())
        .filter(|m: &String| m.is_ascii())
        .collect();
    assert!(
        field_types.len() >= 400,
        "binary-context symbolic-ref resolution must surface 400+ ascii field-type mangled \
         names, got {}",
        field_types.len()
    );

    let demangled: usize = field_types
        .iter()
        .filter(|m: &&String| demangle::demangle_type(m).is_some())
        .count();
    let ratio: f64 = demangled as f64 / field_types.len() as f64;
    assert!(
        ratio >= 0.98,
        "field-type demangling must hold the recovered ceiling, got {demangled}/{} = {:.1}%",
        field_types.len(),
        ratio * 100.0
    );

    let objc: bool = field_types
        .iter()
        .filter_map(|m: &String| demangle::demangle_type(m))
        .any(|d: String| d.contains("__C."));
    assert!(
        objc,
        "objc-imported field types must resolve to the __C clang-importer module"
    );

    let symbolic_resolved: bool = field_types
        .iter()
        .filter_map(|m: &String| demangle::demangle_type(m))
        .any(|d: String| d.contains("swiftscan_") || d.contains("SwiftDriver"));
    assert!(
        symbolic_resolved,
        "a symbolic-referenced field type must resolve to its descriptor name via binary context"
    );

    let c_function: bool = field_types
        .iter()
        .filter_map(|m: &String| demangle::demangle_type(m))
        .any(|d: String| d.contains("@convention(c)"));
    assert!(
        c_function,
        "a C-convention function-pointer field type must demangle to its signature"
    );
}

fn resolve_reference_demangler() -> Option<PathBuf> {
    let exe: &str = if cfg!(windows) {
        "swift-demangle.exe"
    } else {
        "swift-demangle"
    };
    let path_var: std::ffi::OsString = std::env::var_os("PATH")?;
    std::env::split_paths(&path_var)
        .map(|dir: PathBuf| dir.join(exe))
        .find(|candidate: &PathBuf| candidate.is_file())
}

fn reference_demangle(tool: &Path, symbols: &[String]) -> Option<Vec<String>> {
    use std::io::Write;
    let joined: String = symbols.join("\n");
    let mut child: std::process::Child = Command::new(tool)
        .arg("--compact")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    child.stdin.take()?.write_all(joined.as_bytes()).ok()?;
    let output: std::process::Output = child.wait_with_output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text: String = String::from_utf8(output.stdout).ok()?;
    let lines: Vec<String> = text.lines().map(str::to_owned).collect();
    (lines.len() == symbols.len()).then_some(lines)
}

#[test]
fn swift_driver_symbols_match_reference_demangler_exactly() {
    let Some(tool): Option<PathBuf> = resolve_reference_demangler() else {
        eprintln!("skip: swift-demangle not on PATH (reference oracle absent on this host)");
        return;
    };
    let Some((slice, parsed)): Option<(Vec<u8>, ParsedSlice)> = driver_arm64_slice() else {
        eprintln!("skip: macho-mac/swift-driver fixture absent or not universal");
        return;
    };
    let symbols: Vec<String> = swift_mangled_symbols(&slice, &parsed);
    assert!(
        symbols.len() >= 400,
        "swift-driver must expose 400+ Swift-mangled symbols for the reference oracle, got {}",
        symbols.len()
    );
    let Some(reference): Option<Vec<String>> = reference_demangle(&tool, &symbols) else {
        eprintln!("skip: reference swift-demangle produced no comparable output");
        return;
    };

    let ours: Vec<String> = symbols
        .iter()
        .map(|s: &String| demangle::demangle(s).unwrap_or_else(|_| s.clone()))
        .collect();
    let matched: usize = reference
        .iter()
        .zip(ours.iter())
        .filter(|(r, o): &(&String, &String)| r == o)
        .count();
    let ratio: f64 = matched as f64 / symbols.len() as f64;
    assert!(
        ratio >= 0.75,
        "demangler must byte-match the real swift-demangle on >=75% of the binary's own \
         symbols, got {matched}/{} = {:.2}%",
        symbols.len(),
        ratio * 100.0
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
