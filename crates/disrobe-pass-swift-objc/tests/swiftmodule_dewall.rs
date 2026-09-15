#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "support/swift_toolchain.rs"]
#[allow(clippy::redundant_pub_crate, dead_code)]
mod swift_toolchain;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use swift_toolchain::resolve_swift_compiler;

use disrobe_pass_swift_objc::demangle;
use disrobe_pass_swift_objc::swiftinterface::{
    self, InterfaceCase, InterfaceDecl, InterfaceDeclKind, InterfaceMethod, InterfaceProperty,
    ParsedInterface,
};
use disrobe_pass_swift_objc::{SwiftModuleDecls, is_swift_module, read_swift_module};

const MODULE_NAME: &str = "GreetingKit";
const SOURCE_FILE: &str = "Greeting.swift";
const MODULE_FILE: &str = "GreetingKit.swiftmodule";
const INTERFACE_FILE: &str = "GreetingKit.swiftinterface";

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("swiftmodule")
}

fn load(name: &str) -> Vec<u8> {
    let path: PathBuf = fixture_dir().join(name);
    fs::read(&path).unwrap_or_else(|e| panic!("read fixture {}: {e}", path.display()))
}

fn load_text(name: &str) -> String {
    String::from_utf8(load(name)).unwrap_or_else(|e| panic!("fixture {name} is not utf-8: {e}"))
}

fn committed_module() -> SwiftModuleDecls {
    let bytes: Vec<u8> = load(MODULE_FILE);
    assert!(
        is_swift_module(&bytes),
        "fixture must carry the Swift serialized-module signature"
    );
    read_swift_module(&bytes).expect("read swiftmodule")
}

fn recovered_identifiers(decls: &SwiftModuleDecls) -> BTreeSet<String> {
    decls.identifiers.iter().cloned().collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum DeclaredRole {
    Nominal,
    Property,
    Method,
    Case,
}

const fn nominal_role(kind: InterfaceDeclKind) -> Option<DeclaredRole> {
    match kind {
        InterfaceDeclKind::Class
        | InterfaceDeclKind::Struct
        | InterfaceDeclKind::Enum
        | InterfaceDeclKind::Protocol
        | InterfaceDeclKind::Actor => Some(DeclaredRole::Nominal),
        InterfaceDeclKind::Extension => None,
    }
}

fn declared_roles(parsed: &ParsedInterface) -> BTreeMap<String, BTreeSet<DeclaredRole>> {
    let mut out: BTreeMap<String, BTreeSet<DeclaredRole>> = BTreeMap::new();
    let mut record = |name: &str, role: DeclaredRole| {
        if !name.is_empty() {
            out.entry(name.to_owned()).or_default().insert(role);
        }
    };
    for decl in &parsed.decls {
        let d: &InterfaceDecl = decl;
        if let Some(role) = nominal_role(d.kind) {
            record(&d.name, role);
        }
        for p in &d.properties {
            let p: &InterfaceProperty = p;
            record(&p.name, DeclaredRole::Property);
        }
        for m in &d.methods {
            let m: &InterfaceMethod = m;
            record(&m.name, DeclaredRole::Method);
        }
        for c in &d.cases {
            let c: &InterfaceCase = c;
            record(&c.name, DeclaredRole::Case);
        }
    }
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NonDeclarationOrigin {
    ClassInitializerMangledSymbol,
    ArgumentLabelInDeclaredSignature,
    ImplicitSetterParameter,
    SynthesizedHashableWitness,
    ImportedStdlibName,
    ImplicitProtocolConformance,
}

const IDENTIFIER_TABLE_NON_DECLARATIONS: [(&str, NonDeclarationOrigin); 19] = [
    (
        "$s11GreetingKit14CourierServiceC12channelLabelACSS_tcfc",
        NonDeclarationOrigin::ClassInitializerMangledSymbol,
    ),
    (
        "$s11GreetingKit14CourierServiceC12channelLabelACSS_tcfC",
        NonDeclarationOrigin::ClassInitializerMangledSymbol,
    ),
    ("a", NonDeclarationOrigin::ArgumentLabelInDeclaredSignature),
    ("b", NonDeclarationOrigin::ArgumentLabelInDeclaredSignature),
    (
        "into",
        NonDeclarationOrigin::ArgumentLabelInDeclaredSignature,
    ),
    (
        "hasher",
        NonDeclarationOrigin::ArgumentLabelInDeclaredSignature,
    ),
    (
        "greeting",
        NonDeclarationOrigin::ArgumentLabelInDeclaredSignature,
    ),
    ("value", NonDeclarationOrigin::ImplicitSetterParameter),
    (
        "_rawHashValue",
        NonDeclarationOrigin::SynthesizedHashableWitness,
    ),
    ("seed", NonDeclarationOrigin::SynthesizedHashableWitness),
    ("Swift", NonDeclarationOrigin::ImportedStdlibName),
    ("String", NonDeclarationOrigin::ImportedStdlibName),
    ("Int", NonDeclarationOrigin::ImportedStdlibName),
    ("Bool", NonDeclarationOrigin::ImportedStdlibName),
    ("Hasher", NonDeclarationOrigin::ImportedStdlibName),
    ("Equatable", NonDeclarationOrigin::ImportedStdlibName),
    ("Hashable", NonDeclarationOrigin::ImportedStdlibName),
    (
        "Copyable",
        NonDeclarationOrigin::ImplicitProtocolConformance,
    ),
    (
        "Escapable",
        NonDeclarationOrigin::ImplicitProtocolConformance,
    ),
];

const CONVENTION_BREAKING_DECLARATIONS: [&str; 2] = ["lowercaseBox", "PayloadTag"];

fn non_declaration_names() -> BTreeSet<&'static str> {
    IDENTIFIER_TABLE_NON_DECLARATIONS
        .iter()
        .map(|(name, _): &(&'static str, NonDeclarationOrigin)| *name)
        .collect()
}

fn signature_parameter_identifiers(signature: &str) -> BTreeSet<String> {
    let (Some(open), Some(close)): (Option<usize>, Option<usize>) =
        (signature.find('('), signature.rfind(')'))
    else {
        return BTreeSet::new();
    };
    let Some(inside): Option<&str> = signature.get(open + 1..close) else {
        return BTreeSet::new();
    };
    let mut out: BTreeSet<String> = BTreeSet::new();
    for chunk in inside.split(',') {
        let head: &str = chunk.split(':').next().unwrap_or("");
        for token in head.split_whitespace() {
            out.insert(token.to_owned());
        }
    }
    out
}

fn all_signature_parameter_identifiers(parsed: &ParsedInterface) -> BTreeSet<String> {
    parsed
        .decls
        .iter()
        .flat_map(|d: &InterfaceDecl| d.methods.iter())
        .flat_map(|m: &InterfaceMethod| signature_parameter_identifiers(&m.signature))
        .collect()
}

fn source_declared_identifiers(swift_src: &str) -> BTreeSet<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    for raw in swift_src.lines() {
        let line: &str = raw.trim();
        let body: &str = strip_source_modifiers(line);
        for keyword in [
            "struct ", "enum ", "class ", "func ", "let ", "var ", "case ",
        ] {
            if let Some(rest) = body.strip_prefix(keyword) {
                let name: &str = rest
                    .split([' ', '(', '<', ':', '=', '{'])
                    .next()
                    .unwrap_or("")
                    .trim();
                if !name.is_empty() && name.chars().all(|c: char| c.is_alphanumeric() || c == '_') {
                    out.insert(name.to_owned());
                }
            }
        }
    }
    out
}

fn strip_source_modifiers(line: &str) -> &str {
    let mut rest: &str = line.trim();
    loop {
        let word: Option<&str> = rest.split_whitespace().next();
        match word {
            Some(
                w @ ("public" | "private" | "internal" | "fileprivate" | "open" | "final"
                | "static" | "indirect" | "mutating"),
            ) => {
                rest = rest[w.len()..].trim_start();
            }
            _ => return rest,
        }
    }
}

fn interface_flag_value(interface_text: &str, flag: &str) -> Option<String> {
    let line: &str = interface_text
        .lines()
        .find(|l: &&str| l.starts_with("// swift-module-flags:"))?;
    let mut tokens: std::str::SplitWhitespace<'_> = line.split_whitespace();
    while let Some(token) = tokens.next() {
        if token == flag {
            return tokens.next().map(str::to_owned);
        }
    }
    None
}

fn interface_compiler_version(interface_text: &str) -> Option<String> {
    interface_text
        .lines()
        .find_map(|l: &str| l.strip_prefix("// swift-compiler-version:"))
        .map(str::trim)
        .map(str::to_owned)
}

#[test]
fn identifier_table_matches_the_interface_in_both_directions() {
    let decls: SwiftModuleDecls = committed_module();
    assert!(decls.signature_ok);
    let recovered: BTreeSet<String> = recovered_identifiers(&decls);

    let interface_text: String = load_text(INTERFACE_FILE);
    assert!(swiftinterface::looks_like_swiftinterface(&interface_text));
    let interface: ParsedInterface = swiftinterface::parse(&interface_text);
    let declared: BTreeMap<String, BTreeSet<DeclaredRole>> = declared_roles(&interface);
    let declared_names: BTreeSet<String> = declared.keys().cloned().collect();
    assert!(
        declared_names.len() >= 17,
        "the reference interface must declare the whole fixture surface, got {declared_names:?}"
    );

    let excluded: BTreeSet<&str> = non_declaration_names();
    let shadowed: Vec<&&str> = excluded
        .iter()
        .filter(|name: &&&str| declared_names.contains(**name))
        .collect();
    assert!(
        shadowed.is_empty(),
        "a named non-declaration must never shadow a real interface declaration: {shadowed:?}"
    );

    let missing: Vec<&String> = declared_names
        .iter()
        .filter(|name: &&String| !recovered.contains(*name))
        .collect();
    assert!(
        missing.is_empty(),
        "interface declarations absent from the recovered identifier table: {missing:?}"
    );

    let extra: BTreeSet<&str> = recovered
        .iter()
        .map(String::as_str)
        .filter(|name: &&str| !declared_names.contains(*name))
        .collect();
    let unexplained: Vec<&&str> = extra
        .iter()
        .filter(|name: &&&str| !excluded.contains(**name))
        .collect();
    assert!(
        unexplained.is_empty(),
        "recovered identifiers with neither an interface declaration nor a named justification: \
         {unexplained:?}"
    );
    let stale: Vec<&&str> = excluded
        .iter()
        .filter(|name: &&&str| !extra.contains(**name))
        .collect();
    assert!(
        stale.is_empty(),
        "named non-declarations the reader no longer emits: {stale:?}"
    );

    assert_eq!(
        recovered.len(),
        declared_names.len() + excluded.len(),
        "the identifier table is exactly the interface declarations plus the 19 named \
         non-declarations; recovered={recovered:?}"
    );
}

#[test]
fn every_named_non_declaration_is_individually_justified() {
    let interface_text: String = load_text(INTERFACE_FILE);
    let interface: ParsedInterface = swiftinterface::parse(&interface_text);
    let parameters: BTreeSet<String> = all_signature_parameter_identifiers(&interface);
    let settable_stored: Vec<&InterfaceProperty> = interface
        .decls
        .iter()
        .flat_map(|d: &InterfaceDecl| d.properties.iter())
        .filter(|p: &&InterfaceProperty| !p.is_let && !p.is_computed && !p.is_static)
        .collect();
    let hashable_conformance: bool = interface.decls.iter().any(|d: &InterfaceDecl| {
        d.conformances
            .iter()
            .any(|c: &String| c == "Swift.Hashable")
    });

    for (name, origin) in IDENTIFIER_TABLE_NON_DECLARATIONS {
        match origin {
            NonDeclarationOrigin::ClassInitializerMangledSymbol => {
                let demangled: String = demangle::demangle(name)
                    .unwrap_or_else(|e| panic!("{name} must demangle as a Swift symbol: {e}"));
                assert!(
                    demangled.starts_with("GreetingKit.CourierService."),
                    "{name} must demangle into this module's class, got {demangled}"
                );
                assert!(
                    demangled.contains("init(channelLabel: Swift.String)"),
                    "{name} must demangle to the declared initializer, got {demangled}"
                );
                assert!(
                    interface_text.contains("public init(channelLabel: Swift.String)"),
                    "the reference interface must declare the initializer the mangled symbol names"
                );
            }
            NonDeclarationOrigin::ArgumentLabelInDeclaredSignature => {
                assert!(
                    parameters.contains(name),
                    "{name} must appear as an argument label or parameter name in a declared \
                     signature; signature parameters are {parameters:?}"
                );
            }
            NonDeclarationOrigin::ImplicitSetterParameter => {
                assert!(
                    !settable_stored.is_empty(),
                    "{name} is the implicit setter parameter of a settable stored property, but \
                     the interface declares none"
                );
                assert!(
                    !parameters.contains(name),
                    "{name} must not also be a written parameter name, otherwise it belongs to \
                     the argument-label category"
                );
            }
            NonDeclarationOrigin::SynthesizedHashableWitness => {
                assert!(
                    hashable_conformance,
                    "{name} is part of the synthesized Hashable witness, but the interface \
                     declares no Swift.Hashable conformance"
                );
                assert!(
                    !interface_text.contains(name),
                    "{name} must be absent from the interface; a printed declaration would make \
                     it a real declaration, not a synthesis artifact"
                );
            }
            NonDeclarationOrigin::ImportedStdlibName => {
                let imported: bool = interface_text.contains(&format!("import {name}"))
                    || interface_text.contains(&format!("Swift.{name}"));
                assert!(
                    imported,
                    "{name} must be referenced by the interface as an imported module or a \
                     Swift.-qualified type"
                );
            }
            NonDeclarationOrigin::ImplicitProtocolConformance => {
                assert!(
                    matches!(name, "Copyable" | "Escapable"),
                    "only the implicit Swift 6 layout protocols belong to this category, got {name}"
                );
                assert!(
                    !interface_text.contains(name),
                    "{name} is implicit and must never be printed in the interface"
                );
            }
        }
    }
}

#[test]
fn interface_kinds_agree_with_the_case_partition_for_conventional_names() {
    let decls: SwiftModuleDecls = committed_module();
    let types: Vec<&str> = decls.type_like_identifiers();
    let members: Vec<&str> = decls.member_like_identifiers();

    let interface: ParsedInterface = swiftinterface::parse(&load_text(INTERFACE_FILE));
    let declared: BTreeMap<String, BTreeSet<DeclaredRole>> = declared_roles(&interface);

    for breaking in CONVENTION_BREAKING_DECLARATIONS {
        assert!(
            declared.contains_key(breaking),
            "{breaking} must really be declared by the interface for the exclusion to mean anything"
        );
    }

    let mut graded_types: usize = 0;
    let mut graded_members: usize = 0;
    for (name, roles) in &declared {
        if CONVENTION_BREAKING_DECLARATIONS.contains(&name.as_str()) {
            continue;
        }
        if !name
            .chars()
            .all(|c: char| c.is_ascii_alphanumeric() || c == '_')
        {
            continue;
        }
        if roles.contains(&DeclaredRole::Nominal) {
            assert!(
                types.contains(&name.as_str()),
                "{name} is declared as a nominal type by the interface but is not type-like"
            );
            assert!(
                !members.contains(&name.as_str()),
                "{name} is a nominal type and must not also be member-like"
            );
            graded_types += 1;
            continue;
        }
        assert!(
            members.contains(&name.as_str()),
            "{name} is declared as a member ({roles:?}) by the interface but is not member-like"
        );
        assert!(
            !types.contains(&name.as_str()),
            "{name} is a member and must not also be type-like"
        );
        graded_members += 1;
    }
    assert_eq!(graded_types, 3, "graded every conventionally-named type");
    assert_eq!(
        graded_members, 11,
        "graded every conventionally-named member"
    );
}

#[test]
fn case_partition_is_lexical_and_misclassifies_convention_breaking_declarations() {
    let decls: SwiftModuleDecls = committed_module();
    let types: Vec<&str> = decls.type_like_identifiers();
    let members: Vec<&str> = decls.member_like_identifiers();

    let interface: ParsedInterface = swiftinterface::parse(&load_text(INTERFACE_FILE));
    let declared: BTreeMap<String, BTreeSet<DeclaredRole>> = declared_roles(&interface);

    assert_eq!(
        declared.get("lowercaseBox").map(BTreeSet::len),
        Some(1),
        "lowercaseBox must be declared exactly once by the interface"
    );
    assert!(
        declared["lowercaseBox"].contains(&DeclaredRole::Nominal),
        "lowercaseBox is a struct in the interface"
    );
    assert!(
        members.contains(&"lowercaseBox") && !types.contains(&"lowercaseBox"),
        "the partition splits on the first character's case only, so a lowercase struct name \
         lands in the member bucket"
    );

    assert!(
        declared["PayloadTag"].contains(&DeclaredRole::Property),
        "PayloadTag is a stored property in the interface"
    );
    assert!(
        types.contains(&"PayloadTag") && !members.contains(&"PayloadTag"),
        "an uppercase property name lands in the type bucket for the same reason"
    );
}

#[test]
fn operator_declaration_is_recovered_but_joins_neither_case_partition() {
    let decls: SwiftModuleDecls = committed_module();
    let interface: ParsedInterface = swiftinterface::parse(&load_text(INTERFACE_FILE));
    let declared: BTreeMap<String, BTreeSet<DeclaredRole>> = declared_roles(&interface);

    assert!(
        declared
            .get("==")
            .is_some_and(|roles: &BTreeSet<DeclaredRole>| roles.contains(&DeclaredRole::Method)),
        "the interface declares the synthesized == operator as a static method"
    );
    assert!(decls.contains("=="), "the bitstream recovers the operator");
    assert!(!decls.type_like_identifiers().contains(&"=="));
    assert!(!decls.member_like_identifiers().contains(&"=="));
}

#[test]
fn source_declarations_reach_both_the_interface_and_the_bitstream() {
    let source: String = load_text(SOURCE_FILE);
    let source_names: BTreeSet<String> = source_declared_identifiers(&source);
    assert!(
        source_names.len() >= 14,
        "the source fixture must declare the surface under test, got {source_names:?}"
    );

    let interface: ParsedInterface = swiftinterface::parse(&load_text(INTERFACE_FILE));
    let declared: BTreeMap<String, BTreeSet<DeclaredRole>> = declared_roles(&interface);
    let dropped_by_interface: Vec<&String> = source_names
        .iter()
        .filter(|name: &&String| !declared.contains_key(*name))
        .collect();
    assert!(
        dropped_by_interface.is_empty(),
        "every source declaration must survive into the reference interface: \
         {dropped_by_interface:?}"
    );

    let decls: SwiftModuleDecls = committed_module();
    let recovered: BTreeSet<String> = recovered_identifiers(&decls);
    let dropped_by_reader: Vec<&String> = source_names
        .iter()
        .filter(|name: &&String| !recovered.contains(*name))
        .collect();
    assert!(
        dropped_by_reader.is_empty(),
        "every source declaration must survive into the recovered identifier table: \
         {dropped_by_reader:?}"
    );
}

#[test]
fn module_metadata_matches_the_reference_interface_header() {
    let decls: SwiftModuleDecls = committed_module();
    let interface_text: String = load_text(INTERFACE_FILE);
    let interface: ParsedInterface = swiftinterface::parse(&interface_text);

    assert_eq!(decls.module_name.as_deref(), Some(MODULE_NAME));
    assert_eq!(decls.module_name, interface.module_name);

    let target: String =
        interface_flag_value(&interface_text, "-target").expect("interface records its target");
    assert_eq!(
        decls.target_triple.as_deref(),
        Some(target.as_str()),
        "the bitstream target must equal the target the interface header records"
    );

    let compiler: String =
        interface_compiler_version(&interface_text).expect("interface records its compiler");
    let recovered_version: &str = decls
        .compiler_version
        .as_deref()
        .expect("bitstream records its compiler");
    assert!(
        recovered_version.ends_with(&compiler),
        "recovered compiler version {recovered_version:?} must end with the interface's \
         {compiler:?}"
    );
}

const REBUILD_GRADED: &str = "the committed GreetingKit.swiftmodule identifier table, against a \
                              module a live swiftc emits from the same source";

#[test]
fn rebuilding_the_fixture_with_swiftc_reproduces_the_identifier_table() {
    let Some(swiftc): Option<PathBuf> = resolve_swift_compiler(REBUILD_GRADED) else {
        return;
    };
    let work: PathBuf = Path::new(env!("CARGO_TARGET_TMPDIR")).join("swiftmodule_rebuild");
    let _ = fs::remove_dir_all(&work);
    fs::create_dir_all(&work).expect("create rebuild directory");

    let module_out: PathBuf = work.join(MODULE_FILE);
    let interface_out: PathBuf = work.join(INTERFACE_FILE);
    let status: std::process::Output = Command::new(&swiftc)
        .arg("-emit-module")
        .arg("-emit-module-path")
        .arg(&module_out)
        .arg("-emit-module-interface-path")
        .arg(&interface_out)
        .arg("-enable-library-evolution")
        .arg("-swift-version")
        .arg("6")
        .arg("-module-name")
        .arg(MODULE_NAME)
        .arg(fixture_dir().join(SOURCE_FILE))
        .current_dir(&work)
        .output()
        .expect("run swiftc");
    assert!(
        status.status.success(),
        "swiftc at {} is on PATH but exited with {} while rebuilding {MODULE_FILE} from \
         {SOURCE_FILE}; a compiler that is present and fails is never a skip, because that is how \
         a broken toolchain silently stops grading the committed fixture. stderr: {}",
        swiftc.display(),
        status.status,
        String::from_utf8_lossy(&status.stderr).trim()
    );

    let rebuilt_bytes: Vec<u8> = fs::read(&module_out).expect("read rebuilt swiftmodule");
    let rebuilt: SwiftModuleDecls = read_swift_module(&rebuilt_bytes).expect("read rebuilt module");
    let rebuilt_names: BTreeSet<String> = recovered_identifiers(&rebuilt);
    let committed_names: BTreeSet<String> = recovered_identifiers(&committed_module());
    assert_eq!(
        rebuilt_names, committed_names,
        "a freshly compiled module must yield the same identifier table as the committed fixture"
    );

    let rebuilt_interface: String =
        fs::read_to_string(&interface_out).expect("read rebuilt interface");
    let rebuilt_declared: BTreeMap<String, BTreeSet<DeclaredRole>> =
        declared_roles(&swiftinterface::parse(&rebuilt_interface));
    let committed_declared: BTreeMap<String, BTreeSet<DeclaredRole>> =
        declared_roles(&swiftinterface::parse(&load_text(INTERFACE_FILE)));
    assert_eq!(
        rebuilt_declared, committed_declared,
        "the committed interface must still describe what this compiler emits"
    );

    let _ = fs::remove_dir_all(&work);
}

#[test]
fn rejects_non_swift_module_input() {
    let not_a_module: &[u8] = b"\x7fELF not a swift module at all";
    assert!(!is_swift_module(not_a_module));
    assert!(read_swift_module(not_a_module).is_err());
}

#[test]
fn malformed_bitstream_tail_does_not_panic() {
    let mut module_bytes: Vec<u8> = load(MODULE_FILE);
    let original_len: usize = module_bytes.len();
    for cut in [original_len / 2, original_len / 4, 8usize, 5usize] {
        module_bytes.truncate(cut);
        let _ = read_swift_module(&module_bytes);
    }

    let signature_only: &[u8] = &[0xE2, 0x9C, 0xA8, 0x0E];
    let _ = read_swift_module(signature_only);

    let mut garbage: Vec<u8> = vec![0xE2, 0x9C, 0xA8, 0x0E];
    garbage.extend(std::iter::repeat_n(0xFFu8, 256));
    let _ = read_swift_module(&garbage);
}
