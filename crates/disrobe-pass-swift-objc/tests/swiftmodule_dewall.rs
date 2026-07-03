#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use disrobe_pass_swift_objc::swiftinterface::{self, InterfaceDecl, InterfaceDeclKind};
use disrobe_pass_swift_objc::{SwiftModuleDecls, is_swift_module, read_swift_module};

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

fn strip_swift_modifiers(line: &str) -> &str {
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

fn source_identifiers(swift_src: &str) -> BTreeSet<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    for raw in swift_src.lines() {
        let line: &str = strip_swift_modifiers(raw);
        for keyword in [
            "struct ", "enum ", "class ", "func ", "let ", "var ", "case ",
        ] {
            if let Some(rest) = line.strip_prefix(keyword) {
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

fn interface_identifiers(text: &str) -> BTreeSet<String> {
    let parsed = swiftinterface::parse(text);
    let mut out: BTreeSet<String> = BTreeSet::new();
    for decl in &parsed.decls {
        let d: &InterfaceDecl = decl;
        if d.kind != InterfaceDeclKind::Extension {
            out.insert(d.name.clone());
        }
        for p in &d.properties {
            out.insert(p.name.clone());
        }
        for m in &d.methods {
            out.insert(m.name.clone());
        }
        for c in &d.cases {
            out.insert(c.name.clone());
        }
    }
    out
}

#[test]
fn recovers_declared_names_from_real_binary_swiftmodule() {
    let module_bytes: Vec<u8> = load("GreetingKit.swiftmodule");
    assert!(
        is_swift_module(&module_bytes),
        "fixture must carry the Swift serialized-module signature"
    );

    let decls: SwiftModuleDecls = read_swift_module(&module_bytes).expect("read swiftmodule");
    assert!(decls.signature_ok);
    assert_eq!(decls.module_name.as_deref(), Some("GreetingKit"));
    assert!(
        decls
            .target_triple
            .as_deref()
            .is_some_and(|t: &str| t.contains("x86_64")
                || t.contains("apple")
                || t.contains("windows")),
        "target triple recovered: {:?}",
        decls.target_triple
    );

    let recovered: BTreeSet<String> = decls.identifiers.iter().cloned().collect();

    let source: String = String::from_utf8(load("Greeting.swift")).expect("source is utf-8");
    let oracle: BTreeSet<String> = source_identifiers(&source);

    let expected: [&str; 12] = [
        "Greeting",
        "DeliveryChannel",
        "CourierService",
        "recipientName",
        "salutationCount",
        "renderBanner",
        "inbox",
        "archive",
        "spamFolder",
        "pendingMessages",
        "channelLabel",
        "enqueueGreeting",
    ];
    for name in expected {
        assert!(
            oracle.contains(name),
            "source oracle must declare {name} (oracle integrity)"
        );
        assert!(
            recovered.contains(name),
            "binary swiftmodule must recover declared identifier {name}; recovered={:?}",
            decls.identifiers
        );
    }

    let missing: Vec<&String> = oracle
        .iter()
        .filter(|name: &&String| !recovered.contains(*name))
        .collect();
    assert!(
        missing.is_empty(),
        "every source-declared identifier recovered from the bitstream; missing={missing:?}"
    );
}

#[test]
fn binary_module_matches_textual_interface_identifiers() {
    let module_bytes: Vec<u8> = load("GreetingKit.swiftmodule");
    let decls: SwiftModuleDecls = read_swift_module(&module_bytes).expect("read swiftmodule");
    let recovered: BTreeSet<String> = decls.identifiers.iter().cloned().collect();

    let interface_text: String =
        String::from_utf8(load("GreetingKit.swiftinterface")).expect("interface is utf-8");
    assert!(swiftinterface::looks_like_swiftinterface(&interface_text));
    let from_interface: BTreeSet<String> = interface_identifiers(&interface_text);

    let interface_only: Vec<&String> = from_interface
        .iter()
        .filter(|name: &&String| {
            name.chars().all(|c: char| c.is_alphanumeric() || c == '_')
                && !recovered.contains(*name)
        })
        .collect();
    assert!(
        interface_only.is_empty(),
        "every interface-declared identifier also present in the bitstream; missing={interface_only:?}"
    );
}

#[test]
fn type_and_member_partition_is_honest() {
    let module_bytes: Vec<u8> = load("GreetingKit.swiftmodule");
    let decls: SwiftModuleDecls = read_swift_module(&module_bytes).expect("read swiftmodule");

    let types: Vec<&str> = decls.type_like_identifiers();
    for name in ["Greeting", "DeliveryChannel", "CourierService"] {
        assert!(types.contains(&name), "{name} classified as a type");
    }

    let members: Vec<&str> = decls.member_like_identifiers();
    for name in [
        "recipientName",
        "salutationCount",
        "pendingMessages",
        "channelLabel",
    ] {
        assert!(members.contains(&name), "{name} classified as a member");
    }
}

#[test]
fn rejects_non_swift_module_input() {
    let not_a_module: &[u8] = b"\x7fELF not a swift module at all";
    assert!(!is_swift_module(not_a_module));
    assert!(read_swift_module(not_a_module).is_err());
}

#[test]
fn malformed_bitstream_tail_does_not_panic() {
    let mut module_bytes: Vec<u8> = load("GreetingKit.swiftmodule");
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
