#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::uninlined_format_args
)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use disrobe_pass_as3::swf::{DoAbc, Swf, SwfTag, TagCode};
use disrobe_pass_as3::{AbcFile, abc, decompile, swf};

fn scriptlang_fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("disrobe-pass-scriptlang")
        .join("tests")
        .join("fixtures")
        .join(name)
}

fn real_haxe_swf() -> Vec<u8> {
    let path: PathBuf = scriptlang_fixture("haxe_main.swf");
    std::fs::read(&path).unwrap_or_else(|err| {
        panic!(
            "the AS3 recover claim is measured against real Haxe 4.3.7 compiler output at {}, and \
             it could not be read: {err}. This check must fail rather than skip, because a skipped \
             reference leaves the claim graded by nothing.",
            path.display()
        )
    })
}

fn authored_haxe_source() -> String {
    let path: PathBuf = scriptlang_fixture("Main.hx");
    std::fs::read_to_string(&path).unwrap_or_else(|err| {
        panic!(
            "the pre-compilation Haxe source at {} is the recovery target and could not be read: \
             {err}",
            path.display()
        )
    })
}

fn declared_method_names(haxe_source: &str) -> BTreeSet<String> {
    let mut names: BTreeSet<String> = BTreeSet::new();
    for line in haxe_source.lines() {
        let Some(rest): Option<&str> = line.split_once("function ").map(|(_, r): (&str, &str)| r)
        else {
            continue;
        };
        let name: &str = rest
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '$'))
            .next()
            .unwrap_or_default();
        if !name.is_empty() {
            names.insert(name.to_owned());
        }
    }
    names
}

fn declared_class_names(haxe_source: &str) -> BTreeSet<String> {
    let mut names: BTreeSet<String> = BTreeSet::new();
    for line in haxe_source.lines() {
        let Some(rest): Option<&str> = line.split_once("class ").map(|(_, r): (&str, &str)| r)
        else {
            continue;
        };
        let name: &str = rest
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '$'))
            .next()
            .unwrap_or_default();
        if !name.is_empty() {
            names.insert(name.to_owned());
        }
    }
    names
}

fn recovered_source() -> String {
    let bytes: Vec<u8> = real_haxe_swf();
    let parsed: Swf = swf::parse(&bytes).expect("real Haxe SWF must parse");
    let mut rendered: String = String::new();
    let mut abc_payloads: usize = 0usize;
    for tag in &parsed.tags {
        let do_abc: DoAbc = match tag.code {
            TagCode::DO_ABC => swf::parse_do_abc(tag).expect("DoABC2 tag must parse"),
            TagCode::DO_ABC_DEFINE => {
                swf::parse_do_abc_legacy(tag).expect("legacy DoABC tag must parse")
            }
            _ => continue,
        };
        abc_payloads = abc_payloads.saturating_add(1usize);
        let file: AbcFile = abc::parse(&do_abc.abc_bytes).expect("real Haxe ABC must parse");
        rendered.push_str(&decompile::render_program(&file).expect("program must render"));
    }
    assert!(
        abc_payloads >= 1usize,
        "the real Haxe SWF must carry at least one ABC payload"
    );
    rendered
}

fn missing_from(recovered: &str, wanted: &BTreeSet<String>, keyword: &str) -> Vec<String> {
    wanted
        .iter()
        .filter(|name: &&String| !recovered.contains(&format!("{keyword} {name}")))
        .cloned()
        .collect()
}

#[test]
fn the_swf_is_real_compiler_output_not_a_fixture_we_built() {
    let bytes: Vec<u8> = real_haxe_swf();
    assert_eq!(
        &bytes[..3],
        b"CWS",
        "the reference must be a zlib-compressed SWF as the Haxe compiler emits it"
    );
    let parsed: Swf = swf::parse(&bytes).expect("real Haxe SWF must parse");
    let tags: Vec<TagCode> = parsed.tags.iter().map(|t: &SwfTag| t.code).collect();
    assert!(
        tags.contains(&TagCode::DO_ABC) || tags.contains(&TagCode::DO_ABC_DEFINE),
        "tags={tags:?}"
    );
    assert!(
        tags.contains(&TagCode::SYMBOL_CLASS),
        "real compiler output binds a document class through SymbolClass; tags={tags:?}"
    );
}

#[test]
fn every_class_the_haxe_compiler_was_given_is_declared_in_the_recovery() {
    let source: String = authored_haxe_source();
    let wanted: BTreeSet<String> = declared_class_names(&source);
    assert!(!wanted.is_empty(), "the authored source declares no class");
    let recovered: String = recovered_source();
    let missing: Vec<String> = missing_from(&recovered, &wanted, "class");
    assert!(
        missing.is_empty(),
        "classes present in the pre-compilation source are absent from the recovery: {missing:?}"
    );
}

#[test]
fn every_method_the_haxe_compiler_was_given_is_declared_in_the_recovery() {
    let source: String = authored_haxe_source();
    let wanted: BTreeSet<String> = declared_method_names(&source);
    assert_eq!(
        wanted,
        ["add", "greet", "main"]
            .into_iter()
            .map(str::to_owned)
            .collect::<BTreeSet<String>>(),
        "the authored source's method roster changed; update the expectation deliberately"
    );
    let recovered: String = recovered_source();
    let missing: Vec<String> = missing_from(&recovered, &wanted, "function");
    assert!(
        missing.is_empty(),
        "methods present in the pre-compilation source are absent from the recovery: \
         {missing:?}\n--recovered--\n{recovered}"
    );
}

#[test]
fn the_source_comparison_rejects_a_recovery_with_a_method_removed() {
    let source: String = authored_haxe_source();
    let wanted: BTreeSet<String> = declared_method_names(&source);
    let recovered: String = recovered_source();
    let corrupted: String = recovered.replace("function greet", "function __dropped");
    assert_ne!(
        corrupted, recovered,
        "the mutation must actually change the recovered source"
    );
    let missing: Vec<String> = missing_from(&corrupted, &wanted, "function");
    assert_eq!(
        missing,
        vec!["greet".to_owned()],
        "a recovery that lost a method the compiler was given must be reported, otherwise this \
         comparison cannot detect a wrong answer"
    );
}

#[test]
fn recovery_carries_the_haxe_runtime_classes_the_compiler_linked_in() {
    let recovered: String = recovered_source();
    for name in [
        "Main",
        "haxe.Log",
        "haxe.iterators.ArrayIterator",
        "flash.Boot",
    ] {
        assert!(
            recovered.contains(&format!("class {name}")),
            "{name} is in the real ABC the Haxe compiler emitted but not in the recovery\n\
             --recovered--\n{recovered}"
        );
    }
}
