#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::uninlined_format_args
)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

#[cfg(feature = "chain")]
use disrobe_core::chain::Pass;
#[cfg(feature = "chain")]
use disrobe_core::{Artifact, Rung};
#[cfg(feature = "chain")]
use disrobe_pass_as3::chain_detector::AS3_PASS;
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

#[cfg(feature = "chain")]
fn encode_tag(code: TagCode, payload: &[u8]) -> Vec<u8> {
    let payload_length: u32 = u32::try_from(payload.len()).expect("test tag fits in u32");
    let mut encoded: Vec<u8> = Vec::new();
    if payload_length < 0x3f {
        let short_length: u16 = u16::try_from(payload_length).expect("short tag length fits");
        let header: u16 = (code.0 << 6) | short_length;
        encoded.extend_from_slice(&header.to_le_bytes());
    } else {
        let header: u16 = (code.0 << 6) | 0x3f;
        encoded.extend_from_slice(&header.to_le_bytes());
        encoded.extend_from_slice(&payload_length.to_le_bytes());
    }
    encoded.extend_from_slice(payload);
    encoded
}

#[cfg(feature = "chain")]
fn real_haxe_do_abc_tag() -> SwfTag {
    let bytes: Vec<u8> = real_haxe_swf();
    let parsed: Swf = swf::parse(&bytes).expect("real Haxe SWF must parse");
    parsed
        .tags
        .into_iter()
        .find(|tag: &SwfTag| matches!(tag.code, TagCode::DO_ABC | TagCode::DO_ABC_DEFINE))
        .expect("real Haxe SWF must contain an ABC tag")
}

#[cfg(feature = "chain")]
fn fws_with_haxe_and_sibling(code: TagCode, payload: &[u8]) -> (Vec<u8>, usize) {
    let valid: SwfTag = real_haxe_do_abc_tag();
    let valid_tag: Vec<u8> = encode_tag(valid.code, &valid.payload);
    let sibling_tag: Vec<u8> = encode_tag(code, payload);
    let end_tag: Vec<u8> = encode_tag(TagCode::END, &[]);
    let mut body: Vec<u8> = vec![0x00];
    body.extend_from_slice(&24u16.to_le_bytes());
    body.extend_from_slice(&1u16.to_le_bytes());
    body.extend_from_slice(&valid_tag);
    let sibling_offset: usize = 8usize
        .checked_add(body.len())
        .expect("test SWF offset fits in usize");
    body.extend_from_slice(&sibling_tag);
    body.extend_from_slice(&end_tag);
    let total_length: usize = 8usize
        .checked_add(body.len())
        .expect("test SWF length fits in usize");
    let file_length: u32 = u32::try_from(total_length).expect("test SWF length fits in u32");
    let file_capacity: usize = usize::try_from(file_length).expect("test SWF length fits in usize");
    let mut bytes: Vec<u8> = Vec::with_capacity(file_capacity);
    bytes.extend_from_slice(b"FWS");
    bytes.push(10);
    bytes.extend_from_slice(&file_length.to_le_bytes());
    bytes.extend_from_slice(&body);
    (bytes, sibling_offset)
}

#[cfg(feature = "chain")]
fn doabc_payload(name: &str, abc_bytes: &[u8]) -> Vec<u8> {
    let mut payload: Vec<u8> = Vec::new();
    payload.extend_from_slice(&0u32.to_le_bytes());
    payload.extend_from_slice(name.as_bytes());
    payload.push(0);
    payload.extend_from_slice(abc_bytes);
    payload
}

#[cfg(feature = "chain")]
fn abc_with_unrenderable_instance_name() -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();
    bytes.extend_from_slice(&abc::ABC_MINOR.to_le_bytes());
    bytes.extend_from_slice(&abc::ABC_MAJOR.to_le_bytes());
    bytes.extend(std::iter::repeat_n(1u8, 7));
    bytes.extend_from_slice(&[0, 0, 1]);
    bytes.extend_from_slice(&[1, 0, 0, 0, 0, 0]);
    bytes.extend_from_slice(&[0, 0]);
    bytes.extend_from_slice(&[0, 0]);
    bytes
}

#[cfg(feature = "chain")]
fn as3_pass_failure(bytes: Vec<u8>) -> String {
    let artifact: Artifact = Artifact::new(Rung::Raw, bytes, [0u8; 32]);
    let error: disrobe_core::error::CoreError = AS3_PASS
        .run(&artifact)
        .expect_err("a malformed recognized sibling must prevent Surface success");
    let disrobe_core::error::CoreError::PassFailure(message): disrobe_core::error::CoreError =
        error
    else {
        panic!("expected pass failure")
    };
    message
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
            TagCode::DO_ABC => swf::parse_do_abc(tag).expect("DoABC tag must parse"),
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

#[cfg(feature = "chain")]
#[test]
fn swf_surface_rejects_a_malformed_doabc_after_real_haxe_bytecode() {
    let malformed_payload: Vec<u8> = vec![0, 0, 0, 0, b'n', b'o', b'-', b'n', b'u', b'l'];
    let (bytes, sibling_offset): (Vec<u8>, usize) =
        fws_with_haxe_and_sibling(TagCode::DO_ABC, &malformed_payload);
    let message: String = as3_pass_failure(bytes);
    assert!(
        message.starts_with("DR-AS3-0908: swf DoABC tag parse failed"),
        "unexpected stage diagnostic: {message}"
    );
    assert!(
        message.contains(&format!("logical SWF tag offset {sibling_offset}")),
        "diagnostic lacks the malformed sibling offset: {message}"
    );
    assert!(
        message.contains("DR-AS3-0007"),
        "diagnostic lost the parser cause: {message}"
    );
}

#[cfg(feature = "chain")]
#[test]
fn swf_surface_reports_legacy_abc_parse_failure_after_real_haxe_bytecode() {
    let malformed_abc: [u8; 4] = [0, 0, 0, 0];
    let (bytes, sibling_offset): (Vec<u8>, usize) =
        fws_with_haxe_and_sibling(TagCode::DO_ABC_DEFINE, &malformed_abc);
    let message: String = as3_pass_failure(bytes);
    assert!(
        message.starts_with("DR-AS3-0909: swf DoABCDefine ABC parse failed"),
        "unexpected stage diagnostic: {message}"
    );
    assert!(
        message.contains(&format!("logical SWF tag offset {sibling_offset}")),
        "diagnostic lacks the malformed sibling offset: {message}"
    );
    assert!(
        message.contains("DR-AS3-0010"),
        "diagnostic lost the ABC parser cause: {message}"
    );
}

#[cfg(feature = "chain")]
#[test]
fn swf_surface_reports_abc_render_failure_after_real_haxe_bytecode() {
    let unrenderable_abc: Vec<u8> = abc_with_unrenderable_instance_name();
    let payload: Vec<u8> = doabc_payload("unrenderable", &unrenderable_abc);
    let (bytes, sibling_offset): (Vec<u8>, usize) =
        fws_with_haxe_and_sibling(TagCode::DO_ABC, &payload);
    let message: String = as3_pass_failure(bytes);
    assert!(
        message.starts_with("DR-AS3-0910: swf DoABC render failed"),
        "unexpected stage diagnostic: {message}"
    );
    assert!(
        message.contains(&format!("logical SWF tag offset {sibling_offset}")),
        "diagnostic lacks the malformed sibling offset: {message}"
    );
    assert!(
        message.contains("DR-AS3-0013"),
        "diagnostic lost the renderer cause: {message}"
    );
}

#[cfg(feature = "chain")]
#[test]
fn swf_surface_preserves_valid_doabcdefine_after_real_haxe_bytecode() {
    let valid: SwfTag = real_haxe_do_abc_tag();
    let doabc: DoAbc = match valid.code {
        TagCode::DO_ABC => swf::parse_do_abc(&valid).expect("DoABC tag must parse"),
        TagCode::DO_ABC_DEFINE => {
            swf::parse_do_abc_legacy(&valid).expect("DoABCDefine tag must parse")
        }
        _ => panic!("expected a recognized ABC tag"),
    };
    let (bytes, _sibling_offset): (Vec<u8>, usize) =
        fws_with_haxe_and_sibling(TagCode::DO_ABC_DEFINE, &doabc.abc_bytes);
    let artifact: Artifact = Artifact::new(Rung::Raw, bytes, [0u8; 32]);
    let output: Artifact = AS3_PASS
        .run(&artifact)
        .expect("valid DoABC and DoABCDefine siblings must produce Surface source");
    assert_eq!(output.rung, Rung::Surface);
    let source: &str =
        std::str::from_utf8(&output.envelope).expect("AS3 Surface source must be UTF-8");
    assert_eq!(
        source.matches("public class Main extends").count(),
        2,
        "both real Haxe ABC siblings must be rendered: {source}"
    );
}
