#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
#![cfg(feature = "native")]

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

use disrobe_core::scratch::ScratchDir;
use disrobe_core::subprocess::{CapturedOutput, run_captured};
use object::{Object as _, ObjectSection as _};
use serde_json::Value;

const RUN_TIMEOUT: Duration = Duration::from_mins(2);
const MAX_CAPTURE_BYTES: usize = 4 * 1024 * 1024;
const FIXTURES: [&str; 4] = [
    "string-accessor-clang-v1.dll",
    "string-accessor-clang-v2.dll",
    "string-accessor-msvc-v1.dll",
    "string-accessor-msvc-v2.dll",
];
const FUNCTION_NAME: &str = "string_call_1";
const INDEX: u32 = 1;
const INVALID_INDEX: u32 = 64;

fn workspace_root() -> PathBuf {
    let mut root: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    root.pop();
    root.pop();
    root
}

fn fixture(name: &str) -> PathBuf {
    workspace_root()
        .join("corpus")
        .join("native")
        .join("string-accessor")
        .join(name)
}

fn disrobe_bin() -> PathBuf {
    let bin: PathBuf = PathBuf::from(std::env::var_os("DISROBE_BIN").expect(
        "DISROBE_BIN must name the disrobe binary built by `cargo build -p disrobe-cli --bin disrobe` for this caller test",
    ));
    assert!(
        bin.is_file(),
        "DISROBE_BIN does not name a file: {}",
        bin.display()
    );
    bin
}

fn run(args: &[String]) -> CapturedOutput {
    let bin: PathBuf = disrobe_bin();
    let argv: Vec<OsString> = args.iter().map(OsString::from).collect();
    run_captured(&bin, &argv, RUN_TIMEOUT, MAX_CAPTURE_BYTES)
        .unwrap_or_else(|error| panic!("cannot start {}: {error}", bin.display()))
        .unwrap_or_else(|| panic!("disrobe {args:?} exceeded its timeout"))
}

fn run_ok(args: &[String]) -> String {
    let output: CapturedOutput = run(args);
    assert_eq!(
        output.exit_code,
        Some(0),
        "disrobe {args:?} failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("UTF-8 stdout")
}

fn disasm_args(input: &Path, function_rva: u64, json: bool) -> Vec<String> {
    let mut args: Vec<String> = vec![
        "native".to_owned(),
        "disasm".to_owned(),
        input.to_str().expect("UTF-8 fixture path").to_owned(),
        "--function".to_owned(),
        format!("{function_rva:#x}"),
    ];
    if json {
        args.push("--json".to_owned());
    }
    args
}

fn disasm_json(input: &Path, function_rva: u64) -> Value {
    let args: Vec<String> = disasm_args(input, function_rva, true);
    serde_json::from_str(&run_ok(&args)).expect("JSON document on stdout")
}

fn plaintext(index: usize) -> String {
    let source: String = std::fs::read_to_string(fixture("string_accessor.c"))
        .expect("committed indexed-string source");
    let (_, array): (&str, &str) = source
        .split_once("static const char *const reference_plaintext[] = {")
        .expect("plaintext oracle array");
    let (array, _): (&str, &str) = array.split_once("};").expect("plaintext oracle terminator");
    let literals: Vec<String> = array
        .lines()
        .filter_map(|line: &str| {
            line.trim()
                .strip_prefix('"')
                .and_then(|literal: &str| literal.strip_suffix("\","))
                .map(str::to_owned)
        })
        .collect();
    literals
        .get(index)
        .unwrap_or_else(|| panic!("plaintext oracle has no index {index}"))
        .clone()
}

fn function_rva(bytes: &[u8]) -> u64 {
    let file: object::File<'_> = object::File::parse(bytes).expect("parse compiler-built DLL");
    let base: u64 = file.relative_address_base();
    file.exports()
        .expect("DLL exports")
        .into_iter()
        .find_map(|export| {
            let name: &str = std::str::from_utf8(export.name()).ok()?;
            (name == FUNCTION_NAME).then(|| export.address().checked_sub(base))?
        })
        .expect("string_call_1 export RVA")
}

fn file_offset_for_rva(bytes: &[u8], rva: u64) -> usize {
    let file: object::File<'_> = object::File::parse(bytes).expect("parse compiler-built DLL");
    let base: u64 = file.relative_address_base();
    for section in file.sections() {
        let Some(section_rva): Option<u64> = section.address().checked_sub(base) else {
            continue;
        };
        let Some(section_end): Option<u64> = section_rva.checked_add(section.size()) else {
            continue;
        };
        if !(section_rva..section_end).contains(&rva) {
            continue;
        }
        let (file_offset, file_size): (u64, u64) =
            section.file_range().expect("section file range");
        let within: u64 = rva - section_rva;
        assert!(
            within < file_size,
            "function bytes are present in its section"
        );
        let offset: u64 = file_offset
            .checked_add(within)
            .expect("function file offset does not overflow");
        return usize::try_from(offset).expect("function file offset fits host address space");
    }
    panic!("function RVA {rva:#x} is not file-backed");
}

fn indexed_annotation(document: &Value) -> (&Value, &Value) {
    let instructions: &[Value] = document["instructions"]
        .as_array()
        .expect("scoped instructions");
    instructions
        .iter()
        .find_map(|instruction: &Value| {
            instruction["indexed_strings"]
                .as_array()
                .and_then(|annotations| {
                    annotations
                        .iter()
                        .find(|annotation: &&Value| {
                            annotation["index"].as_u64() == Some(u64::from(INDEX))
                        })
                        .map(|annotation: &Value| (instruction, annotation))
                })
        })
        .expect("indexed-string annotation for the selected call")
}

#[test]
fn scoped_disassembly_links_accessor_calls_to_source_literals() {
    let expected: String = plaintext(INDEX as usize);
    for name in FIXTURES {
        let input: PathBuf = fixture(name);
        let bytes: Vec<u8> = std::fs::read(&input)
            .unwrap_or_else(|error| panic!("read committed fixture {name}: {error}"));
        let function: u64 = function_rva(&bytes);
        let document: Value = disasm_json(&input, function);
        assert_eq!(
            document["schema"], "disrobe.native.scoped-disassembly/v1",
            "{name} scoped document"
        );
        let (instruction, annotation): (&Value, &Value) = indexed_annotation(&document);
        assert!(
            instruction["text"]
                .as_str()
                .is_some_and(|text: &str| text.starts_with("call")),
            "{name} annotation belongs to a direct call: {instruction}"
        );
        assert_eq!(
            annotation["index"].as_u64(),
            Some(u64::from(INDEX)),
            "{name}"
        );
        assert_eq!(
            annotation["literal"].as_str(),
            Some(expected.as_str()),
            "{name}"
        );
        let image_base: u64 = document["image_base"].as_u64().expect("image base");
        let instruction_rva: u64 = instruction["rva"].as_u64().expect("instruction RVA");
        assert_eq!(
            annotation["site"].as_u64(),
            image_base.checked_add(instruction_rva),
            "{name} annotation site is the listed call instruction"
        );
        assert!(
            annotation["accessor"].as_u64().is_some(),
            "{name} accessor VA"
        );
    }
}

#[test]
fn invalid_accessor_index_is_refused_without_a_literal_annotation() {
    let source: PathBuf = fixture("string-accessor-clang-v1.dll");
    let mut bytes: Vec<u8> = std::fs::read(&source).expect("committed compiler-built fixture");
    let function: u64 = function_rva(&bytes);
    let offset: usize = file_offset_for_rva(&bytes, function);
    let window_end: usize = offset.checked_add(64).expect("function mutation window");
    let immediate: usize = bytes[offset..window_end]
        .windows(5)
        .position(|window: &[u8]| window == [0xb9, 1, 0, 0, 0])
        .expect("string_call_1 immediate index instruction");
    let immediate_start: usize = offset + immediate + 1;
    bytes[immediate_start..immediate_start + 4].copy_from_slice(&INVALID_INDEX.to_le_bytes());
    let scratch: ScratchDir =
        ScratchDir::create("disrobe-native-indexed-string-refusal").expect("scratch directory");
    let mutated: PathBuf = scratch.path().join("invalid-index.dll");
    std::fs::write(&mutated, &bytes).expect("mutated fixture");
    let document: Value = disasm_json(&mutated, function);
    let refusals: &[Value] = document["indexed_string_refusals"]
        .as_array()
        .expect("indexed-string refusal array");
    let refusal: &Value = refusals
        .iter()
        .find(|refusal: &&Value| {
            refusal["index"].as_u64() == Some(u64::from(INVALID_INDEX))
                && refusal["kind"].as_str() == Some("null_return")
        })
        .unwrap_or_else(|| panic!("the mutated call must report its null return: {document}"));
    let image_base: u64 = document["image_base"].as_u64().expect("image base");
    let refusal_site: u64 = refusal["site"].as_u64().expect("refusal site");
    let refusal_rva: u64 = refusal_site
        .checked_sub(image_base)
        .expect("refusal site belongs to the image");
    let instruction: &Value = document["instructions"]
        .as_array()
        .expect("instructions")
        .iter()
        .find(|instruction: &&Value| instruction["rva"].as_u64() == Some(refusal_rva))
        .unwrap_or_else(|| panic!("the refused call is listed at {refusal_rva:#x}"));
    assert!(
        instruction["indexed_strings"]
            .as_array()
            .is_none_or(Vec::is_empty),
        "the refused call must not gain a literal annotation: {instruction}"
    );
    let text_args: Vec<String> = disasm_args(&mutated, function, false);
    let text: String = run_ok(&text_args);
    assert!(text.contains("DR-NATIVE-0807"), "{text}");
}
