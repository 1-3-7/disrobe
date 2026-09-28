#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::path::PathBuf;

use disrobe_pass_dotnet::decompile::{DecompiledAssembly, decompile_assembly};
use disrobe_pass_dotnet::structurize::StructuredMethod;

const ORIGINAL_NAME: &[u8] = b"NegatedConditions\0";
const HOSTILE_NAME: &[u8] = b"Ne\nt\xe2\x80\xaeConditions\0";

fn fixture() -> Vec<u8> {
    let path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/unsigned_overflow/UnsignedOverflow.dll");
    std::fs::read(path).expect("read the unsigned_overflow fixture")
}

fn with_hostile_type_name(mut bytes: Vec<u8>) -> Vec<u8> {
    assert_eq!(ORIGINAL_NAME.len(), HOSTILE_NAME.len());
    let at: usize = bytes
        .windows(ORIGINAL_NAME.len())
        .position(|window: &[u8]| window == ORIGINAL_NAME)
        .expect("the #Strings heap holds the type name");
    bytes[at..at + HOSTILE_NAME.len()].copy_from_slice(HOSTILE_NAME);
    bytes
}

fn emitted_text(asm: &DecompiledAssembly) -> String {
    asm.methods
        .iter()
        .map(|method: &StructuredMethod| method.body.as_str())
        .collect::<Vec<&str>>()
        .join("\n")
}

#[test]
fn a_type_name_with_a_newline_and_a_bidi_override_stays_on_its_line() {
    let original: DecompiledAssembly = decompile_assembly(&fixture()).expect("decompile original");
    let hostile: DecompiledAssembly =
        decompile_assembly(&with_hostile_type_name(fixture())).expect("decompile patched");
    assert_eq!(
        original.methods.len(),
        hostile.methods.len(),
        "renaming one type must not add or drop methods"
    );
    let text: String = emitted_text(&hostile);
    assert!(
        !text.contains('\u{202e}'),
        "the right-to-left override reached the emitted C#"
    );
    let original_lines: usize = emitted_text(&original).lines().count();
    assert_eq!(
        text.lines().count(),
        original_lines,
        "a newline in the type name added a line to the emitted C#:\n{text}"
    );
    assert!(
        text.lines()
            .any(|line: &str| line.contains("Ne") && line.contains("Conditions")),
        "the renamed type is still named, escaped, on one line:\n{text}"
    );
}
