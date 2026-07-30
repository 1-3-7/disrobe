#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::path::PathBuf;

use disrobe_pass_dotnet::decompile::{DecompiledAssembly, decompile_assembly};

fn load(rel: &str) -> Vec<u8> {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push(rel);
    std::fs::read(&path).unwrap_or_else(|e: std::io::Error| panic!("read {rel}: {e}"))
}

fn decompile() -> DecompiledAssembly {
    let bytes: Vec<u8> = load("../../corpus/dotnet/constructs/Constructs.dll");
    decompile_assembly(&bytes).expect("decompile Constructs.dll")
}

fn decompile_edgecases() -> DecompiledAssembly {
    let bytes: Vec<u8> = load("../../corpus/dotnet/megafile/EdgeCases.baseline.dll");
    decompile_assembly(&bytes).expect("decompile EdgeCases.baseline.dll")
}

fn body_in_type(asm: &DecompiledAssembly, declaring_type: &str, needle: &str) -> String {
    asm.methods
        .iter()
        .find(|m| {
            m.body
                .lines()
                .next()
                .is_some_and(|first: &str| first.contains(declaring_type))
                && m.signature.contains(needle)
        })
        .map_or_else(
            || panic!("method {declaring_type}::{needle} not found"),
            |m| m.body.clone(),
        )
}

fn body_of(asm: &DecompiledAssembly, needle: &str) -> String {
    asm.methods
        .iter()
        .find(|m| m.signature.contains(needle))
        .map_or_else(|| panic!("method {needle} not found"), |m| m.body.clone())
}

#[test]
fn bool_methods_return_true_false_not_integer_literals() {
    let asm: DecompiledAssembly = decompile();
    let print_members: String = body_of(&asm, "PrintMembers");
    assert!(
        print_members.contains("return true;"),
        "a bool method's `return 1;` must render as `return true;`; got:\n{print_members}"
    );
    assert!(
        !print_members.contains("return 1;") && !print_members.contains("return 0;"),
        "no bare integer-literal bool return may survive in a bool method; got:\n{print_members}"
    );
}

#[test]
fn non_bool_methods_keep_their_integer_returns() {
    let asm: DecompiledAssembly = decompile();
    let get_x: String = body_of(&asm, "get_X");
    assert!(
        !get_x.contains("return true;") && !get_x.contains("return false;"),
        "an int-returning accessor must not be rewritten to a bool return; got:\n{get_x}"
    );
}

#[test]
fn integer_constants_take_the_declared_type_of_what_they_are_stored_in() {
    let asm: DecompiledAssembly = decompile_edgecases();
    let dispose: String = body_in_type(&asm, "EdgeCases.DisposableScope", "void Dispose(");
    assert!(
        dispose.contains("this.disposed = true;"),
        "a store of 1 into a bool field must render as true; got:\n{dispose}"
    );
    let object_writer: String = body_in_type(&asm, "EdgeCases.JsonLite", "Object");
    assert!(
        object_writer.contains("local1 = true;") && object_writer.contains("local1 = false;"),
        "stores of 1 and 0 into a bool local must render as true and false; got:\n{object_writer}"
    );
    assert!(
        object_writer.contains("local0.Append(':');"),
        "a char argument must render as a char literal, since Append(58) binds to the int overload and appends digits; got:\n{object_writer}"
    );
    let parse: String = body_in_type(&asm, "EdgeCases.ConfigParser", "Parse");
    assert!(
        parse.contains("new System.Char[1] { '\\u000A' }"),
        "a char array element must render as a char literal; got:\n{parse}"
    );
    assert!(
        parse.contains("local2 = 0;") && parse.contains("local2 = local2 + 1;"),
        "an int local must keep its integer stores; got:\n{parse}"
    );
}

#[test]
fn decompile_remains_lossless_after_bool_return_canon() {
    let asm: DecompiledAssembly = decompile();
    assert_eq!(
        asm.methods_failed, 0,
        "no method may fail to decompile after bool-return canonicalization; got {} failures",
        asm.methods_failed
    );
}
