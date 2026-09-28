#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::fmt::Write as _;
use std::path::PathBuf;

use disrobe_pass_dotnet::decompile::{DecompiledAssembly, decompile_assembly};
use disrobe_pass_dotnet::structurize::StructuredMethod;
use sha2::{Digest, Sha256};

const FIXTURE_DIR: &str = "tests/fixtures/unsigned_overflow";
const UNRESOLVED_OPERAND_KIND: &str = "__unresolved_operand_kind";

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join(FIXTURE_DIR)
        .join(name)
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .fold(String::with_capacity(64), |mut hex: String, byte: &u8| {
            write!(hex, "{byte:02x}").expect("write to a String");
            hex
        })
}

fn decompiled() -> DecompiledAssembly {
    let bytes: Vec<u8> = std::fs::read(fixture("UnsignedOverflow.dll")).expect("read fixture");
    decompile_assembly(&bytes).expect("decompile the unsigned and overflow fixture")
}

fn method_body<'a>(asm: &'a DecompiledAssembly, owner: &str, name: &str) -> &'a str {
    let header: String = format!("// Sample.{owner}");
    let declaration: String = format!(" {name}(");
    asm.methods
        .iter()
        .map(|method: &StructuredMethod| method.body.as_str())
        .find(|body: &&str| {
            body.lines()
                .next()
                .is_some_and(|first: &str| first.trim_start().starts_with(&header))
                && body.contains(&declaration)
        })
        .unwrap_or_else(|| panic!("no recovered body for Sample.{owner}::{name}"))
}

#[test]
fn build_record_pins_every_fixture_file() {
    let manifest: toml::Table = std::fs::read_to_string(fixture("MANIFEST.toml"))
        .expect("read the build record")
        .parse::<toml::Table>()
        .expect("parse the build record");
    let entries: &Vec<toml::Value> = manifest
        .get("fixture")
        .and_then(toml::Value::as_array)
        .expect("the build record lists its fixture files");
    let mut pinned: Vec<&str> = Vec::new();
    for entry in entries {
        let name: &str = entry
            .get("name")
            .and_then(toml::Value::as_str)
            .expect("fixture name");
        let expected: &str = entry
            .get("sha256")
            .and_then(toml::Value::as_str)
            .expect("fixture sha256");
        let bytes: Vec<u8> = std::fs::read(fixture(name)).expect("read pinned fixture file");
        assert_eq!(
            sha256_hex(&bytes),
            expected,
            "{name} no longer matches the sha256 in its build record; rebuild it with the recorded command and update the record"
        );
        pinned.push(name);
    }
    pinned.sort_unstable();
    assert_eq!(
        pinned,
        [
            "UnsignedOverflow.cs",
            "UnsignedOverflow.csproj",
            "UnsignedOverflow.dll"
        ],
        "the build record must pin the source, the project and the assembly it produced"
    );
}

#[test]
fn enum_operands_of_undeclared_width_carry_a_named_refusal() {
    let asm: DecompiledAssembly = decompiled();
    let body: &str = method_body(&asm, "UnsignedOverflowRefusal", "FlagsBelow");
    let refusal: String =
        format!("throw new System.NotSupportedException(\"{UNRESOLVED_OPERAND_KIND}");
    assert!(
        body.contains(&refusal),
        "clt.un over two uint-backed enum values has no stack type the renderer can size its cast from, so the method must be refused by name; got:\n{body}"
    );
    assert!(
        !body.contains("left < right") && !body.contains("return"),
        "a refused method keeps no guessed comparison; got:\n{body}"
    );
}

#[test]
fn unsigned_and_checked_shapes_print_their_il_semantics() {
    let asm: DecompiledAssembly = decompiled();
    let expectations: &[(&str, &str)] = &[
        ("InRange", "(uint)index < (uint)length"),
        ("GuardIndex", "(uint)index >= (uint)length"),
        ("DivideUnsigned", "(int)((uint)dividend / (uint)divisor)"),
        ("RemainderUnsigned", "(int)((uint)dividend % (uint)divisor)"),
        (
            "DivideUnsignedWide",
            "(long)((ulong)dividend / (ulong)divisor)",
        ),
        ("DivideDeclaredUnsigned", "return dividend / divisor;"),
        ("AddChecked", "checked(left + right)"),
        ("MultiplyChecked", "checked(left * right)"),
        ("SubtractCheckedUnsigned", "checked(left - right)"),
        ("ZeroExtend", "(ulong)(uint)value"),
        ("SignExtendUnsigned", "(long)(int)value"),
        ("LessOrUnordered", "!(left >= right)"),
        ("Bucket", "< 10 => \"low\""),
    ];
    for (name, expected) in expectations {
        let body: &str = method_body(&asm, "UnsignedOverflow", name);
        assert!(
            body.contains(expected),
            "{name} must print `{expected}` to keep the IL's signedness, overflow or NaN semantics; got:\n{body}"
        );
    }
}
