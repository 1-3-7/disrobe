#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use disrobe_pass_lua::{
    DecompiledChunk, LuaChunk, LuaDialect, LuaProto, decompile::decompile_chunk,
};

const DECLARED_OPCODES: usize = 88;
const HIGHEST_OPCODE: u8 = 87;
const LIFTED_OPCODES: usize = 87;

const DECODED_NOT_LIFTED: [(&str, u8); 1] = [("NEWCLASSMEMBER", 86)];

const LIFTER_SOURCE: &str = "src/decompile/luau_lift.rs";
const OPCODE_PREFIX: &str = "const LOP_";
const UNKNOWN_WARNING: &str = "unknown luau opcode";

const DIALECT_DOC: &str = "docs/src/languages/lua.md";
const DIALECT_PHRASE: &str = "Luau (87 of the 88 opcodes its table declares are lifted";

const UNDECLARED_PROBE: u8 = 200;

fn repo_root() -> PathBuf {
    let manifest: &Path = Path::new(env!("CARGO_MANIFEST_DIR"));
    let Some(root): Option<&Path> = manifest.parent().and_then(Path::parent) else {
        panic!(
            "the published Luau opcode figure is stated in {DIALECT_DOC}, two directories above \
             {}, so a manifest path with no grandparent leaves it checked against nothing",
            manifest.display()
        )
    };
    root.to_path_buf()
}

fn lifter_source() -> String {
    let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR")).join(LIFTER_SOURCE);
    fs::read_to_string(&path).unwrap_or_else(|error: std::io::Error| {
        panic!(
            "{LIFTER_SOURCE} declares the opcode table the published figure counts, so a run that \
             cannot read it must fail rather than report a green that counted nothing: {error} at \
             {}",
            path.display()
        )
    })
}

fn declared_opcodes(source: &str) -> Vec<(String, u8)> {
    let mut declared: Vec<(String, u8)> = Vec::new();
    for line in source.lines() {
        let trimmed: &str = line.trim();
        let Some(rest): Option<&str> = trimmed.strip_prefix(OPCODE_PREFIX) else {
            continue;
        };
        let Some((name, tail)): Option<(&str, &str)> = rest.split_once(':') else {
            continue;
        };
        let Some(after): Option<&str> = tail.trim_start().strip_prefix("u8 = ") else {
            continue;
        };
        let digits: String = after.chars().take_while(char::is_ascii_digit).collect();
        let Ok(value): Result<u8, core::num::ParseIntError> = digits.parse::<u8>() else {
            panic!("`LOP_{name}` in {LIFTER_SOURCE} is not declared as a plain u8 literal")
        };
        declared.push((name.to_owned(), value));
    }
    declared
}

fn luau_chunk_carrying(op: u8) -> LuaChunk {
    LuaChunk {
        dialect: LuaDialect::Luau,
        version_byte: 6,
        format: 0,
        little_endian: true,
        size_of_int: 4,
        size_of_size_t: 8,
        size_of_instruction: 4,
        size_of_lua_integer: 8,
        size_of_lua_number: 8,
        integral_number: false,
        main: LuaProto {
            source: Some("roster".to_owned()),
            line_defined: 0,
            last_line_defined: 0,
            num_params: 0,
            is_vararg: 0,
            max_stack_size: 8,
            code: vec![u32::from(op), 0, 0],
            constants: Vec::new(),
            protos: Vec::new(),
            source_lines: Vec::new(),
            locals: Vec::new(),
            upvalues: Vec::new(),
        },
    }
}

fn reports_unknown(op: u8) -> bool {
    let chunk: LuaChunk = luau_chunk_carrying(op);
    let decompiled: DecompiledChunk = decompile_chunk(&chunk).unwrap_or_else(|error| {
        panic!("the Luau lifter must accept a one-instruction chunk carrying opcode {op}: {error}")
    });
    let needle: String = format!("{UNKNOWN_WARNING} {op}");
    decompiled
        .warnings
        .iter()
        .any(|warning: &String| warning.contains(&needle))
        || decompiled.source.contains(&format!("unknown luau op {op}"))
}

fn published_doc() -> String {
    let path: PathBuf = repo_root().join(DIALECT_DOC);
    fs::read_to_string(&path).unwrap_or_else(|error: std::io::Error| {
        panic!(
            "{DIALECT_DOC} publishes the Luau opcode figure, so a run that cannot read it must fail \
             rather than report a green that checked no document: {error} at {}",
            path.display()
        )
    })
}

#[test]
fn the_declared_opcode_table_is_contiguous_and_the_size_the_page_publishes() {
    let source: String = lifter_source();
    let declared: Vec<(String, u8)> = declared_opcodes(&source);

    assert_eq!(
        declared.len(),
        DECLARED_OPCODES,
        "{LIFTER_SOURCE} declares {} opcodes against the {DECLARED_OPCODES} {DIALECT_DOC} \
         publishes; the table size is the figure a reader is given, so it is pinned by equality",
        declared.len()
    );

    let values: BTreeSet<u8> = declared
        .iter()
        .map(|entry: &(String, u8)| entry.1)
        .collect();
    assert_eq!(
        values.len(),
        DECLARED_OPCODES,
        "two opcode constants in {LIFTER_SOURCE} share a value, so the table names fewer \
         instructions than it appears to"
    );
    let expected: BTreeSet<u8> = (0..=HIGHEST_OPCODE).collect();
    assert_eq!(
        values, expected,
        "the declared opcode values are not exactly 0 through {HIGHEST_OPCODE}; a gap means the \
         published count includes an instruction the format does not carry, and a value beyond the \
         top means one is missing from the count"
    );

    let mut names: Vec<&str> = declared
        .iter()
        .map(|entry: &(String, u8)| entry.0.as_str())
        .collect();
    let total: usize = names.len();
    names.sort_unstable();
    names.dedup();
    assert_eq!(
        names.len(),
        total,
        "{LIFTER_SOURCE} declares the same opcode name twice"
    );
}

#[test]
fn every_declared_opcode_is_lifted_rather_than_reported_unknown() {
    let source: String = lifter_source();
    let declared: Vec<(String, u8)> = declared_opcodes(&source);

    let handled: BTreeSet<u8> = declared
        .iter()
        .map(|entry: &(String, u8)| entry.1)
        .filter(|op: &u8| !reports_unknown(*op))
        .collect();
    let all: BTreeSet<u8> = declared
        .iter()
        .map(|entry: &(String, u8)| entry.1)
        .collect();

    let unhandled: BTreeSet<u8> = all.difference(&handled).copied().collect();
    let published_unhandled: BTreeSet<u8> = DECODED_NOT_LIFTED
        .into_iter()
        .map(|entry: (&str, u8)| entry.1)
        .collect();

    assert_eq!(
        unhandled, published_unhandled,
        "{DIALECT_DOC} names {DECODED_NOT_LIFTED:?} as the opcodes this lifter decodes without \
         lifting, but the lifter falls through to its unknown-opcode arm for {unhandled:?}; the \
         page must name the residual set rather than a count, so an opcode that stops lifting shows \
         up here and an opcode that starts forces the page to be rewritten"
    );
    for (name, op) in DECODED_NOT_LIFTED {
        let declared_name: Option<&(String, u8)> =
            declared.iter().find(|entry: &&(String, u8)| entry.1 == op);
        let Some(entry): Option<&(String, u8)> = declared_name else {
            panic!(
                "{DIALECT_DOC} names opcode {op} as decoded but not lifted, and {LIFTER_SOURCE} declares no opcode with that value"
            )
        };
        assert_eq!(
            entry.0, name,
            "opcode {op} is published as `{name}` but {LIFTER_SOURCE} declares it as `{}`",
            entry.0
        );
    }
    assert_eq!(
        handled.len(),
        LIFTED_OPCODES,
        "the exercised population is pinned by equality against the published {LIFTED_OPCODES} so \
         that a run inspecting fewer opcodes scores worse rather than shrinking its own denominator"
    );
    assert_eq!(
        handled.len() + unhandled.len(),
        DECLARED_OPCODES,
        "every declared opcode is either lifted or named in the residual; {} lifted plus {} \
         residual does not account for the whole table",
        handled.len(),
        unhandled.len()
    );
}

#[test]
fn the_unknown_opcode_check_fires_on_a_value_the_table_does_not_declare() {
    let source: String = lifter_source();
    let declared: BTreeSet<u8> = declared_opcodes(&source)
        .into_iter()
        .map(|entry: (String, u8)| entry.1)
        .collect();
    assert!(
        !declared.contains(&UNDECLARED_PROBE),
        "the control probe {UNDECLARED_PROBE} must be an opcode the table does not declare"
    );
    assert!(
        reports_unknown(UNDECLARED_PROBE),
        "the lifter must report opcode {UNDECLARED_PROBE} as unknown; if it reported nothing, the \
         assertion above would pass for every opcode whether or not it was handled"
    );
}

#[test]
fn the_dialect_row_states_the_table_size_this_crate_carries() {
    let doc: String = published_doc();
    assert!(
        doc.contains(DIALECT_PHRASE),
        "{DIALECT_DOC} must state `{DIALECT_PHRASE}`; the lifter declares {DECLARED_OPCODES} \
         opcodes and lifts {LIFTED_OPCODES} of them, so a dialect row naming a different number \
         describes a table this crate does not carry"
    );
    for (name, _) in DECODED_NOT_LIFTED {
        assert!(
            doc.contains(name),
            "{DIALECT_DOC} states the lifted figure but never names `{name}`, the opcode it \
             excludes; a reader given only the number cannot tell which instruction is missing"
        );
    }
}
