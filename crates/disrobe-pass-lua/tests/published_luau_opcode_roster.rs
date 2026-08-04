#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use disrobe_pass_lua::{
    DecompiledChunk, Fidelity, LuaChunk, LuaDialect, LuaProto,
    decompile::{decompile_chunk, luau_lift::test_op_length},
    reader::luau,
};

const DECLARED_OPCODES: usize = 88;
const HIGHEST_OPCODE: u8 = 87;
const LIFTED_OPCODES: usize = 86;
const LOP_BREAK: u8 = 1;

const DECODED_NOT_LIFTED: [(&str, u8); 2] = [("BREAK", LOP_BREAK), ("NEWCLASSMEMBER", 86)];

const LIFTER_SOURCE: &str = "src/decompile/luau_lift.rs";
const REAL_LUAU_FIXTURE: &str = "corpus/lua/decompile_samples/arith_loops.luau";
const OPCODE_PREFIX: &str = "const LOP_";
const UNKNOWN_WARNING: &str = "unknown luau opcode";
const DEBUGGER_BREAK_WARNING: &str = "unresolved luau debugger breakpoint";

const DIALECT_DOC: &str = "docs/src/languages/lua.md";
const DIALECT_PHRASE: &str = "Luau (<!-- m:luau_opcode_lift_count -->86 of 88<!-- /m --> opcodes in disrobe's declared table are lifted";
const RECOVERY_DATA: &str = "xtask/data/recovery.json";
const RECOVERY_HEADING: &str = "Luau opcode lifting";
const RECOVERY_BAR: &str = "Luau declared-table opcodes lifted";
const RECOVERY_TEST_PATH: &str = "crates/disrobe-pass-lua/tests/published_luau_opcode_roster.rs";
const RECOVERY_TEST_FUNCTION: &str = "published_luau_opcode_lift_ratio_matches_this_lifter";

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

fn real_luau_fixture() -> LuaChunk {
    let path: PathBuf = repo_root().join(REAL_LUAU_FIXTURE);
    let bytes: Vec<u8> = fs::read(&path).unwrap_or_else(|error: std::io::Error| {
        panic!(
            "the BREAK proof requires the tracked luau-compile fixture {REAL_LUAU_FIXTURE}: {error} at {}",
            path.display()
        )
    });
    luau::read(&bytes).unwrap_or_else(|error| {
        panic!(
            "the tracked luau-compile fixture {REAL_LUAU_FIXTURE} must parse before its instruction stream can grade BREAK: {error}"
        )
    })
}

fn replace_last_single_word_instruction_with_break(chunk: &mut LuaChunk) -> usize {
    let code: &mut [u32] = &mut chunk.main.code;
    let mut pc: usize = 0;
    let mut candidate: Option<usize> = None;
    while pc < code.len() {
        let op: u8 =
            u8::try_from(code[pc] & u32::from(u8::MAX)).expect("a Luau opcode occupies one byte");
        let width: usize = test_op_length(op);
        assert!(width > 0, "Luau instruction width must be positive");
        if width == 1 && op != LOP_BREAK {
            candidate = Some(pc);
        }
        pc = pc
            .checked_add(width)
            .expect("the tracked Luau fixture instruction index must fit usize");
    }
    assert_eq!(
        pc,
        code.len(),
        "the tracked Luau fixture must end on an instruction boundary"
    );
    let Some(selected): Option<usize> = candidate else {
        panic!("the tracked Luau fixture contains no single-word instruction to mutate")
    };
    code[selected] = (code[selected] & !u32::from(u8::MAX)) | u32::from(LOP_BREAK);
    selected
}

fn language_break_count(source: &str) -> usize {
    source
        .lines()
        .filter(|line: &&str| line.trim() == "break")
        .count()
}

fn real_break_mutation_output() -> (usize, usize, DecompiledChunk) {
    let mut chunk: LuaChunk = real_luau_fixture();
    let baseline: DecompiledChunk = decompile_chunk(&chunk)
        .expect("the tracked luau-compile fixture must decompile before mutation");
    let baseline_breaks: usize = language_break_count(&baseline.source);
    let pc: usize = replace_last_single_word_instruction_with_break(&mut chunk);
    let mutated: DecompiledChunk = decompile_chunk(&chunk)
        .expect("the tracked luau-compile fixture must decompile after the BREAK mutation");
    (pc, baseline_breaks, mutated)
}

fn real_break_is_not_lifted() -> bool {
    let (pc, baseline_breaks, mutated): (usize, usize, DecompiledChunk) =
        real_break_mutation_output();
    let expected_warning: String = format!("{DEBUGGER_BREAK_WARNING} at pc={pc}");
    mutated
        .warnings
        .iter()
        .any(|warning: &String| warning == &expected_warning)
        && language_break_count(&mutated.source) == baseline_breaks
        && mutated.fidelity == Fidelity::BestEffort
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

fn reports_not_lifted(op: u8) -> bool {
    if op == LOP_BREAK {
        return real_break_is_not_lifted();
    }
    let chunk: LuaChunk = luau_chunk_carrying(op);
    let decompiled: DecompiledChunk = decompile_chunk(&chunk).unwrap_or_else(|error| {
        panic!("the Luau lifter must accept a one-instruction chunk carrying opcode {op}: {error}")
    });
    let needle: String = format!("{UNKNOWN_WARNING} {op}");
    decompiled.warnings.iter().any(|warning: &String| {
        warning.contains(&needle) || warning.contains(DEBUGGER_BREAK_WARNING)
    }) || decompiled.source.contains(&format!("unknown luau op {op}"))
}

#[test]
fn real_luau_fixture_break_mutation_stays_unresolved_in_lifted_output() {
    let (pc, baseline_breaks, mutated): (usize, usize, DecompiledChunk) =
        real_break_mutation_output();
    let expected_warning: String = format!("{DEBUGGER_BREAK_WARNING} at pc={pc}");
    let matching_warnings: usize = mutated
        .warnings
        .iter()
        .filter(|warning: &&String| *warning == &expected_warning)
        .count();

    assert_eq!(
        matching_warnings, 1,
        "the real fixture mutation must report exactly one unresolved BREAK at its actual pc"
    );
    assert_eq!(
        language_break_count(&mutated.source),
        baseline_breaks,
        "a debugger BREAK mutation must not add a source-language break to real lifted output"
    );
    assert_eq!(
        mutated.fidelity,
        Fidelity::BestEffort,
        "a lift carrying unresolved debugger instrumentation must not claim full fidelity"
    );
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

fn published_recovery_bar() -> serde_json::Value {
    let path: PathBuf = repo_root().join(RECOVERY_DATA);
    let raw: String = fs::read_to_string(&path).unwrap_or_else(|error: std::io::Error| {
        panic!(
            "{RECOVERY_DATA} owns the public Luau opcode ratio, so a run that cannot read it must fail rather than leave the documentation unchecked: {error} at {}",
            path.display()
        )
    });
    let recovery: serde_json::Value =
        serde_json::from_str(&raw).unwrap_or_else(|error: serde_json::Error| {
            panic!("{RECOVERY_DATA} must parse as JSON: {error}")
        });
    let groups: &Vec<serde_json::Value> = recovery["groups"]
        .as_array()
        .unwrap_or_else(|| panic!("{RECOVERY_DATA} must carry a groups array"));
    let mut found: Vec<serde_json::Value> = groups
        .iter()
        .filter(|chart: &&serde_json::Value| {
            chart["heading"]
                .as_str()
                .is_some_and(|heading: &str| heading.contains(RECOVERY_HEADING))
        })
        .flat_map(|chart: &serde_json::Value| {
            chart["bars"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|bar: &&serde_json::Value| bar["label"].as_str() == Some(RECOVERY_BAR))
                .cloned()
        })
        .collect();
    assert_eq!(
        found.len(),
        1,
        "{RECOVERY_DATA} must carry exactly one `{RECOVERY_BAR}` bar under a heading containing `{RECOVERY_HEADING}`, found {}",
        found.len()
    );
    found.remove(0)
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
fn published_luau_opcode_lift_ratio_matches_this_lifter() {
    let source: String = lifter_source();
    let declared: Vec<(String, u8)> = declared_opcodes(&source);

    let handled: BTreeSet<u8> = declared
        .iter()
        .map(|entry: &(String, u8)| entry.1)
        .filter(|op: &u8| !reports_not_lifted(*op))
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
         lifting, but the lifter reports {unhandled:?} as unresolved; the \
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

    let bar: serde_json::Value = published_recovery_bar();
    let published_num: u64 = bar["num"]
        .as_u64()
        .unwrap_or_else(|| panic!("the `{RECOVERY_BAR}` bar must carry a raw integer num"));
    let published_den: u64 = bar["den"]
        .as_u64()
        .unwrap_or_else(|| panic!("the `{RECOVERY_BAR}` bar must carry a raw integer den"));
    let published_value: f64 = bar["value"]
        .as_f64()
        .unwrap_or_else(|| panic!("the `{RECOVERY_BAR}` bar must carry a numeric value"));
    let derived_value: f64 = 100.0 * published_num as f64 / published_den as f64;
    assert_eq!(
        usize::try_from(published_num).expect("the published Luau numerator must fit usize"),
        handled.len(),
        "{RECOVERY_DATA} publishes {published_num} lifted Luau opcodes, but the lifter handles {}",
        handled.len()
    );
    assert_eq!(
        usize::try_from(published_den).expect("the published Luau denominator must fit usize"),
        all.len(),
        "{RECOVERY_DATA} publishes {published_den} declared Luau opcodes, but the lifter declares {}",
        all.len()
    );
    assert_eq!(
        published_value.to_bits(),
        derived_value.to_bits(),
        "{RECOVERY_DATA} publishes {published_value} percent for `{RECOVERY_BAR}`, but its raw \
         {published_num} of {published_den} ratio derives {derived_value} percent"
    );
    assert_eq!(
        bar["verified_by"]["path"].as_str(),
        Some(RECOVERY_TEST_PATH),
        "the `{RECOVERY_BAR}` bar must cite its owning test file"
    );
    assert_eq!(
        bar["verified_by"]["function"].as_str(),
        Some(RECOVERY_TEST_FUNCTION),
        "the `{RECOVERY_BAR}` bar must cite `{RECOVERY_TEST_FUNCTION}`"
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
        reports_not_lifted(UNDECLARED_PROBE),
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
