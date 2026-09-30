#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use disrobe_pass_lua::LuaDialect;
use disrobe_pass_lua::decompile::{DecompiledChunk, decompile_auto};
use disrobe_pass_lua::reader::common::{LuaChunk, LuaProto};
use disrobe_pass_lua::reader::{DetectedFormat, detect, lua55, read_auto};

const EDGE_CASES_55: &[u8] = include_bytes!("../../../corpus/lua/luac/edge_cases.5_5.luac");

const LISTED_FUNCTIONS: usize = 171;
const LISTED_INSTRUCTIONS: usize = 3481;
const LISTED_CONSTANTS: usize = 676;
const LISTED_UPVALUES: usize = 150;

#[derive(Debug, Default, PartialEq, Eq)]
struct Totals {
    functions: usize,
    instructions: usize,
    constants: usize,
    upvalues: usize,
}

fn totals(main: &LuaProto) -> Totals {
    let mut out: Totals = Totals::default();
    let mut pending: Vec<&LuaProto> = vec![main];
    while let Some(p) = pending.pop() {
        out.functions += 1;
        out.instructions += p.code.len();
        out.constants += p.constants.len();
        out.upvalues += p.upvalues.len();
        pending.extend(p.protos.iter());
    }
    out
}

const fn listed() -> Totals {
    Totals {
        functions: LISTED_FUNCTIONS,
        instructions: LISTED_INSTRUCTIONS,
        constants: LISTED_CONSTANTS,
        upvalues: LISTED_UPVALUES,
    }
}

#[test]
fn luac_5_5_megafile_reads_with_the_shape_luac_lists() {
    assert_eq!(detect(EDGE_CASES_55), DetectedFormat::Lua55);
    let chunk: LuaChunk = read_auto(EDGE_CASES_55).expect("the luac 5.5 megafile reads");
    assert_eq!(chunk.dialect, LuaDialect::Lua55);
    assert_eq!(chunk.version_byte, 0x55);
    assert_eq!(chunk.main.source, None, "the fixture is stripped");
    assert_eq!(totals(&chunk.main), listed());
}

#[test]
fn luac_5_5_megafile_decompiles_as_the_5_5_dialect() {
    let decompiled: DecompiledChunk =
        decompile_auto(EDGE_CASES_55).expect("the luac 5.5 megafile decompiles");
    assert!(
        decompiled.source.contains("(lua 5.5 register lifter)"),
        "the recovered source names the 5.5 lifter"
    );
    assert!(
        !decompiled.source.contains("unknown opcode"),
        "every 5.5 opcode in the megafile has a lifting"
    );
}

#[test]
fn a_changed_code_count_no_longer_matches_the_listing() {
    let mut mutated: Vec<u8> = EDGE_CASES_55.to_vec();
    let main_code_count: usize = 46;
    assert_eq!(
        mutated[main_code_count], 0x82,
        "the fixture layout this control edits"
    );
    mutated[main_code_count] = 0x81;
    let changed: bool = match lua55::read(&mutated) {
        Ok(chunk) => totals(&chunk.main) != listed(),
        Err(_) => true,
    };
    assert!(
        changed,
        "a one-byte change to the main code count must change the grade"
    );
}

#[test]
fn every_prefix_of_the_megafile_is_refused_without_a_panic() {
    for len in (0..EDGE_CASES_55.len()).step_by(7) {
        assert!(
            lua55::read(&EDGE_CASES_55[..len]).is_err(),
            "a chunk cut to {len} bytes must be refused"
        );
    }
}
