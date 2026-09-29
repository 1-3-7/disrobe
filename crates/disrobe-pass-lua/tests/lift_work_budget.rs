#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use disrobe_pass_lua::Error;
use disrobe_pass_lua::decompile::budget::LiftBudget;
use disrobe_pass_lua::decompile::{
    DecompiledChunk, decompile_auto_with_budget, decompile_chunk_with_budget,
};
use disrobe_pass_lua::reader::common::LuaChunk;
use disrobe_pass_lua::reader::luau;

const STATED_BUDGET: u64 = 100_000;
const WIDTH: u32 = 4;

const LUA51_MOVE: u32 = 0;
const LUA51_RETURN: u32 = 30;
const LUA51_CLOSURE: u32 = 36;

const LUAU_NOP: u32 = 0;
const LUAU_NEWCLOSURE: u32 = 19;
const LUAU_RETURN: u32 = 22;

const LJ_FNEW: u32 = 51;
const LJ_RET0: u32 = 75;
const LJ_FUNCF: u32 = 89;

const PADDING: usize = 100;

const fn lua51_abc(op: u32, a: u32, b: u32, c: u32) -> u32 {
    op | (a << 6) | (c << 14) | (b << 23)
}

const fn lua51_abx(op: u32, a: u32, bx: u32) -> u32 {
    op | (a << 6) | (bx << 14)
}

fn push_i32(out: &mut Vec<u8>, value: usize) {
    out.extend_from_slice(&i32::try_from(value).unwrap().to_le_bytes());
}

fn push_words(out: &mut Vec<u8>, words: &[u32]) {
    push_i32(out, words.len());
    for word in words {
        out.extend_from_slice(&word.to_le_bytes());
    }
}

fn lua51_function(out: &mut Vec<u8>, levels_below: usize, upvalues: u8) {
    out.extend_from_slice(&0_u32.to_le_bytes());
    push_i32(out, 0);
    push_i32(out, 0);
    out.push(upvalues);
    out.push(0);
    out.push(0);
    let code: Vec<u32> = if levels_below == 0 {
        vec![lua51_abc(LUA51_RETURN, 0, 1, 0)]
    } else {
        let mut code: Vec<u32> = Vec::new();
        for slot in 0..WIDTH {
            code.push(lua51_abx(LUA51_CLOSURE, slot, 0));
            code.push(lua51_abc(LUA51_MOVE, 0, WIDTH + slot, 0));
        }
        code.push(lua51_abc(LUA51_RETURN, 0, 1, 0));
        code
    };
    out.push(u8::try_from(WIDTH * 2).unwrap());
    push_words(out, &code);
    push_i32(out, 0);
    if levels_below == 0 {
        push_i32(out, 0);
    } else {
        push_i32(out, 1);
        lua51_function(out, levels_below - 1, 1);
    }
    push_i32(out, 0);
    push_i32(out, 0);
    push_i32(out, 0);
}

fn lua51_capture_tower(depth: usize) -> Vec<u8> {
    let mut out: Vec<u8> = vec![0x1B, b'L', b'u', b'a', 0x51, 0, 1, 4, 4, 4, 8, 0];
    lua51_function(&mut out, depth, 0);
    out
}

fn write_varint(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let mut byte: u8 = u8::try_from(value & 0x7F).unwrap();
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

fn luau_proto(out: &mut Vec<u8>, child: Option<u64>) {
    out.extend_from_slice(&[u8::try_from(WIDTH).unwrap(), 0, 0, 0, 0]);
    let mut code: Vec<u32> = vec![LUAU_NOP; PADDING];
    if child.is_some() {
        for slot in 0..WIDTH {
            code.push(LUAU_NEWCLOSURE | (slot << 8));
        }
    }
    code.push(LUAU_RETURN | (1 << 16));
    write_varint(out, code.len() as u64);
    for word in &code {
        out.extend_from_slice(&word.to_le_bytes());
    }
    write_varint(out, 0);
    match child {
        Some(id) => {
            write_varint(out, 1);
            write_varint(out, id);
        }
        None => write_varint(out, 0),
    }
    write_varint(out, 0);
    write_varint(out, 0);
    out.push(0);
    out.push(0);
}

fn luau_closure_tower(depth: usize) -> Vec<u8> {
    let mut out: Vec<u8> = vec![5, 0];
    write_varint(&mut out, 0);
    write_varint(&mut out, depth as u64 + 1);
    luau_proto(&mut out, None);
    for level in 1..=depth {
        luau_proto(&mut out, Some(level as u64 - 1));
    }
    write_varint(&mut out, depth as u64);
    out
}

fn luajit_proto(out: &mut Vec<u8>, has_child: bool) {
    let mut code: Vec<u32> = vec![LJ_FUNCF; PADDING];
    if has_child {
        for slot in 0..WIDTH {
            code.push(LJ_FNEW | (slot << 8));
        }
    }
    code.push(LJ_RET0 | (1 << 16));
    let mut body: Vec<u8> = vec![0, 0, u8::try_from(WIDTH).unwrap(), 0];
    write_varint(&mut body, u64::from(has_child));
    write_varint(&mut body, 0);
    write_varint(&mut body, code.len() as u64);
    for word in &code {
        body.extend_from_slice(&word.to_le_bytes());
    }
    if has_child {
        write_varint(&mut body, 0);
    }
    write_varint(out, body.len() as u64);
    out.extend_from_slice(&body);
}

fn luajit_closure_tower(depth: usize) -> Vec<u8> {
    let mut out: Vec<u8> = vec![0x1B, b'L', b'J', 2];
    write_varint(&mut out, 0x02);
    luajit_proto(&mut out, false);
    for _ in 0..depth {
        luajit_proto(&mut out, true);
    }
    write_varint(&mut out, 0);
    out
}

fn decompile_within(
    label: &str,
    run: impl FnOnce(&mut LiftBudget) -> Result<DecompiledChunk, Error>,
) {
    let mut budget: LiftBudget = LiftBudget::new(STATED_BUDGET);
    let outcome: Result<DecompiledChunk, Error> = run(&mut budget);
    let spent: u64 = budget.spent();
    let decompiled: DecompiledChunk = outcome.unwrap_or_else(|error: Error| {
        panic!(
            "{label}: {WIDTH} closures per level over one child must lift each child once and \
             fit {STATED_BUDGET} operations, spent {spent}: {error}"
        )
    });
    assert!(
        spent <= STATED_BUDGET,
        "{label}: spent {spent} of {STATED_BUDGET} operations"
    );
    assert!(
        decompiled.source.contains("function"),
        "{label}: the lifted chunk keeps its closures:\n{}",
        decompiled.source
    );
}

fn refused_by_a_tight_budget(
    label: &str,
    run: impl FnOnce(&mut LiftBudget) -> Result<DecompiledChunk, Error>,
) {
    let limit: u64 = 50;
    let mut budget: LiftBudget = LiftBudget::new(limit);
    match run(&mut budget) {
        Err(Error::LiftBudgetExceeded { limit: named }) => {
            assert_eq!(named, limit, "{label}: the refusal names the budget it hit");
            let text: String = Error::LiftBudgetExceeded { limit: named }.to_string();
            assert!(
                text.contains("DR-LUA-0031") && text.contains("50 operations"),
                "{text}"
            );
        }
        Err(other) => panic!("{label}: expected the work-budget refusal, got {other}"),
        Ok(decompiled) => panic!(
            "{label}: a {limit}-operation budget cannot hold this chunk, yet it decompiled:\n{}",
            decompiled.source
        ),
    }
    assert!(budget.spent() > limit);
}

#[test]
fn lua51_closures_with_distinct_captures_lift_each_child_once_per_capture() {
    let bytes: Vec<u8> = lua51_capture_tower(10);
    decompile_within("lua 5.1", |budget: &mut LiftBudget| {
        decompile_auto_with_budget(&bytes, budget)
    });
    refused_by_a_tight_budget("lua 5.1", |budget: &mut LiftBudget| {
        decompile_auto_with_budget(&bytes, budget)
    });
}

#[test]
fn luau_closures_over_one_child_lift_it_once() {
    let bytes: Vec<u8> = luau_closure_tower(6);
    let chunk: LuaChunk = luau::read(&bytes).expect("luau closure tower parses");
    decompile_within("luau", |budget: &mut LiftBudget| {
        decompile_chunk_with_budget(&chunk, budget)
    });
    refused_by_a_tight_budget("luau", |budget: &mut LiftBudget| {
        decompile_chunk_with_budget(&chunk, budget)
    });
}

#[test]
fn luajit_closures_over_one_child_lift_it_once() {
    let bytes: Vec<u8> = luajit_closure_tower(6);
    decompile_within("luajit", |budget: &mut LiftBudget| {
        decompile_auto_with_budget(&bytes, budget)
    });
    refused_by_a_tight_budget("luajit", |budget: &mut LiftBudget| {
        decompile_auto_with_budget(&bytes, budget)
    });
}
