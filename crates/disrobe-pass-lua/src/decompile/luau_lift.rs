use crate::decompile::{DecompiledChunk, Fidelity};
use crate::error::Result;
use crate::reader::common::{LuaChunk, LuaConstant, LuaProto};

const MAX_LIFT_DEPTH: usize = 200;

const LOP_NOP: u8 = 0;
const LOP_BREAK: u8 = 1;
const LOP_LOADNIL: u8 = 2;
const LOP_LOADB: u8 = 3;
const LOP_LOADN: u8 = 4;
const LOP_LOADK: u8 = 5;
const LOP_MOVE: u8 = 6;
const LOP_GETGLOBAL: u8 = 7;
const LOP_SETGLOBAL: u8 = 8;
const LOP_GETUPVAL: u8 = 9;
const LOP_SETUPVAL: u8 = 10;
const LOP_CLOSEUPVALS: u8 = 11;
const LOP_GETIMPORT: u8 = 12;
const LOP_GETTABLE: u8 = 13;
const LOP_SETTABLE: u8 = 14;
const LOP_GETTABLEKS: u8 = 15;
const LOP_SETTABLEKS: u8 = 16;
const LOP_GETTABLEN: u8 = 17;
const LOP_SETTABLEN: u8 = 18;
const LOP_NEWCLOSURE: u8 = 19;
const LOP_NAMECALL: u8 = 20;
const LOP_CALL: u8 = 21;
const LOP_RETURN: u8 = 22;
const LOP_JUMP: u8 = 23;
const LOP_JUMPBACK: u8 = 24;
const LOP_JUMPIF: u8 = 25;
const LOP_JUMPIFNOT: u8 = 26;
const LOP_JUMPIFEQ: u8 = 27;
const LOP_JUMPIFLE: u8 = 28;
const LOP_JUMPIFLT: u8 = 29;
const LOP_JUMPIFNOTEQ: u8 = 30;
const LOP_JUMPIFNOTLE: u8 = 31;
const LOP_JUMPIFNOTLT: u8 = 32;
const LOP_ADD: u8 = 33;
const LOP_SUB: u8 = 34;
const LOP_MUL: u8 = 35;
const LOP_DIV: u8 = 36;
const LOP_MOD: u8 = 37;
const LOP_POW: u8 = 38;
const LOP_ADDK: u8 = 39;
const LOP_SUBK: u8 = 40;
const LOP_MULK: u8 = 41;
const LOP_DIVK: u8 = 42;
const LOP_MODK: u8 = 43;
const LOP_POWK: u8 = 44;
const LOP_AND: u8 = 45;
const LOP_OR: u8 = 46;
const LOP_ANDK: u8 = 47;
const LOP_ORK: u8 = 48;
const LOP_CONCAT: u8 = 49;
const LOP_NOT: u8 = 50;
const LOP_MINUS: u8 = 51;
const LOP_LENGTH: u8 = 52;
const LOP_NEWTABLE: u8 = 53;
const LOP_DUPTABLE: u8 = 54;
const LOP_SETLIST: u8 = 55;
const LOP_FORNPREP: u8 = 56;
const LOP_FORNLOOP: u8 = 57;
const LOP_FORGLOOP: u8 = 58;
const LOP_FORGPREP_INEXT: u8 = 59;
const LOP_FASTCALL3: u8 = 60;
const LOP_FORGPREP_NEXT: u8 = 61;
const LOP_NATIVECALL: u8 = 62;
const LOP_GETVARARGS: u8 = 63;
const LOP_DUPCLOSURE: u8 = 64;
const LOP_PREPVARARGS: u8 = 65;
const LOP_LOADKX: u8 = 66;
const LOP_JUMPX: u8 = 67;
const LOP_FASTCALL: u8 = 68;
const LOP_COVERAGE: u8 = 69;
const LOP_CAPTURE: u8 = 70;
const LOP_SUBRK: u8 = 71;
const LOP_DIVRK: u8 = 72;
const LOP_FASTCALL1: u8 = 73;
const LOP_FASTCALL2: u8 = 74;
const LOP_FASTCALL2K: u8 = 75;
const LOP_FORGPREP: u8 = 76;
const LOP_JUMPXEQKNIL: u8 = 77;
const LOP_JUMPXEQKB: u8 = 78;
const LOP_JUMPXEQKN: u8 = 79;
const LOP_JUMPXEQKS: u8 = 80;
const LOP_IDIV: u8 = 81;
const LOP_IDIVK: u8 = 82;

pub fn decompile(chunk: &LuaChunk) -> Result<DecompiledChunk> {
    let main: &LuaProto = &chunk.main;
    let mut out: String = String::new();
    out.push_str("-- decompiled by disrobe (luau register lifter)\n");
    out.push_str(&main_signature(main));
    out.push('\n');
    let mut warnings: Vec<String> = Vec::new();
    let mut fully_structured: bool = true;
    let body: String = lift_proto(main, 0, &mut warnings, &mut fully_structured);
    for ln in body.lines() {
        out.push_str(ln);
        out.push('\n');
    }
    out.push_str("end\n");
    let fidelity: Fidelity = if warnings.is_empty() && fully_structured {
        Fidelity::Lossless
    } else if fully_structured {
        Fidelity::Lossy
    } else {
        Fidelity::BestEffort
    };
    Ok(DecompiledChunk {
        source: out,
        fidelity,
        warnings,
    })
}

#[must_use]
fn main_signature(main: &LuaProto) -> String {
    let params: String = (0..main.num_params)
        .map(|i: u8| format!("p{i}"))
        .collect::<Vec<String>>()
        .join(", ");
    match (params.is_empty(), main.is_vararg != 0) {
        (true, false) => "function _main()".to_owned(),
        (true, true) => "function _main(...)".to_owned(),
        (false, false) => format!("function _main({params})"),
        (false, true) => format!("function _main({params}, ...)"),
    }
}

#[derive(Debug, Clone)]
struct LuauState {
    regs: Vec<String>,
    lines: Vec<String>,
    indent: usize,
}

impl LuauState {
    fn new(stack: u8) -> Self {
        Self {
            regs: vec![String::new(); usize::from(stack).max(2)],
            lines: Vec::new(),
            indent: 1,
        }
    }

    #[inline]
    fn reg(&self, i: u32) -> String {
        let idx: usize = i as usize;
        match self.regs.get(idx) {
            Some(s) if !s.is_empty() => s.clone(),
            _ => format!("r{idx}"),
        }
    }

    #[inline]
    fn set_reg(&mut self, i: u32, value: String) {
        let idx: usize = i as usize;
        if idx >= self.regs.len() {
            self.regs.resize(idx + 1, String::new());
        }
        self.regs[idx] = value;
    }

    #[inline]
    fn push(&mut self, stmt: &str) {
        let pad: String = "  ".repeat(self.indent);
        self.lines.push(format!("{pad}{stmt}"));
    }
}

#[derive(Debug, Clone, Copy)]
struct Insn {
    op: u8,
    a: u8,
    b: u8,
    c: u8,
    d: i32,
    e: i32,
}

#[inline]
fn decode(raw: u32) -> Insn {
    let op: u8 = (raw & 0xFF) as u8;
    let arg_a: u8 = ((raw >> 8) & 0xFF) as u8;
    let arg_b: u8 = ((raw >> 16) & 0xFF) as u8;
    let arg_c: u8 = ((raw >> 24) & 0xFF) as u8;
    let arg_d: i32 = (raw as i32) >> 16;
    let arg_e: i32 = (raw as i32) >> 8;
    Insn {
        op,
        a: arg_a,
        b: arg_b,
        c: arg_c,
        d: arg_d,
        e: arg_e,
    }
}

#[must_use]
fn quote_lua(s: &str) -> String {
    let mut out: String = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\{}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[must_use]
fn const_str(c: &LuaConstant) -> String {
    match c {
        LuaConstant::Nil => "nil".to_owned(),
        LuaConstant::Bool(true) => "true".to_owned(),
        LuaConstant::Bool(false) => "false".to_owned(),
        LuaConstant::Integer(i) => i.to_string(),
        LuaConstant::Number(n) => format_num(*n),
        LuaConstant::Str(s) => quote_lua(s),
    }
}

#[must_use]
fn format_num(n: f64) -> String {
    if n.is_nan() {
        return "(0/0)".to_owned();
    }
    if n.is_infinite() {
        return if n > 0.0 {
            "math.huge".to_owned()
        } else {
            "-math.huge".to_owned()
        };
    }
    if n.fract() == 0.0 && n.abs() < 1e15 {
        return format!("{}", n as i64);
    }
    format!("{n}")
}

#[must_use]
fn const_string_raw(p: &LuaProto, idx: u32) -> Option<&str> {
    match p.constants.get(idx as usize) {
        Some(LuaConstant::Str(s)) => Some(s.as_str()),
        _ => None,
    }
}

#[must_use]
fn is_ident(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c: char| c.is_ascii_alphanumeric() || c == '_')
}

#[must_use]
fn const_at(p: &LuaProto, idx: u32) -> String {
    p.constants
        .get(idx as usize)
        .map_or_else(|| format!("k{idx}"), const_str)
}

fn lift_proto(
    proto: &LuaProto,
    depth: usize,
    warnings: &mut Vec<String>,
    fully_structured: &mut bool,
) -> String {
    if depth > MAX_LIFT_DEPTH {
        warnings.push("luau proto nesting exceeds lift depth limit".to_owned());
        *fully_structured = false;
        return "  -- (proto nesting limit reached)\n".to_owned();
    }
    let mut state: LuauState = LuauState::new(proto.max_stack_size);
    for i in 0..u32::from(proto.num_params) {
        state.set_reg(i, format!("p{i}"));
    }
    let jump_targets: Vec<bool> = compute_jump_targets(&proto.code);
    let mut pc: usize = 0;
    let n: usize = proto.code.len();
    while pc < n {
        if jump_targets.get(pc).copied().unwrap_or(false) {
            state.push(&format!("::lu_{pc}::"));
        }
        let raw: u32 = proto.code[pc];
        let inst: Insn = decode(raw);
        let advance: usize = handle(proto, &inst, pc, n, &mut state, warnings, fully_structured);
        pc += advance;
    }
    let mut source: String = String::new();
    for ln in &state.lines {
        source.push_str(ln);
        source.push('\n');
    }
    source
}

fn handle(
    proto: &LuaProto,
    inst: &Insn,
    pc: usize,
    code_len: usize,
    state: &mut LuauState,
    warnings: &mut Vec<String>,
    fully_structured: &mut bool,
) -> usize {
    match inst.op {
        LOP_NOP | LOP_BREAK | LOP_COVERAGE | LOP_CAPTURE | LOP_PREPVARARGS => 1,
        LOP_LOADNIL => {
            state.set_reg(u32::from(inst.a), "nil".to_owned());
            1
        }
        LOP_LOADB => {
            state.set_reg(
                u32::from(inst.a),
                if inst.b != 0 {
                    "true".to_owned()
                } else {
                    "false".to_owned()
                },
            );
            let skip: u32 = u32::from(inst.c);
            if skip > 0 { 1 + skip as usize } else { 1 }
        }
        LOP_LOADN => {
            state.set_reg(u32::from(inst.a), inst.d.to_string());
            1
        }
        LOP_LOADK => {
            let lit: String = const_at(proto, inst.d as u32);
            state.set_reg(u32::from(inst.a), lit);
            1
        }
        LOP_LOADKX => {
            let aux: Option<u32> = proto.code.get(pc + 1).copied();
            match aux {
                Some(idx) => {
                    let lit: String = const_at(proto, idx);
                    state.set_reg(u32::from(inst.a), lit);
                    2
                }
                None => 1,
            }
        }
        LOP_MOVE => {
            let src: String = state.reg(u32::from(inst.b));
            state.set_reg(u32::from(inst.a), src);
            1
        }
        LOP_GETGLOBAL => {
            let aux: Option<u32> = proto.code.get(pc + 1).copied();
            match aux.and_then(|idx: u32| const_string_raw(proto, idx).map(str::to_owned)) {
                Some(name) => state.set_reg(u32::from(inst.a), name),
                None => state.set_reg(u32::from(inst.a), format!("_G[k{}]", inst.c)),
            }
            2
        }
        LOP_SETGLOBAL => {
            let aux: Option<u32> = proto.code.get(pc + 1).copied();
            let val: String = state.reg(u32::from(inst.a));
            match aux.and_then(|idx: u32| const_string_raw(proto, idx).map(str::to_owned)) {
                Some(name) => state.push(&format!("{name} = {val}")),
                None => state.push(&format!("_G[k{}] = {val}", inst.c)),
            }
            2
        }
        LOP_GETUPVAL => {
            state.set_reg(u32::from(inst.a), upval_name(proto, u32::from(inst.b)));
            1
        }
        LOP_SETUPVAL => {
            let name: String = upval_name(proto, u32::from(inst.b));
            let val: String = state.reg(u32::from(inst.a));
            state.push(&format!("{name} = {val}"));
            1
        }
        LOP_CLOSEUPVALS => {
            state.push(&format!("-- close upvalues >= r{}", inst.a));
            1
        }
        LOP_GETIMPORT => {
            let aux: Option<u32> = proto.code.get(pc + 1).copied();
            match aux {
                Some(id) => {
                    let count: u32 = id >> 30;
                    let id0: u32 = (id >> 20) & 0x3FF;
                    let id1: u32 = (id >> 10) & 0x3FF;
                    let id2: u32 = id & 0x3FF;
                    let mut path: Vec<String> = Vec::new();
                    if count >= 1
                        && let Some(s) = const_string_raw(proto, id0)
                    {
                        path.push(s.to_owned());
                    }
                    if count >= 2
                        && let Some(s) = const_string_raw(proto, id1)
                    {
                        path.push(s.to_owned());
                    }
                    if count >= 3
                        && let Some(s) = const_string_raw(proto, id2)
                    {
                        path.push(s.to_owned());
                    }
                    let expr: String = if path.is_empty() {
                        format!("__import_{}", inst.d)
                    } else {
                        path.join(".")
                    };
                    state.set_reg(u32::from(inst.a), expr);
                }
                None => state.set_reg(u32::from(inst.a), format!("__import_{}", inst.d)),
            }
            2
        }
        LOP_GETTABLE => {
            let table: String = state.reg(u32::from(inst.b));
            let key: String = state.reg(u32::from(inst.c));
            state.set_reg(u32::from(inst.a), format!("{table}[{key}]"));
            1
        }
        LOP_SETTABLE => {
            let table: String = state.reg(u32::from(inst.b));
            let key: String = state.reg(u32::from(inst.c));
            let val: String = state.reg(u32::from(inst.a));
            state.push(&format!("{table}[{key}] = {val}"));
            1
        }
        LOP_GETTABLEKS => {
            let table: String = state.reg(u32::from(inst.b));
            let aux: Option<u32> = proto.code.get(pc + 1).copied();
            let key: Option<&str> = aux.and_then(|idx: u32| const_string_raw(proto, idx));
            let expr: String = match key {
                Some(k) if is_ident(k) => format!("{table}.{k}"),
                Some(k) => format!("{table}[{}]", quote_lua(k)),
                None => format!("{table}[k{}]", inst.c),
            };
            state.set_reg(u32::from(inst.a), expr);
            2
        }
        LOP_SETTABLEKS => {
            let table: String = state.reg(u32::from(inst.b));
            let val: String = state.reg(u32::from(inst.a));
            let aux: Option<u32> = proto.code.get(pc + 1).copied();
            let key: Option<&str> = aux.and_then(|idx: u32| const_string_raw(proto, idx));
            let lhs: String = match key {
                Some(k) if is_ident(k) => format!("{table}.{k}"),
                Some(k) => format!("{table}[{}]", quote_lua(k)),
                None => format!("{table}[k{}]", inst.c),
            };
            state.push(&format!("{lhs} = {val}"));
            2
        }
        LOP_GETTABLEN => {
            let table: String = state.reg(u32::from(inst.b));
            let key: u32 = u32::from(inst.c).saturating_add(1);
            state.set_reg(u32::from(inst.a), format!("{table}[{key}]"));
            1
        }
        LOP_SETTABLEN => {
            let table: String = state.reg(u32::from(inst.b));
            let key: u32 = u32::from(inst.c).saturating_add(1);
            let val: String = state.reg(u32::from(inst.a));
            state.push(&format!("{table}[{key}] = {val}"));
            1
        }
        LOP_NEWCLOSURE | LOP_DUPCLOSURE => {
            let child_idx: u32 = inst.d as u32;
            let child: Option<&LuaProto> = proto.protos.get(child_idx as usize);
            let block: String = match child {
                Some(child_p) => {
                    let body: String = lift_proto(child_p, 0, warnings, fully_structured);
                    let params: String = (0..child_p.num_params)
                        .map(|i: u8| format!("p{i}"))
                        .collect::<Vec<String>>()
                        .join(", ");
                    let header: String = if child_p.is_vararg != 0 {
                        if params.is_empty() {
                            "function(...)".to_owned()
                        } else {
                            format!("function({params}, ...)")
                        }
                    } else {
                        format!("function({params})")
                    };
                    let mut block: String = format!("{header}\n");
                    for ln in body.lines() {
                        block.push_str("  ");
                        block.push_str(ln);
                        block.push('\n');
                    }
                    block.push_str("end");
                    block
                }
                None => format!("function() --[[ luau child {child_idx} placeholder ]] end"),
            };
            state.set_reg(u32::from(inst.a), block);
            1
        }
        LOP_NAMECALL => {
            let obj: String = state.reg(u32::from(inst.b));
            let aux: Option<u32> = proto.code.get(pc + 1).copied();
            let method: Option<&str> = aux.and_then(|idx: u32| const_string_raw(proto, idx));
            match method {
                Some(name) if is_ident(name) => {
                    state.set_reg(u32::from(inst.a), format!("{obj}:{name}"));
                    state.set_reg(u32::from(inst.a) + 1, obj);
                }
                Some(name) => {
                    state.set_reg(u32::from(inst.a), format!("{obj}[{}]", quote_lua(name)));
                    state.set_reg(u32::from(inst.a) + 1, obj);
                }
                None => {
                    state.set_reg(u32::from(inst.a), format!("{obj}[k{}]", inst.c));
                    state.set_reg(u32::from(inst.a) + 1, obj);
                }
            }
            2
        }
        LOP_CALL => {
            let a: u32 = u32::from(inst.a);
            let func: String = state.reg(a);
            let b: u8 = inst.b;
            let nargs: u32 = if b == 0 {
                let mut r: u32 = a + 1;
                while (r as usize) < state.regs.len() {
                    r += 1;
                }
                r - a - 1
            } else {
                u32::from(b) - 1
            };
            let args: Vec<String> = (0..nargs).map(|i: u32| state.reg(a + 1 + i)).collect();
            let call: String = format!("{func}({})", args.join(", "));
            let c: u8 = inst.c;
            match c {
                0 => {
                    state.push(&call);
                }
                1 => {
                    state.push(&call);
                }
                2 => {
                    state.push(&format!("local r{a} = {call}"));
                    state.set_reg(a, format!("r{a}"));
                }
                n => {
                    let targets: Vec<String> = (0..(u32::from(n) - 1))
                        .map(|i: u32| format!("r{}_{}", a + i, state.lines.len()))
                        .collect();
                    state.push(&format!("local {} = {call}", targets.join(", ")));
                    for (i, t) in targets.iter().enumerate() {
                        state.set_reg(a + i as u32, t.clone());
                    }
                }
            }
            1
        }
        LOP_RETURN => {
            let a: u32 = u32::from(inst.a);
            let b: u8 = inst.b;
            if b == 1 {
                if pc + 1 != code_len {
                    state.push("return");
                }
            } else if b == 0 {
                let mut vals: Vec<String> = Vec::new();
                let mut r: u32 = a;
                while (r as usize) < state.regs.len() {
                    vals.push(state.reg(r));
                    r += 1;
                }
                state.push(&format!("return {}", vals.join(", ")));
            } else {
                let vals: Vec<String> = (0..u32::from(b) - 1)
                    .map(|i: u32| state.reg(a + i))
                    .collect();
                state.push(&format!("return {}", vals.join(", ")));
            }
            1
        }
        LOP_JUMP | LOP_JUMPBACK | LOP_JUMPX => {
            let off: i32 = if inst.op == LOP_JUMPX { inst.e } else { inst.d };
            let t: i64 = pc as i64 + 1 + i64::from(off);
            if t >= 0 {
                state.push(&format!("goto lu_{t}"));
            }
            *fully_structured = false;
            1
        }
        LOP_JUMPIF | LOP_JUMPIFNOT => {
            let val: String = state.reg(u32::from(inst.a));
            let neg: &str = if inst.op == LOP_JUMPIF { "" } else { "not " };
            let t: i64 = pc as i64 + 1 + i64::from(inst.d);
            state.push(&format!("if {neg}{val} then goto lu_{t} end"));
            *fully_structured = false;
            1
        }
        LOP_JUMPIFEQ | LOP_JUMPIFNOTEQ | LOP_JUMPIFLE | LOP_JUMPIFNOTLE | LOP_JUMPIFLT
        | LOP_JUMPIFNOTLT => {
            let lhs: String = state.reg(u32::from(inst.a));
            let aux: Option<u32> = proto.code.get(pc + 1).copied();
            let rhs: String = aux
                .map(|idx: u32| state.reg(idx))
                .unwrap_or_else(|| format!("r?_{}", inst.a));
            let sym: &str = match inst.op {
                LOP_JUMPIFEQ => "==",
                LOP_JUMPIFNOTEQ => "~=",
                LOP_JUMPIFLE => "<=",
                LOP_JUMPIFNOTLE => ">",
                LOP_JUMPIFLT => "<",
                LOP_JUMPIFNOTLT => ">=",
                _ => "==",
            };
            let t: i64 = pc as i64 + 1 + i64::from(inst.d);
            state.push(&format!("if {lhs} {sym} {rhs} then goto lu_{t} end"));
            *fully_structured = false;
            2
        }
        LOP_ADD | LOP_SUB | LOP_MUL | LOP_DIV | LOP_MOD | LOP_POW | LOP_IDIV => {
            let lhs: String = state.reg(u32::from(inst.b));
            let rhs: String = state.reg(u32::from(inst.c));
            let sym: &str = match inst.op {
                LOP_ADD => "+",
                LOP_SUB => "-",
                LOP_MUL => "*",
                LOP_DIV => "/",
                LOP_MOD => "%",
                LOP_POW => "^",
                LOP_IDIV => "//",
                _ => "?",
            };
            state.set_reg(u32::from(inst.a), format!("({lhs} {sym} {rhs})"));
            1
        }
        LOP_ADDK | LOP_SUBK | LOP_MULK | LOP_DIVK | LOP_MODK | LOP_POWK | LOP_IDIVK => {
            let lhs: String = state.reg(u32::from(inst.b));
            let rhs: String = const_at(proto, u32::from(inst.c));
            let sym: &str = match inst.op {
                LOP_ADDK => "+",
                LOP_SUBK => "-",
                LOP_MULK => "*",
                LOP_DIVK => "/",
                LOP_MODK => "%",
                LOP_POWK => "^",
                LOP_IDIVK => "//",
                _ => "?",
            };
            state.set_reg(u32::from(inst.a), format!("({lhs} {sym} {rhs})"));
            1
        }
        LOP_SUBRK | LOP_DIVRK => {
            let lhs: String = const_at(proto, u32::from(inst.b));
            let rhs: String = state.reg(u32::from(inst.c));
            let sym: &str = if inst.op == LOP_SUBRK { "-" } else { "/" };
            state.set_reg(u32::from(inst.a), format!("({lhs} {sym} {rhs})"));
            1
        }
        LOP_AND | LOP_OR => {
            let lhs: String = state.reg(u32::from(inst.b));
            let rhs: String = state.reg(u32::from(inst.c));
            let sym: &str = if inst.op == LOP_AND { " and " } else { " or " };
            state.set_reg(u32::from(inst.a), format!("({lhs}{sym}{rhs})"));
            1
        }
        LOP_ANDK | LOP_ORK => {
            let lhs: String = state.reg(u32::from(inst.b));
            let rhs: String = const_at(proto, u32::from(inst.c));
            let sym: &str = if inst.op == LOP_ANDK { " and " } else { " or " };
            state.set_reg(u32::from(inst.a), format!("({lhs}{sym}{rhs})"));
            1
        }
        LOP_CONCAT => {
            let start: u32 = u32::from(inst.b);
            let end: u32 = u32::from(inst.c);
            let parts: Vec<String> = (start..=end).map(|r: u32| state.reg(r)).collect();
            state.set_reg(u32::from(inst.a), format!("({})", parts.join(" .. ")));
            1
        }
        LOP_NOT => {
            let v: String = state.reg(u32::from(inst.b));
            state.set_reg(u32::from(inst.a), format!("(not {v})"));
            1
        }
        LOP_MINUS => {
            let v: String = state.reg(u32::from(inst.b));
            state.set_reg(u32::from(inst.a), format!("-({v})"));
            1
        }
        LOP_LENGTH => {
            let v: String = state.reg(u32::from(inst.b));
            state.set_reg(u32::from(inst.a), format!("#({v})"));
            1
        }
        LOP_NEWTABLE => {
            state.push(&format!("local r{} = {{}}", inst.a));
            state.set_reg(u32::from(inst.a), format!("r{}", inst.a));
            2
        }
        LOP_DUPTABLE => {
            state.push(&format!("local r{} = {{}} -- template k{}", inst.a, inst.d));
            state.set_reg(u32::from(inst.a), format!("r{}", inst.a));
            1
        }
        LOP_SETLIST => {
            let a: u32 = u32::from(inst.a);
            let table: String = state.reg(a);
            let count: u32 = u32::from(inst.c).saturating_sub(1);
            let elems: Vec<String> = (0..count).map(|i: u32| state.reg(a + 1 + i)).collect();
            if !elems.is_empty() {
                state.push(&format!("-- setlist {table} += {{ {} }}", elems.join(", ")));
            }
            2
        }
        LOP_FORNPREP => {
            let a: u32 = u32::from(inst.a);
            let limit: String = state.reg(a);
            let step: String = state.reg(a + 1);
            let init: String = state.reg(a + 2);
            let var: String = format!("fv_{a}");
            state.set_reg(a + 3, var.clone());
            state.push(&format!("for {var} = {init}, {limit}, {step} do"));
            state.indent += 1;
            1
        }
        LOP_FORNLOOP | LOP_FORGLOOP => {
            if state.indent > 1 {
                state.indent -= 1;
            }
            state.push("end");
            1
        }
        LOP_FORGPREP | LOP_FORGPREP_INEXT | LOP_FORGPREP_NEXT => {
            let a: u32 = u32::from(inst.a);
            let f: String = state.reg(a);
            let s: String = state.reg(a + 1);
            let v: String = state.reg(a + 2);
            let var: String = format!("kv_{a}");
            state.set_reg(a + 3, var.clone());
            state.push(&format!("for {var} in {f}, {s}, {v} do"));
            state.indent += 1;
            1
        }
        LOP_NATIVECALL => {
            state.push("-- native call hint");
            1
        }
        LOP_FASTCALL | LOP_FASTCALL1 | LOP_FASTCALL2 | LOP_FASTCALL2K | LOP_FASTCALL3 => 1,
        LOP_GETVARARGS => {
            state.set_reg(u32::from(inst.a), "...".to_owned());
            1
        }
        LOP_JUMPXEQKNIL | LOP_JUMPXEQKB | LOP_JUMPXEQKN | LOP_JUMPXEQKS => {
            let lhs: String = state.reg(u32::from(inst.a));
            let aux: u32 = proto.code.get(pc + 1).copied().unwrap_or(0);
            let neg: bool = (aux >> 31) != 0;
            let kidx: u32 = aux & 0xFF_FFFF;
            let rhs: String = match inst.op {
                LOP_JUMPXEQKNIL => "nil".to_owned(),
                LOP_JUMPXEQKB => {
                    if kidx != 0 {
                        "true".to_owned()
                    } else {
                        "false".to_owned()
                    }
                }
                LOP_JUMPXEQKN | LOP_JUMPXEQKS => const_at(proto, kidx),
                _ => "?".to_owned(),
            };
            let sym: &str = if neg { "~=" } else { "==" };
            let t: i64 = pc as i64 + 1 + i64::from(inst.d);
            state.push(&format!("if {lhs} {sym} {rhs} then goto lu_{t} end"));
            *fully_structured = false;
            2
        }
        op => {
            state.push(&format!(
                "-- unknown luau op {op} a={} b={} c={} d={}",
                inst.a, inst.b, inst.c, inst.d
            ));
            warnings.push(format!("unknown luau opcode {op} at pc={pc}"));
            *fully_structured = false;
            1
        }
    }
}

#[must_use]
fn upval_name(proto: &LuaProto, idx: u32) -> String {
    proto
        .upvalues
        .get(idx as usize)
        .map(|u| u.name.clone())
        .filter(|s: &String| !s.is_empty())
        .unwrap_or_else(|| format!("uv_{idx}"))
}

#[must_use]
fn compute_jump_targets(code: &[u32]) -> Vec<bool> {
    let n: usize = code.len();
    let mut targets: Vec<bool> = vec![false; n + 1];
    for (pc, raw) in code.iter().enumerate() {
        let inst: Insn = decode(*raw);
        match inst.op {
            LOP_JUMP | LOP_JUMPBACK | LOP_JUMPIF | LOP_JUMPIFNOT | LOP_JUMPIFEQ
            | LOP_JUMPIFNOTEQ | LOP_JUMPIFLE | LOP_JUMPIFNOTLE | LOP_JUMPIFLT | LOP_JUMPIFNOTLT
            | LOP_JUMPXEQKNIL | LOP_JUMPXEQKB | LOP_JUMPXEQKN | LOP_JUMPXEQKS => {
                let t: i64 = pc as i64 + 1 + i64::from(inst.d);
                if t >= 0 && (t as usize) <= n {
                    targets[t as usize] = true;
                }
            }
            LOP_JUMPX => {
                let t: i64 = pc as i64 + 1 + i64::from(inst.e);
                if t >= 0 && (t as usize) <= n {
                    targets[t as usize] = true;
                }
            }
            _ => {}
        }
    }
    targets
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn decode_basic_layout() {
        let raw: u32 = u32::from(LOP_MOVE) | (3 << 8) | (5 << 16);
        let inst: Insn = decode(raw);
        assert_eq!(inst.op, LOP_MOVE);
        assert_eq!(inst.a, 3);
        assert_eq!(inst.b, 5);
    }

    #[test]
    fn d_field_is_signed() {
        let raw: u32 = u32::from(LOP_JUMP) | 0xFFFF_0000;
        let inst: Insn = decode(raw);
        assert!(inst.d < 0);
    }

    #[test]
    fn const_string_recovers_identifier_path() {
        let mut p: LuaProto = LuaProto {
            source: None,
            line_defined: 0,
            last_line_defined: 0,
            num_params: 0,
            is_vararg: 0,
            max_stack_size: 2,
            code: Vec::new(),
            constants: vec![LuaConstant::Str("print".to_owned())],
            protos: Vec::new(),
            source_lines: Vec::new(),
            locals: Vec::new(),
            upvalues: Vec::new(),
        };
        let s: Option<&str> = const_string_raw(&p, 0);
        assert_eq!(s, Some("print"));
        p.constants.push(LuaConstant::Str("hello".to_owned()));
        assert_eq!(const_string_raw(&p, 1), Some("hello"));
    }
}
