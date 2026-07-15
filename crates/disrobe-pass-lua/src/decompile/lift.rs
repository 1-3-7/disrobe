use std::collections::BTreeMap;

use crate::decompile::opcode::{Decoded, Op, decode, is_k, rk_index};
use crate::reader::common::{LuaChunk, LuaConstant, LuaDialect, LuaLocal, LuaProto};

const MAX_LIFT_DEPTH: usize = 200;
const LFIELDS_PER_FLUSH: u32 = 50;

#[derive(Debug, Clone, Default)]
struct LocalScopes {
    by_pc: Vec<BTreeMap<u32, String>>,
    activations: Vec<Vec<(u32, String)>>,
    has_names: bool,
}

impl LocalScopes {
    fn build(locals: &[LuaLocal], code_len: usize) -> Self {
        let any_named: bool = locals.iter().any(|l: &LuaLocal| is_ident(&l.name));
        if !any_named {
            return Self::default();
        }
        let mut by_pc: Vec<BTreeMap<u32, String>> = vec![BTreeMap::new(); code_len + 1];
        let mut activations: Vec<Vec<(u32, String)>> = vec![Vec::new(); code_len + 1];
        for (pc, slot_map) in by_pc.iter_mut().enumerate() {
            let pc_u: u32 = pc as u32;
            let mut slot: u32 = 0;
            for loc in locals {
                if loc.start_pc <= pc_u && pc_u < loc.end_pc {
                    if is_ident(&loc.name) {
                        slot_map.entry(slot).or_insert_with(|| loc.name.clone());
                        if loc.start_pc == pc_u
                            && let Some(acts) = activations.get_mut(pc)
                        {
                            acts.push((slot, loc.name.clone()));
                        }
                    }
                    slot += 1;
                }
            }
        }
        Self {
            by_pc,
            activations,
            has_names: true,
        }
    }

    #[inline]
    fn name_at(&self, pc: usize, reg: u32) -> Option<&str> {
        if !self.has_names {
            return None;
        }
        self.by_pc
            .get(pc)
            .and_then(|m: &BTreeMap<u32, String>| m.get(&reg))
            .map(String::as_str)
    }

    #[inline]
    fn activating_at(&self, pc: usize) -> &[(u32, String)] {
        self.activations.get(pc).map_or(&[], Vec::as_slice)
    }
}

#[derive(Debug, Clone)]
struct LiftState {
    regs: Vec<String>,
    lines: Vec<String>,
    indent: usize,
    warnings: Vec<String>,
    dialect: LuaDialect,
    scopes: LocalScopes,
    register_alias_tracker: BTreeMap<u32, String>,
    pc: usize,
}

impl LiftState {
    fn new(stack: u8, dialect: LuaDialect) -> Self {
        Self {
            regs: vec![String::new(); usize::from(stack).max(2)],
            lines: Vec::new(),
            indent: 1,
            warnings: Vec::new(),
            dialect,
            scopes: LocalScopes::default(),
            register_alias_tracker: BTreeMap::new(),
            pc: 0,
        }
    }

    #[inline]
    fn synth_alias(&self, idx: u32) -> String {
        self.register_alias_tracker
            .get(&idx)
            .cloned()
            .unwrap_or_else(|| format!("loc{idx}"))
    }

    #[inline]
    fn reg(&self, i: u32) -> String {
        if let Some(name) = self.scopes.name_at(self.pc, i) {
            return name.to_owned();
        }
        let idx: usize = i as usize;
        match self.regs.get(idx) {
            Some(s) if !s.is_empty() => s.clone(),
            _ => self.synth_alias(i),
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

#[inline]
fn define(state: &mut LiftState, slot: u32, value: String) {
    match state.scopes.name_at(state.pc, slot) {
        Some(name) => {
            let name: String = name.to_owned();
            if value != name {
                state.push(&format!("{name} = {value}"));
            }
            state.set_reg(slot, name);
        }
        None => state.set_reg(slot, value),
    }
}

#[must_use]
pub fn const_text(k: &LuaConstant, dialect: LuaDialect) -> String {
    const_repr(k, dialect)
}

#[inline]
#[must_use]
fn floats_are_distinct(dialect: LuaDialect) -> bool {
    matches!(dialect, LuaDialect::Lua53 | LuaDialect::Lua54)
}

#[must_use]
fn const_repr(k: &LuaConstant, dialect: LuaDialect) -> String {
    match k {
        LuaConstant::Nil => "nil".to_owned(),
        LuaConstant::Bool(true) => "true".to_owned(),
        LuaConstant::Bool(false) => "false".to_owned(),
        LuaConstant::Integer(i) => i.to_string(),
        LuaConstant::Number(n) => fmt_number(*n, floats_are_distinct(dialect)),
        LuaConstant::Str(s) => quote_lua_string(s),
        LuaConstant::Import(path) if !path.is_empty() => path.join("."),
        LuaConstant::Import(_) | LuaConstant::ClosureRef(_) | LuaConstant::Vector(_) => {
            "nil".to_owned()
        }
    }
}

#[must_use]
pub fn fmt_number(n: f64, as_float: bool) -> String {
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
        return if as_float {
            format!("{}.0", n as i64)
        } else {
            format!("{}", n as i64)
        };
    }
    let abs: f64 = n.abs();
    if abs != 0.0 && !(1e-4..1e15).contains(&abs) {
        let mut e: String = format!("{n:e}");
        if let Some(pos) = e.find('e')
            && !e[pos + 1..].starts_with('-')
        {
            e.insert(pos + 1, '+');
        }
        return e;
    }
    format!("{n}")
}

#[must_use]
fn quote_lua_string(s: &str) -> String {
    let mut out: String = String::with_capacity(s.len() + 2);
    out.push('"');
    let mut chars: core::iter::Peekable<core::str::Chars<'_>> = s.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 || (c as u32) == 0x7F => {
                let code: u32 = c as u32;
                if chars
                    .peek()
                    .is_some_and(|next: &char| next.is_ascii_digit())
                {
                    out.push_str(&format!("\\{code:03}"));
                } else {
                    out.push_str(&format!("\\{code}"));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[inline]
pub(crate) fn kconst(p: &LuaProto, idx: u32, dialect: LuaDialect) -> String {
    p.constants.get(idx as usize).map_or_else(
        || format!("K{idx}"),
        |k: &LuaConstant| const_repr(k, dialect),
    )
}

#[inline]
fn rk(state: &LiftState, p: &LuaProto, field: u32) -> String {
    if is_k(field) {
        kconst(p, rk_index(field), state.dialect)
    } else {
        state.reg(field)
    }
}

#[inline]
fn rk_or_const(state: &LiftState, p: &LuaProto, field: u32, use_const: bool) -> String {
    if use_const {
        kconst(p, field, state.dialect)
    } else {
        state.reg(field)
    }
}

#[inline]
pub(crate) fn kstr(p: &LuaProto, bx: u32, dialect: LuaDialect) -> String {
    match p.constants.get(bx as usize) {
        Some(LuaConstant::Str(s)) => s.clone(),
        Some(other) => const_repr(other, dialect),
        None => format!("K{bx}"),
    }
}

#[must_use]
fn is_ident(s: &str) -> bool {
    let mut chars: core::str::Chars<'_> = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c: char| c.is_ascii_alphanumeric() || c == '_')
}

#[must_use]
fn const_str_key(p: &LuaProto, field: u32) -> Option<String> {
    if !is_k(field) {
        return None;
    }
    match p.constants.get(rk_index(field) as usize) {
        Some(LuaConstant::Str(s)) if is_ident(s) => Some(s.clone()),
        _ => None,
    }
}

#[must_use]
fn const_str_key_direct(p: &LuaProto, idx: u32) -> Option<String> {
    match p.constants.get(idx as usize) {
        Some(LuaConstant::Str(s)) if is_ident(s) => Some(s.clone()),
        _ => None,
    }
}

#[must_use]
fn index_expr_with_key(table: &str, field_name: Option<&str>, raw_key: &str) -> String {
    match field_name {
        Some(name) => format!("{table}.{name}"),
        None => format!("{table}[{raw_key}]"),
    }
}

#[must_use]
fn arith_sym(op: Op) -> Option<&'static str> {
    let sym: &str = match op {
        Op::Add | Op::AddI | Op::AddK => "+",
        Op::Sub | Op::SubK => "-",
        Op::Mul | Op::MulK => "*",
        Op::Div | Op::DivK => "/",
        Op::Mod | Op::ModK => "%",
        Op::Pow | Op::PowK => "^",
        Op::IDiv | Op::IDivK => "//",
        Op::BAnd | Op::BAndK => "&",
        Op::BOr | Op::BOrK => "|",
        Op::BXor | Op::BXorK => "~",
        Op::Shl | Op::ShlI => "<<",
        Op::Shr | Op::ShrI => ">>",
        _ => return None,
    };
    Some(sym)
}

#[must_use]
fn arith(op: Op, lhs: &str, rhs: &str) -> Option<String> {
    arith_sym(op).map(|sym: &str| format!("({lhs} {sym} {rhs})"))
}

#[derive(Debug)]
pub struct LiftedProto {
    pub source: String,
    pub warnings: Vec<String>,
    pub fully_structured: bool,
}

#[must_use]
pub fn lift_proto(p: &LuaProto, depth: usize) -> LiftedProto {
    lift_proto_dialect(p, LuaDialect::Lua51, depth)
}

#[must_use]
pub fn lift_proto_dialect(p: &LuaProto, dialect: LuaDialect, depth: usize) -> LiftedProto {
    if depth > MAX_LIFT_DEPTH {
        return LiftedProto {
            source: "  -- (proto nesting limit reached)\n".to_owned(),
            warnings: vec!["proto nesting exceeds lift depth limit".to_owned()],
            fully_structured: false,
        };
    }
    let mut state: LiftState = LiftState::new(p.max_stack_size, dialect);
    state.scopes = LocalScopes::build(&p.locals, p.code.len());
    for i in 0..u32::from(p.num_params) {
        let name: String = state
            .scopes
            .name_at(0, i)
            .map_or_else(|| format!("p{i}"), str::to_owned);
        state.set_reg(i, name);
    }
    let jump_targets: Vec<bool> = compute_jump_targets(p, dialect);
    let mut fully_structured: bool = true;
    let mut table_locals: u32 = 0;
    let mut pc: usize = 0;
    let n: usize = p.code.len();

    while pc < n {
        state.pc = pc;
        emit_local_activations(&mut state, p, pc);
        if jump_targets.get(pc).copied().unwrap_or(false) {
            state.push(&format!("::lbl_{pc}::"));
        }
        let raw: u32 = p.code[pc];
        let d: Decoded = decode(raw, dialect);
        match d.op {
            Op::Move => {
                let src: String = state.reg(d.b);
                define(&mut state, d.a, src);
            }
            Op::LoadK => {
                define(&mut state, d.a, kconst(p, d.bx, dialect));
            }
            Op::LoadKx => {
                let extra: Option<u32> = p.code.get(pc + 1).map(|raw2: &u32| {
                    let dx: Decoded = decode(*raw2, dialect);
                    dx.ax
                });
                match extra {
                    Some(ax) => {
                        define(&mut state, d.a, kconst(p, ax, dialect));
                        pc += 1;
                    }
                    None => define(&mut state, d.a, format!("K{}", d.bx)),
                }
            }
            Op::LoadI => {
                define(&mut state, d.a, d.sbx.to_string());
            }
            Op::LoadF => {
                define(&mut state, d.a, fmt_number(f64::from(d.sbx), true));
            }
            Op::LoadBool => {
                define(
                    &mut state,
                    d.a,
                    if d.b != 0 { "true" } else { "false" }.to_owned(),
                );
                if d.c != 0 {
                    fully_structured = false;
                    state
                        .warnings
                        .push("relational boolean materialization not fully recovered".to_owned());
                    skip_and_preserve_label(&mut state, &mut pc, &jump_targets);
                }
            }
            Op::LoadTrue => {
                define(&mut state, d.a, "true".to_owned());
            }
            Op::LoadFalse => {
                define(&mut state, d.a, "false".to_owned());
            }
            Op::LFalseSkip => {
                define(&mut state, d.a, "false".to_owned());
                fully_structured = false;
                state
                    .warnings
                    .push("relational boolean materialization not fully recovered".to_owned());
                skip_and_preserve_label(&mut state, &mut pc, &jump_targets);
            }
            Op::LoadNil => {
                let span: u32 = if matches!(dialect, LuaDialect::Lua54) {
                    d.a + d.b
                } else {
                    d.b
                };
                for r in d.a..=span {
                    define(&mut state, r, "nil".to_owned());
                }
            }
            Op::GetUpval => {
                define(&mut state, d.a, upval_name(p, d.b));
            }
            Op::SetUpval => {
                let name: String = upval_name(p, d.b);
                let val: String = state.reg(d.a);
                state.push(&format!("{name} = {val}"));
            }
            Op::GetGlobal => {
                define(&mut state, d.a, kstr(p, d.bx, dialect));
            }
            Op::SetGlobal => {
                let name: String = kstr(p, d.bx, dialect);
                let val: String = state.reg(d.a);
                state.push(&format!("{name} = {val}"));
            }
            Op::GetTabUp => {
                let up: String = upval_name(p, d.b);
                let (field, raw_key): (Option<String>, String) = tabup_key(&state, p, &d);
                let expr: String = if up == "_ENV" {
                    field.clone().unwrap_or_else(|| format!("_ENV[{raw_key}]"))
                } else {
                    index_expr_with_key(&up, field.as_deref(), &raw_key)
                };
                define(&mut state, d.a, expr);
            }
            Op::SetTabUp => {
                let up: String = upval_name(p, d.a);
                let (field, raw_key, val): (Option<String>, String, String) =
                    settabup_operands(&state, p, &d);
                let lhs: String = if up == "_ENV" {
                    field.clone().unwrap_or_else(|| format!("_ENV[{raw_key}]"))
                } else {
                    index_expr_with_key(&up, field.as_deref(), &raw_key)
                };
                state.push(&format!("{lhs} = {val}"));
            }
            Op::GetTable => {
                let table: String = state.reg(d.b);
                let raw_key: String = rk(&state, p, d.c);
                let field: Option<String> = const_str_key(p, d.c);
                define(
                    &mut state,
                    d.a,
                    index_expr_with_key(&table, field.as_deref(), &raw_key),
                );
            }
            Op::GetField => {
                let table: String = state.reg(d.b);
                let field: Option<String> = const_str_key_direct(p, d.c);
                let raw_key: String = kconst(p, d.c, dialect);
                define(
                    &mut state,
                    d.a,
                    index_expr_with_key(&table, field.as_deref(), &raw_key),
                );
            }
            Op::GetI => {
                let table: String = state.reg(d.b);
                define(&mut state, d.a, format!("{table}[{}]", d.c));
            }
            Op::SetTable => {
                let table: String = state.reg(d.a);
                let raw_key: String = rk(&state, p, d.b);
                let field: Option<String> = const_str_key(p, d.b);
                let val: String = setfield_value(&state, p, &d);
                let lhs: String = index_expr_with_key(&table, field.as_deref(), &raw_key);
                state.push(&format!("{lhs} = {val}"));
            }
            Op::SetField => {
                let table: String = state.reg(d.a);
                let field: Option<String> = const_str_key_direct(p, d.b);
                let raw_key: String = kconst(p, d.b, dialect);
                let val: String = setfield_value(&state, p, &d);
                let lhs: String = index_expr_with_key(&table, field.as_deref(), &raw_key);
                state.push(&format!("{lhs} = {val}"));
            }
            Op::SetI => {
                let table: String = state.reg(d.a);
                let val: String = setfield_value(&state, p, &d);
                state.push(&format!("{table}[{}] = {val}", d.b));
            }
            Op::NewTable => {
                let existing: String = state.reg(d.a);
                let name: String = if existing.starts_with('p') || existing.starts_with("loc_") {
                    existing
                } else {
                    let nm: String = format!("tbl_{table_locals}");
                    table_locals += 1;
                    nm
                };
                if matches!(dialect, LuaDialect::Lua54) {
                    pc += 1;
                }
                state.push(&format!("local {name} = {{}}"));
                state.set_reg(d.a, name);
            }
            Op::Self_ => {
                let table: String = state.reg(d.b);
                let (field, raw_key): (Option<String>, String) = self_key(&state, p, &d, dialect);
                state.set_reg(d.a + 1, table.clone());
                let method: String = match field {
                    Some(name) => format!("{table}:{name}"),
                    None => index_expr_with_key(&table, None, &raw_key),
                };
                state.set_reg(d.a, method);
            }
            Op::Add
            | Op::Sub
            | Op::Mul
            | Op::Div
            | Op::Mod
            | Op::Pow
            | Op::IDiv
            | Op::BAnd
            | Op::BOr
            | Op::BXor
            | Op::Shl
            | Op::Shr => {
                let lhs: String = if matches!(dialect, LuaDialect::Lua54) {
                    state.reg(d.b)
                } else {
                    rk(&state, p, d.b)
                };
                let rhs: String = if matches!(dialect, LuaDialect::Lua54) {
                    state.reg(d.c)
                } else {
                    rk(&state, p, d.c)
                };
                if let Some(e) = arith(d.op, &lhs, &rhs) {
                    define(&mut state, d.a, e);
                }
                skip_mmbin(p, &mut pc, dialect);
            }
            Op::AddK
            | Op::SubK
            | Op::MulK
            | Op::DivK
            | Op::ModK
            | Op::PowK
            | Op::IDivK
            | Op::BAndK
            | Op::BOrK
            | Op::BXorK => {
                let lhs: String = state.reg(d.b);
                let rhs: String = kconst(p, d.c, dialect);
                if let Some(e) = arith(d.op, &lhs, &rhs) {
                    define(&mut state, d.a, e);
                }
                skip_mmbin(p, &mut pc, dialect);
            }
            Op::AddI => {
                let lhs: String = state.reg(d.b);
                let imm: i32 = d.c as i32 - 127;
                define(&mut state, d.a, format!("({lhs} + {imm})"));
                skip_mmbin(p, &mut pc, dialect);
            }
            Op::ShrI => {
                let lhs: String = state.reg(d.b);
                let imm: i32 = d.c as i32 - 127;
                define(&mut state, d.a, format!("({lhs} >> {imm})"));
                skip_mmbin(p, &mut pc, dialect);
            }
            Op::ShlI => {
                let rhs: String = state.reg(d.b);
                let imm: i32 = d.c as i32 - 127;
                define(&mut state, d.a, format!("({imm} << {rhs})"));
                skip_mmbin(p, &mut pc, dialect);
            }
            Op::MmBin | Op::MmBinI | Op::MmBinK => {}
            Op::Unm => {
                let v: String = state.reg(d.b);
                define(&mut state, d.a, format!("(-({v}))"));
            }
            Op::BNot => {
                let v: String = state.reg(d.b);
                define(&mut state, d.a, format!("(~({v}))"));
            }
            Op::Not => {
                let v: String = state.reg(d.b);
                define(&mut state, d.a, format!("(not {v})"));
            }
            Op::Len => {
                let v: String = state.reg(d.b);
                define(&mut state, d.a, format!("(#({v}))"));
            }
            Op::Concat => {
                let end: u32 = if matches!(dialect, LuaDialect::Lua54) {
                    d.a + d.b - 1
                } else {
                    d.c
                };
                let start: u32 = if matches!(dialect, LuaDialect::Lua54) {
                    d.a
                } else {
                    d.b
                };
                let parts: Vec<String> = (start..=end).map(|r: u32| state.reg(r)).collect();
                define(&mut state, d.a, format!("({})", parts.join(" .. ")));
            }
            Op::Jmp => {
                let target: i64 = jump_target(pc, &d, dialect);
                if target >= 0 {
                    state.push(&format!("goto lbl_{target}"));
                }
                fully_structured = false;
            }
            Op::Eq | Op::Lt | Op::Le => {
                emit_compare(&mut state, p, &d, pc, dialect, &mut fully_structured);
                if next_is_jmp(p, pc, dialect) {
                    pc += 1;
                }
            }
            Op::EqK => {
                let lhs: String = state.reg(d.a);
                let rhs: String = kconst(p, d.b, dialect);
                emit_cond_jump(
                    &mut state,
                    p,
                    pc,
                    dialect,
                    &lhs,
                    if d.k { "==" } else { "~=" },
                    &rhs,
                );
                if next_is_jmp(p, pc, dialect) {
                    pc += 1;
                }
                fully_structured = false;
            }
            Op::EqI | Op::LtI | Op::LeI | Op::GtI | Op::GeI => {
                let lhs: String = state.reg(d.a);
                let imm: i32 = d.b as i32 - 127;
                let sym: &str = imm_compare_sym(d.op, d.k);
                emit_cond_jump(&mut state, p, pc, dialect, &lhs, sym, &imm.to_string());
                if next_is_jmp(p, pc, dialect) {
                    pc += 1;
                }
                fully_structured = false;
            }
            Op::Test => {
                let v: String = state.reg(d.a);
                let jump_when_truthy: bool = if matches!(dialect, LuaDialect::Lua54) {
                    d.k
                } else {
                    d.c != 0
                };
                let cond: String = if jump_when_truthy {
                    v
                } else {
                    format!("not {v}")
                };
                emit_cond_jump_lit(&mut state, p, pc, dialect, &cond);
                if next_is_jmp(p, pc, dialect) {
                    pc += 1;
                }
                fully_structured = false;
            }
            Op::TestSet => {
                let v: String = state.reg(d.b);
                state.set_reg(d.a, v);
                fully_structured = false;
            }
            Op::Call => {
                emit_call(&mut state, &d, false, dialect);
            }
            Op::TailCall => {
                emit_call(&mut state, &d, true, dialect);
                suppress_dead_jmp_after_return(p, &mut pc, dialect, &jump_targets);
            }
            Op::Return => {
                let is_last: bool = pc + 1 == n;
                if !(is_last && d.b == 1) {
                    emit_return(&mut state, &d);
                }
                suppress_dead_jmp_after_return(p, &mut pc, dialect, &jump_targets);
            }
            Op::Return0 => {
                if pc + 1 != n {
                    push_return(&mut state, "");
                }
                suppress_dead_jmp_after_return(p, &mut pc, dialect, &jump_targets);
            }
            Op::Return1 => {
                let val: String = state.reg(d.a);
                push_return(&mut state, &val);
                suppress_dead_jmp_after_return(p, &mut pc, dialect, &jump_targets);
            }
            Op::ForPrep => {
                let init: String = state.reg(d.a);
                let limit: String = state.reg(d.a + 1);
                let step: String = state.reg(d.a + 2);
                let var: String = format!("fv_{}", d.a);
                state.set_reg(d.a + 3, var.clone());
                state.push(&format!("for {var} = {init}, {limit}, {step} do"));
                state.indent += 1;
            }
            Op::ForLoop => {
                if state.indent > 1 {
                    state.indent -= 1;
                }
                state.push("end");
            }
            Op::TForPrep => {}
            Op::TForCall => {
                let f: String = state.reg(d.a);
                let nvars: u32 = d.c.max(1);
                let vars: Vec<String> = (0..nvars)
                    .map(|i: u32| format!("tv_{}", d.a + 4 + i))
                    .collect();
                for (i, v) in vars.iter().enumerate() {
                    state.set_reg(d.a + 4 + i as u32, v.clone());
                }
                state.push(&format!(
                    "for {} in {f}, {}, {} do",
                    vars.join(", "),
                    state.reg(d.a + 1),
                    state.reg(d.a + 2)
                ));
                state.indent += 1;
                fully_structured = false;
            }
            Op::TForLoop => {
                if matches!(
                    dialect,
                    LuaDialect::Lua52 | LuaDialect::Lua53 | LuaDialect::Lua54
                ) {
                    if state.indent > 1 {
                        state.indent -= 1;
                    }
                    state.push("end");
                } else {
                    let f: String = state.reg(d.a);
                    let nvars: u32 = d.c.max(1);
                    let vars: Vec<String> = (0..nvars)
                        .map(|i: u32| format!("tv_{}", d.a + 3 + i))
                        .collect();
                    for (i, v) in vars.iter().enumerate() {
                        state.set_reg(d.a + 3 + i as u32, v.clone());
                    }
                    state.push(&format!(
                        "for {} in {f}, {}, {} do",
                        vars.join(", "),
                        state.reg(d.a + 1),
                        state.reg(d.a + 2)
                    ));
                    state.indent += 1;
                    fully_structured = false;
                }
            }
            Op::SetList => {
                let table: String = state.reg(d.a);
                let count: u32 = d.b;
                if matches!(dialect, LuaDialect::Lua54) && d.k {
                    pc += 1;
                }
                if count == 0 {
                    fully_structured = false;
                    state
                        .warnings
                        .push("vararg/multi-value table elements not fully recovered".to_owned());
                } else {
                    let block: u32 = d.c.max(1);
                    let base_index: u32 = (block - 1).saturating_mul(LFIELDS_PER_FLUSH);
                    for i in 1..=count {
                        let elem: String = state.reg(d.a + i);
                        let index: u32 = base_index + i;
                        state.push(&format!("{table}[{index}] = {elem}"));
                    }
                }
            }
            Op::Close => {
                state.push(&format!("-- close upvalues >= R{}", d.a));
            }
            Op::Tbc => {
                state.push(&format!("-- to-be-closed variable R{}", d.a));
            }
            Op::Closure => {
                emit_closure(&mut state, p, &d, dialect, depth, &mut fully_structured);
            }
            Op::Vararg => {
                define(&mut state, d.a, "...".to_owned());
            }
            Op::VarargPrep => {}
            Op::ExtraArg => {}
            Op::Unknown => {
                state.push(&format!("-- unknown opcode raw=0x{raw:08X} pc={pc}"));
                state
                    .warnings
                    .push(format!("unknown opcode at pc={pc} raw=0x{raw:08X}"));
                fully_structured = false;
            }
        }
        pc += 1;
    }

    let mut source: String = String::new();
    for ln in &state.lines {
        source.push_str(ln);
        source.push('\n');
    }
    LiftedProto {
        source,
        warnings: state.warnings,
        fully_structured,
    }
}

#[inline]
fn upval_name(p: &LuaProto, idx: u32) -> String {
    p.upvalues
        .get(idx as usize)
        .map(|u| u.name.clone())
        .filter(|s: &String| !s.is_empty())
        .unwrap_or_else(|| format!("upval_{idx}"))
}

#[inline]
fn tabup_key(state: &LiftState, p: &LuaProto, d: &Decoded) -> (Option<String>, String) {
    if matches!(state.dialect, LuaDialect::Lua54) {
        (const_str_key_direct(p, d.c), kconst(p, d.c, state.dialect))
    } else {
        (const_str_key(p, d.c), rk(state, p, d.c))
    }
}

#[inline]
fn settabup_operands(
    state: &LiftState,
    p: &LuaProto,
    d: &Decoded,
) -> (Option<String>, String, String) {
    if matches!(state.dialect, LuaDialect::Lua54) {
        let field: Option<String> = const_str_key_direct(p, d.b);
        let raw_key: String = kconst(p, d.b, state.dialect);
        let val: String = rk_or_const(state, p, d.c, d.k);
        (field, raw_key, val)
    } else {
        let field: Option<String> = const_str_key(p, d.b);
        let raw_key: String = rk(state, p, d.b);
        let val: String = rk(state, p, d.c);
        (field, raw_key, val)
    }
}

#[inline]
fn setfield_value(state: &LiftState, p: &LuaProto, d: &Decoded) -> String {
    if matches!(state.dialect, LuaDialect::Lua54) {
        rk_or_const(state, p, d.c, d.k)
    } else {
        rk(state, p, d.c)
    }
}

#[inline]
fn self_key(
    state: &LiftState,
    p: &LuaProto,
    d: &Decoded,
    dialect: LuaDialect,
) -> (Option<String>, String) {
    if matches!(dialect, LuaDialect::Lua54) {
        (const_str_key_direct(p, d.c), kconst(p, d.c, dialect))
    } else {
        (const_str_key(p, d.c), rk(state, p, d.c))
    }
}

#[inline]
fn imm_compare_sym(op: Op, k: bool) -> &'static str {
    match (op, k) {
        (Op::EqI, true) => "==",
        (Op::EqI, false) => "~=",
        (Op::LtI, true) => "<",
        (Op::LtI, false) => ">=",
        (Op::LeI, true) => "<=",
        (Op::LeI, false) => ">",
        (Op::GtI, true) => ">",
        (Op::GtI, false) => "<=",
        (Op::GeI, true) => ">=",
        (Op::GeI, false) => "<",
        _ => "==",
    }
}

#[inline]
fn next_is_jmp(p: &LuaProto, pc: usize, dialect: LuaDialect) -> bool {
    p.code
        .get(pc + 1)
        .map(|raw2: &u32| decode(*raw2, dialect).op == Op::Jmp)
        .unwrap_or(false)
}

#[inline]
fn push_return(state: &mut LiftState, values: &str) {
    if values.is_empty() {
        state.push("do return end");
    } else {
        state.push(&format!("do return {values} end"));
    }
}

#[inline]
fn skip_and_preserve_label(state: &mut LiftState, pc: &mut usize, jump_targets: &[bool]) {
    *pc += 1;
    if jump_targets.get(*pc).copied().unwrap_or(false) {
        state.push(&format!("::lbl_{}::", *pc));
    }
}

#[inline]
fn suppress_dead_jmp_after_return(
    p: &LuaProto,
    pc: &mut usize,
    dialect: LuaDialect,
    jump_targets: &[bool],
) {
    let Some(raw2) = p.code.get(*pc + 1) else {
        return;
    };
    let is_unreachable_jmp: bool = decode(*raw2, dialect).op == Op::Jmp
        && !jump_targets.get(*pc + 1).copied().unwrap_or(false);
    if is_unreachable_jmp {
        *pc += 1;
    }
}

#[inline]
fn jump_target(pc: usize, d: &Decoded, dialect: LuaDialect) -> i64 {
    let off: i64 = if matches!(dialect, LuaDialect::Lua54) {
        i64::from(d.sj)
    } else {
        i64::from(d.sbx)
    };
    pc as i64 + 1 + off
}

#[inline]
fn skip_mmbin(p: &LuaProto, pc: &mut usize, dialect: LuaDialect) {
    if matches!(dialect, LuaDialect::Lua54)
        && p.code
            .get(*pc + 1)
            .map(|raw2: &u32| {
                matches!(
                    decode(*raw2, dialect).op,
                    Op::MmBin | Op::MmBinI | Op::MmBinK
                )
            })
            .unwrap_or(false)
    {
        *pc += 1;
    }
}

fn emit_cond_jump(
    state: &mut LiftState,
    p: &LuaProto,
    pc: usize,
    dialect: LuaDialect,
    lhs: &str,
    sym: &str,
    rhs: &str,
) {
    emit_cond_jump_lit(state, p, pc, dialect, &format!("{lhs} {sym} {rhs}"));
}

fn emit_cond_jump_lit(
    state: &mut LiftState,
    p: &LuaProto,
    pc: usize,
    dialect: LuaDialect,
    cond: &str,
) {
    let next_jmp: Option<i64> = p.code.get(pc + 1).and_then(|raw2: &u32| {
        let dj: Decoded = decode(*raw2, dialect);
        if dj.op == Op::Jmp {
            Some(jump_target(pc + 1, &dj, dialect))
        } else {
            None
        }
    });
    match next_jmp {
        Some(t) if t >= 0 => {
            state.push(&format!("if {cond} then goto lbl_{t} end"));
        }
        _ => {
            state.push(&format!("-- cmp {cond}"));
        }
    }
}

fn emit_compare(
    state: &mut LiftState,
    p: &LuaProto,
    d: &Decoded,
    pc: usize,
    dialect: LuaDialect,
    fully_structured: &mut bool,
) {
    let (lhs, rhs): (String, String) = if matches!(dialect, LuaDialect::Lua54) {
        (state.reg(d.a), state.reg(d.b))
    } else {
        (rk(state, p, d.b), rk(state, p, d.c))
    };
    let then_branch_on_true: bool = if matches!(dialect, LuaDialect::Lua54) {
        !d.k
    } else {
        d.a == 0
    };
    let sym: &str = match (d.op, then_branch_on_true) {
        (Op::Eq, true) => "~=",
        (Op::Eq, false) => "==",
        (Op::Lt, true) => ">=",
        (Op::Lt, false) => "<",
        (Op::Le, true) => ">",
        (Op::Le, false) => "<=",
        _ => "==",
    };
    emit_cond_jump(state, p, pc, dialect, &lhs, sym, &rhs);
    *fully_structured = false;
}

fn emit_closure(
    state: &mut LiftState,
    p: &LuaProto,
    d: &Decoded,
    dialect: LuaDialect,
    depth: usize,
    fully_structured: &mut bool,
) {
    let child_idx: usize = d.bx as usize;
    match p.protos.get(child_idx) {
        Some(child) => {
            let lifted: LiftedProto = lift_proto_dialect(child, dialect, depth + 1);
            let params: String = (0..u32::from(child.num_params))
                .map(|i: u32| proto_param_name(child, i))
                .collect::<Vec<String>>()
                .join(", ");
            let header: String = if child.is_vararg != 0 {
                if params.is_empty() {
                    "function(...)".to_owned()
                } else {
                    format!("function({params}, ...)")
                }
            } else {
                format!("function({params})")
            };
            let mut block: String = format!("{header}\n");
            for ln in lifted.source.lines() {
                block.push_str("  ");
                block.push_str(ln);
                block.push('\n');
            }
            block.push_str("end");
            define(state, d.a, block);
            state.warnings.extend(lifted.warnings);
            if !lifted.fully_structured {
                *fully_structured = false;
            }
        }
        None => {
            define(
                state,
                d.a,
                format!("function() --[[ missing proto {child_idx} ]] end"),
            );
            *fully_structured = false;
        }
    }
}

fn emit_call(state: &mut LiftState, d: &Decoded, tail: bool, dialect: LuaDialect) {
    let func: String = state.reg(d.a);
    let args: Vec<String> = if d.b == 0 {
        let mut v: Vec<String> = Vec::new();
        let mut r: u32 = d.a + 1;
        while (r as usize) < state.regs.len() {
            v.push(state.reg(r));
            r += 1;
        }
        v
    } else {
        (1..d.b).map(|i: u32| state.reg(d.a + i)).collect()
    };
    let call: String = format!("{func}({})", args.join(", "));
    if tail {
        push_return(state, &call);
        return;
    }
    let nresults: u32 = d.c;
    let _ = dialect;
    if nresults == 1 {
        state.push(&call);
    } else if nresults == 2 {
        define(state, d.a, call);
    } else if nresults > 2 {
        let next_pc: usize = state.pc + 1;
        let targets: Vec<String> = (0..nresults - 1)
            .map(|i: u32| {
                let slot: u32 = d.a + i;
                state.scopes.name_at(next_pc, slot).map_or_else(
                    || {
                        let synth: String = format!("loc{slot}");
                        state.register_alias_tracker.insert(slot, synth.clone());
                        synth
                    },
                    str::to_owned,
                )
            })
            .collect();
        state.push(&format!("local {} = {call}", targets.join(", ")));
        for (i, t) in targets.iter().enumerate() {
            state.set_reg(d.a + i as u32, t.clone());
        }
    } else {
        state.set_reg(d.a, call);
    }
}

fn emit_return(state: &mut LiftState, d: &Decoded) {
    if d.b == 1 {
        push_return(state, "");
    } else if d.b == 0 {
        let mut vals: Vec<String> = Vec::new();
        let mut r: u32 = d.a;
        while (r as usize) < state.regs.len() {
            vals.push(state.reg(r));
            r += 1;
        }
        push_return(state, &vals.join(", "));
    } else {
        let vals: Vec<String> = (0..d.b - 1).map(|i: u32| state.reg(d.a + i)).collect();
        push_return(state, &vals.join(", "));
    }
}

#[must_use]
pub fn proto_param_name(p: &LuaProto, slot: u32) -> String {
    let mut idx: u32 = 0;
    for loc in &p.locals {
        if loc.start_pc == 0 && idx < u32::from(p.num_params) {
            if idx == slot && is_ident(&loc.name) {
                return loc.name.clone();
            }
            idx += 1;
        }
    }
    format!("p{slot}")
}

fn emit_local_activations(state: &mut LiftState, p: &LuaProto, pc: usize) {
    if pc == 0 || !state.scopes.has_names {
        return;
    }
    let acts: Vec<(u32, String)> = state.scopes.activating_at(pc).to_vec();
    if acts.is_empty() {
        return;
    }
    let num_params: u32 = u32::from(p.num_params);
    for (slot, name) in acts {
        if slot < num_params {
            continue;
        }
        let raw: String = state.regs.get(slot as usize).cloned().unwrap_or_default();
        let trivial_self: bool = raw.is_empty()
            || raw == name
            || (raw.starts_with('R') && raw[1..].chars().all(|c: char| c.is_ascii_digit()));
        if trivial_self {
            state.push(&format!("local {name}"));
        } else {
            state.push(&format!("local {name} = {raw}"));
        }
        state.set_reg(slot, name);
    }
}

#[must_use]
fn compute_jump_targets(p: &LuaProto, dialect: LuaDialect) -> Vec<bool> {
    let n: usize = p.code.len();
    let mut targets: Vec<bool> = vec![false; n + 1];
    for (pc, raw) in p.code.iter().enumerate() {
        let d: Decoded = decode(*raw, dialect);
        if matches!(d.op, Op::Jmp) {
            let t: i64 = jump_target(pc, &d, dialect);
            if t >= 0 && (t as usize) <= n {
                targets[t as usize] = true;
            }
        }
        if matches!(d.op, Op::ForLoop | Op::ForPrep | Op::TForLoop)
            && !matches!(dialect, LuaDialect::Lua54)
        {
            let t: i64 = pc as i64 + 1 + i64::from(d.sbx);
            if t >= 0 && (t as usize) <= n {
                targets[t as usize] = true;
            }
        }
        if matches!(
            d.op,
            Op::Eq
                | Op::Lt
                | Op::Le
                | Op::EqK
                | Op::EqI
                | Op::LtI
                | Op::LeI
                | Op::GtI
                | Op::GeI
                | Op::Test
                | Op::TestSet
        ) && let Some(raw2) = p.code.get(pc + 1)
        {
            let dj: Decoded = decode(*raw2, dialect);
            if dj.op == Op::Jmp {
                let t: i64 = jump_target(pc + 1, &dj, dialect);
                if t >= 0 && (t as usize) <= n {
                    targets[t as usize] = true;
                }
            }
        }
    }
    targets
}

#[must_use]
pub fn lift_chunk(chunk: &LuaChunk) -> LiftedProto {
    lift_proto_dialect(&chunk.main, chunk.dialect, 0)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::reader::common::{LuaDialect, LuaProto, LuaUpvalueName};

    fn proto(code: Vec<u32>, constants: Vec<LuaConstant>, stack: u8) -> LuaProto {
        LuaProto {
            source: None,
            line_defined: 0,
            last_line_defined: 0,
            num_params: 0,
            is_vararg: 0,
            max_stack_size: stack,
            code,
            constants,
            protos: Vec::new(),
            source_lines: Vec::new(),
            locals: Vec::new(),
            upvalues: Vec::new(),
        }
    }

    fn enc_abc(op: u32, a: u32, b: u32, c: u32) -> u32 {
        op | (a << 6) | (c << 14) | (b << 23)
    }

    fn enc_abx(op: u32, a: u32, bx: u32) -> u32 {
        op | (a << 6) | (bx << 14)
    }

    fn enc54_abc(op: u32, a: u32, b: u32, c: u32, k: u32) -> u32 {
        op | (a << 7) | (k << 15) | (b << 16) | (c << 24)
    }

    fn enc54_abx(op: u32, a: u32, bx: u32) -> u32 {
        op | (a << 7) | (bx << 15)
    }

    #[test]
    fn lift_loadk_getglobal_call_emits_print() {
        let consts: Vec<LuaConstant> = vec![
            LuaConstant::Str("print".to_owned()),
            LuaConstant::Str("hello".to_owned()),
        ];
        let code: Vec<u32> = vec![
            enc_abx(5, 0, 0),
            enc_abx(1, 1, 1),
            enc_abc(28, 0, 2, 1),
            enc_abc(30, 0, 1, 0),
        ];
        let p: LuaProto = proto(code, consts, 3);
        let out: LiftedProto = lift_proto(&p, 0);
        assert!(
            out.source.contains("print(\"hello\")"),
            "got: {}",
            out.source
        );
    }

    #[test]
    fn lift_arith_add() {
        let code: Vec<u32> = vec![enc_abc(12, 2, 0, 1), enc_abc(30, 0, 0, 0)];
        let p: LuaProto = proto(code, Vec::new(), 4);
        let out: LiftedProto = lift_proto(&p, 0);
        assert!(out.source.contains("(loc0 + loc1)"), "got: {}", out.source);
    }

    #[test]
    fn lift_settable_field_syntax() {
        let consts: Vec<LuaConstant> = vec![LuaConstant::Str("x".to_owned())];
        let code: Vec<u32> = vec![
            enc_abc(10, 0, 0, 0),
            enc_abc(9, 0, 256, 1),
            enc_abc(30, 0, 1, 0),
        ];
        let p: LuaProto = proto(code, consts, 3);
        let out: LiftedProto = lift_proto(&p, 0);
        assert!(out.source.contains(".x = loc1"), "got: {}", out.source);
    }

    #[test]
    fn lift_numeric_for_loop() {
        let code: Vec<u32> = vec![
            enc_abx(1, 0, 0),
            enc_abx(1, 1, 0),
            enc_abx(1, 2, 0),
            enc_abx(32, 0, 1),
            enc_abc(31, 0, 0, 0),
        ];
        let consts: Vec<LuaConstant> = vec![LuaConstant::Integer(1)];
        let p: LuaProto = proto(code, consts, 5);
        let out: LiftedProto = lift_proto(&p, 0);
        assert!(out.source.contains("for fv_0 ="), "got: {}", out.source);
        assert!(out.source.contains("end"));
    }

    #[test]
    fn lift_closure_nested_function() {
        let mut p: LuaProto = proto(vec![enc_abx(36, 0, 0), enc_abc(30, 0, 2, 0)], Vec::new(), 2);
        let mut child: LuaProto = proto(vec![enc_abc(30, 0, 1, 0)], Vec::new(), 2);
        child.num_params = 1;
        p.protos.push(child);
        let out: LiftedProto = lift_proto(&p, 0);
        assert!(out.source.contains("function(p0)"), "got: {}", out.source);
    }

    #[test]
    fn lift_string_escaping() {
        let s: String = quote_lua_string("a\"b\nc");
        assert_eq!(s, "\"a\\\"b\\nc\"");
    }

    #[test]
    fn lift_string_escaping_roundtrip_pins() {
        assert_eq!(quote_lua_string("\r\t"), "\"\\r\\t\"");
        assert_eq!(quote_lua_string("\\"), "\"\\\\\"");
        assert_eq!(quote_lua_string("\u{1}x"), "\"\\1x\"");
        assert_eq!(quote_lua_string("\u{1}5"), "\"\\0015\"");
        assert_eq!(quote_lua_string("\u{1f}9"), "\"\\0319\"");
        assert_eq!(quote_lua_string("\u{7f}"), "\"\\127\"");
        assert_eq!(quote_lua_string("\u{7f}9"), "\"\\1279\"");
        assert_eq!(quote_lua_string("\u{2028}\u{2029}"), "\"\u{2028}\u{2029}\"");
        assert_eq!(quote_lua_string("café"), "\"café\"");
    }

    #[test]
    fn lift_respects_depth_limit() {
        let p: LuaProto = proto(vec![enc_abc(30, 0, 1, 0)], Vec::new(), 2);
        let out: LiftedProto = lift_proto(&p, MAX_LIFT_DEPTH + 1);
        assert!(!out.fully_structured);
        assert!(out.source.contains("nesting limit"));
    }

    #[test]
    fn lift_upvalue_named() {
        let mut p: LuaProto = proto(
            vec![enc_abc(4, 0, 0, 0), enc_abc(30, 0, 2, 0)],
            Vec::new(),
            2,
        );
        p.upvalues.push(LuaUpvalueName {
            name: "shared".to_owned(),
        });
        let out: LiftedProto = lift_proto(&p, 0);
        assert!(out.source.contains("shared"), "got: {}", out.source);
        let _ = LuaDialect::Lua51;
    }

    #[test]
    fn lift_lua54_gettabup_env_global() {
        let consts: Vec<LuaConstant> = vec![LuaConstant::Str("print".to_owned())];
        let getup: u32 = enc54_abc(11, 0, 0, 0, 0);
        let p: LuaProto = LuaProto {
            upvalues: vec![LuaUpvalueName {
                name: "_ENV".to_owned(),
            }],
            ..proto(vec![getup], consts, 2)
        };
        let out: LiftedProto = lift_proto_dialect(&p, LuaDialect::Lua54, 0);
        assert!(out.source.is_empty() || out.warnings.is_empty());
        assert_eq!(out.warnings.len(), 0, "got: {:?}", out.warnings);
    }

    #[test]
    fn lift_lua54_loadi_immediate() {
        let loadi: u32 = enc54_abx(1, 0, (42i32 + 0xFFFF) as u32);
        let ret: u32 = enc54_abc(72, 0, 0, 0, 0);
        let p: LuaProto = proto(vec![loadi, ret], Vec::new(), 2);
        let out: LiftedProto = lift_proto_dialect(&p, LuaDialect::Lua54, 0);
        assert!(out.source.contains("return 42"), "got: {}", out.source);
    }

    #[test]
    fn lift_lua53_bitwise_band() {
        let band: u32 = enc_abc(20, 2, 0, 1);
        let ret: u32 = enc_abc(38, 2, 2, 0);
        let p: LuaProto = proto(vec![band, ret], Vec::new(), 4);
        let out: LiftedProto = lift_proto_dialect(&p, LuaDialect::Lua53, 0);
        assert!(out.source.contains("(loc0 & loc1)"), "got: {}", out.source);
    }

    #[test]
    fn lift_loadbool_skip_of_hidden_jmp_marks_unstructured() {
        let loadbool_skip: u32 = enc_abc(2, 0, 1, 1);
        let hidden_jmp: u32 = enc_abx(22, 0, (1i32 + 0x1FFFF) as u32);
        let ret: u32 = enc_abc(30, 0, 2, 0);
        let p: LuaProto = proto(vec![loadbool_skip, hidden_jmp, ret], Vec::new(), 2);
        let out: LiftedProto = lift_proto(&p, 0);
        assert!(
            !out.fully_structured,
            "a LOADBOOL boolean-materialization skip elides whatever instruction follows \
             (potentially a Jmp); it must never report fully_structured=true, got: {}",
            out.source
        );
        assert!(
            out.warnings
                .iter()
                .any(|w: &String| w.contains("boolean materialization")),
            "must warn about the lossy boolean-skip recovery; got: {:?}",
            out.warnings
        );
    }

    #[test]
    fn lift_lfalseskip_of_hidden_jmp_marks_unstructured() {
        let lfalseskip: u32 = enc54_abc(6, 0, 0, 0, 0);
        let sj_bias: i64 = 0x00FF_FFFF;
        let ax: u32 = (1i64 + sj_bias) as u32;
        let hidden_jmp: u32 = 0x38_u32 | (ax << 7);
        let ret1: u32 = enc54_abc(72, 0, 0, 0, 0);
        let p: LuaProto = proto(vec![lfalseskip, hidden_jmp, ret1], Vec::new(), 2);
        let out: LiftedProto = lift_proto_dialect(&p, LuaDialect::Lua54, 0);
        assert!(
            !out.fully_structured,
            "LFALSESKIP unconditionally elides the next instruction (potentially a Jmp); \
             it must never report fully_structured=true, got: {}",
            out.source
        );
        assert!(
            out.warnings
                .iter()
                .any(|w: &String| w.contains("boolean materialization")),
            "must warn about the lossy skip recovery; got: {:?}",
            out.warnings
        );
    }

    #[test]
    fn lift_test_opcode_closes_its_if_on_one_line() {
        let test_op: u32 = enc_abc(26, 0, 0, 1);
        let jmp: u32 = enc_abx(22, 0, 0x1FFFF);
        let ret: u32 = enc_abc(30, 0, 2, 0);
        let p: LuaProto = proto(vec![test_op, jmp, ret], Vec::new(), 2);
        let out: LiftedProto = lift_proto(&p, 0);
        assert!(
            out.source.contains("if loc0 then goto lbl_2 end"),
            "TEST must combine with its paired JMP into one self-closed if/goto/end \
             statement, got: {}",
            out.source
        );
        assert!(
            !out.source.contains("skip next"),
            "must not leave a dangling if-without-end that swallows the rest of the \
             function body, got: {}",
            out.source
        );
        assert!(
            !out.source
                .lines()
                .any(|l: &str| l.trim_start().starts_with("if ") && !l.trim_end().ends_with("end")),
            "every emitted if-statement must be self-closed on its own line, got: {}",
            out.source
        );
        assert!(!out.fully_structured);
    }

    #[test]
    fn lift_setlist_emits_real_indexed_assignments_not_a_dead_comment() {
        let consts: Vec<LuaConstant> = vec![LuaConstant::Str("x".to_owned())];
        let code: Vec<u32> = vec![
            enc_abc(10, 0, 0, 0),
            enc_abx(1, 1, 0),
            enc_abc(34, 0, 1, 1),
            enc_abc(30, 0, 2, 0),
        ];
        let p: LuaProto = proto(code, consts, 3);
        let out: LiftedProto = lift_proto(&p, 0);
        assert!(
            out.source.contains("[1] = \"x\""),
            "SETLIST must emit a real indexed assignment so the table is actually \
             populated at runtime, got: {}",
            out.source
        );
        assert!(
            !out.source.contains("-- tbl_0 = {"),
            "must not silently drop the array literal into a dead, non-executed comment, \
             got: {}",
            out.source
        );
    }

    #[test]
    fn lift_setlist_vararg_span_marks_unstructured() {
        let code: Vec<u32> = vec![
            enc_abc(10, 0, 0, 0),
            enc_abc(34, 0, 0, 1),
            enc_abc(30, 0, 2, 0),
        ];
        let p: LuaProto = proto(code, Vec::new(), 3);
        let out: LiftedProto = lift_proto(&p, 0);
        assert!(
            !out.fully_structured,
            "a B=0 (top-of-stack span) SETLIST cannot statically recover its element \
             count/values; it must never report fully_structured=true, got: {}",
            out.source
        );
        assert!(
            out.warnings
                .iter()
                .any(|w: &String| w.contains("multi-value table elements")),
            "must warn about the unresolved vararg/multi-value span; got: {:?}",
            out.warnings
        );
    }
}
