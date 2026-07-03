mod structurer;

use crate::decompile::lift::{LiftedProto, const_text};
use crate::decompile::luau_lift::{LStmt, LiftedStmt, render_blocks};
use crate::decompile::opcode::{Decoded, Op, decode, is_k, rk_index};
use crate::reader::common::{LuaConstant, LuaDialect, LuaLocal, LuaProto};
use structurer::structure_standard;

const MAX_STRUCT_DEPTH: usize = 200;
const MAX_STRUCT_NODES: usize = 1 << 20;

#[derive(Debug, Default)]
struct StructState {
    regs: Vec<String>,
    defined: Vec<bool>,
    pc: usize,
    stmts: Vec<LiftedStmt>,
    warnings: Vec<String>,
    fully_structured: bool,
    table_locals: u32,
    suppress_local: Vec<(usize, u32)>,
    iter_call: Option<(u32, String)>,
    method_regs: std::collections::BTreeSet<u32>,
}

impl StructState {
    fn new(stack: u8) -> Self {
        let size: usize = usize::from(stack).max(2);
        Self {
            regs: vec![String::new(); size],
            defined: vec![false; size],
            pc: 0,
            stmts: Vec::new(),
            warnings: Vec::new(),
            fully_structured: true,
            table_locals: 0,
            suppress_local: Vec::new(),
            iter_call: None,
            method_regs: std::collections::BTreeSet::new(),
        }
    }

    #[inline]
    fn reg(&self, i: u32) -> String {
        match self.regs.get(i as usize) {
            Some(s) if !s.is_empty() => s.clone(),
            _ => format!("R{i}"),
        }
    }

    #[inline]
    fn set_reg(&mut self, i: u32, value: String) {
        let idx: usize = i as usize;
        if idx >= self.regs.len() {
            self.regs.resize(idx + 1, String::new());
            self.defined.resize(idx + 1, false);
        }
        self.regs[idx] = value;
    }

    #[inline]
    fn is_defined(&self, i: u32) -> bool {
        self.defined.get(i as usize).copied().unwrap_or(false)
    }

    #[inline]
    fn mark_defined(&mut self, i: u32) {
        let idx: usize = i as usize;
        if idx >= self.defined.len() {
            self.defined.resize(idx + 1, false);
        }
        self.defined[idx] = true;
    }

    fn push_raw(&mut self, raw: String) {
        self.stmts.push(LiftedStmt {
            pc: self.pc,
            stmt: LStmt::Raw(raw),
        });
    }

    fn push_stmt(&mut self, stmt: LStmt) {
        self.stmts.push(LiftedStmt { pc: self.pc, stmt });
    }
}

struct LocalNames {
    by_pc: Vec<Vec<Option<String>>>,
    activations: Vec<Vec<(u32, String)>>,
    has_names: bool,
}

impl LocalNames {
    fn build(locals: &[LuaLocal], code_len: usize, num_params: u32) -> Self {
        let any_named: bool = locals.iter().any(|l: &LuaLocal| is_ident(&l.name));
        if !any_named {
            return Self {
                by_pc: Vec::new(),
                activations: Vec::new(),
                has_names: false,
            };
        }
        let mut by_pc: Vec<Vec<Option<String>>> = vec![Vec::new(); code_len + 1];
        let mut activations: Vec<Vec<(u32, String)>> = vec![Vec::new(); code_len + 1];
        for (pc, slots) in by_pc.iter_mut().enumerate() {
            let pc_u: u32 = pc as u32;
            let mut slot: u32 = 0;
            for loc in locals {
                if loc.start_pc <= pc_u && pc_u < loc.end_pc {
                    if slot as usize >= slots.len() {
                        slots.resize(slot as usize + 1, None);
                    }
                    if is_ident(&loc.name) {
                        if slots[slot as usize].is_none() {
                            slots[slot as usize] = Some(loc.name.clone());
                        }
                        if loc.start_pc == pc_u
                            && slot >= num_params
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
            .and_then(|s: &Vec<Option<String>>| s.get(reg as usize))
            .and_then(|o: &Option<String>| o.as_deref())
    }

    #[inline]
    fn activating_at(&self, pc: usize) -> &[(u32, String)] {
        self.activations.get(pc).map_or(&[], Vec::as_slice)
    }
}

#[must_use]
pub fn lift_structured(p: &LuaProto, dialect: LuaDialect, depth: usize) -> Option<LiftedProto> {
    if depth > MAX_STRUCT_DEPTH {
        return None;
    }
    if matches!(
        dialect,
        LuaDialect::Luau | LuaDialect::LuaJit20 | LuaDialect::LuaJit21
    ) {
        return None;
    }
    let names: LocalNames = LocalNames::build(&p.locals, p.code.len(), u32::from(p.num_params));
    let mut state: StructState = StructState::new(p.max_stack_size);
    for i in 0..u32::from(p.num_params) {
        let name: String = names
            .name_at(0, i)
            .map_or_else(|| format!("p{i}"), str::to_owned);
        state.set_reg(i, name);
        state.mark_defined(i);
    }
    let live: LiveAcrossBranch = LiveAcrossBranch::compute(p, dialect);
    lower(p, dialect, depth, &names, &live, &mut state)?;
    if state.stmts.len() > MAX_STRUCT_NODES {
        return None;
    }
    fold_table_constructors(&mut state.stmts);
    promote_local_functions(&mut state.stmts);
    let structured: structurer::StructureResult = structure_standard(&state.stmts, p.code.len());
    let body: String = render_blocks(&structured.blocks, 1);
    if structured.unresolved_jumps > 0 {
        state.fully_structured = false;
        state.warnings.push(format!(
            "{} unstructured jump(s) recovered as goto/label",
            structured.unresolved_jumps
        ));
    }
    Some(LiftedProto {
        source: body,
        warnings: state.warnings,
        fully_structured: state.fully_structured,
    })
}

struct LiveAcrossBranch {
    boundaries: Vec<bool>,
    reads: Vec<Vec<u32>>,
}

impl LiveAcrossBranch {
    fn compute(p: &LuaProto, dialect: LuaDialect) -> Self {
        let n: usize = p.code.len();
        let mut boundaries: Vec<bool> = vec![false; n + 1];
        let mut reads: Vec<Vec<u32>> = vec![Vec::new(); n];
        for (pc, raw) in p.code.iter().enumerate() {
            let d: Decoded = decode(*raw, dialect);
            for t in branch_targets(p, pc, &d, dialect) {
                let tu: usize = t as usize;
                if tu <= n {
                    boundaries[tu] = true;
                }
                if pc < n {
                    boundaries[pc + 1] = true;
                }
            }
            if let Some(slot) = reads.get_mut(pc) {
                *slot = read_registers(&d, dialect);
            }
        }
        Self { boundaries, reads }
    }

    #[inline]
    fn should_materialize(&self, def_pc: usize, slot: u32) -> bool {
        let n: usize = self.reads.len();
        let mut use_pc: Option<usize> = None;
        let mut pc: usize = def_pc + 1;
        while pc < n {
            if self.reads[pc].contains(&slot) {
                use_pc = Some(pc);
                break;
            }
            pc += 1;
        }
        match use_pc {
            None => false,
            Some(u) => self
                .boundaries
                .get(def_pc + 1..=u.min(self.boundaries.len().saturating_sub(1)))
                .map(|s: &[bool]| s.iter().any(|b: &bool| *b))
                .unwrap_or(false),
        }
    }
}

#[must_use]
fn read_registers(d: &Decoded, dialect: LuaDialect) -> Vec<u32> {
    let mut out: Vec<u32> = Vec::new();
    let is54: bool = matches!(dialect, LuaDialect::Lua54);
    let push_r = |out: &mut Vec<u32>, v: u32| out.push(v);
    let push_rk = |out: &mut Vec<u32>, v: u32| {
        if is54 || !is_k(v) {
            out.push(v);
        }
    };
    match d.op {
        Op::Move | Op::Unm | Op::BNot | Op::Not | Op::Len | Op::Vararg => push_r(&mut out, d.b),
        Op::GetTable => {
            push_r(&mut out, d.b);
            push_rk(&mut out, d.c);
        }
        Op::GetField | Op::GetI => push_r(&mut out, d.b),
        Op::Self_ => {
            push_r(&mut out, d.b);
            if !is54 {
                push_rk(&mut out, d.c);
            }
        }
        Op::SetGlobal | Op::SetUpval | Op::Return1 | Op::Test | Op::TestSet => {
            push_r(&mut out, d.a);
        }
        Op::SetTable => {
            push_r(&mut out, d.a);
            push_rk(&mut out, d.b);
            push_rk(&mut out, d.c);
        }
        Op::SetField | Op::SetI => {
            push_r(&mut out, d.a);
            push_rk(&mut out, d.c);
        }
        Op::SetTabUp => {
            push_rk(&mut out, d.c);
        }
        Op::GetTabUp if !is54 => {
            push_rk(&mut out, d.c);
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
            if is54 {
                push_r(&mut out, d.b);
                push_r(&mut out, d.c);
            } else {
                push_rk(&mut out, d.b);
                push_rk(&mut out, d.c);
            }
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
        | Op::BXorK
        | Op::AddI
        | Op::ShrI
        | Op::ShlI => push_r(&mut out, d.b),
        Op::Concat => {
            let (start, end): (u32, u32) = if is54 {
                (d.a, d.a + d.b.saturating_sub(1))
            } else {
                (d.b, d.c)
            };
            for r in start..=end {
                push_r(&mut out, r);
            }
        }
        Op::Eq | Op::Lt | Op::Le => {
            if is54 {
                push_r(&mut out, d.a);
                push_r(&mut out, d.b);
            } else {
                push_rk(&mut out, d.b);
                push_rk(&mut out, d.c);
            }
        }
        Op::EqK | Op::EqI | Op::LtI | Op::LeI | Op::GtI | Op::GeI => push_r(&mut out, d.a),
        Op::Call | Op::TailCall => {
            push_r(&mut out, d.a);
            let argc: u32 = d.b;
            if argc == 0 {
                for r in (d.a + 1)..(d.a + 16) {
                    push_r(&mut out, r);
                }
            } else {
                for i in 1..argc {
                    push_r(&mut out, d.a + i);
                }
            }
        }
        Op::Return => {
            let count: u32 = d.b;
            if count == 0 {
                for r in d.a..(d.a + 16) {
                    push_r(&mut out, r);
                }
            } else {
                for i in 0..count.saturating_sub(1) {
                    push_r(&mut out, d.a + i);
                }
            }
        }
        Op::ForPrep => {
            push_r(&mut out, d.a);
            push_r(&mut out, d.a + 1);
            push_r(&mut out, d.a + 2);
        }
        Op::TForCall => {
            push_r(&mut out, d.a);
            push_r(&mut out, d.a + 1);
            push_r(&mut out, d.a + 2);
        }
        Op::SetList => {
            for i in 1..=d.b {
                push_r(&mut out, d.a + i);
            }
        }
        _ => {}
    }
    out
}

#[must_use]
fn branch_targets(p: &LuaProto, pc: usize, d: &Decoded, dialect: LuaDialect) -> Vec<i64> {
    let mut out: Vec<i64> = Vec::new();
    match d.op {
        Op::Jmp => out.push(jump_target(pc, d, dialect)),
        Op::ForLoop | Op::ForPrep | Op::TForLoop if !matches!(dialect, LuaDialect::Lua54) => {
            out.push(pc as i64 + 1 + i64::from(d.sbx));
        }
        Op::ForPrep | Op::TForPrep if matches!(dialect, LuaDialect::Lua54) => {
            out.push(pc as i64 + 1 + i64::from(d.bx));
        }
        Op::ForLoop | Op::TForLoop if matches!(dialect, LuaDialect::Lua54) => {
            out.push(pc as i64 + 1 - i64::from(d.bx));
        }
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
        | Op::TestSet => {
            if let Some(raw2) = p.code.get(pc + 1) {
                let dj: Decoded = decode(*raw2, dialect);
                if dj.op == Op::Jmp {
                    out.push(jump_target(pc + 1, &dj, dialect));
                }
            }
        }
        _ => {}
    }
    out
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

fn lower(
    p: &LuaProto,
    dialect: LuaDialect,
    depth: usize,
    names: &LocalNames,
    live: &LiveAcrossBranch,
    state: &mut StructState,
) -> Option<()> {
    let n: usize = p.code.len();
    let mut pc: usize = 0;
    while pc < n {
        state.pc = pc;
        activate_locals(state, names, pc);
        let raw: u32 = p.code[pc];
        let d: Decoded = decode(raw, dialect);
        match d.op {
            Op::Move => define(state, names, live, p, d.a, state.reg(d.b)),
            Op::LoadK => define(state, names, live, p, d.a, kconst(p, d.bx)),
            Op::LoadKx => {
                let extra: Option<u32> = p.code.get(pc + 1).map(|r: &u32| decode(*r, dialect).ax);
                match extra {
                    Some(ax) => {
                        define(state, names, live, p, d.a, kconst(p, ax));
                        pc += 1;
                    }
                    None => define(state, names, live, p, d.a, format!("K{}", d.bx)),
                }
            }
            Op::LoadI => define(state, names, live, p, d.a, d.sbx.to_string()),
            Op::LoadF => define(state, names, live, p, d.a, format!("{}", f64::from(d.sbx))),
            Op::LoadBool => {
                define(state, names, live, p, d.a, bool_lit(d.b));
                if d.c != 0 {
                    state.fully_structured = false;
                    state
                        .warnings
                        .push("relational boolean materialization not fully recovered".to_owned());
                    pc += 1;
                }
            }
            Op::LoadTrue => define(state, names, live, p, d.a, "true".to_owned()),
            Op::LoadFalse => define(state, names, live, p, d.a, "false".to_owned()),
            Op::LFalseSkip => {
                define(state, names, live, p, d.a, "false".to_owned());
                state.fully_structured = false;
                state
                    .warnings
                    .push("relational boolean materialization not fully recovered".to_owned());
                pc += 1;
            }
            Op::LoadNil => {
                let span: u32 = if matches!(dialect, LuaDialect::Lua54) {
                    d.a + d.b
                } else {
                    d.b
                };
                for r in d.a..=span {
                    define(state, names, live, p, r, "nil".to_owned());
                }
            }
            Op::GetUpval => define(state, names, live, p, d.a, upval_name(p, d.b)),
            Op::SetUpval => {
                let name: String = upval_name(p, d.b);
                let val: String = state.reg(d.a);
                state.push_raw(format!("{name} = {val}"));
            }
            Op::GetGlobal => define(state, names, live, p, d.a, kstr(p, d.bx)),
            Op::SetGlobal => {
                let name: String = kstr(p, d.bx);
                let val: String = state.reg(d.a);
                state.push_raw(format!("{name} = {val}"));
            }
            Op::GetTabUp => {
                let up: String = upval_name(p, d.b);
                let (field, raw_key): (Option<String>, String) = tabup_key(state, p, &d, dialect);
                let expr: String = env_index(&up, field.as_deref(), &raw_key);
                define(state, names, live, p, d.a, expr);
            }
            Op::SetTabUp => {
                let up: String = upval_name(p, d.a);
                let (field, raw_key, val): (Option<String>, String, String) =
                    settabup_operands(state, p, &d, dialect);
                let lhs: String = env_index(&up, field.as_deref(), &raw_key);
                state.push_raw(format!("{lhs} = {val}"));
            }
            Op::GetTable => {
                let table: String = state.reg(d.b);
                let raw_key: String = rk(state, p, d.c, dialect);
                let field: Option<String> = if matches!(dialect, LuaDialect::Lua54) {
                    None
                } else {
                    const_str_key(p, d.c, dialect)
                };
                define(
                    state,
                    names,
                    live,
                    p,
                    d.a,
                    index_expr(&table, field.as_deref(), &raw_key),
                );
            }
            Op::GetField => {
                let table: String = state.reg(d.b);
                let field: Option<String> = const_str_key_direct(p, d.c);
                let raw_key: String = kconst(p, d.c);
                define(
                    state,
                    names,
                    live,
                    p,
                    d.a,
                    index_expr(&table, field.as_deref(), &raw_key),
                );
            }
            Op::GetI => {
                let table: String = state.reg(d.b);
                define(state, names, live, p, d.a, format!("{table}[{}]", d.c));
            }
            Op::SetTable => {
                let table: String = state.reg(d.a);
                let raw_key: String = rk(state, p, d.b, dialect);
                let field: Option<String> = if matches!(dialect, LuaDialect::Lua54) {
                    None
                } else {
                    const_str_key(p, d.b, dialect)
                };
                let val: String = setfield_value(state, p, &d, dialect);
                state.push_raw(format!(
                    "{} = {val}",
                    index_expr(&table, field.as_deref(), &raw_key)
                ));
            }
            Op::SetField => {
                let table: String = state.reg(d.a);
                let field: Option<String> = const_str_key_direct(p, d.b);
                let raw_key: String = kconst(p, d.b);
                let val: String = setfield_value(state, p, &d, dialect);
                state.push_raw(format!(
                    "{} = {val}",
                    index_expr(&table, field.as_deref(), &raw_key)
                ));
            }
            Op::SetI => {
                let table: String = state.reg(d.a);
                let val: String = setfield_value(state, p, &d, dialect);
                state.push_raw(format!("{table}[{}] = {val}", d.b));
            }
            Op::NewTable => {
                if matches!(dialect, LuaDialect::Lua54) {
                    pc += 1;
                }
                define_table(state, names, live, p, &d, pc, dialect);
            }
            Op::Self_ => {
                let table: String = state.reg(d.b);
                let (field, raw_key): (Option<String>, String) = self_key(state, p, &d, dialect);
                set_temp(state, d.a + 1, table.clone());
                state.method_regs.remove(&d.a);
                let method: String = match field {
                    Some(name) => {
                        state.method_regs.insert(d.a);
                        format!("{table}:{name}")
                    }
                    None => index_expr(&table, None, &raw_key),
                };
                set_temp(state, d.a, method);
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
                    rk(state, p, d.b, dialect)
                };
                let rhs: String = if matches!(dialect, LuaDialect::Lua54) {
                    state.reg(d.c)
                } else {
                    rk(state, p, d.c, dialect)
                };
                if let Some(e) = arith(d.op, &lhs, &rhs) {
                    define(state, names, live, p, d.a, e);
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
                let rhs: String = kconst(p, d.c);
                if let Some(e) = arith(d.op, &lhs, &rhs) {
                    define(state, names, live, p, d.a, e);
                }
                skip_mmbin(p, &mut pc, dialect);
            }
            Op::AddI => {
                let lhs: String = state.reg(d.b);
                let imm: i32 = d.c as i32 - 127;
                define(state, names, live, p, d.a, format!("({lhs} + {imm})"));
                skip_mmbin(p, &mut pc, dialect);
            }
            Op::ShrI => {
                let lhs: String = state.reg(d.b);
                let imm: i32 = d.c as i32 - 127;
                define(state, names, live, p, d.a, format!("({lhs} >> {imm})"));
                skip_mmbin(p, &mut pc, dialect);
            }
            Op::ShlI => {
                let rhs: String = state.reg(d.b);
                let imm: i32 = d.c as i32 - 127;
                define(state, names, live, p, d.a, format!("({imm} << {rhs})"));
                skip_mmbin(p, &mut pc, dialect);
            }
            Op::MmBin | Op::MmBinI | Op::MmBinK => {}
            Op::Unm => {
                let v: String = state.reg(d.b);
                define(state, names, live, p, d.a, format!("-({v})"));
            }
            Op::BNot => {
                let v: String = state.reg(d.b);
                define(state, names, live, p, d.a, format!("~({v})"));
            }
            Op::Not => {
                let v: String = state.reg(d.b);
                define(state, names, live, p, d.a, format!("(not {v})"));
            }
            Op::Len => {
                let v: String = state.reg(d.b);
                define(state, names, live, p, d.a, format!("#{v}"));
            }
            Op::Concat => {
                let (start, end): (u32, u32) = if matches!(dialect, LuaDialect::Lua54) {
                    (d.a, d.a + d.b - 1)
                } else {
                    (d.b, d.c)
                };
                let parts: Vec<String> = (start..=end).map(|r: u32| state.reg(r)).collect();
                define(
                    state,
                    names,
                    live,
                    p,
                    d.a,
                    format!("({})", parts.join(" .. ")),
                );
            }
            Op::Jmp => {
                let target: i64 = jump_target(pc, &d, dialect);
                if let Some(ctrl) = forin_controller(p, target, dialect) {
                    emit_forin_head(state, names, &ctrl, pc, dialect);
                } else if target >= 0 {
                    state.push_stmt(LStmt::Jump {
                        target: target as usize,
                    });
                }
            }
            Op::Eq | Op::Lt | Op::Le => {
                emit_compare(state, p, &d, pc, dialect);
                if next_is_jmp(p, pc, dialect) {
                    pc += 1;
                }
            }
            Op::EqK => {
                let lhs: String = state.reg(d.a);
                let rhs: String = kconst(p, d.b);
                let sym: &str = if d.k { "~=" } else { "==" };
                emit_cond(state, p, pc, dialect, &lhs, sym, &rhs);
                if next_is_jmp(p, pc, dialect) {
                    pc += 1;
                }
            }
            Op::EqI | Op::LtI | Op::LeI | Op::GtI | Op::GeI => {
                let lhs: String = state.reg(d.a);
                let imm: i32 = d.b as i32 - 127;
                let sym: &str = imm_compare_sym(d.op, !d.k);
                emit_cond(state, p, pc, dialect, &lhs, sym, &imm.to_string());
                if next_is_jmp(p, pc, dialect) {
                    pc += 1;
                }
            }
            Op::Test => {
                if let Some(consumed) = emit_ternary(state, names, live, p, &d, pc, dialect) {
                    pc = consumed;
                } else {
                    let v: String = state.reg(d.a);
                    let jump_on_truthy: bool = if matches!(dialect, LuaDialect::Lua54) {
                        d.k
                    } else {
                        d.c != 0
                    };
                    let cond: String = if jump_on_truthy {
                        format!("not {v}")
                    } else {
                        v
                    };
                    emit_cond_lit(state, p, pc, dialect, cond);
                    if next_is_jmp(p, pc, dialect) {
                        pc += 1;
                    }
                }
            }
            Op::TestSet => {
                if let Some(consumed) = emit_and_or(state, names, live, p, &d, pc, dialect) {
                    pc = consumed;
                } else {
                    let v: String = state.reg(d.b);
                    set_temp(state, d.a, v);
                    state.fully_structured = false;
                    if next_is_jmp(p, pc, dialect) {
                        pc += 1;
                    }
                }
            }
            Op::Call => emit_call(state, names, live, p, &d, false, dialect),
            Op::TailCall => emit_call(state, names, live, p, &d, true, dialect),
            Op::Return => {
                let is_last: bool = pc + 1 == n;
                if !(is_last && d.b == 1) {
                    emit_return(state, &d);
                }
            }
            Op::Return0 => {
                if pc + 1 != n {
                    state.push_raw("return".to_owned());
                }
            }
            Op::Return1 => state.push_raw(format!("return {}", state.reg(d.a))),
            Op::ForPrep => emit_fornum(state, names, &d, pc, dialect),
            Op::ForLoop => state.push_stmt(LStmt::BlockEnd),
            Op::TForPrep => {
                let target: i64 = pc as i64 + 1 + i64::from(d.bx);
                if let Some(ctrl) = forin_controller(p, target, dialect) {
                    emit_forin_head(state, names, &ctrl, pc, dialect);
                }
            }
            Op::TForCall => {
                state.push_stmt(LStmt::BlockEnd);
            }
            Op::TForLoop => {
                if !matches!(
                    dialect,
                    LuaDialect::Lua52 | LuaDialect::Lua53 | LuaDialect::Lua54
                ) {
                    state.push_stmt(LStmt::BlockEnd);
                }
                if matches!(
                    p.code.get(pc + 1).map(|r: &u32| decode(*r, dialect).op),
                    Some(Op::Jmp)
                ) {
                    pc += 1;
                }
            }
            Op::SetList => emit_setlist(state, &d, &mut pc, dialect),
            Op::Close => {}
            Op::Tbc => {}
            Op::Closure => emit_closure(state, p, &d, dialect, depth)?,
            Op::Vararg => define(state, names, live, p, d.a, "...".to_owned()),
            Op::VarargPrep | Op::ExtraArg => {}
            Op::Unknown => {
                state.push_raw(format!("-- unknown opcode raw=0x{raw:08X} pc={pc}"));
                state
                    .warnings
                    .push(format!("unknown opcode at pc={pc} raw=0x{raw:08X}"));
                state.fully_structured = false;
            }
        }
        pc += 1;
    }
    Some(())
}

#[inline]
fn bool_lit(b: u32) -> String {
    if b != 0 { "true" } else { "false" }.to_owned()
}

fn define(
    state: &mut StructState,
    names: &LocalNames,
    live: &LiveAcrossBranch,
    _p: &LuaProto,
    slot: u32,
    value: String,
) {
    let active_name: Option<String> = names.name_at(state.pc, slot).map(str::to_owned);
    let upcoming_name: Option<String> = if active_name.is_none() {
        names
            .name_at(state.pc + 1, slot)
            .filter(|n: &&str| names.name_at(state.pc, slot) != Some(*n))
            .map(str::to_owned)
    } else {
        None
    };
    if let Some(name) = active_name.or(upcoming_name) {
        if state.is_defined(slot) && state.reg(slot) == name {
            if value != name {
                state.push_raw(format!("{name} = {value}"));
            }
        } else {
            state.push_raw(format!("local {name} = {value}"));
            state.mark_defined(slot);
        }
        state.set_reg(slot, name);
        return;
    }
    let materialize: bool =
        live.should_materialize(state.pc, slot) || value_uses_self(&value, slot);
    if materialize && !value.is_empty() {
        let tmp: String = format!("v{slot}");
        if state.is_defined(slot) {
            state.push_raw(format!("{tmp} = {value}"));
        } else {
            state.push_raw(format!("local {tmp} = {value}"));
            state.mark_defined(slot);
        }
        state.set_reg(slot, tmp);
    } else {
        state.set_reg(slot, value);
    }
}

fn define_table(
    state: &mut StructState,
    names: &LocalNames,
    _live: &LiveAcrossBranch,
    _p: &LuaProto,
    d: &Decoded,
    _pc: usize,
    dialect: LuaDialect,
) {
    let act_pc: usize = if matches!(dialect, LuaDialect::Lua54) {
        state.pc + 2
    } else {
        state.pc + 1
    };
    let nm: Option<String> = names
        .name_at(state.pc, d.a)
        .or_else(|| names.name_at(act_pc, d.a))
        .map(str::to_owned);
    if let Some(name) = nm {
        state.push_raw(format!("local {name} = {{}}"));
        state.mark_defined(d.a);
        state.set_reg(d.a, name);
        state.suppress_local.push((act_pc, d.a));
    } else {
        let tmp: String = format!("tbl_{}", state.table_locals);
        state.table_locals += 1;
        state.push_raw(format!("local {tmp} = {{}}"));
        state.mark_defined(d.a);
        state.set_reg(d.a, tmp);
    }
}

#[inline]
fn set_temp(state: &mut StructState, slot: u32, value: String) {
    state.set_reg(slot, value);
}

#[inline]
fn value_uses_self(value: &str, slot: u32) -> bool {
    let name: String = format!("v{slot}");
    contains_ident(value, &name)
}

#[must_use]
fn contains_ident(hay: &str, needle: &str) -> bool {
    let bytes: &[u8] = hay.as_bytes();
    let nb: &[u8] = needle.as_bytes();
    if nb.is_empty() {
        return false;
    }
    let mut i: usize = 0;
    while i + nb.len() <= bytes.len() {
        if &bytes[i..i + nb.len()] == nb {
            let before_ok: bool = i == 0 || !is_ident_byte(bytes[i - 1]);
            let after_idx: usize = i + nb.len();
            let after_ok: bool = after_idx >= bytes.len() || !is_ident_byte(bytes[after_idx]);
            if before_ok && after_ok {
                return true;
            }
        }
        i += 1;
    }
    false
}

#[inline]
fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn activate_locals(state: &mut StructState, names: &LocalNames, pc: usize) {
    if !names.has_names {
        return;
    }
    let acts: Vec<(u32, String)> = names.activating_at(pc).to_vec();
    for (slot, name) in acts {
        if state.suppress_local.contains(&(pc, slot)) {
            state.mark_defined(slot);
            state.set_reg(slot, name);
            continue;
        }
        if state.reg(slot) == name {
            continue;
        }
        let raw: String = state.regs.get(slot as usize).cloned().unwrap_or_default();
        let is_reg_placeholder: bool =
            raw.starts_with('R') && raw[1..].chars().all(|c: char| c.is_ascii_digit());
        let is_temp_alias: bool = raw.starts_with('v')
            && raw[1..].chars().all(|c: char| c.is_ascii_digit())
            && !state.is_defined(slot);
        let trivial: bool = raw.is_empty() || raw == name || is_reg_placeholder || is_temp_alias;
        if trivial {
            state.push_raw(format!("local {name}"));
        } else {
            state.push_raw(format!("local {name} = {raw}"));
        }
        state.mark_defined(slot);
        state.set_reg(slot, name);
    }
}

fn emit_cond(
    state: &mut StructState,
    p: &LuaProto,
    pc: usize,
    dialect: LuaDialect,
    lhs: &str,
    sym: &str,
    rhs: &str,
) {
    emit_cond_lit(state, p, pc, dialect, format!("{lhs} {sym} {rhs}"));
}

fn emit_cond_lit(
    state: &mut StructState,
    p: &LuaProto,
    pc: usize,
    dialect: LuaDialect,
    cond: String,
) {
    match cond_jump_target(p, pc, dialect) {
        Some(target) if target >= 0 => {
            state.push_stmt(LStmt::Cond {
                cond,
                target: target as usize,
            });
        }
        _ => {
            state.push_raw(format!("-- cond {cond} (no jump)"));
            state.fully_structured = false;
        }
    }
}

#[inline]
fn cond_jump_target(p: &LuaProto, pc: usize, dialect: LuaDialect) -> Option<i64> {
    p.code.get(pc + 1).and_then(|raw2: &u32| {
        let dj: Decoded = decode(*raw2, dialect);
        if dj.op == Op::Jmp {
            Some(jump_target(pc + 1, &dj, dialect))
        } else {
            None
        }
    })
}

fn emit_compare(
    state: &mut StructState,
    p: &LuaProto,
    d: &Decoded,
    pc: usize,
    dialect: LuaDialect,
) {
    let (lhs, rhs): (String, String) = if matches!(dialect, LuaDialect::Lua54) {
        (state.reg(d.a), state.reg(d.b))
    } else {
        (rk(state, p, d.b, dialect), rk(state, p, d.c, dialect))
    };
    let expect_true: bool = if matches!(dialect, LuaDialect::Lua54) {
        !d.k
    } else {
        d.a == 0
    };
    let sym: &str = match (d.op, expect_true) {
        (Op::Eq, true) => "==",
        (Op::Eq, false) => "~=",
        (Op::Lt, true) => "<",
        (Op::Lt, false) => ">=",
        (Op::Le, true) => "<=",
        (Op::Le, false) => ">",
        _ => "==",
    };
    emit_cond(state, p, pc, dialect, &lhs, sym, &rhs);
}

#[allow(clippy::too_many_arguments)]
#[must_use]
fn emit_ternary(
    state: &mut StructState,
    names: &LocalNames,
    _live: &LiveAcrossBranch,
    p: &LuaProto,
    test: &Decoded,
    pc: usize,
    dialect: LuaDialect,
) -> Option<usize> {
    let jmp1: Decoded = decode(*p.code.get(pc + 1)?, dialect);
    if jmp1.op != Op::Jmp {
        return None;
    }
    let l1: i64 = jump_target(pc + 1, &jmp1, dialect);
    let ts: Decoded = decode(*p.code.get(pc + 2)?, dialect);
    if ts.op != Op::TestSet {
        return None;
    }
    let jmp2: Decoded = decode(*p.code.get(pc + 3)?, dialect);
    if jmp2.op != Op::Jmp {
        return None;
    }
    let merge: i64 = jump_target(pc + 3, &jmp2, dialect);
    let other: Decoded = decode(*p.code.get(pc + 4)?, dialect);
    if !is_single_value_op(other.op) || other.a != ts.a {
        return None;
    }
    if l1 != pc as i64 + 4 || merge != pc as i64 + 5 {
        return None;
    }
    let test_truthy: bool = if matches!(dialect, LuaDialect::Lua54) {
        !test.k
    } else {
        test.c == 0
    };
    let cond: String = state.reg(test.a);
    let cond_expr: String = if test_truthy {
        cond
    } else {
        format!("not {cond}")
    };
    let mid: String = state.reg(ts.b);
    let other_val: String = single_value_text(state, p, &other, dialect);
    let expr: String = format!("({cond_expr} and {mid} or {other_val})");
    define_at_merge(state, names, ts.a, expr, merge as usize);
    Some(pc + 4)
}

fn define_at_merge(
    state: &mut StructState,
    names: &LocalNames,
    slot: u32,
    value: String,
    merge_pc: usize,
) {
    if let Some(name) = names.name_at(merge_pc, slot) {
        let name: String = name.to_owned();
        state.push_raw(format!("local {name} = {value}"));
        state.mark_defined(slot);
        state.set_reg(slot, name);
        state.suppress_local.push((merge_pc, slot));
        return;
    }
    let tmp: String = format!("v{slot}");
    state.push_raw(format!("local {tmp} = {value}"));
    state.mark_defined(slot);
    state.set_reg(slot, tmp);
}

#[allow(clippy::too_many_arguments)]
#[must_use]
fn emit_and_or(
    state: &mut StructState,
    names: &LocalNames,
    live: &LiveAcrossBranch,
    p: &LuaProto,
    d: &Decoded,
    pc: usize,
    dialect: LuaDialect,
) -> Option<usize> {
    let jmp_raw: u32 = *p.code.get(pc + 1)?;
    let jmp: Decoded = decode(jmp_raw, dialect);
    if jmp.op != Op::Jmp {
        return None;
    }
    let merge: i64 = jump_target(pc + 1, &jmp, dialect);
    if merge != pc as i64 + 3 {
        return None;
    }
    let second_raw: u32 = *p.code.get(pc + 2)?;
    let second: Decoded = decode(second_raw, dialect);
    if !is_single_value_op(second.op) || second.a != d.a {
        return None;
    }
    let lhs: String = state.reg(d.b);
    let is_or: bool = if matches!(dialect, LuaDialect::Lua54) {
        d.k
    } else {
        d.c != 0
    };
    let rhs: String = single_value_text(state, p, &second, dialect);
    let op: &str = if is_or { "or" } else { "and" };
    let expr: String = format!("({lhs} {op} {rhs})");
    define_at_merge(state, names, d.a, expr, merge as usize);
    let _ = live;
    Some(pc + 2)
}

#[inline]
fn is_single_value_op(op: Op) -> bool {
    matches!(
        op,
        Op::Move
            | Op::LoadK
            | Op::LoadBool
            | Op::LoadTrue
            | Op::LoadFalse
            | Op::LoadNil
            | Op::LoadI
            | Op::GetGlobal
            | Op::GetUpval
    )
}

#[must_use]
fn single_value_text(
    state: &StructState,
    p: &LuaProto,
    d: &Decoded,
    dialect: LuaDialect,
) -> String {
    match d.op {
        Op::Move => state.reg(d.b),
        Op::LoadK => kconst(p, d.bx),
        Op::LoadBool => bool_lit(d.b),
        Op::LoadTrue => "true".to_owned(),
        Op::LoadFalse => "false".to_owned(),
        Op::LoadNil => "nil".to_owned(),
        Op::LoadI => d.sbx.to_string(),
        Op::GetGlobal => kstr(p, d.bx),
        Op::GetUpval => upval_name(p, d.b),
        _ => {
            let _ = dialect;
            state.reg(d.a)
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn emit_call(
    state: &mut StructState,
    names: &LocalNames,
    live: &LiveAcrossBranch,
    p: &LuaProto,
    d: &Decoded,
    tail: bool,
    dialect: LuaDialect,
) {
    let func: String = state.reg(d.a);
    let is_method: bool = state.method_regs.remove(&d.a);
    let first_arg: u32 = if is_method { 2 } else { 1 };
    let args: Vec<String> = if d.b == 0 {
        collect_open(state, d.a + first_arg)
    } else {
        (first_arg..d.b).map(|i: u32| state.reg(d.a + i)).collect()
    };
    let call: String = format!("{func}({})", args.join(", "));
    if tail {
        state.push_raw(format!("return {call}"));
        return;
    }
    if is_iterator_setup_call(p, state.pc, d, dialect) {
        state.iter_call = Some((d.a, call));
        return;
    }
    if d.c == 0 {
        state.set_reg(d.a, call);
        clear_scratch_above(state, d.a + 1);
    } else if d.c == 1 {
        state.push_raw(call);
        clear_from(state, d.a);
    } else if d.c == 2 {
        let dest: u32 = d.a;
        let name: Option<String> = names
            .name_at(state.pc + 1, dest)
            .or_else(|| names.name_at(state.pc, dest))
            .map(str::to_owned);
        if let Some(name) = name {
            state.push_raw(format!("local {name} = {call}"));
            state.mark_defined(dest);
            state.set_reg(dest, name);
        } else if live.should_materialize(state.pc, dest) {
            let tmp: String = format!("v{dest}");
            state.push_raw(format!("local {tmp} = {call}"));
            state.mark_defined(dest);
            state.set_reg(dest, tmp);
        } else {
            state.set_reg(dest, call);
        }
    } else {
        let count: u32 = d.c - 1;
        let targets: Vec<String> = (0..count)
            .map(|i: u32| {
                let slot: u32 = d.a + i;
                names
                    .name_at(state.pc + 1, slot)
                    .or_else(|| names.name_at(state.pc, slot))
                    .map_or_else(|| format!("v{slot}"), str::to_owned)
            })
            .collect();
        state.push_raw(format!("local {} = {call}", targets.join(", ")));
        for (i, t) in targets.iter().enumerate() {
            state.mark_defined(d.a + i as u32);
            state.set_reg(d.a + i as u32, t.clone());
        }
    }
}

#[inline]
fn clear_from(state: &mut StructState, start: u32) {
    let mut r: usize = start as usize;
    while r < state.regs.len() {
        if !state.defined.get(r).copied().unwrap_or(false) {
            state.regs[r] = String::new();
        }
        r += 1;
    }
}

#[inline]
fn clear_scratch_above(state: &mut StructState, start: u32) {
    let mut r: usize = start as usize;
    while r < state.regs.len() {
        state.regs[r] = String::new();
        if let Some(d) = state.defined.get_mut(r) {
            *d = false;
        }
        r += 1;
    }
}

#[inline]
fn collect_open(state: &StructState, start: u32) -> Vec<String> {
    let mut v: Vec<String> = Vec::new();
    let mut r: u32 = start;
    while (r as usize) < state.regs.len() {
        if state.regs[r as usize].is_empty() {
            break;
        }
        v.push(state.reg(r));
        r += 1;
    }
    v
}

fn emit_return(state: &mut StructState, d: &Decoded) {
    if d.b == 1 {
        state.push_raw("return".to_owned());
    } else if d.b == 0 {
        let vals: Vec<String> = collect_open(state, d.a);
        state.push_raw(format!("return {}", vals.join(", ")));
    } else {
        let vals: Vec<String> = (0..d.b - 1).map(|i: u32| state.reg(d.a + i)).collect();
        state.push_raw(format!("return {}", vals.join(", ")));
    }
}

fn emit_fornum(
    state: &mut StructState,
    names: &LocalNames,
    d: &Decoded,
    pc: usize,
    dialect: LuaDialect,
) {
    let init: String = state.reg(d.a);
    let limit: String = state.reg(d.a + 1);
    let step: String = state.reg(d.a + 2);
    let var: String = names
        .name_at(pc + 1, d.a + 3)
        .map_or_else(|| format!("fv_{}", d.a), str::to_owned);
    state.set_reg(d.a + 3, var.clone());
    state.mark_defined(d.a + 3);
    state.suppress_local.push((pc + 1, d.a + 3));
    let end: usize = loop_end_from_prep(pc, d, dialect);
    state.push_stmt(LStmt::ForNum {
        var,
        init,
        limit,
        step,
        end,
    });
}

#[inline]
fn loop_end_from_prep(pc: usize, d: &Decoded, dialect: LuaDialect) -> usize {
    let off: i64 = if matches!(dialect, LuaDialect::Lua54) {
        i64::from(d.bx)
    } else {
        i64::from(d.sbx)
    };
    let target: i64 = pc as i64 + 1 + off;
    (target + 1).max(0) as usize
}

#[derive(Debug, Clone, Copy)]
struct ForinController {
    base: u32,
    nvars: u32,
    ctrl_pc: usize,
}

#[must_use]
fn forin_controller(p: &LuaProto, target: i64, dialect: LuaDialect) -> Option<ForinController> {
    if target < 0 {
        return None;
    }
    let tpc: usize = target as usize;
    let raw: u32 = *p.code.get(tpc)?;
    let d: Decoded = decode(raw, dialect);
    let is51: bool = !matches!(
        dialect,
        LuaDialect::Lua52 | LuaDialect::Lua53 | LuaDialect::Lua54
    );
    match d.op {
        Op::TForCall if !is51 => Some(ForinController {
            base: d.a,
            nvars: d.c.max(1),
            ctrl_pc: tpc,
        }),
        Op::TForLoop if is51 => Some(ForinController {
            base: d.a,
            nvars: d.c.max(1),
            ctrl_pc: tpc,
        }),
        _ => None,
    }
}

#[must_use]
fn is_iterator_setup_call(p: &LuaProto, pc: usize, d: &Decoded, dialect: LuaDialect) -> bool {
    let Some(raw) = p.code.get(pc + 1) else {
        return false;
    };
    let nd: Decoded = decode(*raw, dialect);
    let ctrl: Option<ForinController> = match nd.op {
        Op::Jmp => forin_controller(p, jump_target(pc + 1, &nd, dialect), dialect),
        Op::TForPrep if matches!(dialect, LuaDialect::Lua54) => {
            forin_controller(p, pc as i64 + 2 + i64::from(nd.bx), dialect)
        }
        _ => None,
    };
    ctrl.is_some_and(|c: ForinController| c.base == d.a)
}

fn emit_forin_head(
    state: &mut StructState,
    names: &LocalNames,
    ctrl: &ForinController,
    head_pc: usize,
    dialect: LuaDialect,
) {
    let iter: String = match state.iter_call.take() {
        Some((base, expr)) if base == ctrl.base => expr,
        other => {
            state.iter_call = other;
            let f: String = state.reg(ctrl.base);
            let s: String = state.reg(ctrl.base + 1);
            let c: String = state.reg(ctrl.base + 2);
            format!("{f}, {s}, {c}")
        }
    };
    let var_base: u32 = if matches!(dialect, LuaDialect::Lua54) {
        ctrl.base + 4
    } else {
        ctrl.base + 3
    };
    let body_pc: usize = head_pc + 1;
    let vars: Vec<String> = (0..ctrl.nvars)
        .map(|i: u32| {
            let slot: u32 = var_base + i;
            names
                .name_at(body_pc, slot)
                .map_or_else(|| format!("k{slot}"), str::to_owned)
        })
        .collect();
    for (i, v) in vars.iter().enumerate() {
        let slot: u32 = var_base + i as u32;
        state.set_reg(slot, v.clone());
        state.mark_defined(slot);
        state.suppress_local.push((body_pc, slot));
    }
    state.push_stmt(LStmt::ForGen {
        iter,
        end: ctrl.ctrl_pc,
    });
    state.push_raw(format!("--FORGLOOP_VARS {}", vars.join(",")));
}

const SETLIST_TAG: &str = "--[[@dl_setlist]]";

enum CtorField {
    Positional { index: u64, value: String },
    Named { key: String, value: String },
    Keyed { key: String, value: String },
}

fn table_def_name(raw: &str) -> Option<&str> {
    let rest: &str = raw.strip_prefix("local ")?;
    let name: &str = rest.strip_suffix(" = {}")?;
    if !name.is_empty() && name.bytes().all(is_ident_byte) && !name.as_bytes()[0].is_ascii_digit() {
        Some(name)
    } else {
        None
    }
}

fn parse_table_assign(raw: &str, table: &str) -> Option<CtorField> {
    let after_eq: usize = raw.find(" = ")?;
    let lhs: &str = &raw[..after_eq];
    let value: &str = &raw[after_eq + 3..];
    let (lhs, is_setlist): (&str, bool) = lhs
        .strip_suffix(SETLIST_TAG)
        .map_or((lhs, false), |base: &str| (base, true));
    let key_part: &str = lhs.strip_prefix(table)?;
    if contains_ident(value, table) {
        return None;
    }
    if let Some(field) = key_part.strip_prefix('.') {
        if !field.is_empty()
            && field.bytes().all(is_ident_byte)
            && !field.as_bytes()[0].is_ascii_digit()
        {
            return Some(CtorField::Named {
                key: field.to_owned(),
                value: value.to_owned(),
            });
        }
        return None;
    }
    let inner: &str = key_part.strip_prefix('[')?.strip_suffix(']')?;
    if is_setlist {
        let idx: u64 = inner.parse::<u64>().ok()?;
        return Some(CtorField::Positional {
            index: idx,
            value: value.to_owned(),
        });
    }
    Some(CtorField::Keyed {
        key: inner.to_owned(),
        value: value.to_owned(),
    })
}

fn render_constructor(name: &str, fields: &[CtorField]) -> String {
    let mut positional: Vec<(u64, &str)> = Vec::new();
    let mut keyed: Vec<String> = Vec::new();
    for f in fields {
        match f {
            CtorField::Positional { index, value } => positional.push((*index, value.as_str())),
            CtorField::Named { key, value } => keyed.push(format!("{key} = {value}")),
            CtorField::Keyed { key, value } => keyed.push(format!("[{key}] = {value}")),
        }
    }
    positional.sort_by_key(|(idx, _): &(u64, &str)| *idx);
    let contiguous_from_one: bool = positional
        .iter()
        .enumerate()
        .all(|(i, (idx, _)): (usize, &(u64, &str))| *idx == i as u64 + 1);
    let mut parts: Vec<String> = Vec::with_capacity(fields.len());
    if contiguous_from_one {
        for (_, value) in &positional {
            parts.push((*value).to_owned());
        }
    } else {
        for (idx, value) in &positional {
            keyed.push(format!("[{idx}] = {value}"));
        }
    }
    parts.extend(keyed);
    format!("local {name} = {{{}}}", parts.join(", "))
}

fn strip_setlist_tags(stmts: &mut [LiftedStmt]) {
    for s in stmts.iter_mut() {
        if let LStmt::Raw(raw) = &mut s.stmt
            && raw.contains(SETLIST_TAG)
        {
            *raw = raw.replace(SETLIST_TAG, "");
        }
    }
}

fn fold_table_constructors(stmts: &mut Vec<LiftedStmt>) {
    let mut i: usize = 0;
    while i < stmts.len() {
        let LStmt::Raw(raw) = &stmts[i].stmt else {
            i += 1;
            continue;
        };
        let Some(name): Option<String> = table_def_name(raw).map(str::to_owned) else {
            i += 1;
            continue;
        };
        let mut fields: Vec<CtorField> = Vec::new();
        let mut j: usize = i + 1;
        while j < stmts.len() {
            let LStmt::Raw(next) = &stmts[j].stmt else {
                break;
            };
            let Some(field): Option<CtorField> = parse_table_assign(next, &name) else {
                break;
            };
            fields.push(field);
            j += 1;
        }
        if fields.is_empty() {
            i += 1;
            continue;
        }
        let def_pc: usize = stmts[i].pc;
        let ctor: String = render_constructor(&name, &fields);
        stmts[i] = LiftedStmt {
            pc: def_pc,
            stmt: LStmt::Raw(ctor),
        };
        stmts.drain(i + 1..j);
        i += 1;
    }
    strip_setlist_tags(stmts);
    eliminate_synthetic_table_aliases(stmts);
}

fn promote_local_functions(stmts: &mut [LiftedStmt]) {
    for s in stmts.iter_mut() {
        if let LStmt::Raw(raw) = &mut s.stmt
            && let Some(promoted) = promoted_local_function(raw)
        {
            *raw = promoted;
        }
    }
}

#[must_use]
fn promoted_local_function(raw: &str) -> Option<String> {
    let rest: &str = raw.strip_prefix("local ")?;
    let (name, after): (&str, &str) = rest.split_once(" = function(")?;
    if !is_ident(name) || !contains_ident(after, name) {
        return None;
    }
    Some(format!("local function {name}({after}"))
}

fn eliminate_synthetic_table_aliases(stmts: &mut Vec<LiftedStmt>) {
    let mut def_idx: usize = 0;
    while def_idx < stmts.len() {
        let LStmt::Raw(raw) = &stmts[def_idx].stmt else {
            def_idx += 1;
            continue;
        };
        let Some(name): Option<String> = synthetic_table_name(raw).map(str::to_owned) else {
            def_idx += 1;
            continue;
        };
        let Some((alias_idx, alias)): Option<(usize, String)> =
            sole_alias_consumer(stmts, def_idx, &name)
        else {
            def_idx += 1;
            continue;
        };
        rename_ident_in_stmts(&mut stmts[def_idx..alias_idx], &name, &alias);
        stmts.remove(alias_idx);
        def_idx += 1;
    }
}

fn synthetic_table_name(raw: &str) -> Option<&str> {
    let rest: &str = raw.strip_prefix("local ")?;
    let (name, rhs): (&str, &str) = rest.split_once(" = ")?;
    if name.starts_with("tbl_")
        && name.bytes().all(is_ident_byte)
        && (rhs == "{}" || rhs.starts_with('{'))
    {
        Some(name)
    } else {
        None
    }
}

fn sole_alias_consumer(
    stmts: &[LiftedStmt],
    def_idx: usize,
    name: &str,
) -> Option<(usize, String)> {
    let mut alias: Option<(usize, String)> = None;
    for (offset, s) in stmts.iter().enumerate().skip(def_idx + 1) {
        if let LStmt::Raw(raw) = &s.stmt
            && let Some(rest) = raw.strip_prefix("local ")
            && let Some((lhs, rhs)) = rest.split_once(" = ")
            && rhs == name
            && !lhs.is_empty()
            && lhs.bytes().all(is_ident_byte)
            && !lhs.as_bytes()[0].is_ascii_digit()
        {
            if alias.is_some() {
                return None;
            }
            alias = Some((offset, lhs.to_owned()));
            continue;
        }
        if let Some((alias_idx, _)) = &alias
            && offset > *alias_idx
            && stmt_references(&s.stmt, name)
        {
            return None;
        }
        if alias.is_none() && stmt_references(&s.stmt, name) {
            let is_field_assign: bool = matches!(&s.stmt, LStmt::Raw(r) if r.starts_with(name));
            if !is_field_assign {
                return None;
            }
        }
    }
    alias
}

fn rename_ident_in_stmts(stmts: &mut [LiftedStmt], from: &str, to: &str) {
    for s in stmts.iter_mut() {
        match &mut s.stmt {
            LStmt::Raw(r) => *r = replace_ident(r, from, to),
            LStmt::Cond { cond, .. } => *cond = replace_ident(cond, from, to),
            LStmt::ForNum {
                init, limit, step, ..
            } => {
                *init = replace_ident(init, from, to);
                *limit = replace_ident(limit, from, to);
                *step = replace_ident(step, from, to);
            }
            LStmt::ForGen { iter, .. } => *iter = replace_ident(iter, from, to),
            LStmt::Jump { .. } | LStmt::Break | LStmt::BlockEnd => {}
        }
    }
}

fn replace_ident(hay: &str, from: &str, to: &str) -> String {
    if from.is_empty() || !contains_ident(hay, from) {
        return hay.to_owned();
    }
    let bytes: &[u8] = hay.as_bytes();
    let fb: &[u8] = from.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(hay.len());
    let mut i: usize = 0;
    while i < bytes.len() {
        if i + fb.len() <= bytes.len() && &bytes[i..i + fb.len()] == fb {
            let before_ok: bool = i == 0 || !is_ident_byte(bytes[i - 1]);
            let after_idx: usize = i + fb.len();
            let after_ok: bool = after_idx >= bytes.len() || !is_ident_byte(bytes[after_idx]);
            if before_ok && after_ok {
                out.extend_from_slice(to.as_bytes());
                i = after_idx;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(out).unwrap_or_else(|_| hay.to_owned())
}

fn stmt_references(stmt: &LStmt, name: &str) -> bool {
    match stmt {
        LStmt::Raw(r) => contains_ident(r, name),
        LStmt::Cond { cond, .. } => contains_ident(cond, name),
        LStmt::ForNum {
            init, limit, step, ..
        } => {
            contains_ident(init, name) || contains_ident(limit, name) || contains_ident(step, name)
        }
        LStmt::ForGen { iter, .. } => contains_ident(iter, name),
        LStmt::Jump { .. } | LStmt::Break | LStmt::BlockEnd => false,
    }
}

const LFIELDS_PER_FLUSH: u32 = 50;

fn emit_setlist(state: &mut StructState, d: &Decoded, pc: &mut usize, dialect: LuaDialect) {
    let table: String = state.reg(d.a);
    let count: u32 = d.b;
    if matches!(dialect, LuaDialect::Lua54) && d.k {
        *pc += 1;
    }
    if count == 0 {
        state.fully_structured = false;
        state
            .warnings
            .push("vararg/multi-value table elements not fully recovered".to_owned());
        return;
    }
    let block: u32 = d.c.max(1);
    let base_index: u32 = (block - 1).saturating_mul(LFIELDS_PER_FLUSH);
    for i in 1..=count {
        let elem: String = state.reg(d.a + i);
        let index: u32 = base_index + i;
        state.push_raw(format!("{table}[{index}]{SETLIST_TAG} = {elem}"));
    }
}

fn emit_closure(
    state: &mut StructState,
    p: &LuaProto,
    d: &Decoded,
    dialect: LuaDialect,
    depth: usize,
) -> Option<()> {
    let child_idx: usize = d.bx as usize;
    match p.protos.get(child_idx) {
        Some(child) => {
            let lifted: Option<LiftedProto> = lift_structured(child, dialect, depth + 1);
            let inner: LiftedProto = match lifted {
                Some(l) => l,
                None => {
                    return None;
                }
            };
            let params: String = (0..u32::from(child.num_params))
                .map(|i: u32| child_param_name(child, i))
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
            for ln in inner.source.lines() {
                block.push_str("  ");
                block.push_str(ln);
                block.push('\n');
            }
            block.push_str("end");
            state.set_reg(d.a, block);
            state.mark_defined(d.a);
            state.warnings.extend(inner.warnings);
            if !inner.fully_structured {
                state.fully_structured = false;
            }
            Some(())
        }
        None => {
            state.set_reg(
                d.a,
                format!("function() --[[ missing proto {child_idx} ]] end"),
            );
            state.mark_defined(d.a);
            state.fully_structured = false;
            Some(())
        }
    }
}

#[must_use]
fn child_param_name(p: &LuaProto, slot: u32) -> String {
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

#[inline]
fn next_is_jmp(p: &LuaProto, pc: usize, dialect: LuaDialect) -> bool {
    p.code
        .get(pc + 1)
        .map(|raw2: &u32| decode(*raw2, dialect).op == Op::Jmp)
        .unwrap_or(false)
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
fn kconst(p: &LuaProto, idx: u32) -> String {
    p.constants
        .get(idx as usize)
        .map_or_else(|| format!("K{idx}"), const_text)
}

#[inline]
fn kstr(p: &LuaProto, bx: u32) -> String {
    match p.constants.get(bx as usize) {
        Some(LuaConstant::Str(s)) => s.clone(),
        Some(other) => const_text(other),
        None => format!("K{bx}"),
    }
}

#[inline]
fn rk(state: &StructState, p: &LuaProto, field: u32, _dialect: LuaDialect) -> String {
    if is_k(field) {
        kconst(p, rk_index(field))
    } else {
        state.reg(field)
    }
}

#[inline]
fn rk_or_const(state: &StructState, p: &LuaProto, field: u32, use_const: bool) -> String {
    if use_const {
        kconst(p, field)
    } else {
        state.reg(field)
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
fn const_str_key(p: &LuaProto, field: u32, dialect: LuaDialect) -> Option<String> {
    if matches!(dialect, LuaDialect::Lua54) {
        return const_str_key_direct(p, field);
    }
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
fn index_expr(table: &str, field_name: Option<&str>, raw_key: &str) -> String {
    match field_name {
        Some(name) => format!("{table}.{name}"),
        None => format!("{table}[{raw_key}]"),
    }
}

#[must_use]
fn env_index(up: &str, field_name: Option<&str>, raw_key: &str) -> String {
    if up == "_ENV" {
        field_name
            .map(str::to_owned)
            .unwrap_or_else(|| format!("_ENV[{raw_key}]"))
    } else {
        index_expr(up, field_name, raw_key)
    }
}

#[inline]
fn tabup_key(
    state: &StructState,
    p: &LuaProto,
    d: &Decoded,
    dialect: LuaDialect,
) -> (Option<String>, String) {
    if matches!(dialect, LuaDialect::Lua54) {
        (const_str_key_direct(p, d.c), kconst(p, d.c))
    } else {
        (const_str_key(p, d.c, dialect), rk(state, p, d.c, dialect))
    }
}

#[inline]
fn settabup_operands(
    state: &StructState,
    p: &LuaProto,
    d: &Decoded,
    dialect: LuaDialect,
) -> (Option<String>, String, String) {
    if matches!(dialect, LuaDialect::Lua54) {
        let field: Option<String> = const_str_key_direct(p, d.b);
        let raw_key: String = kconst(p, d.b);
        let val: String = rk_or_const(state, p, d.c, d.k);
        (field, raw_key, val)
    } else {
        let field: Option<String> = const_str_key(p, d.b, dialect);
        let raw_key: String = rk(state, p, d.b, dialect);
        let val: String = rk(state, p, d.c, dialect);
        (field, raw_key, val)
    }
}

#[inline]
fn setfield_value(state: &StructState, p: &LuaProto, d: &Decoded, dialect: LuaDialect) -> String {
    if matches!(dialect, LuaDialect::Lua54) {
        rk_or_const(state, p, d.c, d.k)
    } else {
        rk(state, p, d.c, dialect)
    }
}

#[inline]
fn self_key(
    state: &StructState,
    p: &LuaProto,
    d: &Decoded,
    dialect: LuaDialect,
) -> (Option<String>, String) {
    if matches!(dialect, LuaDialect::Lua54) {
        (const_str_key_direct(p, d.c), kconst(p, d.c))
    } else {
        (const_str_key(p, d.c, dialect), rk(state, p, d.c, dialect))
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

#[must_use]
fn arith(op: Op, lhs: &str, rhs: &str) -> Option<String> {
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
    Some(format!("({lhs} {sym} {rhs})"))
}
