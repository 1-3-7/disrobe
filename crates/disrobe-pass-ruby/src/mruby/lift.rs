//! Register-machine surface lifter for the mruby (RITE) IREP instruction stream.

use core::fmt::Write as _;

use crate::error::Result;
use crate::mruby::disasm::{MrubyInstruction, disassemble_iseq};
use crate::mruby::irep::{IrepRecord, IrepTree, PoolEntry, PoolKind};
use crate::mruby::ops::MrubyOp;

const MAX_REGS: usize = 4096;
const MAX_LIFT_DEPTH: u32 = 64;
const INDENT: &str = "  ";

#[derive(Debug, Clone)]
enum RegVal {
    Nil,
    SelfRef,
    True,
    False,
    Int(i64),
    Sym(String),
    Str(String),
    PoolLit(String),
    Expr(String),
    MethodProc(u32),
    Unknown,
}

impl RegVal {
    #[allow(clippy::match_same_arms)]
    fn render(&self) -> String {
        match self {
            Self::Nil => "nil".to_owned(),
            Self::SelfRef => "self".to_owned(),
            Self::True => "true".to_owned(),
            Self::False => "false".to_owned(),
            Self::Int(v) => v.to_string(),
            Self::Sym(s) => format!(":{s}"),
            Self::Str(s) => format!("{s:?}"),
            Self::PoolLit(s) => s.clone(),
            Self::Expr(s) => s.clone(),
            Self::MethodProc(idx) => format!("<proc irep[{idx}]>"),
            Self::Unknown => "_".to_owned(),
        }
    }
}

/// Tracks `class`/`module`/`<<self` openings created by `OP_CLASS`/`OP_MODULE`/`OP_SCLASS` in a
/// register, consumed by the following `OP_EXEC` that runs the body IREP.
struct PendingDefs {
    by_reg: Vec<Option<(&'static str, String)>>,
}

impl PendingDefs {
    fn new(n: u16) -> Self {
        Self {
            by_reg: vec![None; usize::from(n).clamp(1, MAX_REGS)],
        }
    }

    fn set_pending(&mut self, reg: u32, keyword: &'static str, name: String) {
        if let Ok(i) = usize::try_from(reg)
            && i < MAX_REGS
        {
            if i >= self.by_reg.len() {
                self.by_reg.resize(i + 1, None);
            }
            self.by_reg[i] = Some((keyword, name));
        }
    }

    fn take_pending(&mut self, reg: u32) -> Option<(&'static str, String)> {
        usize::try_from(reg)
            .ok()
            .and_then(|i| self.by_reg.get_mut(i))
            .and_then(Option::take)
    }
}

struct Regs {
    slots: Vec<RegVal>,
}

impl Regs {
    fn new(n: u16) -> Self {
        let cap: usize = usize::from(n).clamp(1, MAX_REGS);
        Self {
            slots: vec![RegVal::Unknown; cap],
        }
    }

    fn get(&self, idx: u32) -> RegVal {
        usize::try_from(idx)
            .ok()
            .and_then(|i| self.slots.get(i))
            .cloned()
            .unwrap_or(RegVal::Unknown)
    }

    fn set(&mut self, idx: u32, val: RegVal) {
        if let Ok(i) = usize::try_from(idx)
            && i < MAX_REGS
        {
            if i >= self.slots.len() {
                self.slots.resize(i + 1, RegVal::Unknown);
            }
            self.slots[i] = val;
        }
    }
}

/// Lift the full IREP tree to Ruby surface, starting at the top-level record.
pub(crate) fn lift_tree(tree: &IrepTree) -> Result<String> {
    let mut out: String = String::with_capacity(tree.total_insn_bytes as usize + 256);
    lift_record(tree, 0, 0, 0, &mut out)?;
    Ok(out)
}

fn lift_record(
    tree: &IrepTree,
    index: u32,
    indent: u32,
    depth: u32,
    out: &mut String,
) -> Result<()> {
    if depth > MAX_LIFT_DEPTH {
        return Ok(());
    }
    let Some(rec): Option<&IrepRecord> = tree.records.get(index as usize) else {
        return Ok(());
    };
    let ins: Vec<MrubyInstruction> = disassemble_iseq(&rec.iseq)?;
    let mut regs: Regs = Regs::new(rec.nregs);
    let mut pending: PendingDefs = PendingDefs::new(rec.nregs);
    let pad: String = INDENT.repeat(indent as usize);

    for instr in &ins {
        lift_instruction(
            tree,
            rec,
            instr,
            &mut regs,
            &mut pending,
            &pad,
            indent,
            depth,
            out,
        )?;
    }
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    clippy::many_single_char_names,
    clippy::match_same_arms
)]
fn lift_instruction(
    tree: &IrepTree,
    rec: &IrepRecord,
    instr: &MrubyInstruction,
    regs: &mut Regs,
    pending: &mut PendingDefs,
    pad: &str,
    indent: u32,
    depth: u32,
    out: &mut String,
) -> Result<()> {
    let a: u32 = instr.operands.first().copied().unwrap_or(0);
    let b: u32 = instr.operands.get(1).copied().unwrap_or(0);
    let c: u32 = instr.operands.get(2).copied().unwrap_or(0);

    match instr.op {
        MrubyOp::Move => {
            let v: RegVal = regs.get(b);
            regs.set(a, v);
        }
        MrubyOp::LoadNil => regs.set(a, RegVal::Nil),
        MrubyOp::LoadSelf => regs.set(a, RegVal::SelfRef),
        MrubyOp::LoadT => regs.set(a, RegVal::True),
        MrubyOp::LoadF => regs.set(a, RegVal::False),
        MrubyOp::LoadI => regs.set(a, RegVal::Int(i64::from(b))),
        MrubyOp::LoadINeg => regs.set(a, RegVal::Int(-i64::from(b))),
        MrubyOp::LoadI16 => regs.set(a, RegVal::Int(i64::from(b as i16))),
        MrubyOp::LoadI32 => {
            let v: i64 = i64::from(((b << 16) | c) as i32);
            regs.set(a, RegVal::Int(v));
        }
        MrubyOp::LoadISmall(n) => regs.set(a, RegVal::Int(i64::from(n))),
        MrubyOp::LoadL => {
            let v: RegVal = pool_value(rec, b);
            regs.set(a, v);
        }
        MrubyOp::Strng => {
            let s: String = pool_string(rec, b);
            regs.set(a, RegVal::Str(s));
        }
        MrubyOp::LoadSym | MrubyOp::Symbol => {
            let s: String = symbol(rec, b);
            regs.set(a, RegVal::Sym(s));
        }
        MrubyOp::StrCat => {
            let lhs: String = regs.get(a).render();
            let rhs: String = regs.get(a.saturating_add(1)).render();
            regs.set(a, RegVal::Expr(format!("{lhs} + {rhs}")));
        }
        MrubyOp::GetIv => regs.set(a, RegVal::Expr(format!("@{}", symbol(rec, b)))),
        MrubyOp::GetCv => regs.set(a, RegVal::Expr(format!("@@{}", symbol(rec, b)))),
        MrubyOp::GetGv => regs.set(a, RegVal::Expr(symbol(rec, b))),
        MrubyOp::GetConst | MrubyOp::GetMCnst => {
            regs.set(a, RegVal::Expr(symbol(rec, b)));
        }
        MrubyOp::SetIv => {
            writeln!(out, "{pad}@{} = {}", symbol(rec, b), regs.get(a).render()).ok();
        }
        MrubyOp::SetCv => {
            writeln!(out, "{pad}@@{} = {}", symbol(rec, b), regs.get(a).render()).ok();
        }
        MrubyOp::SetGv => {
            writeln!(out, "{pad}{} = {}", symbol(rec, b), regs.get(a).render()).ok();
        }
        MrubyOp::SetConst | MrubyOp::SetMCnst => {
            writeln!(out, "{pad}{} = {}", symbol(rec, b), regs.get(a).render()).ok();
        }
        MrubyOp::Add | MrubyOp::Sub | MrubyOp::Mul | MrubyOp::Div => {
            let opc: &str = match instr.op {
                MrubyOp::Add => "+",
                MrubyOp::Sub => "-",
                MrubyOp::Mul => "*",
                _ => "/",
            };
            let lhs: String = regs.get(a).render();
            let rhs: String = regs.get(a.saturating_add(1)).render();
            regs.set(a, RegVal::Expr(format!("{lhs} {opc} {rhs}")));
        }
        MrubyOp::AddI | MrubyOp::SubI => {
            let opc: &str = if matches!(instr.op, MrubyOp::AddI) {
                "+"
            } else {
                "-"
            };
            let lhs: String = regs.get(a).render();
            regs.set(a, RegVal::Expr(format!("{lhs} {opc} {b}")));
        }
        MrubyOp::Eq | MrubyOp::Lt | MrubyOp::Le | MrubyOp::Gt | MrubyOp::Ge => {
            let opc: &str = match instr.op {
                MrubyOp::Eq => "==",
                MrubyOp::Lt => "<",
                MrubyOp::Le => "<=",
                MrubyOp::Gt => ">",
                _ => ">=",
            };
            let lhs: String = regs.get(a).render();
            let rhs: String = regs.get(a.saturating_add(1)).render();
            regs.set(a, RegVal::Expr(format!("{lhs} {opc} {rhs}")));
        }
        MrubyOp::Send | MrubyOp::SendB | MrubyOp::SSend | MrubyOp::SSendB => {
            let call: String = render_call(
                rec,
                regs,
                a,
                b,
                c,
                matches!(instr.op, MrubyOp::SendB | MrubyOp::SSendB),
            );
            regs.set(a, RegVal::Expr(call));
        }
        MrubyOp::Array => {
            let elems: String = render_consecutive(regs, a, c.max(b));
            regs.set(a, RegVal::Expr(format!("[{elems}]")));
        }
        MrubyOp::Hash => {
            regs.set(a, RegVal::Expr("{}".to_owned()));
        }
        MrubyOp::Method => {
            let child: u32 = nth_child(rec, b);
            regs.set(a, RegVal::MethodProc(child));
        }
        MrubyOp::Def => {
            let name: String = symbol(rec, b);
            let child: u32 = match regs.get(a) {
                RegVal::MethodProc(idx) => idx,
                _ => u32::MAX,
            };
            emit_def(tree, &name, child, indent, depth, out)?;
            regs.set(a, RegVal::Sym(name));
        }
        MrubyOp::Class => {
            let name: String = symbol(rec, b);
            regs.set(a, RegVal::Expr(format!("<class {name}>")));
            pending.set_pending(a, "class", name);
        }
        MrubyOp::Module => {
            let name: String = symbol(rec, b);
            regs.set(a, RegVal::Expr(format!("<module {name}>")));
            pending.set_pending(a, "module", name);
        }
        MrubyOp::SClass => {
            regs.set(a, RegVal::Expr("<<self".to_owned()));
            pending.set_pending(a, "class", "<<self".to_owned());
        }
        MrubyOp::Exec => {
            let child: u32 = nth_child(rec, b);
            match pending.take_pending(a) {
                Some((keyword, name)) => {
                    emit_block(tree, keyword, &name, child, indent, depth, out)?;
                }
                None => lift_record(tree, child, indent, depth.saturating_add(1), out)?,
            }
        }
        MrubyOp::Return | MrubyOp::ReturnBlk => {
            let v: RegVal = regs.get(a);
            match v {
                RegVal::Expr(ref e) if !is_bare_value(&v) => {
                    writeln!(out, "{pad}{e}").ok();
                }
                RegVal::Nil => {}
                other => {
                    writeln!(out, "{pad}{}", other.render()).ok();
                }
            }
        }
        _ => {}
    }
    Ok(())
}

const fn is_bare_value(v: &RegVal) -> bool {
    matches!(
        v,
        RegVal::Nil
            | RegVal::SelfRef
            | RegVal::True
            | RegVal::False
            | RegVal::Int(_)
            | RegVal::Sym(_)
            | RegVal::Str(_)
    )
}

fn emit_def(
    tree: &IrepTree,
    name: &str,
    child: u32,
    indent: u32,
    depth: u32,
    out: &mut String,
) -> Result<()> {
    let pad: String = INDENT.repeat(indent as usize);
    let params: String = def_params(tree, child);
    writeln!(out, "{pad}def {name}{params}").ok();
    lift_record(
        tree,
        child,
        indent.saturating_add(1),
        depth.saturating_add(1),
        out,
    )?;
    writeln!(out, "{pad}end").ok();
    Ok(())
}

fn emit_block(
    tree: &IrepTree,
    keyword: &str,
    name: &str,
    child: u32,
    indent: u32,
    depth: u32,
    out: &mut String,
) -> Result<()> {
    let pad: String = INDENT.repeat(indent as usize);
    writeln!(out, "{pad}{keyword} {name}").ok();
    lift_record(
        tree,
        child,
        indent.saturating_add(1),
        depth.saturating_add(1),
        out,
    )?;
    writeln!(out, "{pad}end").ok();
    Ok(())
}

/// Render a method's parameter list as count-derived placeholders `(arg0, arg1, ...)`.
fn def_params(tree: &IrepTree, child: u32) -> String {
    let Some(rec): Option<&IrepRecord> = tree.records.get(child as usize) else {
        return String::new();
    };
    let nargs: u16 = rec.nlocals.saturating_sub(1);
    if nargs == 0 {
        return String::new();
    }
    let names: Vec<String> = (0..nargs).map(|i| format!("arg{i}")).collect();
    format!("({})", names.join(", "))
}

fn render_call(
    rec: &IrepRecord,
    regs: &Regs,
    recv_reg: u32,
    method_sym: u32,
    argc: u32,
    has_block: bool,
) -> String {
    let method: String = symbol(rec, method_sym);
    let recv: RegVal = regs.get(recv_reg);
    let args: String = render_consecutive(regs, recv_reg.saturating_add(1), argc);

    let prefix: String = match recv {
        RegVal::SelfRef => String::new(),
        other => format!("{}.", other.render()),
    };
    let block_suffix: &str = if has_block { " { ... }" } else { "" };
    if argc == 0 && !has_block {
        format!("{prefix}{method}")
    } else if argc == 0 {
        format!("{prefix}{method}{block_suffix}")
    } else {
        format!("{prefix}{method}({args}){block_suffix}")
    }
}

fn render_consecutive(regs: &Regs, start: u32, count: u32) -> String {
    let n: u32 = count.min(64);
    let mut parts: Vec<String> = Vec::with_capacity(n as usize);
    for i in 0..n {
        parts.push(regs.get(start.saturating_add(i)).render());
    }
    parts.join(", ")
}

fn pool_value(rec: &IrepRecord, idx: u32) -> RegVal {
    let Some(entry): Option<&PoolEntry> = rec.pool.get(idx as usize) else {
        return RegVal::Unknown;
    };
    match (entry.kind, entry.value.as_ref()) {
        (PoolKind::String, Some(v)) => RegVal::Str(v.clone()),
        (_, Some(v)) => RegVal::PoolLit(v.clone()),
        (_, None) => RegVal::Unknown,
    }
}

fn pool_string(rec: &IrepRecord, idx: u32) -> String {
    rec.pool
        .get(idx as usize)
        .and_then(|e| e.value.clone())
        .unwrap_or_default()
}

fn symbol(rec: &IrepRecord, idx: u32) -> String {
    rec.symbols
        .get(idx as usize)
        .cloned()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("sym{idx}"))
}

fn nth_child(rec: &IrepRecord, n: u32) -> u32 {
    rec.child_indices
        .get(n as usize)
        .copied()
        .or_else(|| rec.child_indices.first().copied())
        .unwrap_or(u32::MAX)
}

/// SPEC-VALIDATED, NOT real-corpus recovery. These tests hand-construct the `IrepTree` to the RITE
#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::mruby::irep::{IrepRecord, PoolEntry};

    fn rec(
        iseq: Vec<u8>,
        pool: Vec<PoolEntry>,
        symbols: Vec<String>,
        children: Vec<u32>,
    ) -> IrepRecord {
        IrepRecord {
            depth: 0,
            index: 0,
            nlocals: 1,
            nregs: 8,
            child_count: u16::try_from(children.len()).unwrap_or(0),
            catch_count: 0,
            insn_len: u32::try_from(iseq.len()).unwrap_or(0),
            iseq,
            pool,
            symbols,
            child_indices: children,
        }
    }

    #[test]
    fn lifts_puts_hello_world_from_synthetic_irep() {
        let iseq: Vec<u8> = vec![
            0x12, 0x01, 0x51, 0x02, 0x00, 0x2f, 0x01, 0x00, 0x01, 0x38, 0x01,
        ];
        let pool: Vec<PoolEntry> = vec![PoolEntry {
            kind: PoolKind::String,
            value: Some("hello world".to_owned()),
        }];
        let tree: IrepTree = IrepTree {
            records: vec![rec(iseq, pool, vec!["puts".to_owned()], vec![])],
            total_insn_bytes: 11,
            total_symbols: 1,
            total_pool_entries: 1,
        };
        let src: String = lift_tree(&tree).expect("lift");
        assert!(src.contains("puts(\"hello world\")"), "got: {src}");
    }

    #[test]
    fn lifts_method_definition_with_recursion_from_synthetic_irep() {
        let parent_iseq: Vec<u8> = vec![0x58, 0x00, 0x00, 0x5f, 0x00, 0x00, 0x38, 0x00];
        let child_iseq: Vec<u8> = vec![
            0x12, 0x01, 0x51, 0x02, 0x00, 0x2f, 0x01, 0x00, 0x01, 0x38, 0x01,
        ];
        let parent: IrepRecord = rec(parent_iseq, vec![], vec!["greet".to_owned()], vec![1]);
        let child: IrepRecord = rec(
            child_iseq,
            vec![PoolEntry {
                kind: PoolKind::String,
                value: Some("hi".to_owned()),
            }],
            vec!["puts".to_owned()],
            vec![],
        );
        let tree: IrepTree = IrepTree {
            records: vec![parent, child],
            total_insn_bytes: 18,
            total_symbols: 2,
            total_pool_entries: 1,
        };
        let src: String = lift_tree(&tree).expect("lift");
        assert!(src.contains("def greet"), "got: {src}");
        assert!(src.contains("puts(\"hi\")"), "got: {src}");
        assert!(src.contains("end"), "got: {src}");
    }
}
