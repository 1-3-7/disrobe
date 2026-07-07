use core::fmt::Arguments;
use std::collections::BTreeSet;

use crate::error::Result;
use crate::mruby::disasm::{MrubyInstruction, disassemble_iseq};
use crate::mruby::irep::{IrepRecord, IrepTree, PoolEntry, PoolKind};
use crate::mruby::ops::MrubyOp;

const MAX_REGS: usize = 4096;
const MAX_LIFT_DEPTH: u32 = 64;
const MAX_LIFT_OUTPUT_PREALLOC: usize = 1 << 20;
const INDENT: &str = "  ";
const CALL_MAXARGS: u32 = 15;

fn push_line(out: &mut String, args: Arguments<'_>) {
    match core::fmt::write(out, args) {
        Ok(()) => {}
        Err(error) => unreachable!("string formatting failed: {error:?}"),
    }
    out.push('\n');
}

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
    Local(String),
    MethodProc(u32),
    BlockProc(u32),
    ArgForward,
    BlockYield,
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
            Self::Expr(s) | Self::Local(s) => s.clone(),
            Self::MethodProc(idx) => format!("<proc irep[{idx}]>"),
            Self::BlockProc(_) => "proc {}".to_owned(),
            Self::ArgForward => "<super args>".to_owned(),
            Self::BlockYield => "<block>".to_owned(),
            Self::Unknown => "_".to_owned(),
        }
    }
}

#[derive(Debug, Default)]
struct LiftStats {
    total: u32,
    unmodeled: u32,
    unmodeled_ops: BTreeSet<String>,
}

#[derive(Debug)]
pub(crate) struct LiftOutput {
    pub(crate) source: String,
    pub(crate) modeled_opcodes: u32,
    pub(crate) unmodeled_opcodes: u32,
    pub(crate) total_opcodes: u32,
    pub(crate) unmodeled_mnemonics: Vec<String>,
}

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

struct Frame<'a> {
    rec: &'a IrepRecord,
    ins: &'a [MrubyInstruction],
    dests: &'a [Option<u32>],
    srcs: &'a [Vec<u32>],
    nlocals: u32,
    nargs: u32,
    indent: u32,
    depth: u32,
}

struct Lifter<'a> {
    tree: &'a IrepTree,
    stats: LiftStats,
    scopes: Vec<u32>,
}

pub(crate) fn lift_tree(tree: &IrepTree) -> Result<LiftOutput> {
    let cap: usize = lift_output_prealloc(tree.total_insn_bytes);
    let mut out: String = String::with_capacity(cap);
    let mut lifter: Lifter<'_> = Lifter {
        tree,
        stats: LiftStats::default(),
        scopes: Vec::new(),
    };
    lifter.record(0, 0, 0, &mut out)?;
    let modeled: u32 = lifter.stats.total.saturating_sub(lifter.stats.unmodeled);
    Ok(LiftOutput {
        source: out,
        modeled_opcodes: modeled,
        unmodeled_opcodes: lifter.stats.unmodeled,
        total_opcodes: lifter.stats.total,
        unmodeled_mnemonics: lifter.stats.unmodeled_ops.into_iter().collect(),
    })
}

fn lift_output_prealloc(total_insn_bytes: u32) -> usize {
    usize::try_from(total_insn_bytes)
        .unwrap_or(usize::MAX)
        .saturating_add(256)
        .min(MAX_LIFT_OUTPUT_PREALLOC)
}

impl Lifter<'_> {
    fn record(&mut self, index: u32, indent: u32, depth: u32, out: &mut String) -> Result<()> {
        if depth > MAX_LIFT_DEPTH {
            return Ok(());
        }
        let Some(rec): Option<&IrepRecord> = self.tree.records.get(index as usize) else {
            return Ok(());
        };
        let ins: Vec<MrubyInstruction> = disassemble_iseq(&rec.iseq)?;
        let nargs: u32 = arg_count(rec);
        let nlocals: u32 = u32::from(rec.nlocals);
        let mut dests: Vec<Option<u32>> = Vec::with_capacity(ins.len());
        let mut srcs: Vec<Vec<u32>> = Vec::with_capacity(ins.len());
        for instr in &ins {
            let (dest, read): (Option<u32>, Vec<u32>) = effect(instr);
            dests.push(dest);
            srcs.push(read);
        }
        let mut regs: Regs = Regs::new(rec.nregs);
        regs.set(0, RegVal::SelfRef);
        for i in 0..nargs {
            regs.set(i.saturating_add(1), RegVal::Local(format!("arg{i}")));
        }
        let mut pending: PendingDefs = PendingDefs::new(rec.nregs);
        let frame: Frame<'_> = Frame {
            rec,
            ins: &ins,
            dests: &dests,
            srcs: &srcs,
            nlocals,
            nargs,
            indent,
            depth,
        };
        self.scopes.push(nargs);
        let mut result: Result<()> = Ok(());
        for i in 0..ins.len() {
            self.stats.total = self.stats.total.saturating_add(1);
            if let Err(e) = self.instruction(&frame, i, &mut regs, &mut pending, out) {
                result = Err(e);
                break;
            }
        }
        self.scopes.pop();
        result
    }

    fn resolve_upvar(&self, index: u32, up: u32) -> String {
        let target: Option<&u32> = self
            .scopes
            .len()
            .checked_sub(2 + up as usize)
            .and_then(|i| self.scopes.get(i));
        match target {
            Some(&nargs) => local_name(index, nargs),
            None => format!("__up_{index}_{up}"),
        }
    }

    #[allow(
        clippy::too_many_lines,
        clippy::match_same_arms,
        clippy::many_single_char_names
    )]
    fn instruction(
        &mut self,
        frame: &Frame<'_>,
        i: usize,
        regs: &mut Regs,
        pending: &mut PendingDefs,
        out: &mut String,
    ) -> Result<()> {
        let instr: &MrubyInstruction = &frame.ins[i];
        let rec: &IrepRecord = frame.rec;
        let a: u32 = instr.operands.first().copied().unwrap_or(0);
        let b: u32 = instr.operands.get(1).copied().unwrap_or(0);
        let c: u32 = instr.operands.get(2).copied().unwrap_or(0);
        let pad: String = pad_for(frame.indent);

        match instr.op {
            MrubyOp::Move => {
                let v: RegVal = regs.get(b);
                place(regs, frame, i, a, v, false, out);
            }
            MrubyOp::LoadNil => place(regs, frame, i, a, RegVal::Nil, false, out),
            MrubyOp::LoadSelf => place(regs, frame, i, a, RegVal::SelfRef, false, out),
            MrubyOp::LoadT => place(regs, frame, i, a, RegVal::True, false, out),
            MrubyOp::LoadF => place(regs, frame, i, a, RegVal::False, false, out),
            MrubyOp::LoadI => place(regs, frame, i, a, RegVal::Int(i64::from(b)), false, out),
            MrubyOp::LoadINeg => place(regs, frame, i, a, RegVal::Int(-i64::from(b)), false, out),
            MrubyOp::LoadI16 => {
                place(
                    regs,
                    frame,
                    i,
                    a,
                    RegVal::Int(i64::from(b as i16)),
                    false,
                    out,
                );
            }
            MrubyOp::LoadI32 => {
                let v: i64 = i64::from(((b << 16) | c) as i32);
                place(regs, frame, i, a, RegVal::Int(v), false, out);
            }
            MrubyOp::LoadISmall(n) => {
                place(regs, frame, i, a, RegVal::Int(i64::from(n)), false, out);
            }
            MrubyOp::LoadL => {
                let v: RegVal = pool_value(rec, b);
                place(regs, frame, i, a, v, false, out);
            }
            MrubyOp::Strng => {
                let s: String = pool_string(rec, b);
                place(regs, frame, i, a, RegVal::Str(s), false, out);
            }
            MrubyOp::LoadSym | MrubyOp::Symbol => {
                let s: String = symbol(rec, b);
                place(regs, frame, i, a, RegVal::Sym(s), false, out);
            }
            MrubyOp::StrCat => {
                let lhs: String = regs.get(a).render();
                let rhs: String = regs.get(a.saturating_add(1)).render();
                place(
                    regs,
                    frame,
                    i,
                    a,
                    RegVal::Expr(format!("({lhs} + {rhs})")),
                    false,
                    out,
                );
            }
            MrubyOp::GetIv | MrubyOp::GetCv => {
                let v: RegVal = RegVal::Expr(symbol(rec, b));
                place(regs, frame, i, a, v, false, out);
            }
            MrubyOp::GetGv | MrubyOp::GetSv => {
                let v: RegVal = RegVal::Expr(symbol(rec, b));
                place(regs, frame, i, a, v, false, out);
            }
            MrubyOp::GetConst | MrubyOp::GetMCnst => {
                let v: RegVal = RegVal::Expr(symbol(rec, b));
                place(regs, frame, i, a, v, false, out);
            }
            MrubyOp::GetUpvar => {
                let v: RegVal = RegVal::Expr(self.resolve_upvar(b, c));
                place(regs, frame, i, a, v, false, out);
            }
            MrubyOp::OClass => place(
                regs,
                frame,
                i,
                a,
                RegVal::Expr("::Object".to_owned()),
                false,
                out,
            ),
            MrubyOp::TClass => place(regs, frame, i, a, RegVal::SelfRef, false, out),
            MrubyOp::SetIv | MrubyOp::SetCv => {
                push_line(
                    out,
                    format_args!("{pad}{} = {}", symbol(rec, b), regs.get(a).render()),
                );
            }
            MrubyOp::SetGv | MrubyOp::SetSv => {
                push_line(
                    out,
                    format_args!("{pad}{} = {}", symbol(rec, b), regs.get(a).render()),
                );
            }
            MrubyOp::SetConst | MrubyOp::SetMCnst => {
                push_line(
                    out,
                    format_args!("{pad}{} = {}", symbol(rec, b), regs.get(a).render()),
                );
            }
            MrubyOp::SetUpvar => {
                let target: String = self.resolve_upvar(b, c);
                push_line(
                    out,
                    format_args!("{pad}{target} = {}", regs.get(a).render()),
                );
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
                place(
                    regs,
                    frame,
                    i,
                    a,
                    RegVal::Expr(format!("({lhs} {opc} {rhs})")),
                    false,
                    out,
                );
            }
            MrubyOp::AddI | MrubyOp::SubI => {
                let opc: &str = if matches!(instr.op, MrubyOp::AddI) {
                    "+"
                } else {
                    "-"
                };
                let lhs: String = regs.get(a).render();
                place(
                    regs,
                    frame,
                    i,
                    a,
                    RegVal::Expr(format!("({lhs} {opc} {b})")),
                    false,
                    out,
                );
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
                place(
                    regs,
                    frame,
                    i,
                    a,
                    RegVal::Expr(format!("({lhs} {opc} {rhs})")),
                    false,
                    out,
                );
            }
            MrubyOp::Send | MrubyOp::SSend => {
                let is_self: bool = matches!(instr.op, MrubyOp::SSend);
                let argc: u32 = c & 0x0f;
                let kwargc: u32 = (c >> 4) & 0x0f;
                let call: String = render_call(rec, regs, a, b, argc, kwargc, is_self, true);
                place(regs, frame, i, a, RegVal::Expr(call), true, out);
            }
            MrubyOp::SendB | MrubyOp::SSendB => {
                let is_self: bool = matches!(instr.op, MrubyOp::SSendB);
                let argc: u32 = c & 0x0f;
                let kwargc: u32 = (c >> 4) & 0x0f;
                let head: String = render_call(rec, regs, a, b, argc, kwargc, is_self, false);
                let block_reg: u32 = a
                    .saturating_add(argc)
                    .saturating_add(kwargc.saturating_mul(2))
                    .saturating_add(1);
                let child: u32 = match regs.get(block_reg) {
                    RegVal::BlockProc(idx) | RegVal::MethodProc(idx) => idx,
                    _ => u32::MAX,
                };
                let block: String = self.render_block(child, frame.depth);
                place(
                    regs,
                    frame,
                    i,
                    a,
                    RegVal::Expr(format!("{head}{block}")),
                    true,
                    out,
                );
            }
            MrubyOp::Array => {
                let elems: String = render_consecutive(regs, a, b);
                place(
                    regs,
                    frame,
                    i,
                    a,
                    RegVal::Expr(format!("[{elems}]")),
                    false,
                    out,
                );
            }
            MrubyOp::Array2 => {
                let elems: String = render_consecutive(regs, b, c);
                place(
                    regs,
                    frame,
                    i,
                    a,
                    RegVal::Expr(format!("[{elems}]")),
                    false,
                    out,
                );
            }
            MrubyOp::AryCat => {
                let lhs: String = regs.get(a).render();
                let rhs: String = regs.get(a.saturating_add(1)).render();
                place(
                    regs,
                    frame,
                    i,
                    a,
                    RegVal::Expr(format!("({lhs} + {rhs})")),
                    false,
                    out,
                );
            }
            MrubyOp::AryPush => {
                let base: String = regs.get(a).render();
                let pushed: String = render_consecutive(regs, a.saturating_add(1), b);
                place(
                    regs,
                    frame,
                    i,
                    a,
                    RegVal::Expr(format!("({base} + [{pushed}])")),
                    false,
                    out,
                );
            }
            MrubyOp::ArySplat => {
                let v: String = regs.get(a).render();
                place(regs, frame, i, a, RegVal::Expr(format!("*{v}")), false, out);
            }
            MrubyOp::Aref => {
                let recv: String = regs.get(b).render();
                place(
                    regs,
                    frame,
                    i,
                    a,
                    RegVal::Expr(format!("{recv}[{c}]")),
                    false,
                    out,
                );
            }
            MrubyOp::Aset => {
                let recv: String = regs.get(b).render();
                let val: String = regs.get(a).render();
                push_line(out, format_args!("{pad}{recv}[{c}] = {val}"));
            }
            MrubyOp::Hash => {
                let pairs: String = render_pairs(regs, a, b);
                place(
                    regs,
                    frame,
                    i,
                    a,
                    RegVal::Expr(format!("{{{pairs}}}")),
                    false,
                    out,
                );
            }
            MrubyOp::HashAdd => {
                let base: String = regs.get(a).render();
                let pairs: String = render_pairs(regs, a.saturating_add(1), b);
                let merged: String = match base.as_str() {
                    "{}" => format!("{{{pairs}}}"),
                    other => format!("{other}.merge({{{pairs}}})"),
                };
                place(regs, frame, i, a, RegVal::Expr(merged), false, out);
            }
            MrubyOp::HashCat => {
                let lhs: String = regs.get(a).render();
                let rhs: String = regs.get(a.saturating_add(1)).render();
                place(
                    regs,
                    frame,
                    i,
                    a,
                    RegVal::Expr(format!("{lhs}.merge({rhs})")),
                    false,
                    out,
                );
            }
            MrubyOp::GetIdx => {
                let recv: String = regs.get(a).render();
                let idx: String = regs.get(a.saturating_add(1)).render();
                place(
                    regs,
                    frame,
                    i,
                    a,
                    RegVal::Expr(format!("{recv}[{idx}]")),
                    false,
                    out,
                );
            }
            MrubyOp::SetIdx => {
                let recv: String = regs.get(a).render();
                let idx: String = regs.get(a.saturating_add(1)).render();
                let val: String = regs.get(a.saturating_add(2)).render();
                push_line(out, format_args!("{pad}{recv}[{idx}] = {val}"));
            }
            MrubyOp::RangeInc => {
                let lo: String = regs.get(a).render();
                let hi: String = regs.get(a.saturating_add(1)).render();
                place(
                    regs,
                    frame,
                    i,
                    a,
                    RegVal::Expr(format!("({lo}..{hi})")),
                    false,
                    out,
                );
            }
            MrubyOp::RangeExc => {
                let lo: String = regs.get(a).render();
                let hi: String = regs.get(a.saturating_add(1)).render();
                place(
                    regs,
                    frame,
                    i,
                    a,
                    RegVal::Expr(format!("({lo}...{hi})")),
                    false,
                    out,
                );
            }
            MrubyOp::Intern => {
                let sym: String = match regs.get(a) {
                    RegVal::Str(text) => format!(":{text}"),
                    other => format!(":{}", other.render()),
                };
                place(regs, frame, i, a, RegVal::Expr(sym), false, out);
            }
            MrubyOp::Super => {
                let argc: u32 = b & 0x0f;
                let kwargc: u32 = (b >> 4) & 0x0f;
                let forwarded: bool = argc == CALL_MAXARGS
                    && matches!(regs.get(a.saturating_add(1)), RegVal::ArgForward);
                let call: String = if b == 0 || forwarded {
                    "super".to_owned()
                } else {
                    let joined: String =
                        join_args_and_kwargs(regs, a.saturating_add(1), argc, kwargc);
                    format!("super({joined})")
                };
                place(regs, frame, i, a, RegVal::Expr(call), true, out);
            }
            MrubyOp::ArgAry => regs.set(a, RegVal::ArgForward),
            MrubyOp::BlkPush => regs.set(a, RegVal::BlockYield),
            MrubyOp::Call => {
                place(
                    regs,
                    frame,
                    i,
                    a,
                    RegVal::Expr("self.call".to_owned()),
                    true,
                    out,
                );
            }
            MrubyOp::Lambda => {
                let child: u32 = nth_child(rec, b);
                regs.set(a, RegVal::BlockProc(child));
            }
            MrubyOp::Block => {
                let child: u32 = nth_child(rec, b);
                regs.set(a, RegVal::BlockProc(child));
            }
            MrubyOp::Break => {
                let v: RegVal = regs.get(a);
                match v {
                    RegVal::Nil | RegVal::Unknown => push_line(out, format_args!("{pad}break")),
                    other => push_line(out, format_args!("{pad}break {}", other.render())),
                }
            }
            MrubyOp::Alias => {
                push_line(
                    out,
                    format_args!("{pad}alias {} {}", symbol(rec, a), symbol(rec, b)),
                );
            }
            MrubyOp::Undef => {
                push_line(out, format_args!("{pad}undef {}", symbol(rec, a)));
            }
            MrubyOp::Err => {
                push_line(out, format_args!("{pad}raise LocalJumpError"));
            }
            MrubyOp::Except => {
                place(regs, frame, i, a, RegVal::Expr("$!".to_owned()), false, out);
            }
            MrubyOp::Rescue => {
                let exc: String = regs.get(a).render();
                let class: String = regs.get(b).render();
                place(
                    regs,
                    frame,
                    i,
                    b,
                    RegVal::Expr(format!("{exc}.is_a?({class})")),
                    false,
                    out,
                );
            }
            MrubyOp::RaiseIf => match regs.get(a) {
                RegVal::Expr(v) if v == "$!" => {
                    push_line(out, format_args!("{pad}raise({v}) if {v}"));
                }
                _ => self.mark(instr, &pad, out),
            },
            MrubyOp::Karg => regs.set(a, RegVal::Local(symbol(rec, b))),
            MrubyOp::Apost => {
                let pre: u32 = b;
                let post: u32 = c;
                let source: String = regs.get(a).render();
                let sliced: String = if pre == 0 {
                    source
                } else {
                    format!("{source}[{pre}..]")
                };
                let rest_name: String = local_name(a, frame.nargs);
                let mut targets: Vec<String> = vec![format!("*{rest_name}")];
                for k in 1..=post {
                    targets.push(local_name(a.saturating_add(k), frame.nargs));
                }
                push_line(out, format_args!("{pad}{} = {sliced}", targets.join(", ")));
                regs.set(a, RegVal::Local(rest_name));
                for k in 1..=post {
                    let reg: u32 = a.saturating_add(k);
                    regs.set(reg, RegVal::Local(local_name(reg, frame.nargs)));
                }
            }
            MrubyOp::Nop
            | MrubyOp::Enter
            | MrubyOp::KeyEnd
            | MrubyOp::Debug
            | MrubyOp::Stop
            | MrubyOp::Ext1
            | MrubyOp::Ext2
            | MrubyOp::Ext3 => {}
            MrubyOp::Method => {
                let child: u32 = nth_child(rec, b);
                regs.set(a, RegVal::MethodProc(child));
            }
            MrubyOp::Def => {
                let name: String = symbol(rec, b);
                let child: u32 = match regs.get(a.saturating_add(1)) {
                    RegVal::MethodProc(idx) => idx,
                    _ => u32::MAX,
                };
                self.emit_def(&name, child, frame.indent, frame.depth, out)?;
                regs.set(a, RegVal::Sym(name));
            }
            MrubyOp::Class => {
                let name: String = symbol(rec, b);
                let label: String = match regs.get(a.saturating_add(1)) {
                    RegVal::Nil => name,
                    superclass => format!("{name} < {}", superclass.render()),
                };
                regs.set(a, RegVal::Expr(format!("<class {label}>")));
                pending.set_pending(a, "class", label);
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
                        self.emit_block(keyword, &name, child, frame.indent, frame.depth, out)?;
                    }
                    None => self.record(child, frame.indent, frame.depth.saturating_add(1), out)?,
                }
            }
            MrubyOp::Return | MrubyOp::ReturnBlk => {
                emit_return_value(&regs.get(a), &pad, out);
            }
            _ => {
                self.mark(instr, &pad, out);
            }
        }
        Ok(())
    }

    fn mark(&mut self, instr: &MrubyInstruction, pad: &str, out: &mut String) {
        push_line(
            out,
            format_args!("{pad}# unmodeled {} {:?}", instr.mnemonic, instr.operands),
        );
        self.stats.unmodeled = self.stats.unmodeled.saturating_add(1);
        self.stats.unmodeled_ops.insert(instr.mnemonic.clone());
    }

    fn render_block(&mut self, child: u32, depth: u32) -> String {
        if child == u32::MAX {
            return " { }".to_owned();
        }
        let nargs: u32 = self.tree.records.get(child as usize).map_or(0, arg_count);
        let params: String = if nargs == 0 {
            String::new()
        } else {
            let names: Vec<String> = (0..nargs).map(|i| format!("arg{i}")).collect();
            format!("|{}| ", names.join(", "))
        };
        let mut body: String = String::new();
        let _: Result<()> = self.record(child, 0, depth.saturating_add(1), &mut body);
        let joined: String = body
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect::<Vec<&str>>()
            .join("; ");
        if joined.is_empty() {
            format!(" {{ {params}}}")
        } else {
            format!(" {{ {params}{joined} }}")
        }
    }

    fn emit_def(
        &mut self,
        name: &str,
        child: u32,
        indent: u32,
        depth: u32,
        out: &mut String,
    ) -> Result<()> {
        let pad: String = pad_for(indent);
        let params: String = self.def_params(child);
        push_line(out, format_args!("{pad}def {name}{params}"));
        self.record(
            child,
            indent.saturating_add(1),
            depth.saturating_add(1),
            out,
        )?;
        push_line(out, format_args!("{pad}end"));
        Ok(())
    }

    fn emit_block(
        &mut self,
        keyword: &str,
        name: &str,
        child: u32,
        indent: u32,
        depth: u32,
        out: &mut String,
    ) -> Result<()> {
        let pad: String = pad_for(indent);
        push_line(out, format_args!("{pad}{keyword} {name}"));
        self.record(
            child,
            indent.saturating_add(1),
            depth.saturating_add(1),
            out,
        )?;
        push_line(out, format_args!("{pad}end"));
        Ok(())
    }

    fn def_params(&self, child: u32) -> String {
        let Some(rec): Option<&IrepRecord> = self.tree.records.get(child as usize) else {
            return String::new();
        };
        let nargs: u32 = arg_count(rec);
        let mut names: Vec<String> = (0..nargs).map(|i| format!("arg{i}")).collect();
        if let Ok(ins) = disassemble_iseq(&rec.iseq) {
            for kw in required_kwarg_names(&ins, rec) {
                names.push(format!("{kw}:"));
            }
        }
        if names.is_empty() {
            String::new()
        } else {
            format!("({})", names.join(", "))
        }
    }
}

fn required_kwarg_names(ins: &[MrubyInstruction], rec: &IrepRecord) -> Vec<String> {
    let Some(enter_idx): Option<usize> = ins.iter().position(|i| i.op == MrubyOp::Enter) else {
        return Vec::new();
    };
    let mut names: Vec<String> = Vec::new();
    for instr in ins.iter().skip(enter_idx.saturating_add(1)) {
        match instr.op {
            MrubyOp::Karg => {
                let sym_idx: u32 = instr.operands.get(1).copied().unwrap_or(0);
                names.push(symbol(rec, sym_idx));
            }
            MrubyOp::KeyP => return Vec::new(),
            _ => break,
        }
    }
    names
}

fn place(
    regs: &mut Regs,
    frame: &Frame<'_>,
    i: usize,
    d: u32,
    val: RegVal,
    is_call: bool,
    out: &mut String,
) {
    if d >= 1 && d < frame.nlocals {
        let name: String = local_name(d, frame.nargs);
        let pad: String = pad_for(frame.indent);
        push_line(out, format_args!("{pad}{name} = {}", val.render()));
        regs.set(d, RegVal::Local(name));
        return;
    }
    let is_consumed: bool = consumed(frame.dests, frame.srcs, i, d);
    if is_call && !is_consumed {
        let pad: String = pad_for(frame.indent);
        push_line(out, format_args!("{pad}{}", val.render()));
    }
    regs.set(d, val);
}

fn emit_return_value(v: &RegVal, pad: &str, out: &mut String) {
    match v {
        RegVal::Nil | RegVal::SelfRef | RegVal::MethodProc(_) | RegVal::BlockProc(_) => {}
        other => {
            push_line(out, format_args!("{pad}{}", other.render()));
        }
    }
}

fn consumed(dests: &[Option<u32>], srcs: &[Vec<u32>], i: usize, d: u32) -> bool {
    let mut k: usize = i.saturating_add(1);
    while k < dests.len() {
        if srcs[k].contains(&d) {
            return true;
        }
        if dests[k] == Some(d) {
            return false;
        }
        k = k.saturating_add(1);
    }
    false
}

fn local_name(reg: u32, nargs: u32) -> String {
    if reg >= 1 && reg <= nargs {
        format!("arg{}", reg - 1)
    } else {
        format!("t{reg}")
    }
}

fn pad_for(indent: u32) -> String {
    INDENT.repeat(indent as usize)
}

#[allow(clippy::match_same_arms, clippy::many_single_char_names)]
fn effect(instr: &MrubyInstruction) -> (Option<u32>, Vec<u32>) {
    let a: u32 = instr.operands.first().copied().unwrap_or(0);
    let b: u32 = instr.operands.get(1).copied().unwrap_or(0);
    let c: u32 = instr.operands.get(2).copied().unwrap_or(0);
    let n: u32 = c & 0x0f;
    match instr.op {
        MrubyOp::Move => (Some(a), vec![b]),
        MrubyOp::LoadL
        | MrubyOp::LoadI
        | MrubyOp::LoadINeg
        | MrubyOp::LoadI16
        | MrubyOp::LoadI32
        | MrubyOp::LoadISmall(_)
        | MrubyOp::LoadSym
        | MrubyOp::Symbol
        | MrubyOp::LoadNil
        | MrubyOp::LoadSelf
        | MrubyOp::LoadT
        | MrubyOp::LoadF
        | MrubyOp::Strng
        | MrubyOp::GetGv
        | MrubyOp::GetSv
        | MrubyOp::GetIv
        | MrubyOp::GetCv
        | MrubyOp::GetConst
        | MrubyOp::GetUpvar
        | MrubyOp::OClass
        | MrubyOp::TClass
        | MrubyOp::ArgAry
        | MrubyOp::BlkPush
        | MrubyOp::Lambda
        | MrubyOp::Block
        | MrubyOp::Method
        | MrubyOp::KeyP
        | MrubyOp::Karg
        | MrubyOp::Except => (Some(a), vec![]),
        MrubyOp::GetMCnst => (Some(a), vec![a]),
        MrubyOp::GetIdx
        | MrubyOp::Add
        | MrubyOp::Sub
        | MrubyOp::Mul
        | MrubyOp::Div
        | MrubyOp::Eq
        | MrubyOp::Lt
        | MrubyOp::Le
        | MrubyOp::Gt
        | MrubyOp::Ge
        | MrubyOp::StrCat
        | MrubyOp::AryCat
        | MrubyOp::HashCat
        | MrubyOp::RangeInc
        | MrubyOp::RangeExc => (Some(a), vec![a, a.saturating_add(1)]),
        MrubyOp::AddI | MrubyOp::SubI | MrubyOp::ArySplat | MrubyOp::Intern | MrubyOp::Apost => {
            (Some(a), vec![a])
        }
        MrubyOp::AryPush => (Some(a), range_regs(a, b.saturating_add(1))),
        MrubyOp::Array => (Some(a), range_regs(a, b)),
        MrubyOp::Array2 => (Some(a), range_regs(b, c)),
        MrubyOp::Aref => (Some(a), vec![b]),
        MrubyOp::Hash => (Some(a), range_regs(a, b.saturating_mul(2))),
        MrubyOp::HashAdd => (
            Some(a),
            range_regs(a, b.saturating_mul(2).saturating_add(1)),
        ),
        MrubyOp::Send | MrubyOp::SendB => (Some(a), range_regs(a, n.saturating_add(2))),
        MrubyOp::SSend | MrubyOp::SSendB => (
            Some(a),
            range_regs(a.saturating_add(1), n.saturating_add(1)),
        ),
        MrubyOp::Super => (Some(a), range_regs(a.saturating_add(1), b)),
        MrubyOp::Call => (Some(a), vec![a]),
        MrubyOp::Rescue => (Some(b), vec![a, b]),
        MrubyOp::Class => (Some(a), vec![a, a.saturating_add(1)]),
        MrubyOp::Module | MrubyOp::SClass | MrubyOp::Exec => (Some(a), vec![a]),
        MrubyOp::Def => (Some(a), vec![a, a.saturating_add(1)]),
        MrubyOp::SetGv
        | MrubyOp::SetSv
        | MrubyOp::SetIv
        | MrubyOp::SetCv
        | MrubyOp::SetConst
        | MrubyOp::SetUpvar => (None, vec![a]),
        MrubyOp::SetMCnst => (None, vec![a, a.saturating_add(1)]),
        MrubyOp::SetIdx => (None, vec![a, a.saturating_add(1), a.saturating_add(2)]),
        MrubyOp::Aset => (None, vec![a, b]),
        MrubyOp::Return
        | MrubyOp::ReturnBlk
        | MrubyOp::Break
        | MrubyOp::RaiseIf
        | MrubyOp::JmpIf
        | MrubyOp::JmpNot
        | MrubyOp::JmpNil => (None, vec![a]),
        MrubyOp::Jmp
        | MrubyOp::JmpUw
        | MrubyOp::Alias
        | MrubyOp::Undef
        | MrubyOp::Err
        | MrubyOp::Debug
        | MrubyOp::KeyEnd
        | MrubyOp::Nop
        | MrubyOp::Stop
        | MrubyOp::Enter
        | MrubyOp::Ext1
        | MrubyOp::Ext2
        | MrubyOp::Ext3 => (None, vec![]),
    }
}

fn range_regs(start: u32, count: u32) -> Vec<u32> {
    let n: u32 = count.min(64);
    (0..n).map(|i| start.saturating_add(i)).collect()
}

fn render_call(
    rec: &IrepRecord,
    regs: &Regs,
    recv_reg: u32,
    method_sym: u32,
    argc: u32,
    kwargc: u32,
    is_self_send: bool,
    allow_yield: bool,
) -> String {
    let method: String = symbol(rec, method_sym);
    let joined: String = join_args_and_kwargs(regs, recv_reg.saturating_add(1), argc, kwargc);
    if allow_yield
        && !is_self_send
        && method == "call"
        && matches!(regs.get(recv_reg), RegVal::BlockYield)
    {
        return if joined.is_empty() {
            "yield".to_owned()
        } else {
            format!("yield({joined})")
        };
    }
    let prefix: String = if is_self_send {
        String::new()
    } else {
        match regs.get(recv_reg) {
            RegVal::SelfRef => String::new(),
            other => format!("{}.", other.render()),
        }
    };
    if joined.is_empty() {
        format!("{prefix}{method}")
    } else {
        format!("{prefix}{method}({joined})")
    }
}

fn join_args_and_kwargs(regs: &Regs, start: u32, argc: u32, kwargc: u32) -> String {
    let args: String = render_consecutive(regs, start, argc);
    let kwargs: String = render_pairs(regs, start.saturating_add(argc), kwargc);
    match (args.is_empty(), kwargs.is_empty()) {
        (true, true) => String::new(),
        (false, true) => args,
        (true, false) => kwargs,
        (false, false) => format!("{args}, {kwargs}"),
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

fn render_pairs(regs: &Regs, start: u32, pairs: u32) -> String {
    let n: u32 = pairs.min(64);
    let mut out: Vec<String> = Vec::with_capacity(n as usize);
    for i in 0..n {
        let key: String = regs.get(start.saturating_add(i * 2)).render();
        let val: String = regs.get(start.saturating_add(i * 2 + 1)).render();
        out.push(format!("{key} => {val}"));
    }
    out.join(", ")
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

fn arg_count(rec: &IrepRecord) -> u32 {
    let Ok(ins): Result<Vec<MrubyInstruction>> = disassemble_iseq(&rec.iseq) else {
        return 0;
    };
    let Some(enter): Option<&MrubyInstruction> = ins.iter().find(|i| i.op == MrubyOp::Enter) else {
        return 0;
    };
    let arg_spec: u32 = enter.operands.first().copied().unwrap_or(0);
    let required: u32 = (arg_spec >> 18) & 0x1f;
    let optional: u32 = (arg_spec >> 13) & 0x1f;
    required.saturating_add(optional)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::mruby::irep::{IrepRecord, PoolEntry};
    use crate::mruby::ops::{OPS, OperandFormat};

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

    fn asm(program: &[(&str, &[u32])]) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::new();
        for (mnemonic, operands) in program {
            let idx: usize = OPS
                .iter()
                .position(|o| o.mnemonic == *mnemonic)
                .expect("mnemonic present in OPS table");
            bytes.push(u8::try_from(idx).expect("opcode index fits u8"));
            let format: OperandFormat = OPS[idx].format;
            let widths: &[usize] = match format {
                OperandFormat::Z => &[],
                OperandFormat::B => &[1],
                OperandFormat::Bb => &[1, 1],
                OperandFormat::Bbb => &[1, 1, 1],
                OperandFormat::Bs => &[1, 2],
                OperandFormat::Bss => &[1, 2, 2],
                OperandFormat::S => &[2],
                OperandFormat::W => &[3],
            };
            assert_eq!(
                widths.len(),
                operands.len(),
                "operand count mismatch for {mnemonic}"
            );
            for (&w, &v) in widths.iter().zip(operands.iter()) {
                match w {
                    1 => bytes.push(u8::try_from(v).expect("operand fits u8")),
                    2 => bytes.extend_from_slice(
                        &u16::try_from(v).expect("operand fits u16").to_be_bytes(),
                    ),
                    _ => {
                        let b: [u8; 4] = v.to_be_bytes();
                        bytes.extend_from_slice(&b[1..]);
                    }
                }
            }
        }
        bytes
    }

    fn lift_single(iseq: Vec<u8>, pool: Vec<PoolEntry>, symbols: Vec<String>) -> String {
        let tree: IrepTree = IrepTree {
            total_insn_bytes: u32::try_from(iseq.len()).unwrap_or(0),
            total_symbols: u32::try_from(symbols.len()).unwrap_or(0),
            total_pool_entries: u32::try_from(pool.len()).unwrap_or(0),
            records: vec![rec(iseq, pool, symbols, vec![])],
        };
        lift_tree(&tree).expect("lift").source
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
        let src: String = lift_tree(&tree).expect("lift").source;
        assert!(src.contains("puts(\"hello world\")"), "got: {src}");
    }

    #[test]
    fn lifts_method_definition_with_recursion_from_synthetic_irep() {
        let parent_iseq: Vec<u8> = vec![0x58, 0x01, 0x00, 0x5f, 0x00, 0x00, 0x38, 0x00];
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
        let src: String = lift_tree(&tree).expect("lift").source;
        assert!(src.contains("def greet"), "got: {src}");
        assert!(src.contains("puts(\"hi\")"), "got: {src}");
        assert!(src.contains("end"), "got: {src}");
    }

    #[test]
    fn lift_output_prealloc_is_capped() {
        assert_eq!(lift_output_prealloc(0), 256);
        assert_eq!(lift_output_prealloc(u32::MAX), MAX_LIFT_OUTPUT_PREALLOC);
    }

    #[test]
    fn lifts_inclusive_range_from_range_inc() {
        let iseq: Vec<u8> = asm(&[
            ("LOADI_1", &[1]),
            ("LOADI_5", &[2]),
            ("RANGE_INC", &[1]),
            ("RETURN", &[1]),
        ]);
        let src: String = lift_single(iseq, vec![], vec![]);
        assert!(src.contains("(1..5)"), "got: {src}");
    }

    #[test]
    fn lifts_exclusive_range_from_range_exc() {
        let iseq: Vec<u8> = asm(&[
            ("LOADI_0", &[1]),
            ("LOADI_7", &[2]),
            ("RANGE_EXC", &[1]),
            ("RETURN", &[1]),
        ]);
        let src: String = lift_single(iseq, vec![], vec![]);
        assert!(src.contains("(0...7)"), "got: {src}");
    }

    #[test]
    fn lifts_index_get_from_getidx() {
        let iseq: Vec<u8> = asm(&[
            ("LOADSELF", &[1]),
            ("LOADI_2", &[2]),
            ("GETIDX", &[1]),
            ("RETURN", &[1]),
        ]);
        let src: String = lift_single(iseq, vec![], vec![]);
        assert!(src.contains("self[2]"), "got: {src}");
    }

    #[test]
    fn lifts_index_set_statement_from_setidx() {
        let iseq: Vec<u8> = asm(&[
            ("LOADSELF", &[1]),
            ("LOADI_0", &[2]),
            ("LOADI_3", &[3]),
            ("SETIDX", &[1]),
            ("RETURN", &[0]),
        ]);
        let src: String = lift_single(iseq, vec![], vec![]);
        assert!(src.contains("self[0] = 3"), "got: {src}");
    }

    #[test]
    fn lifts_array_literal_from_array2() {
        let iseq: Vec<u8> = asm(&[
            ("LOADI_1", &[2]),
            ("LOADI_2", &[3]),
            ("LOADI_3", &[4]),
            ("ARRAY2", &[1, 2, 3]),
            ("RETURN", &[1]),
        ]);
        let src: String = lift_single(iseq, vec![], vec![]);
        assert!(src.contains("[1, 2, 3]"), "got: {src}");
    }

    #[test]
    fn lifts_symbol_from_intern_of_string() {
        let iseq: Vec<u8> = asm(&[("STRING", &[1, 0]), ("INTERN", &[1]), ("RETURN", &[1])]);
        let pool: Vec<PoolEntry> = vec![PoolEntry {
            kind: PoolKind::String,
            value: Some("flavor".to_owned()),
        }];
        let src: String = lift_single(iseq, pool, vec![]);
        assert!(src.contains(":flavor"), "got: {src}");
    }

    #[test]
    fn lifts_break_statement_with_value() {
        let iseq: Vec<u8> = asm(&[("LOADI_4", &[1]), ("BREAK", &[1])]);
        let src: String = lift_single(iseq, vec![], vec![]);
        assert!(src.contains("break 4"), "got: {src}");
    }

    #[test]
    fn lifts_super_call_with_args() {
        let iseq: Vec<u8> = asm(&[
            ("LOADSELF", &[1]),
            ("LOADI_1", &[2]),
            ("SUPER", &[1, 1]),
            ("RETURN", &[1]),
        ]);
        let src: String = lift_single(iseq, vec![], vec![]);
        assert!(src.contains("super(1)"), "got: {src}");
    }

    #[test]
    fn lifts_alias_statement_from_symbols() {
        let iseq: Vec<u8> = asm(&[("ALIAS", &[0, 1]), ("RETURN", &[0])]);
        let symbols: Vec<String> = vec!["renamed".to_owned(), "original".to_owned()];
        let src: String = lift_single(iseq, vec![], symbols);
        assert!(src.contains("alias renamed original"), "got: {src}");
    }

    #[test]
    fn lifts_undef_statement_from_symbol() {
        let iseq: Vec<u8> = asm(&[("UNDEF", &[0]), ("RETURN", &[0])]);
        let symbols: Vec<String> = vec!["gone".to_owned()];
        let src: String = lift_single(iseq, vec![], symbols);
        assert!(src.contains("undef gone"), "got: {src}");
    }

    #[test]
    fn lifts_reraise_from_except_and_raiseif() {
        let iseq: Vec<u8> = asm(&[("EXCEPT", &[1]), ("RAISEIF", &[1]), ("RETURN", &[0])]);
        let src: String = lift_single(iseq, vec![], vec![]);
        assert!(src.contains("raise($!) if $!"), "got: {src}");
    }

    #[test]
    fn raiseif_sound_rejects_when_register_was_overwritten() {
        let iseq: Vec<u8> = asm(&[
            ("EXCEPT", &[1]),
            ("LOADI__1", &[1]),
            ("RAISEIF", &[1]),
            ("RETURN", &[0]),
        ]);
        let tree: IrepTree = IrepTree {
            total_insn_bytes: u32::try_from(iseq.len()).unwrap_or(0),
            total_symbols: 0,
            total_pool_entries: 0,
            records: vec![rec(iseq, vec![], vec![], vec![])],
        };
        let out: LiftOutput = lift_tree(&tree).expect("lift");
        assert!(
            out.source.contains("# unmodeled RAISEIF"),
            "a raiseif over a clobbered register must not fabricate a raise: got {}",
            out.source
        );
        assert!(!out.source.contains("raise(-1)"), "got: {}", out.source);
    }

    #[test]
    fn lifts_rescue_as_class_membership_check() {
        let iseq: Vec<u8> = asm(&[
            ("LOADSELF", &[1]),
            ("GETCONST", &[2, 0]),
            ("RESCUE", &[1, 2]),
            ("RETURN", &[2]),
        ]);
        let symbols: Vec<String> = vec!["StandardError".to_owned()];
        let src: String = lift_single(iseq, vec![], symbols);
        assert!(src.contains("self.is_a?(StandardError)"), "got: {src}");
    }

    #[test]
    fn lifts_keyword_arg_value_via_karg() {
        let iseq: Vec<u8> = asm(&[("KARG", &[1, 0]), ("RETURN", &[1])]);
        let symbols: Vec<String> = vec!["amount".to_owned()];
        let src: String = lift_single(iseq, vec![], symbols);
        assert!(src.contains("amount"), "got: {src}");
    }

    #[test]
    fn lifts_bare_super_from_argary_forwarding() {
        let iseq: Vec<u8> = asm(&[("ARGARY", &[2, 0]), ("SUPER", &[1, 15]), ("RETURN", &[1])]);
        let src: String = lift_single(iseq, vec![], vec![]);
        assert!(src.contains("super"), "got: {src}");
        assert!(!src.contains("super("), "got: {src}");
    }

    #[test]
    fn lifts_yield_from_blkpush_and_send_call() {
        let iseq: Vec<u8> = asm(&[
            ("LOADI_1", &[2]),
            ("BLKPUSH", &[1, 0]),
            ("SEND", &[1, 0, 1]),
            ("RETURN", &[1]),
        ]);
        let symbols: Vec<String> = vec!["call".to_owned()];
        let src: String = lift_single(iseq, vec![], symbols);
        assert!(src.contains("yield(1)"), "got: {src}");
    }

    #[test]
    fn lifts_post_splat_destructure_from_apost() {
        let iseq: Vec<u8> = asm(&[("LOADSELF", &[1]), ("APOST", &[1, 1, 1]), ("RETURN", &[2])]);
        let src: String = lift_single(iseq, vec![], vec![]);
        assert!(src.contains("*t1, t2 = self[1..]"), "got: {src}");
    }

    #[test]
    fn def_params_recovers_required_keyword_argument() {
        let child_iseq: Vec<u8> = asm(&[("ENTER", &[0]), ("KARG", &[1, 0]), ("RETURN", &[1])]);
        let parent_iseq: Vec<u8> = asm(&[("METHOD", &[1, 0]), ("DEF", &[0, 0]), ("RETURN", &[0])]);
        let parent: IrepRecord = rec(parent_iseq, vec![], vec!["greet".to_owned()], vec![1]);
        let child: IrepRecord = rec(child_iseq, vec![], vec!["amount".to_owned()], vec![]);
        let tree: IrepTree = IrepTree {
            records: vec![parent, child],
            total_insn_bytes: 0,
            total_symbols: 2,
            total_pool_entries: 0,
        };
        let src: String = lift_tree(&tree).expect("lift").source;
        assert!(src.contains("def greet(amount:)"), "got: {src}");
    }

    #[test]
    fn jump_opcodes_are_marked_not_dropped() {
        let iseq: Vec<u8> = asm(&[("LOADI_1", &[1]), ("JMP", &[0]), ("RETURN", &[1])]);
        let tree: IrepTree = IrepTree {
            total_insn_bytes: u32::try_from(iseq.len()).unwrap_or(0),
            total_symbols: 0,
            total_pool_entries: 0,
            records: vec![rec(iseq, vec![], vec![], vec![])],
        };
        let out: LiftOutput = lift_tree(&tree).expect("lift");
        assert!(
            out.source.contains("# unmodeled JMP"),
            "got: {}",
            out.source
        );
        assert_eq!(out.unmodeled_opcodes, 1);
        assert!(out.unmodeled_mnemonics.contains(&"JMP".to_owned()));
        assert!(out.modeled_opcodes >= 2);
    }
}
