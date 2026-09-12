use crate::decompile::luau_structure::{
    MAX_STRUCTURE_WORK, StructureResult, StructuredBlock, structure_blocks,
};
use crate::decompile::{DecompiledChunk, Fidelity};
use crate::error::Result;
use crate::reader::common::{LuaChunk, LuaConstant, LuaProto};

const MAX_LIFT_DEPTH: usize = 200;
const MAX_DIRECT_RENDER_NESTING: usize = 256;
pub(crate) const MAX_RENDERED_STRUCTURE_BYTES: usize = 16 * 1024 * 1024;
const RENDER_LIMIT_MARKER: &str = "error(\"disrobe: rendered structure exceeds output limit\")";

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
const LOP_GETUDATAKS: u8 = 83;
const LOP_SETUDATAKS: u8 = 84;
const LOP_NAMECALLUDATA: u8 = 85;
const LOP_NEWCLASSMEMBER: u8 = 86;
const LOP_CALLFB: u8 = 87;

pub fn decompile(chunk: &LuaChunk) -> Result<DecompiledChunk> {
    let main: &LuaProto = &chunk.main;
    let mut out: String = String::new();
    out.push_str("-- decompiled by disrobe (luau register lifter)\n");
    let mut warnings: Vec<String> = Vec::new();
    let mut fully_structured: bool = true;
    let mut next_scope: usize = 1;
    let body: String = lift_proto(
        main,
        0,
        0,
        &[],
        &mut next_scope,
        &mut warnings,
        &mut fully_structured,
    );
    out.push_str(&body);
    if main.is_vararg != 0 {
        out.push_str("return _main(...)\n");
    } else {
        out.push_str("return _main()\n");
    }
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

#[derive(Debug, Clone)]
pub(crate) enum LStmt {
    Raw(String),
    Cond {
        cond: String,
        target: usize,
    },
    Jump {
        target: usize,
    },
    ForNum {
        var: String,
        init: String,
        limit: String,
        step: String,
        end: usize,
    },
    ForGen {
        iter: String,
        end: usize,
    },
    BlockEnd,
}

#[derive(Debug, Clone)]
pub(crate) struct LiftedStmt {
    pub pc: usize,
    pub stmt: LStmt,
}

#[derive(Debug, Clone)]
struct LuauState {
    regs: Vec<String>,
    set: Vec<bool>,
    declared: Vec<bool>,
    scope_id: usize,
    open_multi: Option<(u32, String)>,
    last_multi: Option<(u32, String)>,
    method_call: Option<u32>,
    upvals: Vec<String>,
    stmts: Vec<LiftedStmt>,
    pc: usize,
}

impl LuauState {
    fn new(stack: u8, scope_id: usize, upvals: &[String]) -> Self {
        let size: usize = usize::from(stack).max(2);
        Self {
            regs: vec![String::new(); size],
            set: vec![false; size],
            declared: vec![false; size],
            scope_id,
            open_multi: None,
            last_multi: None,
            method_call: None,
            upvals: upvals.to_vec(),
            stmts: Vec::new(),
            pc: 0,
        }
    }

    #[inline]
    fn slot_name(&self, i: u32) -> String {
        if self.scope_id == 0 {
            format!("r{i}")
        } else {
            format!("v{}_{i}", self.scope_id)
        }
    }

    #[inline]
    fn reg(&self, i: u32) -> String {
        match self.regs.get(i as usize) {
            Some(s) if !s.is_empty() => s.clone(),
            _ => self.slot_name(i),
        }
    }

    #[inline]
    fn set_reg(&mut self, i: u32, value: String) {
        let idx: usize = i as usize;
        if idx >= self.regs.len() {
            self.regs.resize(idx + 1, String::new());
            self.set.resize(idx + 1, false);
            self.declared.resize(idx + 1, false);
        }
        self.regs[idx] = value;
        self.set[idx] = true;
    }

    #[inline]
    fn declared(&self, i: u32) -> bool {
        self.declared.get(i as usize).copied().unwrap_or(false)
    }

    #[inline]
    fn mark_declared(&mut self, i: u32) {
        let idx: usize = i as usize;
        if idx >= self.declared.len() {
            self.declared.resize(idx + 1, false);
        }
        self.declared[idx] = true;
    }

    #[inline]
    fn uv(&self, i: u32) -> String {
        match self.upvals.get(i as usize) {
            Some(s) if !s.is_empty() => s.clone(),
            _ => format!("uv{i}"),
        }
    }

    fn push(&mut self, raw: String) {
        self.stmts.push(LiftedStmt {
            pc: self.pc,
            stmt: LStmt::Raw(raw),
        });
    }

    fn push_stmt(&mut self, stmt: LStmt) {
        self.stmts.push(LiftedStmt { pc: self.pc, stmt });
    }

    fn declare_local(&mut self, slot: u32, value: &str) {
        let name: String = self.slot_name(slot);
        if self.declared(slot) {
            if name != value {
                self.push(format!("{name} = {value}"));
            }
        } else {
            self.push(format!("local {name} = {value}"));
            self.mark_declared(slot);
        }
        self.set_reg(slot, name);
    }

    fn set_open_multi(&mut self, slot: u32, expr: String) {
        self.open_multi = Some((slot, expr.clone()));
        self.last_multi = Some((slot, expr));
    }

    fn take_open_multi(&mut self, slot: u32) -> Option<String> {
        match self.open_multi.take() {
            Some((s, e)) if s == slot => Some(e),
            _ => None,
        }
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
    Insn {
        op: (raw & 0xFF) as u8,
        a: ((raw >> 8) & 0xFF) as u8,
        b: ((raw >> 16) & 0xFF) as u8,
        c: ((raw >> 24) & 0xFF) as u8,
        d: (raw as i32) >> 16,
        e: (raw as i32) >> 8,
    }
}

#[must_use]
fn quote_lua(s: &str) -> String {
    let bytes: &[u8] = s.as_bytes();
    let mut out: String = String::with_capacity(bytes.len() + 2);
    out.push('"');
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'"' => out.push_str("\\\""),
            b'\\' => out.push_str("\\\\"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            0x20..=0x7E => out.push(b as char),
            other => {
                if bytes
                    .get(i + 1)
                    .is_some_and(|next: &u8| next.is_ascii_digit())
                {
                    out.push_str(&format!("\\{other:03}"));
                } else {
                    out.push_str(&format!("\\{other}"));
                }
            }
        }
    }
    out.push('"');
    out
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
    for precision in 1..=17 {
        let candidate: String = format!("{n:.precision$}");
        if candidate.parse::<f64>() == Ok(n) {
            return candidate;
        }
    }
    format!("{n}")
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
        LuaConstant::Import(path) if !path.is_empty() => path.join("."),
        LuaConstant::Import(_) => "nil".to_owned(),
        LuaConstant::ClosureRef(_) => "function() end".to_owned(),
        LuaConstant::Vector([vx, vy, vz, vw]) => format!("Vector3.new({vx}, {vy}, {vz}, {vw})"),
    }
}

#[must_use]
fn const_at(p: &LuaProto, idx: u32) -> String {
    p.constants
        .get(idx as usize)
        .map_or_else(|| "nil".to_owned(), const_str)
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
    if is_lua_keyword(s) {
        return false;
    }
    let mut chars: core::str::Chars<'_> = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c: char| c.is_ascii_alphanumeric() || c == '_')
}

#[must_use]
fn is_lua_keyword(s: &str) -> bool {
    matches!(
        s,
        "and"
            | "break"
            | "do"
            | "else"
            | "elseif"
            | "end"
            | "false"
            | "for"
            | "function"
            | "if"
            | "in"
            | "local"
            | "nil"
            | "not"
            | "or"
            | "repeat"
            | "return"
            | "then"
            | "true"
            | "until"
            | "while"
            | "continue"
    )
}

#[inline]
#[must_use]
pub fn test_op_length(op: u8) -> usize {
    op_length(op)
}

#[inline]
#[must_use]
const fn op_length(op: u8) -> usize {
    match op {
        LOP_GETGLOBAL | LOP_SETGLOBAL | LOP_GETIMPORT | LOP_GETTABLEKS | LOP_SETTABLEKS
        | LOP_NAMECALL | LOP_JUMPIFEQ | LOP_JUMPIFLE | LOP_JUMPIFLT | LOP_JUMPIFNOTEQ
        | LOP_JUMPIFNOTLE | LOP_JUMPIFNOTLT | LOP_NEWTABLE | LOP_SETLIST | LOP_FORGLOOP
        | LOP_LOADKX | LOP_FASTCALL2 | LOP_FASTCALL2K | LOP_FASTCALL3 | LOP_JUMPXEQKNIL
        | LOP_JUMPXEQKB | LOP_JUMPXEQKN | LOP_JUMPXEQKS | LOP_GETUDATAKS | LOP_SETUDATAKS
        | LOP_NAMECALLUDATA | LOP_NEWCLASSMEMBER | LOP_CALLFB => 2,
        _ => 1,
    }
}

fn lift_proto(
    proto: &LuaProto,
    depth: usize,
    scope_id: usize,
    upvals: &[String],
    next_scope: &mut usize,
    warnings: &mut Vec<String>,
    fully_structured: &mut bool,
) -> String {
    let header: String = proto_header(proto, depth, scope_id);
    if depth > MAX_LIFT_DEPTH {
        warnings.push("luau proto nesting exceeds lift depth limit".to_owned());
        *fully_structured = false;
        return format!("{header}\n  -- (proto nesting limit reached)\nend\n");
    }
    let mut state: LuauState = LuauState::new(proto.max_stack_size, scope_id, upvals);
    for i in 0..u32::from(proto.num_params) {
        let name: String = state.slot_name(i);
        state.set_reg(i, name);
        state.mark_declared(i);
    }
    let predeclare: Vec<u32> = compute_predeclare(proto);
    let mut pre: Vec<LiftedStmt> = Vec::new();
    for slot in &predeclare {
        let name: String = state.slot_name(*slot);
        pre.push(LiftedStmt {
            pc: 0,
            stmt: LStmt::Raw(format!("local {name}")),
        });
        state.set_reg(*slot, name);
        state.mark_declared(*slot);
    }

    lower_instructions(
        proto,
        &mut state,
        depth,
        next_scope,
        warnings,
        fully_structured,
    );

    let mut all: Vec<LiftedStmt> = pre;
    all.extend(state.stmts);
    let structured: StructureResult = structure_blocks(&all, proto.code.len());
    if structured.unresolved_jumps > 0 {
        warnings.push(format!(
            "{} unresolved luau control-flow jump(s) retained as markers",
            structured.unresolved_jumps
        ));
        *fully_structured = false;
    }
    if structured.refused_regions > 0 {
        warnings.push(format!(
            "{} region(s) exceeded the {MAX_STRUCTURE_WORK}-operation structuring work budget, so \
             recovery stopped inside the affected blocks",
            structured.refused_regions,
        ));
        *fully_structured = false;
    }
    let rendered: RenderedBlocks = render_blocks(&structured.blocks, 1);
    if rendered.refused {
        warnings.push(format!(
            "rendered structure exceeded the {MAX_RENDERED_STRUCTURE_BYTES}-byte output limit"
        ));
        *fully_structured = false;
    }

    let mut out: String = String::new();
    out.push_str(&header);
    out.push('\n');
    out.push_str(&rendered.source);
    out.push_str("end\n");
    out
}

fn proto_header(proto: &LuaProto, depth: usize, scope_id: usize) -> String {
    let params: Vec<String> = (0..u32::from(proto.num_params))
        .map(|i: u32| {
            if depth == 0 {
                format!("r{i}")
            } else {
                format!("v{scope_id}_{i}")
            }
        })
        .collect();
    let joined: String = params.join(", ");
    if depth == 0 {
        match (joined.is_empty(), proto.is_vararg != 0) {
            (true, false) => "local function _main()".to_owned(),
            (true, true) => "local function _main(...)".to_owned(),
            (false, false) => format!("local function _main({joined})"),
            (false, true) => format!("local function _main({joined}, ...)"),
        }
    } else {
        match (joined.is_empty(), proto.is_vararg != 0) {
            (true, false) => "function()".to_owned(),
            (true, true) => "function(...)".to_owned(),
            (false, false) => format!("function({joined})"),
            (false, true) => format!("function({joined}, ...)"),
        }
    }
}

enum RenderTask<'a> {
    Blocks {
        blocks: &'a [StructuredBlock],
        indent: usize,
    },
    Block {
        block: &'a StructuredBlock,
        indent: usize,
    },
    Line {
        indent: usize,
        text: &'static str,
    },
    Until {
        indent: usize,
        cond: &'a str,
    },
}

pub(crate) struct RenderedBlocks {
    pub(crate) source: String,
    pub(crate) refused: bool,
}

struct BoundedRenderBuffer {
    source: String,
    limit: usize,
}

impl BoundedRenderBuffer {
    fn new(limit: usize) -> Self {
        Self {
            source: String::with_capacity(limit.min(64 * 1024)),
            limit,
        }
    }

    fn push_str(&mut self, value: &str) -> bool {
        let Some(next_len): Option<usize> = self.source.len().checked_add(value.len()) else {
            return false;
        };
        if next_len > self.limit {
            return false;
        }
        self.source.push_str(value);
        true
    }

    fn push_char(&mut self, value: char) -> bool {
        let mut encoded: [u8; 4] = [0; 4];
        self.push_str(value.encode_utf8(&mut encoded))
    }

    fn push_indent(&mut self, indent: usize) -> bool {
        let Some(width): Option<usize> = indent.checked_mul(2) else {
            return false;
        };
        let Some(next_len): Option<usize> = self.source.len().checked_add(width) else {
            return false;
        };
        if next_len > self.limit {
            return false;
        }
        self.source.extend(std::iter::repeat_n(' ', width));
        true
    }

    fn into_source(self) -> String {
        self.source
    }
}

pub(crate) fn render_blocks(blocks: &[StructuredBlock], indent: usize) -> RenderedBlocks {
    let mut out: BoundedRenderBuffer = BoundedRenderBuffer::new(MAX_RENDERED_STRUCTURE_BYTES);
    let mut pending: Vec<RenderTask<'_>> = vec![RenderTask::Blocks { blocks, indent }];
    let mut refused: bool = false;
    while let Some(task) = pending.pop() {
        let accepted: bool = match task {
            RenderTask::Blocks { blocks, indent } => {
                for block in blocks.iter().rev() {
                    pending.push(RenderTask::Block { block, indent });
                }
                true
            }
            RenderTask::Block { block, indent } => {
                if out.push_indent(indent) {
                    match block {
                        StructuredBlock::Raw(s) => out.push_str(s) && out.push_char('\n'),
                        StructuredBlock::Break => out.push_str("break\n"),
                        StructuredBlock::Goto { pc } => {
                            out.push_str("goto lbl_")
                                && out.push_str(&pc.to_string())
                                && out.push_char('\n')
                        }
                        StructuredBlock::Label { pc } => {
                            out.push_str("::lbl_")
                                && out.push_str(&pc.to_string())
                                && out.push_str("::\n")
                        }
                        StructuredBlock::If {
                            cond,
                            then_body,
                            else_body,
                        } => {
                            if let Some((conditions, guarded_body)) = guard_chain(block) {
                                let mut accepted: bool = out.push_str("if ");
                                for (index, condition) in conditions.iter().enumerate() {
                                    if index > 0 {
                                        accepted = accepted && out.push_str(" and ");
                                    }
                                    accepted = accepted
                                        && out.push_char('(')
                                        && out.push_str(condition)
                                        && out.push_char(')');
                                }
                                accepted = accepted && out.push_str(" then\n");
                                pending.push(RenderTask::Line {
                                    indent,
                                    text: "end\n",
                                });
                                pending.push(RenderTask::Blocks {
                                    blocks: guarded_body,
                                    indent: indent + 1,
                                });
                                accepted
                            } else {
                                let accepted: bool = out.push_str("if ")
                                    && out.push_str(cond)
                                    && out.push_str(" then\n");
                                pending.push(RenderTask::Line {
                                    indent,
                                    text: "end\n",
                                });
                                if !else_body.is_empty() {
                                    pending.push(RenderTask::Blocks {
                                        blocks: else_body,
                                        indent: indent + 1,
                                    });
                                    pending.push(RenderTask::Line {
                                        indent,
                                        text: "else\n",
                                    });
                                }
                                pending.push(RenderTask::Blocks {
                                    blocks: then_body,
                                    indent: indent + 1,
                                });
                                accepted
                            }
                        }
                        StructuredBlock::While { cond, body } => {
                            let accepted: bool = out.push_str("while ")
                                && out.push_str(cond)
                                && out.push_str(" do\n");
                            pending.push(RenderTask::Line {
                                indent,
                                text: "end\n",
                            });
                            pending.push(RenderTask::Blocks {
                                blocks: body,
                                indent: indent + 1,
                            });
                            accepted
                        }
                        StructuredBlock::Repeat { cond, body } => {
                            let accepted: bool = out.push_str("repeat\n");
                            pending.push(RenderTask::Until { indent, cond });
                            pending.push(RenderTask::Blocks {
                                blocks: body,
                                indent: indent + 1,
                            });
                            accepted
                        }
                        StructuredBlock::NumericFor {
                            var,
                            init,
                            limit,
                            step,
                            body,
                        } => {
                            let mut accepted: bool = out.push_str("for ")
                                && out.push_str(var)
                                && out.push_str(" = ")
                                && out.push_str(init)
                                && out.push_str(", ")
                                && out.push_str(limit);
                            if step != "1" {
                                accepted = accepted && out.push_str(", ") && out.push_str(step);
                            }
                            accepted = accepted && out.push_str(" do\n");
                            pending.push(RenderTask::Line {
                                indent,
                                text: "end\n",
                            });
                            pending.push(RenderTask::Blocks {
                                blocks: body,
                                indent: indent + 1,
                            });
                            accepted
                        }
                        StructuredBlock::GenericFor { vars, iter, body } => {
                            let mut accepted: bool = out.push_str("for ");
                            for (index, var) in vars.iter().enumerate() {
                                if index > 0 {
                                    accepted = accepted && out.push_str(", ");
                                }
                                accepted = accepted && out.push_str(var);
                            }
                            accepted = accepted
                                && out.push_str(" in ")
                                && out.push_str(iter)
                                && out.push_str(" do\n");
                            pending.push(RenderTask::Line {
                                indent,
                                text: "end\n",
                            });
                            pending.push(RenderTask::Blocks {
                                blocks: body,
                                indent: indent + 1,
                            });
                            accepted
                        }
                    }
                } else {
                    false
                }
            }
            RenderTask::Line { indent, text } => out.push_indent(indent) && out.push_str(text),
            RenderTask::Until { indent, cond } => {
                out.push_indent(indent)
                    && out.push_str("until ")
                    && out.push_str(cond)
                    && out.push_char('\n')
            }
        };
        if !accepted {
            refused = true;
            break;
        }
    }
    if refused {
        let mut marker: BoundedRenderBuffer = BoundedRenderBuffer::new(256);
        let marker_written: bool = marker.push_indent(indent)
            && marker.push_str(RENDER_LIMIT_MARKER)
            && marker.push_char('\n');
        return RenderedBlocks {
            source: if marker_written {
                marker.into_source()
            } else {
                format!("{RENDER_LIMIT_MARKER}\n")
            },
            refused: true,
        };
    }
    RenderedBlocks {
        source: out.into_source(),
        refused: false,
    }
}

fn guard_chain(block: &StructuredBlock) -> Option<(Vec<&str>, &[StructuredBlock])> {
    let mut conditions: Vec<&str> = Vec::new();
    let mut current: &StructuredBlock = block;
    loop {
        let StructuredBlock::If {
            cond,
            then_body,
            else_body,
        } = current
        else {
            return None;
        };
        if !else_body.is_empty() {
            return None;
        }
        conditions.push(cond);
        let next: Option<&StructuredBlock> = match then_body.as_slice() {
            [nested @ StructuredBlock::If { else_body, .. }] if else_body.is_empty() => {
                Some(nested)
            }
            _ => None,
        };
        if let Some(nested) = next {
            current = nested;
            continue;
        }
        return (conditions.len() > MAX_DIRECT_RENDER_NESTING).then_some((conditions, then_body));
    }
}

#[inline]
fn touches_multi(op: u8) -> bool {
    matches!(
        op,
        LOP_CALL
            | LOP_CALLFB
            | LOP_RETURN
            | LOP_GETVARARGS
            | LOP_SETLIST
            | LOP_FASTCALL
            | LOP_FASTCALL1
            | LOP_FASTCALL2
            | LOP_FASTCALL2K
            | LOP_FASTCALL3
    )
}

fn lower_instructions(
    proto: &LuaProto,
    state: &mut LuauState,
    depth: usize,
    next_scope: &mut usize,
    warnings: &mut Vec<String>,
    fully_structured: &mut bool,
) {
    let code: &[u32] = &proto.code;
    let mut pc: usize = 0;
    let n: usize = code.len();
    while pc < n {
        state.pc = pc;
        let inst: Insn = decode(code[pc]);
        if !touches_multi(inst.op) {
            state.open_multi = None;
        }
        let advance: usize = handle(
            proto,
            &inst,
            pc,
            n,
            state,
            depth,
            next_scope,
            warnings,
            fully_structured,
        );
        pc += advance;
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn handle(
    proto: &LuaProto,
    inst: &Insn,
    pc: usize,
    code_len: usize,
    state: &mut LuauState,
    depth: usize,
    next_scope: &mut usize,
    warnings: &mut Vec<String>,
    fully_structured: &mut bool,
) -> usize {
    match inst.op {
        LOP_BREAK => {
            warnings.push(format!("unresolved luau debugger breakpoint at pc={pc}"));
            *fully_structured = false;
            1
        }
        LOP_NOP | LOP_COVERAGE | LOP_CAPTURE | LOP_PREPVARARGS | LOP_CLOSEUPVALS
        | LOP_NATIVECALL => 1,
        LOP_LOADNIL => {
            state.declare_local(u32::from(inst.a), "nil");
            1
        }
        LOP_LOADB => {
            let v: &str = if inst.b != 0 { "true" } else { "false" };
            state.declare_local(u32::from(inst.a), v);
            let skip: u32 = u32::from(inst.c);
            if skip > 0 { 1 + skip as usize } else { 1 }
        }
        LOP_LOADN => {
            state.declare_local(u32::from(inst.a), &inst.d.to_string());
            1
        }
        LOP_LOADK => {
            let lit: String = const_at(proto, inst.d as u32);
            state.declare_local(u32::from(inst.a), &lit);
            1
        }
        LOP_LOADKX => {
            let aux: u32 = proto.code.get(pc + 1).copied().unwrap_or(0);
            let lit: String = const_at(proto, aux);
            state.declare_local(u32::from(inst.a), &lit);
            2
        }
        LOP_MOVE => {
            let src: String = state.reg(u32::from(inst.b));
            state.declare_local(u32::from(inst.a), &src);
            1
        }
        LOP_GETGLOBAL => {
            let aux: u32 = proto.code.get(pc + 1).copied().unwrap_or(0);
            let name: String = const_string_raw(proto, aux)
                .map(str::to_owned)
                .unwrap_or_else(|| "_G".to_owned());
            state.declare_local(u32::from(inst.a), &name);
            2
        }
        LOP_SETGLOBAL => {
            let aux: u32 = proto.code.get(pc + 1).copied().unwrap_or(0);
            let val: String = state.reg(u32::from(inst.a));
            let name: String = const_string_raw(proto, aux)
                .map(str::to_owned)
                .unwrap_or_else(|| "_G".to_owned());
            state.push(format!("{name} = {val}"));
            2
        }
        LOP_GETUPVAL => {
            let v: String = state.uv(u32::from(inst.b));
            state.declare_local(u32::from(inst.a), &v);
            1
        }
        LOP_SETUPVAL => {
            let name: String = state.uv(u32::from(inst.b));
            let val: String = state.reg(u32::from(inst.a));
            state.push(format!("{name} = {val}"));
            1
        }
        LOP_GETIMPORT => {
            let aux: u32 = proto.code.get(pc + 1).copied().unwrap_or(0);
            let expr: String = resolve_import(proto, inst.d as u32, aux);
            state.declare_local(u32::from(inst.a), &expr);
            2
        }
        LOP_GETTABLE => {
            let table: String = state.reg(u32::from(inst.b));
            let key: String = state.reg(u32::from(inst.c));
            state.declare_local(u32::from(inst.a), &format!("{table}[{key}]"));
            1
        }
        LOP_SETTABLE => {
            let table: String = state.reg(u32::from(inst.b));
            let key: String = state.reg(u32::from(inst.c));
            let val: String = state.reg(u32::from(inst.a));
            state.push(format!("{table}[{key}] = {val}"));
            1
        }
        LOP_GETTABLEKS | LOP_GETUDATAKS => {
            let table: String = state.reg(u32::from(inst.b));
            let aux: u32 = proto.code.get(pc + 1).copied().unwrap_or(0);
            let expr: String = index_field(&table, const_string_raw(proto, aux));
            state.declare_local(u32::from(inst.a), &expr);
            2
        }
        LOP_SETTABLEKS | LOP_SETUDATAKS => {
            let table: String = state.reg(u32::from(inst.b));
            let val: String = state.reg(u32::from(inst.a));
            let aux: u32 = proto.code.get(pc + 1).copied().unwrap_or(0);
            let lhs: String = index_field(&table, const_string_raw(proto, aux));
            state.push(format!("{lhs} = {val}"));
            2
        }
        LOP_GETTABLEN => {
            let table: String = state.reg(u32::from(inst.b));
            let key: u32 = u32::from(inst.c).saturating_add(1);
            state.declare_local(u32::from(inst.a), &format!("{table}[{key}]"));
            1
        }
        LOP_SETTABLEN => {
            let table: String = state.reg(u32::from(inst.b));
            let key: u32 = u32::from(inst.c).saturating_add(1);
            let val: String = state.reg(u32::from(inst.a));
            state.push(format!("{table}[{key}] = {val}"));
            1
        }
        LOP_NEWCLOSURE | LOP_DUPCLOSURE => {
            emit_closure(
                proto,
                inst,
                pc,
                state,
                depth,
                next_scope,
                warnings,
                fully_structured,
            );
            1
        }
        LOP_NAMECALL | LOP_NAMECALLUDATA => {
            let obj: String = state.reg(u32::from(inst.b));
            let aux: u32 = proto.code.get(pc + 1).copied().unwrap_or(0);
            let method: Option<&str> = const_string_raw(proto, aux);
            let callee: String = match method {
                Some(name) if is_ident(name) => format!("{obj}:{name}"),
                Some(name) => format!("{obj}[{}]", quote_lua(name)),
                None => format!("{obj}.__namecall"),
            };
            state.set_reg(u32::from(inst.a), callee);
            state.set_reg(u32::from(inst.a) + 1, obj);
            state.method_call = Some(u32::from(inst.a));
            2
        }
        LOP_CALL => {
            emit_call(inst, state);
            1
        }
        LOP_CALLFB => {
            emit_call(inst, state);
            2
        }
        LOP_RETURN => {
            emit_return(inst, state, pc, code_len);
            1
        }
        LOP_JUMP | LOP_JUMPX => {
            let off: i32 = if inst.op == LOP_JUMPX { inst.e } else { inst.d };
            let t: i64 = pc as i64 + 1 + i64::from(off);
            if t >= 0 {
                state.push_stmt(LStmt::Jump { target: t as usize });
            }
            1
        }
        LOP_JUMPBACK => {
            let t: i64 = pc as i64 + 1 + i64::from(inst.d);
            if t >= 0 {
                state.push_stmt(LStmt::Jump { target: t as usize });
            }
            1
        }
        LOP_JUMPIF => {
            let val: String = state.reg(u32::from(inst.a));
            let t: i64 = pc as i64 + 1 + i64::from(inst.d);
            if t >= 0
                && let Some(adv) = try_loadb_bool(proto, pc, 1, t as usize, &val, state)
            {
                return adv;
            }
            emit_cond(state, format!("not ({val})"), t);
            1
        }
        LOP_JUMPIFNOT => {
            let val: String = state.reg(u32::from(inst.a));
            let t: i64 = pc as i64 + 1 + i64::from(inst.d);
            if t >= 0
                && let Some(adv) =
                    try_loadb_bool(proto, pc, 1, t as usize, &format!("not ({val})"), state)
            {
                return adv;
            }
            emit_cond(state, val, t);
            1
        }
        LOP_JUMPIFEQ | LOP_JUMPIFNOTEQ | LOP_JUMPIFLE | LOP_JUMPIFNOTLE | LOP_JUMPIFLT
        | LOP_JUMPIFNOTLT => {
            let lhs: String = state.reg(u32::from(inst.a));
            let aux: u32 = proto.code.get(pc + 1).copied().unwrap_or(0);
            let rhs: String = state.reg(aux);
            let taken_sym: &str = jump_cmp_taken(inst.op);
            let t: i64 = pc as i64 + 1 + i64::from(inst.d);
            if t >= 0
                && let Some(adv) = try_loadb_bool(
                    proto,
                    pc,
                    2,
                    t as usize,
                    &format!("{lhs} {taken_sym} {rhs}"),
                    state,
                )
            {
                return adv;
            }
            let inv_sym: &str = jump_cmp_inverse(inst.op);
            emit_cond(state, format!("{lhs} {inv_sym} {rhs}"), t);
            2
        }
        LOP_JUMPXEQKNIL | LOP_JUMPXEQKB | LOP_JUMPXEQKN | LOP_JUMPXEQKS => {
            let lhs: String = state.reg(u32::from(inst.a));
            let aux: u32 = proto.code.get(pc + 1).copied().unwrap_or(0);
            let not_flag: bool = (aux >> 31) != 0;
            let kidx: u32 = aux & 0x00FF_FFFF;
            let rhs: String = match inst.op {
                LOP_JUMPXEQKNIL => "nil".to_owned(),
                LOP_JUMPXEQKB => {
                    if kidx != 0 {
                        "true".to_owned()
                    } else {
                        "false".to_owned()
                    }
                }
                _ => const_at(proto, kidx),
            };
            let inv_sym: &str = if not_flag { "==" } else { "~=" };
            let taken_sym: &str = if not_flag { "~=" } else { "==" };
            let t: i64 = pc as i64 + 1 + i64::from(inst.d);
            if t >= 0
                && let Some(adv) = try_loadb_bool(
                    proto,
                    pc,
                    2,
                    t as usize,
                    &format!("{lhs} {taken_sym} {rhs}"),
                    state,
                )
            {
                return adv;
            }
            emit_cond(state, format!("{lhs} {inv_sym} {rhs}"), t);
            2
        }
        LOP_ADD | LOP_SUB | LOP_MUL | LOP_DIV | LOP_MOD | LOP_POW | LOP_IDIV => {
            let lhs: String = state.reg(u32::from(inst.b));
            let rhs: String = state.reg(u32::from(inst.c));
            let sym: &str = arith_sym(inst.op);
            state.declare_local(u32::from(inst.a), &format!("({lhs} {sym} {rhs})"));
            1
        }
        LOP_ADDK | LOP_SUBK | LOP_MULK | LOP_DIVK | LOP_MODK | LOP_POWK | LOP_IDIVK => {
            let lhs: String = state.reg(u32::from(inst.b));
            let rhs: String = const_at(proto, u32::from(inst.c));
            let sym: &str = arithk_sym(inst.op);
            state.declare_local(u32::from(inst.a), &format!("({lhs} {sym} {rhs})"));
            1
        }
        LOP_SUBRK | LOP_DIVRK => {
            let lhs: String = const_at(proto, u32::from(inst.b));
            let rhs: String = state.reg(u32::from(inst.c));
            let sym: &str = if inst.op == LOP_SUBRK { "-" } else { "/" };
            state.declare_local(u32::from(inst.a), &format!("({lhs} {sym} {rhs})"));
            1
        }
        LOP_AND | LOP_OR => {
            let lhs: String = state.reg(u32::from(inst.b));
            let rhs: String = state.reg(u32::from(inst.c));
            let sym: &str = if inst.op == LOP_AND { "and" } else { "or" };
            state.declare_local(u32::from(inst.a), &format!("({lhs} {sym} {rhs})"));
            1
        }
        LOP_ANDK | LOP_ORK => {
            let lhs: String = state.reg(u32::from(inst.b));
            let rhs: String = const_at(proto, u32::from(inst.c));
            let sym: &str = if inst.op == LOP_ANDK { "and" } else { "or" };
            state.declare_local(u32::from(inst.a), &format!("({lhs} {sym} {rhs})"));
            1
        }
        LOP_CONCAT => {
            let start: u32 = u32::from(inst.b);
            let end: u32 = u32::from(inst.c);
            let parts: Vec<String> = (start..=end).map(|r: u32| state.reg(r)).collect();
            state.declare_local(u32::from(inst.a), &format!("({})", parts.join(" .. ")));
            1
        }
        LOP_NOT => {
            let v: String = state.reg(u32::from(inst.b));
            state.declare_local(u32::from(inst.a), &format!("(not {v})"));
            1
        }
        LOP_MINUS => {
            let v: String = state.reg(u32::from(inst.b));
            state.declare_local(u32::from(inst.a), &format!("(-{v})"));
            1
        }
        LOP_LENGTH => {
            let v: String = state.reg(u32::from(inst.b));
            state.declare_local(u32::from(inst.a), &format!("(#{v})"));
            1
        }
        LOP_NEWTABLE => {
            state.declare_local(u32::from(inst.a), "{}");
            2
        }
        LOP_DUPTABLE => {
            let lit: String = render_template_table(proto, inst.d as u32);
            state.declare_local(u32::from(inst.a), &lit);
            1
        }
        LOP_SETLIST => {
            emit_setlist(proto, inst, pc, state);
            2
        }
        LOP_FORNPREP => {
            let a: u32 = u32::from(inst.a);
            let limit: String = state.reg(a);
            let step: String = state.reg(a + 1);
            let init: String = state.reg(a + 2);
            let var: String = state.slot_name(a + 2);
            state.set_reg(a + 2, var.clone());
            state.mark_declared(a + 2);
            let end: i64 = pc as i64 + 1 + i64::from(inst.d);
            state.push_stmt(LStmt::ForNum {
                var,
                init,
                limit,
                step,
                end: end.max(0) as usize,
            });
            1
        }
        LOP_FORNLOOP => {
            state.push_stmt(LStmt::BlockEnd);
            1
        }
        LOP_FORGPREP | LOP_FORGPREP_INEXT | LOP_FORGPREP_NEXT => {
            let a: u32 = u32::from(inst.a);
            let f: String = state.reg(a);
            let s: String = state.reg(a + 1);
            let v: String = state.reg(a + 2);
            let iter: String = if s == "nil" && v == "nil" {
                f
            } else {
                format!("{f}, {s}, {v}")
            };
            let end: i64 = pc as i64 + 1 + i64::from(inst.d);
            state.push_stmt(LStmt::ForGen {
                iter,
                end: end.max(0) as usize,
            });
            1
        }
        LOP_FORGLOOP => {
            let a: u32 = u32::from(inst.a);
            let aux: u32 = proto.code.get(pc + 1).copied().unwrap_or(0);
            let nvars: u32 = (aux & 0xFF).max(1);
            let vars: Vec<String> = (0..nvars)
                .map(|i: u32| {
                    let slot: u32 = a + 3 + i;
                    let name: String = state.slot_name(slot);
                    state.set_reg(slot, name.clone());
                    state.mark_declared(slot);
                    name
                })
                .collect();
            state.push_stmt(LStmt::Raw(format!("--FORGLOOP_VARS {}", vars.join(","))));
            state.push_stmt(LStmt::BlockEnd);
            2
        }
        LOP_GETVARARGS => {
            emit_getvarargs(inst, state);
            1
        }
        LOP_FASTCALL | LOP_FASTCALL1 | LOP_FASTCALL2 | LOP_FASTCALL2K | LOP_FASTCALL3 => {
            op_length(inst.op)
        }
        op => {
            state.push(format!("-- unknown luau op {op}"));
            warnings.push(format!("unknown luau opcode {op} at pc={pc}"));
            *fully_structured = false;
            op_length(op)
        }
    }
}

fn emit_cond(state: &mut LuauState, cond: String, target: i64) {
    if target >= 0 {
        state.push_stmt(LStmt::Cond {
            cond,
            target: target as usize,
        });
    }
}

#[must_use]
fn loadb_at(code: &[u32], pc: usize, reg: u32) -> Option<(bool, u32)> {
    let raw: u32 = *code.get(pc)?;
    let inst: Insn = decode(raw);
    if inst.op != LOP_LOADB || u32::from(inst.a) != reg {
        return None;
    }
    let skip: u32 = u32::from(inst.c);
    Some((inst.b != 0, skip))
}

fn try_loadb_bool(
    proto: &LuaProto,
    pc: usize,
    insn_len: usize,
    taken_target: usize,
    taken_cmp: &str,
    state: &mut LuauState,
) -> Option<usize> {
    let fall_pc: usize = pc + insn_len;
    let fall: Insn = decode(*proto.code.get(fall_pc)?);
    if fall.op != LOP_LOADB {
        return None;
    }
    let reg: u32 = u32::from(fall.a);
    let (fall_val, fall_skip): (bool, u32) = loadb_at(&proto.code, fall_pc, reg)?;
    let fall_after: usize = fall_pc + 1 + fall_skip as usize;
    if taken_target != fall_pc + 1 {
        return None;
    }
    let (taken_val, _): (bool, u32) = loadb_at(&proto.code, taken_target, reg)?;
    if taken_val == fall_val {
        return None;
    }
    let expr: String = if taken_val {
        taken_cmp.to_owned()
    } else {
        format!("not ({taken_cmp})")
    };
    state.declare_local(reg, &expr);
    let end: usize = fall_after.max(taken_target + 1);
    Some(end - pc)
}

#[inline]
fn jump_cmp_inverse(op: u8) -> &'static str {
    match op {
        LOP_JUMPIFEQ => "~=",
        LOP_JUMPIFNOTEQ => "==",
        LOP_JUMPIFLE => ">",
        LOP_JUMPIFNOTLE => "<=",
        LOP_JUMPIFLT => ">=",
        LOP_JUMPIFNOTLT => "<",
        _ => "==",
    }
}

#[inline]
fn jump_cmp_taken(op: u8) -> &'static str {
    match op {
        LOP_JUMPIFEQ => "==",
        LOP_JUMPIFNOTEQ => "~=",
        LOP_JUMPIFLE => "<=",
        LOP_JUMPIFNOTLE => ">",
        LOP_JUMPIFLT => "<",
        LOP_JUMPIFNOTLT => ">=",
        _ => "==",
    }
}

#[inline]
fn arith_sym(op: u8) -> &'static str {
    match op {
        LOP_ADD => "+",
        LOP_SUB => "-",
        LOP_MUL => "*",
        LOP_DIV => "/",
        LOP_MOD => "%",
        LOP_POW => "^",
        LOP_IDIV => "//",
        _ => "+",
    }
}

#[inline]
fn arithk_sym(op: u8) -> &'static str {
    match op {
        LOP_ADDK => "+",
        LOP_SUBK => "-",
        LOP_MULK => "*",
        LOP_DIVK => "/",
        LOP_MODK => "%",
        LOP_POWK => "^",
        LOP_IDIVK => "//",
        _ => "+",
    }
}

#[must_use]
fn index_field(table: &str, key: Option<&str>) -> String {
    match key {
        Some(k) if is_ident(k) => format!("{table}.{k}"),
        Some(k) => format!("{table}[{}]", quote_lua(k)),
        None => format!("{table}.__index"),
    }
}

#[must_use]
fn resolve_import(proto: &LuaProto, d: u32, aux: u32) -> String {
    let count: u32 = aux >> 30;
    let parts: [u32; 3] = [(aux >> 20) & 0x3FF, (aux >> 10) & 0x3FF, aux & 0x3FF];
    let mut path: Vec<String> = Vec::new();
    for slot in parts.iter().take(count.min(3) as usize) {
        if let Some(s) = const_string_raw(proto, *slot) {
            path.push(s.to_owned());
        }
    }
    if path.is_empty() {
        const_at(proto, d)
    } else {
        path.join(".")
    }
}

#[must_use]
fn render_template_table(proto: &LuaProto, idx: u32) -> String {
    match proto.constants.get(idx as usize) {
        Some(LuaConstant::Str(_)) | None => "{}".to_owned(),
        Some(_) => "{}".to_owned(),
    }
}

const CALL_ARG_BASE: u32 = 1;

fn collect_args(state: &mut LuauState, base: u32, count: u32) -> Vec<String> {
    (0..count)
        .map(|i: u32| {
            let slot: u32 = base + i;
            if i + 1 == count {
                state
                    .take_open_multi(slot)
                    .unwrap_or_else(|| state.reg(slot))
            } else {
                state.reg(slot)
            }
        })
        .collect()
}

fn emit_call(inst: &Insn, state: &mut LuauState) {
    let a: u32 = u32::from(inst.a);
    let func: String = state.reg(a);
    let b: u8 = inst.b;
    let is_method: bool = state.method_call == Some(a);
    state.method_call = None;
    let self_skip: u32 = u32::from(is_method);
    let args: Vec<String> = if b == 0 {
        let arg_base: u32 = a + CALL_ARG_BASE + self_skip;
        match state.open_multi.take() {
            Some((slot, expr)) if slot >= arg_base => {
                let mut v: Vec<String> = (arg_base..slot).map(|r: u32| state.reg(r)).collect();
                v.push(expr);
                v
            }
            other => {
                state.open_multi = other;
                let mut r: u32 = arg_base;
                let mut v: Vec<String> = Vec::new();
                while state.set.get(r as usize).copied().unwrap_or(false) {
                    v.push(state.reg(r));
                    r += 1;
                }
                v.push("...".to_owned());
                v
            }
        }
    } else {
        let nargs: u32 = (u32::from(b) - 1).saturating_sub(self_skip);
        collect_args(state, a + CALL_ARG_BASE + self_skip, nargs)
    };
    let call: String = format!("{}({})", paren_callee(&func), args.join(", "));
    let c: u8 = inst.c;
    if c == 0 {
        state.set_reg(a, call.clone());
        state.set_open_multi(a, call);
        return;
    }
    let nresults: u32 = u32::from(c) - 1;
    match nresults {
        0 => state.push(call),
        1 => state.declare_local(a, &call),
        _ => {
            let targets: Vec<String> = (0..nresults).map(|i: u32| state.slot_name(a + i)).collect();
            let all_declared: bool = (0..nresults).all(|i: u32| state.declared(a + i));
            let prefix: &str = if all_declared { "" } else { "local " };
            state.push(format!("{prefix}{} = {call}", targets.join(", ")));
            for (i, t) in targets.iter().enumerate() {
                state.set_reg(a + i as u32, t.clone());
                state.mark_declared(a + i as u32);
            }
        }
    }
}

#[must_use]
fn paren_callee(func: &str) -> String {
    if func.starts_with("function") {
        format!("({func})")
    } else {
        func.to_owned()
    }
}

fn emit_return(inst: &Insn, state: &mut LuauState, pc: usize, code_len: usize) {
    let a: u32 = u32::from(inst.a);
    let b: u8 = inst.b;
    if b == 1 {
        if pc + 1 != code_len {
            state.push("do return end".to_owned());
        }
        return;
    }
    if b == 0 {
        let open: Option<(u32, String)> =
            state.open_multi.take().or_else(|| state.last_multi.clone());
        match open {
            Some((slot, expr)) if slot >= a => {
                let mut vals: Vec<String> = (a..slot).map(|r: u32| state.reg(r)).collect();
                vals.push(expr);
                state.push(format!("do return {} end", vals.join(", ")));
            }
            _ => {
                let mut vals: Vec<String> = Vec::new();
                let mut r: u32 = a;
                while state.set.get(r as usize).copied().unwrap_or(false) {
                    vals.push(state.reg(r));
                    r += 1;
                }
                vals.push("...".to_owned());
                state.push(format!("do return {} end", vals.join(", ")));
            }
        }
        return;
    }
    let nret: u32 = u32::from(b) - 1;
    let vals: Vec<String> = collect_args(state, a, nret);
    state.push(format!("do return {} end", vals.join(", ")));
}

fn emit_getvarargs(inst: &Insn, state: &mut LuauState) {
    let a: u32 = u32::from(inst.a);
    let b: u8 = inst.b;
    if b == 0 {
        state.set_reg(a, "...".to_owned());
        state.set_open_multi(a, "...".to_owned());
        return;
    }
    let nvals: u32 = u32::from(b) - 1;
    if nvals == 1 {
        state.declare_local(a, "...");
    } else {
        let targets: Vec<String> = (0..nvals).map(|i: u32| state.slot_name(a + i)).collect();
        let all_declared: bool = (0..nvals).all(|i: u32| state.declared(a + i));
        let prefix: &str = if all_declared { "" } else { "local " };
        state.push(format!("{prefix}{} = ...", targets.join(", ")));
        for (i, t) in targets.iter().enumerate() {
            state.set_reg(a + i as u32, t.clone());
            state.mark_declared(a + i as u32);
        }
    }
}

fn emit_setlist(proto: &LuaProto, inst: &Insn, pc: usize, state: &mut LuauState) {
    let a: u32 = u32::from(inst.a);
    let b: u32 = u32::from(inst.b);
    let count_field: u32 = u32::from(inst.c);
    let aux: u32 = proto.code.get(pc + 1).copied().unwrap_or(1);
    let start_index: u32 = aux;
    let table: String = state.reg(a);
    if count_field == 0 {
        let multi: String = state.take_open_multi(b).unwrap_or_else(|| state.reg(b));
        state.push(format!(
            "do local _m = {{{multi}}}; for _i = 1, #_m do {table}[{start_index} + _i - 1] = _m[_i] end end"
        ));
        return;
    }
    let count: u32 = count_field.saturating_sub(1);
    for i in 0..count {
        let val: String = state.reg(b + i);
        let key: u32 = start_index + i;
        state.push(format!("{table}[{key}] = {val}"));
    }
}

#[allow(clippy::too_many_arguments)]
fn emit_closure(
    proto: &LuaProto,
    inst: &Insn,
    pc: usize,
    state: &mut LuauState,
    depth: usize,
    next_scope: &mut usize,
    warnings: &mut Vec<String>,
    fully_structured: &mut bool,
) {
    let child_idx: u32 = if inst.op == LOP_DUPCLOSURE {
        match proto.constants.get(inst.d as usize) {
            Some(LuaConstant::ClosureRef(slot)) => *slot,
            _ => inst.d as u32,
        }
    } else {
        inst.d as u32
    };
    let child: Option<&LuaProto> = proto.protos.get(child_idx as usize);
    let dst: u32 = u32::from(inst.a);
    match child {
        Some(child_p) => {
            let capture_count: usize = count_captures(&proto.code, pc + 1);
            let child_uv: Vec<String> = resolve_captures(&proto.code, pc + 1, capture_count, state);
            let child_scope: usize = *next_scope;
            *next_scope += 1;
            let body: String = lift_proto(
                child_p,
                depth + 1,
                child_scope,
                &child_uv,
                next_scope,
                warnings,
                fully_structured,
            );
            let trimmed: &str = body.strip_suffix('\n').unwrap_or(&body);
            let prefix: &str = if state.declared(dst) { "" } else { "local " };
            let name: String = state.slot_name(dst);
            let mut lines: std::str::Lines<'_> = trimmed.lines();
            if let Some(first) = lines.next() {
                state.push(format!("{prefix}{name} = {first}"));
            }
            for ln in lines {
                state.push(ln.to_owned());
            }
            state.set_reg(dst, name);
            state.mark_declared(dst);
        }
        None => {
            state.declare_local(dst, "function() end");
            warnings.push("luau closure child proto missing".to_owned());
            *fully_structured = false;
        }
    }
}

#[must_use]
fn count_captures(code: &[u32], mut pc: usize) -> usize {
    let mut count: usize = 0;
    while pc < code.len() {
        let inst: Insn = decode(code[pc]);
        if inst.op == LOP_CAPTURE {
            count += 1;
            pc += 1;
        } else {
            break;
        }
    }
    count
}

const LCT_VAL: u8 = 0;
const LCT_REF: u8 = 1;
const LCT_UPVAL: u8 = 2;

#[must_use]
fn resolve_captures(code: &[u32], pc: usize, count: usize, state: &LuauState) -> Vec<String> {
    let mut names: Vec<String> = Vec::with_capacity(count);
    for i in 0..count {
        let Some(raw): Option<&u32> = code.get(pc + i) else {
            break;
        };
        let inst: Insn = decode(*raw);
        let kind: u8 = inst.a;
        let slot: u32 = u32::from(inst.b);
        let name: String = match kind {
            LCT_VAL | LCT_REF => state.reg(slot),
            LCT_UPVAL => state.uv(slot),
            _ => state.reg(slot),
        };
        names.push(name);
    }
    names
}

#[must_use]
fn compute_predeclare(proto: &LuaProto) -> Vec<u32> {
    let frame: usize = usize::from(proto.max_stack_size).max(2);
    let mut counts: Vec<u32> = vec![0; frame + 1];
    let code: &[u32] = &proto.code;
    let mut pc: usize = 0;
    while pc < code.len() {
        let inst: Insn = decode(code[pc]);
        let a: usize = usize::from(inst.a);
        match inst.op {
            LOP_CALL | LOP_CALLFB => {
                let c: u8 = inst.c;
                let nres: u32 = if c == 0 { 1 } else { u32::from(c) - 1 };
                for i in 0..nres.max(1) {
                    bump(&mut counts, a + i as usize);
                }
            }
            LOP_GETVARARGS => {
                let b: u8 = inst.b;
                let nvals: u32 = if b == 0 { 1 } else { u32::from(b) - 1 };
                for i in 0..nvals.max(1) {
                    bump(&mut counts, a + i as usize);
                }
            }
            LOP_LOADNIL | LOP_LOADB | LOP_LOADN | LOP_LOADK | LOP_LOADKX | LOP_MOVE
            | LOP_GETGLOBAL | LOP_GETUPVAL | LOP_GETIMPORT | LOP_GETTABLE | LOP_GETTABLEKS
            | LOP_GETTABLEN | LOP_NEWCLOSURE | LOP_DUPCLOSURE | LOP_ADD | LOP_SUB | LOP_MUL
            | LOP_DIV | LOP_MOD | LOP_POW | LOP_IDIV | LOP_ADDK | LOP_SUBK | LOP_MULK
            | LOP_DIVK | LOP_MODK | LOP_POWK | LOP_IDIVK | LOP_SUBRK | LOP_DIVRK | LOP_AND
            | LOP_OR | LOP_ANDK | LOP_ORK | LOP_CONCAT | LOP_NOT | LOP_MINUS | LOP_LENGTH
            | LOP_NEWTABLE | LOP_DUPTABLE | LOP_NAMECALL | LOP_NAMECALLUDATA | LOP_GETUDATAKS => {
                bump(&mut counts, a);
            }
            _ => {}
        }
        pc += op_length(inst.op).max(1);
    }
    let num_params: u32 = u32::from(proto.num_params);
    (0..frame as u32)
        .filter(|slot: &u32| {
            counts.get(*slot as usize).copied().unwrap_or(0) >= 1 && *slot >= num_params
        })
        .collect()
}

#[inline]
fn bump(counts: &mut [u32], slot: usize) {
    if slot < counts.len() {
        counts[slot] += 1;
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    const PREVIOUS_STRUCTURE_DEPTH_LIMIT: usize = 256;

    fn luau_proto(code: Vec<u32>, stack: u8) -> LuaProto {
        LuaProto {
            source: None,
            line_defined: 0,
            last_line_defined: 0,
            num_params: 0,
            is_vararg: 0,
            max_stack_size: stack,
            code,
            constants: Vec::new(),
            protos: Vec::new(),
            source_lines: Vec::new(),
            locals: Vec::new(),
            upvalues: Vec::new(),
        }
    }

    fn nested_conditional_code(depth: usize) -> Vec<u32> {
        let span: usize = depth * 2;
        let mut code: Vec<u32> = Vec::with_capacity(span + 1);
        for i in 0..depth {
            let target: i64 = (span - i) as i64;
            let offset: i64 = target - i as i64 - 1;
            let d: u32 = u32::from(offset as u16);
            code.push(u32::from(LOP_JUMPIF) | (d << 16));
        }
        for i in depth..span {
            code.push(u32::from(LOP_LOADN) | (1 << 8) | ((i as u32 & 0xFFFF) << 16));
        }
        code.push(u32::from(LOP_RETURN));
        code
    }

    fn lift_once(proto: &LuaProto) -> (String, Vec<String>, bool) {
        let mut warnings: Vec<String> = Vec::new();
        let mut fully_structured: bool = true;
        let mut next_scope: usize = 1;
        let body: String = lift_proto(
            proto,
            0,
            0,
            &[],
            &mut next_scope,
            &mut warnings,
            &mut fully_structured,
        );
        (body, warnings, fully_structured)
    }

    fn nested_guarded_assignment(depth: usize) -> Vec<StructuredBlock> {
        let mut body: Vec<StructuredBlock> =
            vec![StructuredBlock::Raw("result = result + 1".to_owned())];
        for _ in 0..depth {
            body = vec![StructuredBlock::If {
                cond: "enabled".to_owned(),
                then_body: body,
                else_body: Vec::new(),
            }];
        }
        body
    }

    #[test]
    fn iterative_render_preserves_the_existing_surface_for_each_region_kind() {
        let blocks: Vec<StructuredBlock> = vec![
            StructuredBlock::Raw("local x = 0".to_owned()),
            StructuredBlock::Break,
            StructuredBlock::Goto { pc: 7 },
            StructuredBlock::Label { pc: 7 },
            StructuredBlock::If {
                cond: "x == 0".to_owned(),
                then_body: vec![StructuredBlock::Raw("x = 1".to_owned())],
                else_body: vec![StructuredBlock::Raw("x = 2".to_owned())],
            },
            StructuredBlock::While {
                cond: "x < 4".to_owned(),
                body: vec![StructuredBlock::Raw("x = x + 1".to_owned())],
            },
            StructuredBlock::Repeat {
                cond: "x == 0".to_owned(),
                body: vec![StructuredBlock::Raw("x = x - 1".to_owned())],
            },
            StructuredBlock::NumericFor {
                var: "i".to_owned(),
                init: "1".to_owned(),
                limit: "3".to_owned(),
                step: "1".to_owned(),
                body: vec![StructuredBlock::Raw("x = x + i".to_owned())],
            },
            StructuredBlock::NumericFor {
                var: "i".to_owned(),
                init: "3".to_owned(),
                limit: "1".to_owned(),
                step: "-1".to_owned(),
                body: vec![StructuredBlock::Raw("x = x + i".to_owned())],
            },
            StructuredBlock::GenericFor {
                vars: vec!["k".to_owned(), "v".to_owned()],
                iter: "pairs(t)".to_owned(),
                body: vec![StructuredBlock::Raw("x = x + v".to_owned())],
            },
        ];

        let rendered: RenderedBlocks = render_blocks(&blocks, 1);

        assert_eq!(
            rendered.source,
            "  local x = 0\n  break\n  goto lbl_7\n  ::lbl_7::\n  if x == 0 then\n    x = 1\n  else\n    x = 2\n  end\n  while x < 4 do\n    x = x + 1\n  end\n  repeat\n    x = x - 1\n  until x == 0\n  for i = 1, 3 do\n    x = x + i\n  end\n  for i = 3, 1, -1 do\n    x = x + i\n  end\n  for k, v in pairs(t) do\n    x = x + v\n  end\n"
        );
    }

    #[test]
    fn rendering_at_the_previous_limit_remains_byte_identical() {
        let blocks: Vec<StructuredBlock> =
            nested_guarded_assignment(PREVIOUS_STRUCTURE_DEPTH_LIMIT);
        let mut expected: String = String::new();
        for indent in 0..PREVIOUS_STRUCTURE_DEPTH_LIMIT {
            expected.push_str(&"  ".repeat(indent));
            expected.push_str("if enabled then\n");
        }
        expected.push_str(&"  ".repeat(PREVIOUS_STRUCTURE_DEPTH_LIMIT));
        expected.push_str("result = result + 1\n");
        for indent in (0..PREVIOUS_STRUCTURE_DEPTH_LIMIT).rev() {
            expected.push_str(&"  ".repeat(indent));
            expected.push_str("end\n");
        }

        let rendered: RenderedBlocks = render_blocks(&blocks, 0);
        assert!(!rendered.refused);
        assert_eq!(rendered.source, expected);
    }

    #[test]
    fn every_region_kind_refuses_before_rendered_output_exceeds_the_byte_ceiling() {
        let depth: usize = 3_000;
        let maximum_bytes: usize = 16 * 1024 * 1024;
        let mut body: Vec<StructuredBlock> =
            vec![StructuredBlock::Raw("guarded_leaf()".to_owned())];
        for level in 0..depth {
            body = vec![match level % 6 {
                0 => StructuredBlock::If {
                    cond: "enabled".to_owned(),
                    then_body: body,
                    else_body: vec![StructuredBlock::Raw("fallback()".to_owned())],
                },
                1 => StructuredBlock::While {
                    cond: "enabled".to_owned(),
                    body,
                },
                2 => StructuredBlock::Repeat {
                    cond: "finished".to_owned(),
                    body,
                },
                3 => StructuredBlock::NumericFor {
                    var: format!("i{level}"),
                    init: "1".to_owned(),
                    limit: "2".to_owned(),
                    step: "1".to_owned(),
                    body,
                },
                4 => StructuredBlock::GenericFor {
                    vars: vec![format!("k{level}"), format!("v{level}")],
                    iter: "pairs(values)".to_owned(),
                    body,
                },
                _ => StructuredBlock::If {
                    cond: "ready".to_owned(),
                    then_body: body,
                    else_body: Vec::new(),
                },
            }];
        }

        let rendered: RenderedBlocks = render_blocks(&body, 0);

        assert!(rendered.refused);
        assert_eq!(
            rendered.source,
            "error(\"disrobe: rendered structure exceeds output limit\")\n"
        );
        assert!(
            rendered.source.len() <= maximum_bytes,
            "{}",
            rendered.source.len()
        );
    }

    #[test]
    fn a_proto_nested_past_the_previous_limit_reports_a_complete_structure() {
        let proto: LuaProto = luau_proto(nested_conditional_code(400), 4);

        let (body, warnings, fully_structured): (String, Vec<String>, bool) = lift_once(&proto);

        assert!(
            fully_structured,
            "the iterative structurer retains every guarded statement at this depth; warnings: \
             {warnings:?}; body:\n{body}"
        );
        assert!(
            !warnings
                .iter()
                .any(|warning: &String| warning.contains("structuring work budget")),
            "nesting alone must not consume the work budget: {warnings:?}"
        );
        assert!(body.contains("r1 = 400"), "body:\n{body}");
    }

    #[test]
    fn a_proto_nested_inside_the_limit_still_reports_a_complete_structure() {
        let proto: LuaProto = luau_proto(nested_conditional_code(32), 4);

        let (body, warnings, fully_structured): (String, Vec<String>, bool) = lift_once(&proto);

        assert!(
            fully_structured,
            "a body that fits the limit must keep its complete-structure report, or the limit is \
             refusing ordinary input; warnings {warnings:?}; body:\n{body}"
        );
    }

    const PAST_THE_TABLE: u32 = 250;

    #[test]
    fn a_dropped_plain_jump_lowers_the_flag_this_lifter_reports() {
        let proto: LuaProto = luau_proto(
            vec![u32::from(LOP_JUMP) | (5 << 16), u32::from(LOP_RETURN)],
            4,
        );

        let (body, _, fully_structured): (String, Vec<String>, bool) = lift_once(&proto);

        assert!(
            !fully_structured,
            "the jump names a target outside every region this walk visits, so no structure \
             carries it; the count the structurer reports has to reach the flag this lifter \
             publishes, not stop at the structurer; body:\n{body}"
        );
    }

    #[test]
    fn every_luau_arm_that_loses_an_edge_lowers_the_flag() {
        let cases: Vec<(&str, Vec<u32>)> = vec![
            (
                "a BREAK is a debugger trap the recovered source cannot carry, so the edge it \
                 interrupts is lost",
                vec![u32::from(LOP_BREAK), u32::from(LOP_RETURN)],
            ),
            (
                "an opcode past the end of the table decodes to nothing this lifter can place",
                vec![PAST_THE_TABLE, u32::from(LOP_RETURN)],
            ),
            (
                "a NEWCLOSURE naming a child proto the chunk does not carry recovers no body at \
                 all",
                vec![u32::from(LOP_NEWCLOSURE) | (7 << 16), u32::from(LOP_RETURN)],
            ),
        ];

        for (why, code) in cases {
            let proto: LuaProto = luau_proto(code, 4);

            let (body, _, fully_structured): (String, Vec<String>, bool) = lift_once(&proto);

            assert!(
                !fully_structured,
                "{why}; the flag must not claim a complete structure here, got:\n{body}"
            );
        }
    }

    #[test]
    fn a_proto_nested_past_the_lift_depth_limit_lowers_the_flag() {
        let proto: LuaProto = luau_proto(vec![u32::from(LOP_RETURN)], 4);
        let mut warnings: Vec<String> = Vec::new();
        let mut fully_structured: bool = true;
        let mut next_scope: usize = 1;

        let body: String = lift_proto(
            &proto,
            MAX_LIFT_DEPTH + 1,
            0,
            &[],
            &mut next_scope,
            &mut warnings,
            &mut fully_structured,
        );

        assert!(
            !fully_structured,
            "past this depth the body is never lifted at all, so every edge it holds is lost and \
             the flag cannot stand; body:\n{body}"
        );
    }

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
    fn keyword_is_not_identifier() {
        assert!(!is_ident("end"));
        assert!(!is_ident("continue"));
        assert!(is_ident("foo"));
    }

    #[test]
    fn op_length_two_for_aux_ops() {
        assert_eq!(op_length(LOP_GETIMPORT), 2);
        assert_eq!(op_length(LOP_NAMECALL), 2);
        assert_eq!(op_length(LOP_MOVE), 1);
    }

    #[test]
    fn unresolved_jump_downgrades_fidelity() {
        let jump: u32 = u32::from(LOP_JUMP) | (1 << 16);
        let proto: LuaProto = LuaProto {
            source: None,
            line_defined: 0,
            last_line_defined: 0,
            num_params: 0,
            is_vararg: 0,
            max_stack_size: 2,
            code: vec![jump, u32::from(LOP_RETURN)],
            constants: Vec::new(),
            protos: Vec::new(),
            source_lines: Vec::new(),
            locals: Vec::new(),
            upvalues: Vec::new(),
        };
        let chunk: LuaChunk = LuaChunk {
            dialect: crate::reader::common::LuaDialect::Luau,
            version_byte: 11,
            format: 0,
            little_endian: true,
            size_of_int: 4,
            size_of_size_t: 8,
            size_of_instruction: 4,
            size_of_lua_integer: 8,
            size_of_lua_number: 8,
            integral_number: false,
            main: proto,
        };

        let decompiled: DecompiledChunk = decompile(&chunk)
            .unwrap_or_else(|error: crate::error::Error| panic!("decompile failed: {error}"));

        assert_eq!(decompiled.fidelity, Fidelity::BestEffort);
        assert_eq!(
            decompiled.warnings,
            vec!["1 unresolved luau control-flow jump(s) retained as markers"]
        );
        assert!(
            decompiled
                .source
                .contains("error(\"disrobe: unresolved luau jump to pc 2\")")
        );
    }
}
