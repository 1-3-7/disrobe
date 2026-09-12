use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use regex::Regex;

use crate::obfuscator::ironbrew2_dispatch::{
    ArgForm, CallForm, CmpForm, IbOpcode, RetCount, RetForm,
};
use crate::obfuscator::ironbrew2_real::{IbChunk, IbInstr};
use crate::reader::common::LuaConstant;

fn push_fmt(out: &mut String, args: std::fmt::Arguments<'_>) {
    match std::fmt::write(out, args) {
        Ok(()) => {}
        Err(error) => unreachable!("string formatting failed: {error:?}"),
    }
}

macro_rules! push_fmt_line {
    ($out:expr, $($arg:tt)*) => {{
        push_fmt($out, format_args!($($arg)*));
        $out.push('\n');
    }};
}

pub fn emit_program(chunk: &IbChunk, optable: &BTreeMap<u16, Vec<IbOpcode>>) -> String {
    let mut out: String = String::new();
    out.push_str("local function __ib_main(__up, ...)\n");
    emit_chunk(chunk, optable, &mut out, 1, true);
    out.push_str("end\nreturn __ib_main({}, ...)\n");
    out
}

fn op_of(optable: &BTreeMap<u16, Vec<IbOpcode>>, vindex: u16) -> IbOpcode {
    optable
        .get(&vindex)
        .and_then(|v: &Vec<IbOpcode>| v.first().copied())
        .unwrap_or(IbOpcode::Unknown)
}

fn super_len(optable: &BTreeMap<u16, Vec<IbOpcode>>, vindex: u16) -> usize {
    optable
        .get(&vindex)
        .map_or(1, |v: &Vec<IbOpcode>| v.len().max(1))
}

fn closure_capture_count(ins: &IbInstr, pc: usize, instr_len: usize) -> usize {
    let declared: usize = usize::try_from(ins.c.max(0)).unwrap_or(usize::MAX);
    let available: usize = instr_len.saturating_sub(pc.saturating_add(1));
    declared.min(available)
}

fn indent(out: &mut String, depth: usize) {
    for _ in 0..depth {
        out.push_str("  ");
    }
}

fn emit_chunk(
    chunk: &IbChunk,
    optable: &BTreeMap<u16, Vec<IbOpcode>>,
    out: &mut String,
    depth: usize,
    top: bool,
) {
    indent(out, depth);
    out.push_str("local R = {}\n");
    indent(out, depth);
    out.push_str("local top = 0\n");
    if i64::from(chunk.param_count) > 0 || top {
        indent(out, depth);
        push_fmt_line!(
            out,
            "for i = 0, {} - 1 do R[i] = (select(i + 1, ...)) end",
            chunk.param_count
        );
    }

    let mut proto_names: Vec<String> = Vec::with_capacity(chunk.functions.len());
    for (fi, f) in chunk.functions.iter().enumerate() {
        let name: String = format!("__proto_{depth}_{fi}");
        indent(out, depth);
        push_fmt_line!(out, "local function {name}(__up, ...)");
        emit_chunk(f, optable, out, depth + 1, false);
        indent(out, depth);
        out.push_str("end\n");
        proto_names.push(name);
    }

    let targets: BTreeSet<usize> = jump_targets(chunk, optable);
    let consumed: BTreeSet<usize> = consumed_instrs(chunk, optable);

    let mut blocks: Vec<EmitBlock> = Vec::new();
    let mut current: EmitBlock = EmitBlock {
        pc: 0,
        lines: Vec::new(),
    };
    for (pc, ins) in chunk.instrs.iter().enumerate() {
        if consumed.contains(&pc) {
            continue;
        }
        if targets.contains(&pc) && (!current.lines.is_empty() || current.pc != pc) {
            blocks.push(std::mem::replace(
                &mut current,
                EmitBlock {
                    pc,
                    lines: Vec::new(),
                },
            ));
        }
        current.pc = if current.lines.is_empty() {
            pc
        } else {
            current.pc
        };
        let ops: &[IbOpcode] = optable
            .get(&ins.op)
            .map_or(&[IbOpcode::Unknown][..], |v: &Vec<IbOpcode>| v.as_slice());
        let mut stmt: String = String::new();
        if ops.len() > 1 {
            for (k, sub) in ops.iter().enumerate() {
                let sub_ins: &IbInstr = chunk.instrs.get(pc + k).unwrap_or(ins);
                emit_instr(
                    *sub,
                    sub_ins,
                    pc + k,
                    chunk,
                    optable,
                    &proto_names,
                    &mut stmt,
                    0,
                );
            }
        } else {
            let op: IbOpcode = ops.first().copied().unwrap_or(IbOpcode::Unknown);
            emit_instr(op, ins, pc, chunk, optable, &proto_names, &mut stmt, 0);
        }
        for ln in stmt.lines() {
            current.lines.push(ln.to_owned());
        }
    }
    blocks.push(current);

    let n: usize = chunk.instrs.len();
    emit_trampoline(out, depth, &blocks, n);
}

#[derive(Debug, Clone)]
struct EmitBlock {
    pc: usize,
    lines: Vec<String>,
}

#[allow(clippy::expect_used)]
fn goto_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"goto L(\d+)").expect("static goto regex"))
}

fn rewrite_gotos(line: &str) -> String {
    goto_re()
        .replace_all(line, |caps: &regex::Captures<'_>| {
            format!("__pc = {}", &caps[1])
        })
        .into_owned()
}

fn line_returns(line: &str) -> bool {
    let t: &str = line.trim();
    t.starts_with("do return") || t == "return"
}

fn conditional_branches_transfer(inner: &str) -> bool {
    if let Some(else_pos) = inner.rfind(" else ") {
        let then_body: &str = &inner[..else_pos];
        let else_body: &str = &inner[else_pos + 6..];
        then_body.contains("__pc") && else_body.contains("__pc")
    } else {
        false
    }
}

fn finalize_transfer(line: &str, fallthrough: usize) -> Option<String> {
    if line_returns(line) {
        return Some(line.to_owned());
    }
    let trimmed: &str = line.trim();
    let is_conditional: bool = trimmed.starts_with("if ") && trimmed.ends_with(" end");
    if is_conditional && trimmed.contains("__pc") {
        let inner: &str = &trimmed[..trimmed.len() - 4];
        if conditional_branches_transfer(inner) {
            return Some(trimmed.to_owned());
        }
        if inner.contains(" else ") {
            return Some(format!("{inner} __pc = {fallthrough} end"));
        }
        return Some(format!("{inner} else __pc = {fallthrough} end"));
    }
    if !is_conditional && trimmed.contains("__pc") {
        return Some(trimmed.to_owned());
    }
    None
}

fn emit_trampoline(out: &mut String, depth: usize, blocks: &[EmitBlock], n: usize) {
    let entry: usize = blocks.first().map_or(n, |b: &EmitBlock| b.pc);
    indent(out, depth);
    push_fmt_line!(out, "local __pc = {entry}");
    indent(out, depth);
    out.push_str("while true do\n");
    for (bi, block) in blocks.iter().enumerate() {
        let fallthrough: usize = blocks.get(bi + 1).map_or(n, |b: &EmitBlock| b.pc);
        indent(out, depth + 1);
        let keyword: &str = if bi == 0 { "if" } else { "elseif" };
        push_fmt_line!(out, "{keyword} __pc == {} then", block.pc);
        let mut transferred: bool = false;
        for raw in &block.lines {
            let rewritten: String = rewrite_gotos(raw);
            if let Some(transfer) = finalize_transfer(&rewritten, fallthrough) {
                indent(out, depth + 2);
                out.push_str(transfer.trim_start());
                out.push('\n');
                transferred = true;
                break;
            }
            indent(out, depth + 2);
            out.push_str(rewritten.trim_start());
            out.push('\n');
        }
        if !transferred {
            indent(out, depth + 2);
            push_fmt_line!(out, "__pc = {fallthrough}");
        }
    }
    indent(out, depth + 1);
    push_fmt_line!(out, "else return end");
    indent(out, depth);
    out.push_str("end\n");
}

fn consumed_instrs(chunk: &IbChunk, optable: &BTreeMap<u16, Vec<IbOpcode>>) -> BTreeSet<usize> {
    let mut consumed: BTreeSet<usize> = BTreeSet::new();
    let n: usize = chunk.instrs.len();
    let mut pc: usize = 0;
    while pc < n {
        if consumed.contains(&pc) {
            pc += 1;
            continue;
        }
        let ins: &IbInstr = &chunk.instrs[pc];
        let op: IbOpcode = op_of(optable, ins.op);
        if matches!(op, IbOpcode::Closure) {
            let count: usize = closure_capture_count(ins, pc, n);
            for k in 1..=count {
                consumed.insert(pc + k);
            }
            pc += 1;
            continue;
        }
        let slen: usize = super_len(optable, ins.op);
        if slen > 1 {
            for k in 1..slen {
                consumed.insert(pc + k);
            }
            pc += slen;
            continue;
        }
        pc += 1;
    }
    consumed
}

fn jump_targets(chunk: &IbChunk, optable: &BTreeMap<u16, Vec<IbOpcode>>) -> BTreeSet<usize> {
    let mut set: BTreeSet<usize> = BTreeSet::new();
    let consumed: BTreeSet<usize> = consumed_instrs(chunk, optable);
    for (pc, ins) in chunk.instrs.iter().enumerate() {
        if consumed.contains(&pc) {
            continue;
        }
        let ops: &[IbOpcode] = optable
            .get(&ins.op)
            .map_or(&[IbOpcode::Unknown][..], |v: &Vec<IbOpcode>| v.as_slice());
        for (k, op) in ops.iter().enumerate() {
            let sub_pc: usize = pc + k;
            let sub_ins: &IbInstr = chunk.instrs.get(sub_pc).unwrap_or(ins);
            collect_targets(*op, sub_ins, sub_pc, &mut set);
        }
    }
    set
}

fn collect_targets(op: IbOpcode, ins: &IbInstr, pc: usize, set: &mut BTreeSet<usize>) {
    match op {
        IbOpcode::Jmp | IbOpcode::ForLoop | IbOpcode::ForPrep if ins.b >= 0 => {
            set.insert(ins.b as usize);
        }
        IbOpcode::Eq
        | IbOpcode::Lt
        | IbOpcode::Le
        | IbOpcode::Compare(_)
        | IbOpcode::Test
        | IbOpcode::TestC
        | IbOpcode::TForLoop => {
            if ins.b >= 0 {
                set.insert(ins.b as usize);
            }
            set.insert(pc + 2);
        }
        IbOpcode::LoadBoolC => {
            set.insert(pc + 2);
        }
        _ => {}
    }
}

fn const_repr(k: &LuaConstant) -> String {
    match k {
        LuaConstant::Nil => "nil".to_owned(),
        LuaConstant::Bool(b) => b.to_string(),
        LuaConstant::Integer(i) => i.to_string(),
        LuaConstant::Number(n) => format_number(*n),
        LuaConstant::Str(s) => lua_string(s),
        _ => "nil".to_owned(),
    }
}

fn format_number(n: f64) -> String {
    if n.is_finite() && n.fract() == 0.0 && n.abs() < 1e15 {
        format!("{}", n as i64)
    } else {
        let s: String = format!("{n:?}");
        s
    }
}

fn lua_string(s: &str) -> String {
    let mut out: String = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                push_fmt(&mut out, format_args!("\\{}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn ib_const(chunk: &IbChunk, idx1: i64) -> Option<&LuaConstant> {
    let i: usize = usize::try_from(idx1 - 1).ok()?;
    chunk.constants.get(i)
}

fn operand_const_or_reg(chunk: &IbChunk, value: i64, is_const: bool) -> String {
    if is_const {
        ib_const(chunk, value).map_or_else(|| "nil".to_owned(), const_repr)
    } else {
        format!("R[{value}]")
    }
}

fn mask_ra(ins: &IbInstr) -> bool {
    ins.mask & 1 != 0
}
fn mask_rb(ins: &IbInstr) -> bool {
    ins.mask & 2 != 0
}
fn mask_rc(ins: &IbInstr) -> bool {
    ins.mask & 4 != 0
}

fn b_operand(chunk: &IbChunk, ins: &IbInstr) -> String {
    operand_const_or_reg(chunk, ins.b, mask_rb(ins))
}
fn c_operand(chunk: &IbChunk, ins: &IbInstr) -> String {
    operand_const_or_reg(chunk, ins.c, mask_rc(ins))
}
fn a_operand(chunk: &IbChunk, ins: &IbInstr) -> String {
    operand_const_or_reg(chunk, ins.a, mask_ra(ins))
}

fn emit_instr(
    op: IbOpcode,
    ins: &IbInstr,
    pc: usize,
    chunk: &IbChunk,
    optable: &BTreeMap<u16, Vec<IbOpcode>>,
    proto_names: &[String],
    out: &mut String,
    depth: usize,
) {
    let a: i64 = ins.a;
    macro_rules! line {
        ($($arg:tt)*) => {{
            indent(out, depth);
            push_fmt_line!(out, $($arg)*);
        }};
    }
    match op {
        IbOpcode::Move => line!("R[{a}] = R[{}]", ins.b),
        IbOpcode::LoadK => line!(
            "R[{a}] = {}",
            ib_const(chunk, ins.b).map_or_else(|| "nil".to_owned(), const_repr)
        ),
        IbOpcode::LoadBool | IbOpcode::LoadBoolC => {
            line!("R[{a}] = {}", ins.b != 0);
            if matches!(op, IbOpcode::LoadBoolC) {
                line!("goto L{}", pc + 2);
            }
        }
        IbOpcode::LoadNil => line!("for i = {a}, {} do R[i] = nil end", ins.b),
        IbOpcode::GetGlobal => {
            let name: String = ib_const(chunk, ins.b).map_or_else(|| "nil".to_owned(), const_name);
            line!("R[{a}] = __ENV[{name}]");
        }
        IbOpcode::SetGlobal => {
            let name: String = ib_const(chunk, ins.b).map_or_else(|| "nil".to_owned(), const_name);
            line!("__ENV[{name}] = R[{a}]");
        }
        IbOpcode::GetTable => line!("R[{a}] = R[{}][{}]", ins.b, c_operand(chunk, ins)),
        IbOpcode::SetTable => line!(
            "R[{a}][{}] = {}",
            b_operand(chunk, ins),
            c_operand(chunk, ins)
        ),
        IbOpcode::NewTable => line!("R[{a}] = {{}}"),
        IbOpcode::Self_ => {
            line!("R[{}] = R[{}]", a + 1, ins.b);
            line!("R[{a}] = R[{}][{}]", ins.b, c_operand(chunk, ins));
        }
        IbOpcode::Add => line!(
            "R[{a}] = ({} + {})",
            b_operand(chunk, ins),
            c_operand(chunk, ins)
        ),
        IbOpcode::Sub => line!(
            "R[{a}] = ({} - {})",
            b_operand(chunk, ins),
            c_operand(chunk, ins)
        ),
        IbOpcode::Mul => line!(
            "R[{a}] = ({} * {})",
            b_operand(chunk, ins),
            c_operand(chunk, ins)
        ),
        IbOpcode::Div => line!(
            "R[{a}] = ({} / {})",
            b_operand(chunk, ins),
            c_operand(chunk, ins)
        ),
        IbOpcode::Mod => line!(
            "R[{a}] = ({} % {})",
            b_operand(chunk, ins),
            c_operand(chunk, ins)
        ),
        IbOpcode::Pow => line!(
            "R[{a}] = ({} ^ {})",
            b_operand(chunk, ins),
            c_operand(chunk, ins)
        ),
        IbOpcode::Unm => line!("R[{a}] = -R[{}]", ins.b),
        IbOpcode::Not => line!("R[{a}] = (not R[{}])", ins.b),
        IbOpcode::Len => line!("R[{a}] = #R[{}]", ins.b),
        IbOpcode::Concat => {
            line!(
                "do local __s = R[{}] for __i = {} + 1, {} do __s = __s .. R[__i] end R[{a}] = __s end",
                ins.b,
                ins.b,
                ins.c
            );
        }
        IbOpcode::Jmp => line!("goto L{}", ins.b),
        IbOpcode::Eq => emit_compare(
            out,
            depth,
            "==",
            a_operand(chunk, ins),
            c_operand(chunk, ins),
            ins.b,
            pc,
        ),
        IbOpcode::Lt => emit_compare(
            out,
            depth,
            "<",
            a_operand(chunk, ins),
            c_operand(chunk, ins),
            ins.b,
            pc,
        ),
        IbOpcode::Le => emit_compare(
            out,
            depth,
            "<=",
            a_operand(chunk, ins),
            c_operand(chunk, ins),
            ins.b,
            pc,
        ),
        IbOpcode::Compare(form) => emit_compare_form(
            out,
            depth,
            form,
            a_operand(chunk, ins),
            c_operand(chunk, ins),
            ins.b,
            pc,
        ),
        IbOpcode::Test => line!("if R[{a}] then goto L{} else goto L{} end", pc + 2, ins.b),
        IbOpcode::TestC => line!(
            "if not R[{a}] then goto L{} else goto L{} end",
            pc + 2,
            ins.b
        ),
        IbOpcode::Call(form) => emit_call(out, depth, a, ins, form),
        IbOpcode::TailCall => emit_call(
            out,
            depth,
            a,
            ins,
            CallForm {
                b: ArgForm::Fixed,
                c: RetCount::None,
            },
        ),
        IbOpcode::Return(form) => emit_return(out, depth, a, ins, form),
        IbOpcode::ForPrep => {
            let lim: i64 = a + 1;
            let step: i64 = a + 2;
            let idx: i64 = a + 3;
            line!(
                "if (R[{step}] > 0 and R[{a}] > R[{lim}]) or (R[{step}] <= 0 and R[{a}] < R[{lim}]) then goto L{} else R[{idx}] = R[{a}] end",
                ins.b
            );
        }
        IbOpcode::ForLoop => {
            let lim: i64 = a + 1;
            let step: i64 = a + 2;
            let idx: i64 = a + 3;
            line!("R[{a}] = R[{a}] + R[{step}]");
            line!(
                "if (R[{step}] > 0 and R[{a}] <= R[{lim}]) or (R[{step}] <= 0 and R[{a}] >= R[{lim}]) then R[{idx}] = R[{a}] goto L{} end",
                ins.b
            );
        }
        IbOpcode::SetList => {
            line!(
                "for __i = {} + 1, {} do R[{a}][__i - {a}] = R[__i] end",
                a,
                ins.b
            );
        }
        IbOpcode::ClosureNu => {
            let idx: usize = usize::try_from(ins.b.max(0)).unwrap_or(0);
            let name: &str = proto_names.get(idx).map_or("nil", |s: &String| s.as_str());
            line!("R[{a}] = (function(...) return {name}({{}}, ...) end)");
        }
        IbOpcode::Closure => {
            let idx: usize = usize::try_from(ins.b.max(0)).unwrap_or(0);
            let name: &str = proto_names.get(idx).map_or("nil", |s: &String| s.as_str());
            let count: usize = closure_capture_count(ins, pc, chunk.instrs.len());
            let mut cells: Vec<String> = Vec::with_capacity(count);
            for k in 0..count {
                let pseudo: Option<&IbInstr> =
                    chunk.instrs.get(pc.saturating_add(1).saturating_add(k));
                let cell: String = if let Some(p) = pseudo {
                    let pop: IbOpcode = op_of(optable, p.op);
                    if matches!(pop, IbOpcode::GetUpval) {
                        format!("__up[{}]", p.b)
                    } else {
                        format!("{{R, {}}}", p.b)
                    }
                } else {
                    "{R, 0}".to_owned()
                };
                cells.push(format!("[{k}] = {cell}"));
            }
            let up_table: String = format!("{{ {} }}", cells.join(", "));
            line!("R[{a}] = (function(...) return {name}({up_table}, ...) end)");
        }
        IbOpcode::TForLoop => {
            let cb: i64 = a + 2;
            line!(
                "do local __res = {{ R[{a}](R[{}], R[{cb}]) }} for __i = 1, {} do R[{cb} + __i] = __res[__i] end if __res[1] ~= nil then R[{cb}] = __res[1] goto L{} else goto L{} end end",
                a + 1,
                ins.c,
                ins.b,
                pc + 2
            );
        }
        IbOpcode::Vararg => {
            line!(
                "do local __n = select('#', ...) for __i = 0, __n - 1 do R[{a} + __i] = select(__i + 1, ...) end top = {a} + __n - 1 end"
            );
        }
        IbOpcode::GetUpval => line!("R[{a}] = __up[{}][1][__up[{}][2]]", ins.b, ins.b),
        IbOpcode::SetUpval => line!("__up[{}][1][__up[{}][2]] = R[{a}]", ins.b, ins.b),
        IbOpcode::Unknown => {
            line!("-- unhandled opcode vindex {} ({})", ins.op, op.label());
        }
    }
}

fn const_name(k: &LuaConstant) -> String {
    match k {
        LuaConstant::Str(s) => lua_string(s),
        other => const_repr(other),
    }
}

fn emit_compare(
    out: &mut String,
    depth: usize,
    sym: &str,
    left: String,
    right: String,
    target: i64,
    pc: usize,
) {
    indent(out, depth);
    push_fmt_line!(
        out,
        "if ({left} {sym} {right}) then goto L{} else goto L{target} end",
        pc + 2
    );
}

fn emit_compare_form(
    out: &mut String,
    depth: usize,
    form: CmpForm,
    left: String,
    right: String,
    target: i64,
    pc: usize,
) {
    let sym: &str = form.op.lua_symbol();
    let fallthrough: usize = pc + 2;
    indent(out, depth);
    if form.jump_when_true {
        push_fmt_line!(
            out,
            "if ({left} {sym} {right}) then goto L{target} else goto L{fallthrough} end"
        );
    } else {
        push_fmt_line!(
            out,
            "if ({left} {sym} {right}) then goto L{fallthrough} else goto L{target} end"
        );
    }
}

fn emit_call(out: &mut String, depth: usize, a: i64, ins: &IbInstr, form: CallForm) {
    indent(out, depth);
    let args: String = match form.b {
        ArgForm::Fixed => {
            let last: i64 = ins.b - (ins.a - 1) + a - 1;
            range_args(a + 1, last)
        }
        ArgForm::Two => format!("R[{}]", a + 1),
        ArgForm::None => String::new(),
        ArgForm::Top => format!("unpack(R, {}, top)", a + 1),
    };
    match form.c {
        RetCount::One => {
            push_fmt_line!(out, "R[{a}]({args})");
        }
        RetCount::Single => {
            push_fmt_line!(out, "R[{a}] = R[{a}]({args})");
        }
        RetCount::Fixed => {
            let last: i64 = ins.c - (ins.a - 2) + a - 1;
            push_fmt_line!(
                out,
                "do local __r = {{ R[{a}]({args}) }} local __k = 0 for __i = {a}, {last} do __k = __k + 1 R[__i] = __r[__k] end end"
            );
        }
        RetCount::None | RetCount::Top => {
            push_fmt_line!(
                out,
                "do local __r = {{ R[{a}]({args}) }} local __k = 0 for __i = {a}, {a} + #__r - 1 do __k = __k + 1 R[__i] = __r[__k] end top = {a} + #__r - 1 end"
            );
        }
    }
}

fn range_args(first: i64, last: i64) -> String {
    if last < first {
        return String::new();
    }
    let mut parts: Vec<String> = Vec::new();
    for r in first..=last {
        parts.push(format!("R[{r}]"));
    }
    parts.join(", ")
}

fn emit_return(out: &mut String, depth: usize, a: i64, ins: &IbInstr, form: RetForm) {
    indent(out, depth);
    match form {
        RetForm::None => {
            out.push_str("do return end\n");
        }
        RetForm::Two => {
            push_fmt_line!(out, "do return R[{a}] end");
        }
        RetForm::Three => {
            push_fmt_line!(out, "do return R[{a}], R[{}] end", a + 1);
        }
        RetForm::Fixed => {
            let last: i64 = a + ins.b + 2 - 1;
            push_fmt_line!(out, "do return {} end", range_args(a, last));
        }
        RetForm::Top => {
            push_fmt_line!(out, "do return unpack(R, {a}, top) end");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::obfuscator::ironbrew2_real::IbType;

    fn instr(op: u16, b: i64, c: i64) -> IbInstr {
        IbInstr {
            itype: IbType::Abc,
            mask: 0,
            op,
            a: 0,
            b,
            c,
        }
    }

    #[test]
    fn closure_capture_count_uses_available_pseudos() {
        let chunk: IbChunk = IbChunk {
            constants: Vec::new(),
            param_count: 0,
            instrs: vec![instr(1, 0, 1024), instr(2, 7, 0)],
            functions: Vec::new(),
        };
        let mut optable: BTreeMap<u16, Vec<IbOpcode>> = BTreeMap::new();
        optable.insert(1, vec![IbOpcode::Closure]);
        optable.insert(2, vec![IbOpcode::GetUpval]);

        let out: String = emit_program(&chunk, &optable);

        assert!(out.contains("[0] = __up[7]"));
        assert!(!out.contains("[1] = {R, 0}"));
    }
}
