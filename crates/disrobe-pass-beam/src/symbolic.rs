use std::collections::BTreeMap;

use serde::Serialize;

use crate::chunks::{Chunks, FunEntry, ImportEntry, LineChunk, LiteralChunk, StringTable};
use crate::disasm::{self, Disassembly, Instruction, Operand};
use crate::error::{Error, Result};
use crate::etf::Term;
use crate::file::BeamFile;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SymbolicFunction {
    pub name: String,
    pub arity: u32,
    pub entry_label: u32,
    pub instructions: Vec<SymbolicInstruction>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SymbolicInstruction {
    pub offset: usize,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SymbolicModule {
    pub module: String,
    pub functions: Vec<SymbolicFunction>,
}

struct ResolveCtx<'a> {
    atoms: &'a crate::chunks::AtomTable,
    imports: &'a [ImportEntry],
    literals: Option<&'a LiteralChunk>,
    strings: Option<&'a StringTable>,
    line: Option<&'a LineChunk>,
    funs: &'a [FunEntry],
    module: &'a str,
    label_to_mfa: BTreeMap<u32, (String, u32)>,
}

impl ResolveCtx<'_> {
    fn atom(&self, index: u32) -> String {
        if index == 0 {
            return "nil".to_owned();
        }
        match self.atoms.get(index) {
            Some(name) => render_atom_literal(name),
            None => format!("atom_{index}"),
        }
    }

    fn raw_atom(&self, index: u32) -> String {
        self.atoms.get(index).map_or_else(
            || format!("atom_{index}"),
            |name: &str| render_atom_literal(name),
        )
    }

    fn import(&self, index: u32) -> (String, String, u32) {
        match self.imports.get(index as usize) {
            Some(entry) => (
                self.atoms
                    .get(entry.module_atom_index)
                    .unwrap_or("?")
                    .to_owned(),
                self.atoms
                    .get(entry.function_atom_index)
                    .unwrap_or("?")
                    .to_owned(),
                entry.arity,
            ),
            None => ("?".to_owned(), "?".to_owned(), 0),
        }
    }

    fn literal(&self, index: u32) -> String {
        let term: Option<&Term> = self
            .literals
            .and_then(|c: &LiteralChunk| c.literals.get(index as usize));
        match term {
            Some(Term::Float(f)) => format!("{{float,{}}}", render_float(*f)),
            Some(t) => format!("{{literal,{}}}", render_term(t)),
            None => format!("{{literal,index_{index}}}"),
        }
    }

    fn line_location(&self, index: u32) -> String {
        if index == 0 {
            return "{line,[]}".to_owned();
        }
        let Some(chunk) = self.line else {
            return "{line,[]}".to_owned();
        };
        let Some(item) = chunk.items.get((index - 1) as usize) else {
            return "{line,[]}".to_owned();
        };
        let default_file: String = strip_elixir_prefix(self.module);
        let file: String = chunk
            .filenames
            .get((item.filename_index.saturating_sub(1)) as usize)
            .map_or(default_file, |s: &String| s.clone());
        format!(
            "{{line,[{{location,\"{}\",{}}}]}}",
            escape_string(&file),
            item.line
        )
    }
}

pub fn symbolic_disassemble(beam: &BeamFile) -> Result<SymbolicModule> {
    let chunks: &Chunks = &beam.chunks;
    let code: &crate::chunks::CodeChunk =
        chunks.code.as_ref().ok_or(Error::MissingChunk("Code"))?;
    let module: String = chunks
        .atoms
        .module_name()
        .ok_or(Error::MissingChunk("Atom (module name)"))?
        .to_owned();
    let disassembly: Disassembly = disasm::disassemble(code)?;
    let instrs: &[Instruction] = &disassembly.instructions;
    let label_to_mfa: BTreeMap<u32, (String, u32)> = build_label_mfa(instrs, chunks);
    let ctx: ResolveCtx<'_> = ResolveCtx {
        atoms: &chunks.atoms,
        imports: &chunks.imports,
        literals: chunks.literals.as_ref(),
        strings: chunks.strings.as_ref(),
        line: chunks.line.as_ref(),
        funs: &chunks.funs,
        module: &module,
        label_to_mfa,
    };
    let functions: Vec<SymbolicFunction> = split_symbolic_functions(instrs, &ctx);
    Ok(SymbolicModule { module, functions })
}

fn build_label_mfa(instrs: &[Instruction], chunks: &Chunks) -> BTreeMap<u32, (String, u32)> {
    let mut map: BTreeMap<u32, (String, u32)> = BTreeMap::new();
    let mut current: Option<(String, u32)> = None;
    for instr in instrs {
        match instr.name {
            "func_info" => {
                let fun_atom: u32 = match instr.operands.get(1) {
                    Some(Operand::Atom(a)) => *a,
                    _ => 0,
                };
                let arity: u32 = match instr.operands.get(2) {
                    Some(Operand::Literal(v)) => u32::try_from(*v).unwrap_or(0),
                    _ => 0,
                };
                let name: String = chunks.atoms.get(fun_atom).unwrap_or("?").to_owned();
                current = Some((name, arity));
            }
            "label" => {
                if let (Some((name, arity)), Some(Operand::Literal(l))) =
                    (&current, instr.operands.first())
                    && let Ok(label) = u32::try_from(*l)
                {
                    map.insert(label, (name.clone(), *arity));
                }
            }
            _ => {}
        }
    }
    map
}

fn split_symbolic_functions(instrs: &[Instruction], ctx: &ResolveCtx<'_>) -> Vec<SymbolicFunction> {
    let mut functions: Vec<SymbolicFunction> = Vec::new();
    let mut idx: usize = 0;
    while idx < instrs.len() {
        if instrs[idx].name != "func_info" {
            idx += 1;
            continue;
        }
        let func_info: &Instruction = &instrs[idx];
        let fun_atom: u32 = match func_info.operands.get(1) {
            Some(Operand::Atom(a)) => *a,
            _ => 0,
        };
        let arity: u32 = match func_info.operands.get(2) {
            Some(Operand::Literal(v)) => u32::try_from(*v).unwrap_or(0),
            _ => 0,
        };
        let name: String = ctx.atoms.get(fun_atom).unwrap_or("__unknown__").to_owned();
        let preamble_start: usize = back_to_preamble(instrs, idx);
        let body_end: usize = next_func_boundary(instrs, idx + 1);
        let entry_label: u32 = instrs[idx + 1..body_end]
            .iter()
            .find(|i: &&Instruction| i.name == "label")
            .and_then(|i: &Instruction| match i.operands.first() {
                Some(Operand::Literal(l)) => u32::try_from(*l).ok(),
                _ => None,
            })
            .unwrap_or(0);
        let mut rendered: Vec<SymbolicInstruction> = Vec::new();
        for instr in &instrs[preamble_start..body_end] {
            if instr.name == "int_code_end" {
                continue;
            }
            rendered.push(SymbolicInstruction {
                offset: instr.offset,
                text: resolve_instruction(instr, ctx),
            });
        }
        functions.push(SymbolicFunction {
            name,
            arity,
            entry_label,
            instructions: rendered,
        });
        idx = body_end;
    }
    functions
}

fn back_to_preamble(instrs: &[Instruction], func_info_at: usize) -> usize {
    let mut start: usize = func_info_at;
    while start > 0 {
        let prev: &str = instrs[start - 1].name;
        if prev == "label" || prev == "line" {
            start -= 1;
        } else {
            break;
        }
    }
    start
}

fn next_func_boundary(instrs: &[Instruction], from: usize) -> usize {
    let mut cursor: usize = from;
    while cursor < instrs.len() {
        if instrs[cursor].name == "func_info" {
            return back_to_preamble(instrs, cursor);
        }
        cursor += 1;
    }
    instrs.len()
}

fn resolve_instruction(instr: &Instruction, ctx: &ResolveCtx<'_>) -> String {
    let ops: &[Operand] = &instr.operands;
    match instr.name {
        "label" => format!("{{label,{}}}", lit_u(ops.first())),
        "func_info" => format!(
            "{{func_info,{{atom,{}}},{{atom,{}}},{}}}",
            mod_atom(ops.first(), ctx),
            ctx.raw_atom(atom_index(ops.get(1))),
            lit_u(ops.get(2))
        ),
        "int_code_end" => "int_code_end".to_owned(),
        "return" => "return".to_owned(),
        "send" => "send".to_owned(),
        "remove_message" => "remove_message".to_owned(),
        "timeout" => "timeout".to_owned(),
        "if_end" => "if_end".to_owned(),
        "on_load" => "on_load".to_owned(),
        "fclearerror" => "fclearerror".to_owned(),
        "build_stacktrace" => "build_stacktrace".to_owned(),
        "raw_raise" => "raw_raise".to_owned(),
        "nif_start" => "nif_start".to_owned(),
        "bs_init_writable" => "bs_init_writable".to_owned(),
        "line" => ctx.line_location(value_u_raw(ops.first())),
        "call" => format!(
            "{{call,{},{}}}",
            lit_u(ops.first()),
            mfa_of_label(ops.get(1), ctx)
        ),
        "call_only" => format!(
            "{{call_only,{},{}}}",
            lit_u(ops.first()),
            mfa_of_label(ops.get(1), ctx)
        ),
        "call_last" => format!(
            "{{call_last,{},{},{}}}",
            lit_u(ops.first()),
            mfa_of_label(ops.get(1), ctx),
            lit_u(ops.get(2))
        ),
        "call_ext" => format!(
            "{{call_ext,{},{}}}",
            lit_u(ops.first()),
            extfunc(value_u_index(ops.get(1)), ctx)
        ),
        "call_ext_only" => format!(
            "{{call_ext_only,{},{}}}",
            lit_u(ops.first()),
            extfunc(value_u_index(ops.get(1)), ctx)
        ),
        "call_ext_last" => format!(
            "{{call_ext_last,{},{},{}}}",
            lit_u(ops.first()),
            extfunc(value_u_index(ops.get(1)), ctx),
            lit_u(ops.get(2))
        ),
        "bif0" => bif(ctx, ops, 0),
        "bif1" => bif(ctx, ops, 1),
        "bif2" => bif(ctx, ops, 2),
        "bif3" => bif(ctx, ops, 3),
        "gc_bif1" => gc_bif(ctx, ops, 1),
        "gc_bif2" => gc_bif(ctx, ops, 2),
        "gc_bif3" => gc_bif(ctx, ops, 3),
        "fadd" | "fsub" | "fmul" | "fdiv" => float_bif(instr.name, ops, ctx),
        "fnegate" => format!(
            "{{bif,fnegate,{},[{}],{}}}",
            arg(ops.first(), ctx),
            arg(ops.get(1), ctx),
            arg(ops.get(2), ctx)
        ),
        "fmove" => format!(
            "{{fmove,{},{}}}",
            arg(ops.first(), ctx),
            arg(ops.get(1), ctx)
        ),
        "fconv" => format!(
            "{{fconv,{},{}}}",
            arg(ops.first(), ctx),
            arg(ops.get(1), ctx)
        ),
        "fcheckerror" => format!("{{fcheckerror,{}}}", arg(ops.first(), ctx)),
        "raise" => format!(
            "{{bif,raise,{{f,0}},[{},{}],{{x,0}}}}",
            arg(ops.first(), ctx),
            arg(ops.get(1), ctx)
        ),
        "bs_start_match3" => format!(
            "{{test,bs_start_match3,{},{},[{}],{}}}",
            arg(ops.first(), ctx),
            value_u(ops.get(2)),
            arg(ops.get(1), ctx),
            arg(ops.get(3), ctx)
        ),
        "bs_start_match2" => format!(
            "{{test,bs_start_match2,{},[{},{},{},{}]}}",
            arg(ops.first(), ctx),
            arg(ops.get(1), ctx),
            value_u(ops.get(2)),
            value_u(ops.get(3)),
            arg(ops.get(4), ctx)
        ),
        "bs_get_integer2" => bs_get2("bs_get_integer2", ops, ctx),
        "bs_get_binary2" => bs_get2("bs_get_binary2", ops, ctx),
        "bs_get_float2" => bs_get2("bs_get_float2", ops, ctx),
        "bs_skip_bits2" => format!(
            "{{test,bs_skip_bits2,{},[{},{},{},{}]}}",
            arg(ops.first(), ctx),
            arg(ops.get(1), ctx),
            arg(ops.get(2), ctx),
            value_u(ops.get(3)),
            field_flags(ops.get(4))
        ),
        "bs_test_tail2" => format!(
            "{{test,bs_test_tail2,{},[{},{}]}}",
            arg(ops.first(), ctx),
            arg(ops.get(1), ctx),
            value_u(ops.get(2))
        ),
        "bs_test_unit" => format!(
            "{{test,bs_test_unit,{},[{},{}]}}",
            arg(ops.first(), ctx),
            arg(ops.get(1), ctx),
            value_u(ops.get(2))
        ),
        "bs_match_string" => bs_match_string(ops, ctx),
        "bs_get_tail" => format!(
            "{{bs_get_tail,{},{},{}}}",
            arg(ops.first(), ctx),
            arg(ops.get(1), ctx),
            value_u(ops.get(2))
        ),
        "bs_get_position" => format!(
            "{{bs_get_position,{},{},{}}}",
            arg(ops.first(), ctx),
            arg(ops.get(1), ctx),
            value_u(ops.get(2))
        ),
        "bs_set_position" => format!(
            "{{bs_set_position,{},{}}}",
            arg(ops.first(), ctx),
            arg(ops.get(1), ctx)
        ),
        "call_fun2" => call_fun2(ops, ctx),
        "put_map_assoc" => put_map("put_map_assoc", ops, ctx),
        "put_map_exact" => put_map("put_map_exact", ops, ctx),
        "bs_create_bin" => bs_create_bin(ops, ctx),
        "bs_match" => bs_match(ops, ctx),
        "update_record" => format!(
            "{{update_record,{},{},{},{},{}}}",
            arg(ops.first(), ctx),
            value_u(ops.get(1)),
            arg(ops.get(2), ctx),
            arg(ops.get(3), ctx),
            list_arg(ops.get(4), ctx)
        ),
        "has_map_fields" => format!(
            "{{test,has_map_fields,{},{},{}}}",
            arg(ops.first(), ctx),
            arg(ops.get(1), ctx),
            list_arg(ops.get(2), ctx)
        ),
        "move" => format!(
            "{{move,{},{}}}",
            arg(ops.first(), ctx),
            arg(ops.get(1), ctx)
        ),
        "swap" => format!(
            "{{swap,{},{}}}",
            arg(ops.first(), ctx),
            arg(ops.get(1), ctx)
        ),
        "get_hd" => generic("get_hd", ops, ctx),
        "get_tl" => generic("get_tl", ops, ctx),
        "get_list" => generic("get_list", ops, ctx),
        "put_list" => generic("put_list", ops, ctx),
        "get_tuple_element" => format!(
            "{{get_tuple_element,{},{},{}}}",
            arg(ops.first(), ctx),
            value_u(ops.get(1)),
            arg(ops.get(2), ctx)
        ),
        "set_tuple_element" => format!(
            "{{set_tuple_element,{},{},{}}}",
            arg(ops.first(), ctx),
            arg(ops.get(1), ctx),
            value_u(ops.get(2))
        ),
        "put_tuple2" => format!(
            "{{put_tuple2,{},{}}}",
            arg(ops.first(), ctx),
            list_arg(ops.get(1), ctx)
        ),
        "put_tuple" => format!(
            "{{put_tuple,{},{}}}",
            value_u(ops.first()),
            arg(ops.get(1), ctx)
        ),
        "put" => format!("{{put,{}}}", arg(ops.first(), ctx)),
        "badmatch" => format!("{{badmatch,{}}}", arg(ops.first(), ctx)),
        "badrecord" => format!("{{badrecord,{}}}", arg(ops.first(), ctx)),
        "case_end" => format!("{{case_end,{}}}", arg(ops.first(), ctx)),
        "try_case_end" => format!("{{try_case_end,{}}}", arg(ops.first(), ctx)),
        "allocate" => two_u("allocate", ops),
        "allocate_zero" => two_u("allocate_zero", ops),
        "allocate_heap" => alloc_heap("allocate_heap", ops),
        "allocate_heap_zero" => alloc_heap("allocate_heap_zero", ops),
        "test_heap" => format!(
            "{{test_heap,{},{}}}",
            heap_need(ops.first()),
            value_u(ops.get(1))
        ),
        "init" => format!("{{init,{}}}", arg(ops.first(), ctx)),
        "init_yregs" => format!("{{init_yregs,{}}}", list_arg(ops.first(), ctx)),
        "deallocate" => format!("{{deallocate,{}}}", value_u(ops.first())),
        "trim" => two_u("trim", ops),
        "jump" => format!("{{jump,{}}}", arg(ops.first(), ctx)),
        "catch" => format!(
            "{{'catch',{},{}}}",
            arg(ops.first(), ctx),
            arg(ops.get(1), ctx)
        ),
        "catch_end" => format!("{{catch_end,{}}}", arg(ops.first(), ctx)),
        "try" => format!(
            "{{'try',{},{}}}",
            arg(ops.first(), ctx),
            arg(ops.get(1), ctx)
        ),
        "try_end" => format!("{{try_end,{}}}", arg(ops.first(), ctx)),
        "try_case" => format!("{{try_case,{}}}", arg(ops.first(), ctx)),
        "loop_rec" => generic("loop_rec", ops, ctx),
        "loop_rec_end" => format!("{{loop_rec_end,{}}}", arg(ops.first(), ctx)),
        "wait" => format!("{{wait,{}}}", arg(ops.first(), ctx)),
        "wait_timeout" => format!(
            "{{wait_timeout,{},{}}}",
            arg(ops.first(), ctx),
            arg(ops.get(1), ctx)
        ),
        "recv_mark" => format!("{{recv_mark,{}}}", arg(ops.first(), ctx)),
        "recv_set" => format!("{{recv_set,{}}}", arg(ops.first(), ctx)),
        "recv_marker_bind" => generic("recv_marker_bind", ops, ctx),
        "recv_marker_clear" => format!("{{recv_marker_clear,{}}}", arg(ops.first(), ctx)),
        "recv_marker_reserve" => format!("{{recv_marker_reserve,{}}}", arg(ops.first(), ctx)),
        "recv_marker_use" => format!("{{recv_marker_use,{}}}", arg(ops.first(), ctx)),
        "apply" => format!("{{apply,{}}}", value_u(ops.first())),
        "apply_last" => two_u("apply_last", ops),
        "call_fun" => format!("{{call_fun,{}}}", value_u(ops.first())),
        "select_val" => select("select_val", ops, ctx),
        "select_tuple_arity" => select("select_tuple_arity", ops, ctx),
        "make_fun2" => make_fun2(ops, ctx),
        "make_fun3" => make_fun3(ops, ctx),
        "get_map_elements" => format!(
            "{{get_map_elements,{},{},{}}}",
            arg(ops.first(), ctx),
            arg(ops.get(1), ctx),
            list_arg(ops.get(2), ctx)
        ),
        "is_lt" | "is_ge" | "is_eq" | "is_ne" | "is_eq_exact" | "is_ne_exact" | "is_integer"
        | "is_float" | "is_number" | "is_atom" | "is_pid" | "is_reference" | "is_port"
        | "is_nil" | "is_binary" | "is_list" | "is_nonempty_list" | "is_tuple" | "test_arity"
        | "is_function" | "is_boolean" | "is_function2" | "is_bitstr" | "is_map"
        | "is_tagged_tuple" => test(instr.name, ops, ctx),
        _ => generic(instr.name, ops, ctx),
    }
}

fn bif(ctx: &ResolveCtx<'_>, ops: &[Operand], argc: usize) -> String {
    let bif_name: String = match argc {
        0 => {
            let name: String = bif_name(value_u_index(ops.first()), ctx);
            return format!("{{bif,{name},nofail,[],{}}}", arg(ops.get(1), ctx));
        }
        _ => bif_name(value_u_index(ops.get(1)), ctx),
    };
    let fail: String = arg(ops.first(), ctx);
    let mut inner: Vec<String> = Vec::with_capacity(argc);
    for i in 0..argc {
        inner.push(arg(ops.get(2 + i), ctx));
    }
    let dst: String = arg(ops.get(2 + argc), ctx);
    format!("{{bif,{bif_name},{fail},[{}],{dst}}}", inner.join(","))
}

fn gc_bif(ctx: &ResolveCtx<'_>, ops: &[Operand], argc: usize) -> String {
    let fail: String = arg(ops.first(), ctx);
    let live: String = value_u(ops.get(1));
    let name: String = bif_name(value_u_index(ops.get(2)), ctx);
    let mut inner: Vec<String> = Vec::with_capacity(argc);
    for i in 0..argc {
        inner.push(arg(ops.get(3 + i), ctx));
    }
    let dst: String = arg(ops.get(3 + argc), ctx);
    format!(
        "{{gc_bif,{name},{fail},{live},[{}],{dst}}}",
        inner.join(",")
    )
}

fn test(name: &str, ops: &[Operand], ctx: &ResolveCtx<'_>) -> String {
    let fail: String = arg(ops.first(), ctx);
    let args: Vec<String> = ops[1..]
        .iter()
        .map(|o: &Operand| arg(Some(o), ctx))
        .collect();
    format!("{{test,{name},{fail},[{}]}}", args.join(","))
}

fn bs_create_bin(ops: &[Operand], ctx: &ResolveCtx<'_>) -> String {
    let fail: String = arg(ops.first(), ctx);
    let heap: String = value_u(ops.get(1));
    let live: String = value_u(ops.get(2));
    let unit: String = value_u(ops.get(3));
    let dst: String = arg(ops.get(4), ctx);
    let segments: &[Operand] = match ops.get(5) {
        Some(Operand::List(items)) => items.as_slice(),
        _ => &[],
    };
    let resolved: String = resolve_create_bin_segments(segments, ctx);
    format!("{{bs_create_bin,{fail},{heap},{live},{unit},{dst},{{list,{resolved}}}}}")
}

fn resolve_create_bin_segments(segments: &[Operand], ctx: &ResolveCtx<'_>) -> String {
    let mut parts: Vec<String> = Vec::new();
    let mut idx: usize = 0;
    while idx + 6 <= segments.len() {
        let chunk: &[Operand] = &segments[idx..idx + 6];
        let is_string: bool = matches!(
            chunk.first(),
            Some(Operand::Atom(a)) if ctx.atoms.get(*a) == Some("string")
        );
        if is_string {
            let offset: u32 = value_u_raw(Some(&chunk[4]));
            let size: u32 = match &chunk[5] {
                Operand::SignedInteger(v) => u32::try_from(*v).unwrap_or(0),
                Operand::Literal(v) => u32::try_from(*v).unwrap_or(0),
                _ => 0,
            };
            parts.push(arg(Some(&chunk[0]), ctx));
            parts.push(arg(Some(&chunk[1]), ctx));
            parts.push(arg(Some(&chunk[2]), ctx));
            parts.push(arg(Some(&chunk[3]), ctx));
            parts.push(string_bytes(ctx, offset, size));
            parts.push(arg(Some(&chunk[5]), ctx));
        } else {
            for op in chunk {
                parts.push(arg(Some(op), ctx));
            }
        }
        idx += 6;
    }
    for op in &segments[idx..] {
        parts.push(arg(Some(op), ctx));
    }
    format!("[{}]", parts.join(","))
}

fn bs_get2(name: &str, ops: &[Operand], ctx: &ResolveCtx<'_>) -> String {
    let fail: String = arg(ops.first(), ctx);
    let ms: String = arg(ops.get(1), ctx);
    let live: String = value_u(ops.get(2));
    let size: String = arg(ops.get(3), ctx);
    let unit: String = value_u(ops.get(4));
    let flags: String = field_flags(ops.get(5));
    let dst: String = arg(ops.get(6), ctx);
    format!("{{test,{name},{fail},{live},[{ms},{size},{unit},{flags}],{dst}}}")
}

fn bs_match_string(ops: &[Operand], ctx: &ResolveCtx<'_>) -> String {
    let fail: String = arg(ops.first(), ctx);
    let ms: String = arg(ops.get(1), ctx);
    let bits: u32 = value_u_raw(ops.get(2));
    let offset: u32 = value_u_raw(ops.get(3));
    let len: usize = (bits as usize).div_ceil(8);
    let string: String = string_bytes(ctx, offset, u32::try_from(len).unwrap_or(0));
    format!("{{test,bs_match_string,{fail},[{ms},{bits},{string}]}}")
}

fn call_fun2(ops: &[Operand], ctx: &ResolveCtx<'_>) -> String {
    let tag: String = match ops.first() {
        Some(Operand::Literal(index)) => {
            let lambda: u32 = u32::try_from(*index).unwrap_or(0);
            match ctx.funs.iter().find(|f: &&FunEntry| f.index == lambda) {
                Some(entry) => format!("{{f,{}}}", entry.label),
                None => value_u(ops.first()),
            }
        }
        other => arg(other, ctx),
    };
    let arity: String = value_u(ops.get(1));
    let func: String = arg(ops.get(2), ctx);
    format!("{{call_fun2,{tag},{arity},{func}}}")
}

fn field_flags(op: Option<&Operand>) -> String {
    let raw: u32 = value_u_raw(op);
    if raw == 0 {
        return "{field_flags,[]}".to_owned();
    }
    let mut flags: Vec<&str> = Vec::with_capacity(3);
    if raw & 0x02 != 0 {
        flags.push("little");
    }
    if raw & 0x04 != 0 {
        flags.push("signed");
    }
    if raw & 0x10 != 0 {
        flags.push("native");
    }
    format!("{{field_flags,[{}]}}", flags.join(","))
}

fn bs_match(ops: &[Operand], ctx: &ResolveCtx<'_>) -> String {
    let fail: String = arg(ops.first(), ctx);
    let context: String = arg(ops.get(1), ctx);
    let commands: &[Operand] = match ops.get(2) {
        Some(Operand::List(items)) => items.as_slice(),
        _ => &[],
    };
    let resolved: String = resolve_bs_match_commands(commands, ctx);
    format!("{{bs_match,{fail},{context},{{commands,{resolved}}}}}")
}

fn resolve_bs_match_commands(commands: &[Operand], ctx: &ResolveCtx<'_>) -> String {
    let mut parts: Vec<String> = Vec::new();
    let mut idx: usize = 0;
    while idx < commands.len() {
        let tag: Option<&str> = match &commands[idx] {
            Operand::Atom(a) => ctx.atoms.get(*a),
            _ => None,
        };
        match tag {
            Some("ensure_at_least") if idx + 2 < commands.len() => {
                parts.push(format!(
                    "{{ensure_at_least,{},{}}}",
                    value_u(commands.get(idx + 1)),
                    value_u(commands.get(idx + 2))
                ));
                idx += 3;
            }
            Some("ensure_exactly") if idx + 1 < commands.len() => {
                parts.push(format!(
                    "{{ensure_exactly,{}}}",
                    value_u(commands.get(idx + 1))
                ));
                idx += 2;
            }
            Some("integer" | "binary") if idx + 5 < commands.len() => {
                let kind: &str = tag.unwrap_or("integer");
                parts.push(format!(
                    "{{{kind},{},{},{},{},{}}}",
                    value_u(commands.get(idx + 1)),
                    match_flags(commands.get(idx + 2), ctx),
                    arg(commands.get(idx + 3), ctx),
                    value_u(commands.get(idx + 4)),
                    arg(commands.get(idx + 5), ctx)
                ));
                idx += 6;
            }
            Some("=:=") if idx + 3 < commands.len() => {
                parts.push(format!(
                    "{{'=:=',{},{},{}}}",
                    arg(commands.get(idx + 1), ctx),
                    value_u(commands.get(idx + 2)),
                    arg(commands.get(idx + 3), ctx)
                ));
                idx += 4;
            }
            Some("skip") if idx + 1 < commands.len() => {
                parts.push(format!("{{skip,{}}}", value_u(commands.get(idx + 1))));
                idx += 2;
            }
            Some("get_tail") if idx + 3 < commands.len() => {
                parts.push(format!(
                    "{{get_tail,{},{},{}}}",
                    value_u(commands.get(idx + 1)),
                    value_u(commands.get(idx + 2)),
                    arg(commands.get(idx + 3), ctx)
                ));
                idx += 4;
            }
            _ => {
                parts.push(arg(commands.get(idx), ctx));
                idx += 1;
            }
        }
    }
    format!("[{}]", parts.join(","))
}

fn match_flags(op: Option<&Operand>, ctx: &ResolveCtx<'_>) -> String {
    match op {
        Some(Operand::Atom(0)) => "{literal,[]}".to_owned(),
        Some(Operand::LiteralIndex(i)) => ctx.literal(*i),
        other => arg(other, ctx),
    }
}

fn string_bytes(ctx: &ResolveCtx<'_>, offset: u32, size: u32) -> String {
    let bytes: &[u8] = ctx
        .strings
        .and_then(|s: &StringTable| s.slice(offset as usize, size as usize))
        .unwrap_or(&[]);
    let inner: String = bytes
        .iter()
        .map(|b: &u8| b.to_string())
        .collect::<Vec<_>>()
        .join(",");
    format!("{{string,<<{inner}>>}}")
}

fn float_bif(name: &str, ops: &[Operand], ctx: &ResolveCtx<'_>) -> String {
    format!(
        "{{bif,{name},{},[{},{}],{}}}",
        arg(ops.first(), ctx),
        arg(ops.get(1), ctx),
        arg(ops.get(2), ctx),
        arg(ops.get(3), ctx)
    )
}

fn put_map(name: &str, ops: &[Operand], ctx: &ResolveCtx<'_>) -> String {
    format!(
        "{{{name},{},{},{},{},{}}}",
        arg(ops.first(), ctx),
        arg(ops.get(1), ctx),
        arg(ops.get(2), ctx),
        value_u(ops.get(3)),
        list_arg(ops.get(4), ctx)
    )
}

fn select(name: &str, ops: &[Operand], ctx: &ResolveCtx<'_>) -> String {
    let src: String = arg(ops.first(), ctx);
    let fail: String = arg(ops.get(1), ctx);
    let list: String = list_arg(ops.get(2), ctx);
    format!("{{{name},{src},{fail},{list}}}")
}

fn make_fun2(ops: &[Operand], ctx: &ResolveCtx<'_>) -> String {
    let lambda: u32 = value_u_raw(ops.first());
    let (mfa, old_uniq, num_free): (String, u32, u32) = lambda_lookup(lambda, ctx);
    format!("{{make_fun2,{mfa},{lambda},{old_uniq},{num_free}}}")
}

fn make_fun3(ops: &[Operand], ctx: &ResolveCtx<'_>) -> String {
    let lambda: u32 = value_u_raw(ops.first());
    let (mfa, old_uniq, _num_free): (String, u32, u32) = lambda_lookup(lambda, ctx);
    let dst: String = arg(ops.get(1), ctx);
    let env: String = list_arg(ops.get(2), ctx);
    format!("{{make_fun3,{mfa},{lambda},{old_uniq},{dst},{env}}}")
}

fn lambda_lookup(lambda: u32, ctx: &ResolveCtx<'_>) -> (String, u32, u32) {
    match ctx.funs.iter().find(|f: &&FunEntry| f.index == lambda) {
        Some(entry) => {
            let fun: &str = ctx.atoms.get(entry.function_atom_index).unwrap_or("?");
            (
                format!(
                    "{{{},{},{}}}",
                    render_atom_literal(ctx.module),
                    render_atom_literal(fun),
                    entry.arity
                ),
                entry.old_uniq,
                entry.num_free,
            )
        }
        None => (
            format!("{{{},'?',0}}", render_atom_literal(ctx.module)),
            0,
            0,
        ),
    }
}

fn generic(name: &str, ops: &[Operand], ctx: &ResolveCtx<'_>) -> String {
    if ops.is_empty() {
        return name.to_owned();
    }
    let args: Vec<String> = ops.iter().map(|o: &Operand| arg(Some(o), ctx)).collect();
    format!("{{{name},{}}}", args.join(","))
}

fn two_u(name: &str, ops: &[Operand]) -> String {
    format!(
        "{{{name},{},{}}}",
        value_u(ops.first()),
        value_u(ops.get(1))
    )
}

fn alloc_heap(name: &str, ops: &[Operand]) -> String {
    format!(
        "{{{name},{},{},{}}}",
        value_u(ops.first()),
        heap_need(ops.get(1)),
        value_u(ops.get(2))
    )
}

fn arg(op: Option<&Operand>, ctx: &ResolveCtx<'_>) -> String {
    match op {
        Some(Operand::Literal(v)) => v.to_string(),
        Some(Operand::SignedInteger(v)) => format!("{{integer,{v}}}"),
        Some(Operand::Atom(0)) => "nil".to_owned(),
        Some(Operand::Atom(i)) => format!("{{atom,{}}}", ctx.atom(*i)),
        Some(Operand::XReg(r)) => format!("{{x,{r}}}"),
        Some(Operand::YReg(r)) => format!("{{y,{r}}}"),
        Some(Operand::Label(l)) => format!("{{f,{l}}}"),
        Some(Operand::Character(c)) => format!("{{integer,{c}}}"),
        Some(Operand::LiteralIndex(i)) => ctx.literal(*i),
        Some(Operand::FpReg(r)) => format!("{{fr,{r}}}"),
        Some(Operand::List(items)) => list_items(items, ctx),
        Some(Operand::AllocList(items)) => alloc_list(items),
        Some(Operand::TypedReg { reg, .. }) => arg(Some(reg), ctx),
        Some(Operand::BigInteger { sign, magnitude_be }) => {
            let digits: String = big_to_decimal(magnitude_be);
            if *sign == 1 {
                format!("{{integer,-{digits}}}")
            } else {
                format!("{{integer,{digits}}}")
            }
        }
        None => "_".to_owned(),
    }
}

fn list_arg(op: Option<&Operand>, ctx: &ResolveCtx<'_>) -> String {
    match op {
        Some(Operand::List(items)) => format!("{{list,{}}}", list_items(items, ctx)),
        other => format!("{{list,{}}}", arg(other, ctx)),
    }
}

fn list_items(items: &[Operand], ctx: &ResolveCtx<'_>) -> String {
    let inner: Vec<String> = items.iter().map(|o: &Operand| arg(Some(o), ctx)).collect();
    format!("[{}]", inner.join(","))
}

fn heap_need(op: Option<&Operand>) -> String {
    match op {
        Some(Operand::AllocList(items)) => alloc_list(items),
        other => value_u(other),
    }
}

fn alloc_list(items: &[Operand]) -> String {
    let mut parts: Vec<String> = Vec::with_capacity(items.len() / 2);
    let mut chunks = items.chunks_exact(2);
    for pair in &mut chunks {
        let kind: u32 = match pair[0] {
            Operand::Literal(v) => u32::try_from(v).unwrap_or(0),
            _ => 0,
        };
        let val: u32 = match pair[1] {
            Operand::Literal(v) => u32::try_from(v).unwrap_or(0),
            _ => 0,
        };
        let tag: &str = match kind {
            0 => "words",
            1 => "floats",
            2 => "funs",
            _ => "words",
        };
        parts.push(format!("{{{tag},{val}}}"));
    }
    format!("{{alloc,[{}]}}", parts.join(","))
}

fn mfa_of_label(op: Option<&Operand>, ctx: &ResolveCtx<'_>) -> String {
    let label: u32 = match op {
        Some(Operand::Label(l)) => *l,
        Some(Operand::Literal(v)) => u32::try_from(*v).unwrap_or(0),
        _ => 0,
    };
    match ctx.label_to_mfa.get(&label) {
        Some((fun, arity)) => format!(
            "{{{},{},{}}}",
            render_atom_literal(ctx.module),
            render_atom_literal(fun),
            arity
        ),
        None => format!("{{f,{label}}}"),
    }
}

fn extfunc(index: Option<u32>, ctx: &ResolveCtx<'_>) -> String {
    let (m, f, a): (String, String, u32) = index.map_or_else(
        || ("?".to_owned(), "?".to_owned(), 0),
        |i: u32| ctx.import(i),
    );
    format!(
        "{{extfunc,{},{},{}}}",
        render_atom_literal(&m),
        render_atom_literal(&f),
        a
    )
}

fn bif_name(index: Option<u32>, ctx: &ResolveCtx<'_>) -> String {
    let name: String = index.map_or_else(|| "?".to_owned(), |i: u32| ctx.import(i).1);
    render_atom_literal(&name)
}

fn mod_atom(op: Option<&Operand>, ctx: &ResolveCtx<'_>) -> String {
    match op {
        Some(Operand::Atom(i)) => ctx.raw_atom(*i),
        _ => render_atom_literal(ctx.module),
    }
}

fn atom_index(op: Option<&Operand>) -> u32 {
    match op {
        Some(Operand::Atom(i)) => *i,
        _ => 0,
    }
}

fn lit_u(op: Option<&Operand>) -> String {
    value_u(op)
}

fn value_u(op: Option<&Operand>) -> String {
    value_u_raw(op).to_string()
}

fn value_u_raw(op: Option<&Operand>) -> u32 {
    value_u_index(op).unwrap_or(0)
}

fn value_u_index(op: Option<&Operand>) -> Option<u32> {
    match op {
        Some(Operand::Literal(v)) => u32::try_from(*v).ok(),
        Some(Operand::SignedInteger(v)) => u32::try_from(*v).ok(),
        Some(
            Operand::Atom(v)
            | Operand::XReg(v)
            | Operand::YReg(v)
            | Operand::Label(v)
            | Operand::Character(v)
            | Operand::LiteralIndex(v)
            | Operand::FpReg(v),
        ) => Some(*v),
        _ => None,
    }
}

fn render_term(term: &Term) -> String {
    let mut out: String = String::new();
    write_term(&mut out, term);
    out
}

fn write_term(out: &mut String, term: &Term) {
    match term {
        Term::SmallInt(v) => {
            out.push_str(&v.to_string());
        }
        Term::Int(v) => {
            out.push_str(&v.to_string());
        }
        Term::BigInt { sign, magnitude_le } => {
            let mut be: Vec<u8> = magnitude_le.clone();
            be.reverse();
            let digits: String = big_to_decimal(&be);
            if *sign == 1 {
                out.push('-');
            }
            out.push_str(&digits);
        }
        Term::Float(f) => out.push_str(&render_float(*f)),
        Term::Atom(a) => out.push_str(&render_atom_literal(a)),
        Term::Nil => out.push_str("[]"),
        Term::Tuple(items) => {
            out.push('{');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_term(out, item);
            }
            out.push('}');
        }
        Term::String(bytes) => {
            out.push('[');
            for (i, &b) in bytes.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&b.to_string());
            }
            out.push(']');
        }
        Term::List { elements, tail } => {
            out.push('[');
            for (i, item) in elements.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_term(out, item);
            }
            if !matches!(**tail, Term::Nil) {
                out.push('|');
                write_term(out, tail);
            }
            out.push(']');
        }
        Term::Binary(bytes) => {
            out.push_str("<<");
            for (i, &b) in bytes.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&b.to_string());
            }
            out.push_str(">>");
        }
        Term::BitBinary { bits, data } => {
            out.push_str("<<");
            for (i, &b) in data.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&b.to_string());
                if i + 1 == data.len() && *bits != 0 {
                    out.push(':');
                    out.push_str(&bits.to_string());
                }
            }
            out.push_str(">>");
        }
        Term::Map(m) => {
            out.push_str("#{");
            for (i, (k, v)) in m.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&render_atom_literal(k));
                out.push_str("=>");
                write_term(out, v);
            }
            out.push('}');
        }
        Term::MapMixed(pairs) => {
            out.push_str("#{");
            for (i, (k, v)) in pairs.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_term(out, k);
                out.push_str("=>");
                write_term(out, v);
            }
            out.push('}');
        }
        Term::Pid { .. } => out.push_str("<pid>"),
        Term::Reference { .. } => out.push_str("<ref>"),
        Term::Export {
            module,
            function,
            arity,
        } => {
            out.push_str("fun ");
            out.push_str(&render_atom_literal(module));
            out.push(':');
            out.push_str(&render_atom_literal(function));
            out.push('/');
            out.push_str(&arity.to_string());
        }
    }
}

fn render_float(f: f64) -> String {
    if f.is_finite() && f.fract() == 0.0 && f.abs() < 1e16 {
        format!("{f:.1}")
    } else {
        let s: String = format!("{f}");
        if s.contains(['.', 'e', 'E']) {
            s
        } else {
            format!("{s}.0")
        }
    }
}

fn strip_elixir_prefix(module: &str) -> String {
    match module.strip_prefix("Elixir.") {
        Some(rest) => format!("{rest}.ex"),
        None => format!("{module}.erl"),
    }
}

fn escape_string(s: &str) -> String {
    let mut out: String = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            _ => out.push(ch),
        }
    }
    out
}

fn render_atom_literal(name: &str) -> String {
    if is_unquoted_atom(name) {
        name.to_owned()
    } else {
        format!("'{}'", name.replace('\\', "\\\\").replace('\'', "\\'"))
    }
}

const RESERVED_WORDS: &[&str] = &[
    "after", "and", "andalso", "band", "begin", "bnot", "bor", "bsl", "bsr", "bxor", "case",
    "catch", "cond", "div", "end", "fun", "if", "let", "maybe", "not", "of", "or", "orelse",
    "receive", "rem", "try", "when", "xor",
];

fn is_unquoted_atom(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_lowercase() {
        return false;
    }
    if !chars.all(|c: char| c.is_ascii_alphanumeric() || c == '_' || c == '@') {
        return false;
    }
    !RESERVED_WORDS.contains(&name)
}

fn big_to_decimal(magnitude_be: &[u8]) -> String {
    let mut digits: Vec<u8> = vec![0];
    for &byte in magnitude_be {
        let mut carry: u32 = u32::from(byte);
        for digit in &mut digits {
            let value: u32 = u32::from(*digit) * 256 + carry;
            *digit = (value % 10) as u8;
            carry = value / 10;
        }
        while carry > 0 {
            digits.push((carry % 10) as u8);
            carry /= 10;
        }
    }
    while digits.len() > 1 && *digits.last().unwrap_or(&0) == 0 {
        digits.pop();
    }
    digits
        .iter()
        .rev()
        .map(|d: &u8| (b'0' + d) as char)
        .collect()
}

#[must_use]
pub fn render_symbolic(module: &SymbolicModule) -> String {
    let mut out: String = String::new();
    out.push_str("%% module ");
    out.push_str(&module.module);
    out.push('\n');
    for func in &module.functions {
        out.push_str("\n{function, ");
        out.push_str(&render_atom_literal(&func.name));
        out.push_str(", ");
        out.push_str(&func.arity.to_string());
        out.push_str(", ");
        out.push_str(&func.entry_label.to_string());
        out.push_str(",\n");
        for inst in &func.instructions {
            out.push_str("  ");
            out.push_str(&inst.text);
            out.push('\n');
        }
        out.push_str("}.\n");
    }
    out
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::chunks::AtomTable;

    fn ctx_with_import() -> ResolveCtx<'static> {
        let atoms: &'static AtomTable = Box::leak(Box::new(AtomTable {
            atoms: vec!["mod".to_owned(), "io".to_owned(), "format".to_owned()],
        }));
        let imports: &'static [ImportEntry] = Box::leak(Box::new([ImportEntry {
            module_atom_index: 2,
            function_atom_index: 3,
            arity: 1,
        }]));
        ResolveCtx {
            atoms,
            imports,
            literals: None,
            strings: None,
            line: None,
            funs: &[],
            module: "mod",
            label_to_mfa: BTreeMap::new(),
        }
    }

    #[test]
    fn reserved_words_are_quoted() {
        assert_eq!(render_atom_literal("rem"), "'rem'");
        assert_eq!(render_atom_literal("and"), "'and'");
        assert_eq!(render_atom_literal("or"), "'or'");
        assert_eq!(render_atom_literal("div"), "'div'");
        assert_eq!(render_atom_literal("ok"), "ok");
        assert_eq!(render_atom_literal("handle_call"), "handle_call");
    }

    #[test]
    fn special_atoms_are_quoted() {
        assert_eq!(
            render_atom_literal("-sumlist/1-fun-0-"),
            "'-sumlist/1-fun-0-'"
        );
        assert_eq!(render_atom_literal("Upper"), "'Upper'");
        assert_eq!(render_atom_literal("with space"), "'with space'");
    }

    #[test]
    fn float_renders_with_decimal_point() {
        assert_eq!(render_float(2.0), "2.0");
        assert_eq!(render_float(3.0), "3.0");
        assert_eq!(render_float(0.5), "0.5");
    }

    #[test]
    fn big_decimal_round_trips() {
        let term: Term = Term::BigInt {
            sign: 0,
            magnitude_le: vec![
                0xd2, 0x0a, 0x3f, 0x4e, 0xee, 0xe0, 0x73, 0xc3, 0xf6, 0x0f, 0xe9, 0x8e, 0x01,
            ],
        };
        let rendered: String = render_term(&term);
        assert_eq!(rendered, "123456789012345678901234567890");
    }

    #[test]
    fn string_term_renders_as_integer_list() {
        let term: Term = Term::String(vec![104, 105]);
        assert_eq!(render_term(&term), "[104,105]");
    }

    #[test]
    fn tuple_literal_renders_canonically() {
        let term: Term = Term::Tuple(vec![
            Term::Atom("ok".to_owned()),
            Term::SmallInt(42),
            Term::String(vec![115, 116, 114]),
        ]);
        assert_eq!(render_term(&term), "{ok,42,[115,116,114]}");
    }

    #[test]
    fn invalid_call_ext_operand_does_not_render_first_import() {
        let ctx: ResolveCtx<'_> = ctx_with_import();
        let instr: Instruction = Instruction {
            offset: 0,
            opcode: 0,
            name: "call_ext",
            operands: vec![Operand::Literal(1), Operand::SignedInteger(-1)],
        };

        assert_eq!(
            resolve_instruction(&instr, &ctx),
            "{call_ext,1,{extfunc,'?','?',0}}"
        );
    }

    #[test]
    fn invalid_bif_operand_does_not_render_first_import() {
        let ctx: ResolveCtx<'_> = ctx_with_import();
        let instr: Instruction = Instruction {
            offset: 0,
            opcode: 0,
            name: "bif1",
            operands: vec![
                Operand::Label(9),
                Operand::Literal(u64::from(u32::MAX) + 1),
                Operand::XReg(0),
                Operand::XReg(1),
            ],
        };

        assert_eq!(
            resolve_instruction(&instr, &ctx),
            "{bif,'?',{f,9},[{x,0}],{x,1}}"
        );
    }

    fn ctx_with_strings_and_funs() -> ResolveCtx<'static> {
        let atoms: &'static AtomTable = Box::leak(Box::new(AtomTable {
            atoms: vec!["mod".to_owned()],
        }));
        let strings: &'static StringTable = Box::leak(Box::new(StringTable {
            bytes: vec![0xab, 0xcd, 0xef],
        }));
        let funs: &'static [FunEntry] = Box::leak(Box::new([FunEntry {
            function_atom_index: 0,
            arity: 1,
            label: 42,
            index: 3,
            num_free: 0,
            old_uniq: 0,
        }]));
        ResolveCtx {
            atoms,
            imports: &[],
            literals: None,
            strings: Some(strings),
            line: None,
            funs,
            module: "mod",
            label_to_mfa: BTreeMap::new(),
        }
    }

    fn render(name: &'static str, operands: Vec<Operand>) -> String {
        let ctx: ResolveCtx<'_> = ctx_with_strings_and_funs();
        let instr: Instruction = Instruction {
            offset: 0,
            opcode: 0,
            name,
            operands,
        };
        resolve_instruction(&instr, &ctx)
    }

    #[test]
    fn bs_start_match2_renders_as_test_tuple_like_beam_disasm() {
        assert_eq!(
            render(
                "bs_start_match2",
                vec![
                    Operand::Label(12),
                    Operand::XReg(0),
                    Operand::Literal(1),
                    Operand::Literal(0),
                    Operand::XReg(0),
                ],
            ),
            "{test,bs_start_match2,{f,12},[{x,0},1,0,{x,0}]}"
        );
    }

    #[test]
    fn bs_get_integer2_renders_field_flags_and_test_shape() {
        assert_eq!(
            render(
                "bs_get_integer2",
                vec![
                    Operand::Label(12),
                    Operand::XReg(0),
                    Operand::Literal(2),
                    Operand::SignedInteger(8),
                    Operand::Literal(1),
                    Operand::Literal(0),
                    Operand::XReg(1),
                ],
            ),
            "{test,bs_get_integer2,{f,12},2,[{x,0},{integer,8},1,{field_flags,[]}],{x,1}}"
        );
    }

    #[test]
    fn bs_get_binary2_decodes_signed_native_flags() {
        assert_eq!(
            render(
                "bs_get_binary2",
                vec![
                    Operand::Label(5),
                    Operand::XReg(0),
                    Operand::Literal(3),
                    Operand::XReg(2),
                    Operand::Literal(8),
                    Operand::Literal(0x14),
                    Operand::XReg(3),
                ],
            ),
            "{test,bs_get_binary2,{f,5},3,[{x,0},{x,2},8,{field_flags,[signed,native]}],{x,3}}"
        );
    }

    #[test]
    fn bs_skip_bits2_renders_test_with_flags() {
        assert_eq!(
            render(
                "bs_skip_bits2",
                vec![
                    Operand::Label(7),
                    Operand::XReg(0),
                    Operand::SignedInteger(4),
                    Operand::Literal(8),
                    Operand::Literal(2),
                ],
            ),
            "{test,bs_skip_bits2,{f,7},[{x,0},{integer,4},8,{field_flags,[little]}]}"
        );
    }

    #[test]
    fn bs_test_tail2_renders_two_element_list() {
        assert_eq!(
            render(
                "bs_test_tail2",
                vec![Operand::Label(9), Operand::XReg(0), Operand::Literal(16)],
            ),
            "{test,bs_test_tail2,{f,9},[{x,0},16]}"
        );
    }

    #[test]
    fn bs_test_unit_renders_test_shape() {
        assert_eq!(
            render(
                "bs_test_unit",
                vec![Operand::Label(3), Operand::XReg(0), Operand::Literal(8)],
            ),
            "{test,bs_test_unit,{f,3},[{x,0},8]}"
        );
    }

    #[test]
    fn bs_match_string_resolves_bytes_from_string_table() {
        assert_eq!(
            render(
                "bs_match_string",
                vec![
                    Operand::Label(2),
                    Operand::XReg(0),
                    Operand::Literal(16),
                    Operand::Literal(0),
                ],
            ),
            "{test,bs_match_string,{f,2},[{x,0},16,{string,<<171,205>>}]}"
        );
    }

    #[test]
    fn bs_get_tail_renders_live_as_bare_integer() {
        assert_eq!(
            render(
                "bs_get_tail",
                vec![Operand::XReg(0), Operand::XReg(1), Operand::Literal(3)],
            ),
            "{bs_get_tail,{x,0},{x,1},3}"
        );
    }

    #[test]
    fn bs_get_position_and_set_position_render_like_beam_disasm() {
        assert_eq!(
            render(
                "bs_get_position",
                vec![Operand::XReg(0), Operand::YReg(1), Operand::Literal(2)],
            ),
            "{bs_get_position,{x,0},{y,1},2}"
        );
        assert_eq!(
            render("bs_set_position", vec![Operand::XReg(0), Operand::YReg(1)],),
            "{bs_set_position,{x,0},{y,1}}"
        );
    }

    #[test]
    fn call_fun2_integer_tag_resolves_to_lambda_label() {
        assert_eq!(
            render(
                "call_fun2",
                vec![Operand::Literal(3), Operand::Literal(1), Operand::XReg(0)],
            ),
            "{call_fun2,{f,42},1,{x,0}}"
        );
    }
}
