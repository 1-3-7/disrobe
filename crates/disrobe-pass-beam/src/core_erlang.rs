use std::collections::BTreeMap;

use serde::Serialize;

use crate::body_lift::expr::Expr;
use crate::body_lift::{self, LiftedBody};
use crate::chunks::{Chunks, ExportEntry, LocalEntry};
use crate::disasm::{self, Disassembly, Instruction, Operand};
use crate::error::{Error, Result};
use crate::file::BeamFile;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CoreFunction {
    pub name: String,
    pub arity: u32,
    pub label: u32,
    pub exported: bool,
    pub clauses: Vec<CoreClause>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CoreClause {
    pub params: Vec<String>,
    pub patterns: Vec<Expr>,
    pub guard: Option<Expr>,
    pub instructions: Vec<RenderedInstruction>,
    pub body: LiftedBody,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RenderedInstruction {
    pub offset: usize,
    pub mnemonic: &'static str,
    pub args: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CoreModule {
    pub module: String,
    pub exports: Vec<(String, u32)>,
    pub imports: Vec<(String, String, u32)>,
    pub functions: Vec<CoreFunction>,
}

pub fn lift(beam: &BeamFile) -> Result<CoreModule> {
    let chunks: &Chunks = &beam.chunks;
    let code: &crate::chunks::CodeChunk =
        chunks.code.as_ref().ok_or(Error::MissingChunk("Code"))?;
    let module: String = chunks
        .atoms
        .module_name()
        .ok_or(Error::MissingChunk("Atom (module name)"))?
        .to_owned();
    let disassembly: Disassembly = disasm::disassemble(code)?;
    let mut exports: Vec<(String, u32)> = Vec::with_capacity(chunks.exports.len());
    for e in &chunks.exports {
        let name: &str = chunks.atoms.require(e.function_atom_index)?;
        exports.push((name.to_owned(), e.arity));
    }
    let mut imports: Vec<(String, String, u32)> = Vec::with_capacity(chunks.imports.len());
    for i in &chunks.imports {
        let m: &str = chunks.atoms.require(i.module_atom_index)?;
        let f: &str = chunks.atoms.require(i.function_atom_index)?;
        imports.push((m.to_owned(), f.to_owned(), i.arity));
    }
    let functions: Vec<CoreFunction> = split_functions(&disassembly, chunks)?;
    Ok(CoreModule {
        module,
        exports,
        imports,
        functions,
    })
}

struct FuncSpan {
    name: String,
    arity: u32,
    func_info_at: usize,
    body_start: usize,
    body_end: usize,
}

fn split_functions(disassembly: &Disassembly, chunks: &Chunks) -> Result<Vec<CoreFunction>> {
    let instrs: &[Instruction] = &disassembly.instructions;
    let label_index: BTreeMap<u32, (String, u32)> = body_lift::build_label_index(chunks);
    let spans: Vec<FuncSpan> = collect_func_spans(instrs, chunks);
    let mut functions: Vec<CoreFunction> = Vec::with_capacity(spans.len());
    for span in &spans {
        let exported: bool = chunks.exports.iter().any(|e: &ExportEntry| {
            chunks
                .atoms
                .get(e.function_atom_index)
                .is_some_and(|n: &str| n == span.name && e.arity == span.arity)
        });
        let label: u32 = resolve_label(chunks, &span.name, span.arity, span.func_info_at, instrs);
        let body_slice: &[Instruction] = &instrs[span.body_start..span.body_end];
        let (fn_clauses, fully_recovered): (Vec<body_lift::expr::FnClause>, bool) =
            body_lift::lift_function(body_slice, span.arity, chunks, &label_index);
        let mut instructions: Vec<RenderedInstruction> = body_slice
            .iter()
            .filter(|i: &&Instruction| i.name != "label")
            .map(|i: &Instruction| render_instruction(i, chunks))
            .collect();
        annotate_ext_calls(&mut instructions, chunks);
        let params: Vec<String> = (0..span.arity).map(|i: u32| format!("X{i}")).collect();
        let clauses: Vec<CoreClause> = fn_clauses
            .into_iter()
            .enumerate()
            .map(|(i, c): (usize, body_lift::expr::FnClause)| CoreClause {
                params: params.clone(),
                patterns: c.patterns,
                guard: c.guard,
                instructions: if i == 0 {
                    std::mem::take(&mut instructions)
                } else {
                    Vec::new()
                },
                body: LiftedBody {
                    stmts: c.body,
                    fully_recovered,
                },
            })
            .collect();
        functions.push(CoreFunction {
            name: span.name.clone(),
            arity: span.arity,
            label,
            exported,
            clauses,
        });
    }
    Ok(functions)
}

fn collect_func_spans(instrs: &[Instruction], chunks: &Chunks) -> Vec<FuncSpan> {
    let mut spans: Vec<FuncSpan> = Vec::new();
    let mut pending: Option<(String, u32, usize)> = None;
    for (idx, instr) in instrs.iter().enumerate() {
        if instr.name == "func_info" {
            if let Some((name, arity, info_at)) = pending.take() {
                spans.push(FuncSpan {
                    name,
                    arity,
                    func_info_at: info_at,
                    body_start: info_at + 1,
                    body_end: idx.saturating_sub(1).max(info_at + 1),
                });
            }
            let function_atom: u32 = match instr.operands.get(1) {
                Some(Operand::Atom(a)) => *a,
                _ => 0,
            };
            let arity: u32 = match instr.operands.get(2) {
                Some(Operand::Literal(v)) => u32::try_from(*v).unwrap_or(0),
                _ => 0,
            };
            let name: String = chunks
                .atoms
                .get(function_atom)
                .unwrap_or("__unknown__")
                .to_owned();
            pending = Some((name, arity, idx));
        }
    }
    if let Some((name, arity, info_at)) = pending.take() {
        let mut end: usize = instrs.len();
        if instrs
            .last()
            .is_some_and(|i: &Instruction| i.name == "int_code_end")
        {
            end -= 1;
        }
        spans.push(FuncSpan {
            name,
            arity,
            func_info_at: info_at,
            body_start: info_at + 1,
            body_end: end.max(info_at + 1),
        });
    }
    spans
}

fn resolve_label(
    chunks: &Chunks,
    name: &str,
    arity: u32,
    func_info_at: usize,
    instrs: &[Instruction],
) -> u32 {
    let export_label: Option<u32> = chunks
        .exports
        .iter()
        .find(|e: &&ExportEntry| {
            chunks
                .atoms
                .get(e.function_atom_index)
                .is_some_and(|n: &str| n == name && e.arity == arity)
        })
        .map(|e: &ExportEntry| e.label);
    if let Some(l) = export_label {
        return l;
    }
    let local_label: Option<u32> = chunks
        .locals
        .iter()
        .find(|l: &&LocalEntry| {
            chunks
                .atoms
                .get(l.function_atom_index)
                .is_some_and(|n: &str| n == name && l.arity == arity)
        })
        .map(|l: &LocalEntry| l.label);
    if let Some(l) = local_label {
        return l;
    }
    instrs
        .get(func_info_at + 1)
        .filter(|i: &&Instruction| i.name == "label")
        .and_then(|i: &Instruction| match i.operands.first() {
            Some(Operand::Literal(v)) => u32::try_from(*v).ok(),
            _ => None,
        })
        .unwrap_or(0)
}

fn annotate_ext_calls(instructions: &mut [RenderedInstruction], chunks: &Chunks) {
    for inst in instructions.iter_mut() {
        if (inst.mnemonic == "call_ext"
            || inst.mnemonic == "call_ext_last"
            || inst.mnemonic == "call_ext_only")
            && inst.args.len() >= 2
            && let Some(idx_str) = inst.args.last()
            && let Some(idx) = parse_literal_arg(idx_str)
            && let Some(import) = chunks.imports.get(idx as usize)
        {
            let module: &str = chunks.atoms.get(import.module_atom_index).unwrap_or("?");
            let name: &str = chunks.atoms.get(import.function_atom_index).unwrap_or("?");
            let last: usize = inst.args.len() - 1;
            inst.args[last] = format!("import({module}:{name}/{})", import.arity);
        }
    }
}

fn parse_literal_arg(s: &str) -> Option<u32> {
    s.strip_prefix("lit:")
        .and_then(|n: &str| n.parse::<u32>().ok())
}

fn render_instruction(instr: &Instruction, chunks: &Chunks) -> RenderedInstruction {
    let args: Vec<String> = instr
        .operands
        .iter()
        .map(|op: &Operand| render_operand(op, chunks))
        .collect();
    RenderedInstruction {
        offset: instr.offset,
        mnemonic: instr.name,
        args,
    }
}

fn render_operand(op: &Operand, chunks: &Chunks) -> String {
    match op {
        Operand::Literal(v) => format!("lit:{v}"),
        Operand::SignedInteger(v) => format!("int:{v}"),
        Operand::Atom(0) => "nil".to_owned(),
        Operand::Atom(i) => match chunks.atoms.get(*i) {
            Some(name) => format!("atom:{name}"),
            None => format!("atom:#{i}"),
        },
        Operand::XReg(r) => format!("x{r}"),
        Operand::YReg(r) => format!("y{r}"),
        Operand::Label(l) => format!("L{l}"),
        Operand::Character(c) => format!("char:{c}"),
        Operand::LiteralIndex(i) => format!("literal[{i}]"),
        Operand::FpReg(r) => format!("fr{r}"),
        Operand::List(items) => {
            let inner: String = items
                .iter()
                .map(|o: &Operand| render_operand(o, chunks))
                .collect::<Vec<_>>()
                .join(",");
            format!("[{inner}]")
        }
        Operand::AllocList(items) => {
            let inner: String = items
                .iter()
                .map(|o: &Operand| render_operand(o, chunks))
                .collect::<Vec<_>>()
                .join(",");
            format!("alloc[{inner}]")
        }
        Operand::TypedReg { reg, type_index } => {
            format!("{}:T{type_index}", render_operand(reg, chunks))
        }
        Operand::BigInteger { sign, magnitude_be } => {
            let hex: String = magnitude_be
                .iter()
                .map(|b: &u8| format!("{b:02x}"))
                .collect();
            format!("big:{sign}:{hex}")
        }
    }
}
