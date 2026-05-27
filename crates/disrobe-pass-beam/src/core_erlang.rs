use serde::Serialize;

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
    pub instructions: Vec<RenderedInstruction>,
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

fn split_functions(disassembly: &Disassembly, chunks: &Chunks) -> Result<Vec<CoreFunction>> {
    let mut functions: Vec<CoreFunction> = Vec::new();
    let mut current_label: u32 = 0;
    let mut current_buf: Vec<RenderedInstruction> = Vec::new();
    let mut current_name: Option<(String, u32)> = None;
    for instr in &disassembly.instructions {
        match instr.name {
            "label" => {
                if let Operand::Literal(v) = instr.operands.first().unwrap_or(&Operand::Literal(0))
                {
                    current_label = u32::try_from(*v).unwrap_or(0);
                }
            }
            "func_info" => {
                if let Some((name, arity)) = current_name.take() {
                    let exported: bool = chunks.exports.iter().any(|e: &ExportEntry| {
                        chunks
                            .atoms
                            .get(e.function_atom_index)
                            .is_some_and(|n: &str| n == name && e.arity == arity)
                    });
                    let local: Option<&LocalEntry> =
                        chunks.locals.iter().find(|l: &&LocalEntry| {
                            chunks
                                .atoms
                                .get(l.function_atom_index)
                                .is_some_and(|n: &str| n == name && l.arity == arity)
                        });
                    let label: u32 = chunks
                        .exports
                        .iter()
                        .find(|e: &&ExportEntry| {
                            chunks
                                .atoms
                                .get(e.function_atom_index)
                                .is_some_and(|n: &str| n == name && e.arity == arity)
                        })
                        .map_or_else(
                            || local.map_or(current_label, |l: &LocalEntry| l.label),
                            |e: &ExportEntry| e.label,
                        );
                    let params: Vec<String> = (0..arity).map(|i: u32| format!("X{i}")).collect();
                    functions.push(CoreFunction {
                        name,
                        arity,
                        label,
                        exported,
                        clauses: vec![CoreClause {
                            params,
                            instructions: core::mem::take(&mut current_buf),
                        }],
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
                current_name = Some((name, arity));
            }
            _ => {
                current_buf.push(render_instruction(instr, chunks));
            }
        }
    }
    if let Some((name, arity)) = current_name.take() {
        let exported: bool = chunks.exports.iter().any(|e: &ExportEntry| {
            chunks
                .atoms
                .get(e.function_atom_index)
                .is_some_and(|n: &str| n == name && e.arity == arity)
        });
        let local: Option<&LocalEntry> = chunks.locals.iter().find(|l: &&LocalEntry| {
            chunks
                .atoms
                .get(l.function_atom_index)
                .is_some_and(|n: &str| n == name && l.arity == arity)
        });
        let label: u32 = chunks
            .exports
            .iter()
            .find(|e: &&ExportEntry| {
                chunks
                    .atoms
                    .get(e.function_atom_index)
                    .is_some_and(|n: &str| n == name && e.arity == arity)
            })
            .map_or_else(
                || local.map_or(current_label, |l: &LocalEntry| l.label),
                |e: &ExportEntry| e.label,
            );
        let params: Vec<String> = (0..arity).map(|i: u32| format!("X{i}")).collect();
        functions.push(CoreFunction {
            name,
            arity,
            label,
            exported,
            clauses: vec![CoreClause {
                params,
                instructions: core::mem::take(&mut current_buf),
            }],
        });
    }
    for f in &mut functions {
        for clause in &mut f.clauses {
            for inst in &mut clause.instructions {
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
    }
    Ok(functions)
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
