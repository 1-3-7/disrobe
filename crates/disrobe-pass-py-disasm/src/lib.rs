#![forbid(unsafe_code)]

pub mod alt_runtimes;
mod cfg;
#[cfg(feature = "chain")]
pub mod chain_detector;
mod exception_table;
pub mod format_wire;
#[cfg(feature = "llm-metadata")]
pub mod llm;
mod opcodes;
mod provenance_header;

use disrobe_py_marshal::{CodeObject, PyVersion};
use serde::Serialize;

pub use alt_runtimes::{AltRuntime, AltRuntimeError, detect_runtime};
pub use cfg::{
    Block as CfgBlock, BlockId, Cfg, EdgeKind as CfgEdgeKind, TerminatorKind as CfgTerminatorKind,
    build_cfg, render_dot,
};
pub use exception_table::{
    ExceptionEntry, decode_exception_table, render_exception_table, render_exception_table_json,
};
pub use format_wire::{format_identity, format_python};
#[cfg(feature = "llm-metadata")]
pub use llm::{METADATA_CAPABILITY, PyDisasmLlmInput};
pub use opcodes::{cache_size, has_arg, opname};
pub use provenance_header::{python_disasm_header, render_disasm_with_header};

const EXTENDED_ARG_OPCODE: u8 = 144;
const LEGACY_HAVE_ARGUMENT: u8 = 90;
const WIDE_INSTRUCTION_STEP: usize = 2;
const NARROW_INSTRUCTION_STEP: usize = 1;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Instruction {
    pub offset: usize,
    pub opcode: u8,
    pub opname: String,
    pub arg: Option<u32>,
    pub argrepr: Option<String>,
    pub line: Option<u32>,
    pub is_jump_target: bool,
}

#[must_use]
pub fn disassemble(co: &CodeObject, version: PyVersion) -> Vec<Instruction> {
    if version.is_wordcode() {
        disassemble_wordcode(co, version)
    } else {
        disassemble_legacy(co, version)
    }
}

fn disassemble_wordcode(co: &CodeObject, version: PyVersion) -> Vec<Instruction> {
    let code: &Vec<u8> = &co.code;
    let mut out: Vec<Instruction> = Vec::with_capacity(code.len() / 2);
    let mut extended_arg: u32 = 0;
    let mut cursor: usize = 0usize;
    while cursor + 1 < code.len() {
        let op: u8 = code[cursor];
        let arg_byte: u8 = code[cursor + 1];
        let name: &'static str = opname(op, version);
        if is_extended_arg(op) {
            extended_arg = (extended_arg | u32::from(arg_byte)) << 8;
            out.push(Instruction {
                offset: cursor,
                opcode: op,
                opname: name.to_owned(),
                arg: Some(u32::from(arg_byte)),
                argrepr: None,
                line: None,
                is_jump_target: false,
            });
            cursor += WIDE_INSTRUCTION_STEP;
            continue;
        }
        let arg: Option<u32> = if has_arg(op, version) {
            Some(extended_arg | u32::from(arg_byte))
        } else {
            None
        };
        extended_arg = 0;
        out.push(Instruction {
            offset: cursor,
            opcode: op,
            opname: name.to_owned(),
            arg,
            argrepr: argrepr(co, name, arg),
            line: None,
            is_jump_target: false,
        });
        cursor += WIDE_INSTRUCTION_STEP;
        let caches: usize = usize::from(cache_size(op, version));
        if caches > 0 {
            cursor += caches * WIDE_INSTRUCTION_STEP;
        }
    }
    out
}

fn disassemble_legacy(co: &CodeObject, version: PyVersion) -> Vec<Instruction> {
    let code: &Vec<u8> = &co.code;
    let mut out: Vec<Instruction> = Vec::with_capacity(code.len());
    let mut cursor: usize = 0usize;
    while cursor < code.len() {
        let op: u8 = code[cursor];
        let name: &'static str = opname(op, version);
        if op < LEGACY_HAVE_ARGUMENT {
            out.push(Instruction {
                offset: cursor,
                opcode: op,
                opname: name.to_owned(),
                arg: None,
                argrepr: None,
                line: None,
                is_jump_target: false,
            });
            cursor += NARROW_INSTRUCTION_STEP;
            continue;
        }
        if cursor + 2 >= code.len() {
            break;
        }
        let arg: u32 = u32::from(code[cursor + 1]) | (u32::from(code[cursor + 2]) << 8);
        out.push(Instruction {
            offset: cursor,
            opcode: op,
            opname: name.to_owned(),
            arg: Some(arg),
            argrepr: argrepr(co, name, Some(arg)),
            line: None,
            is_jump_target: false,
        });
        cursor += 3;
    }
    out
}

#[inline]
const fn is_extended_arg(op: u8) -> bool {
    op == EXTENDED_ARG_OPCODE
}

fn argrepr(co: &CodeObject, opname: &str, arg: Option<u32>) -> Option<String> {
    let arg: u32 = arg?;
    let idx: usize = arg as usize;
    match opname {
        "LOAD_CONST" => co.consts.get(idx).map(|c| format!("{c:?}")),
        "LOAD_NAME" | "STORE_NAME" | "DELETE_NAME" | "LOAD_GLOBAL" | "STORE_GLOBAL"
        | "DELETE_GLOBAL" | "LOAD_ATTR" | "STORE_ATTR" | "DELETE_ATTR" | "IMPORT_NAME"
        | "IMPORT_FROM" => co.names.get(idx).map(object_label),
        "LOAD_FAST"
        | "STORE_FAST"
        | "DELETE_FAST"
        | "LOAD_FAST_CHECK"
        | "LOAD_FAST_AND_CLEAR"
        | "LOAD_FAST_BORROW" => co.varnames.get(idx).map(object_label),
        _ => None,
    }
}

fn object_label(obj: &disrobe_py_marshal::Object) -> String {
    match obj {
        disrobe_py_marshal::Object::String { value, .. }
        | disrobe_py_marshal::Object::ShortAscii { value, .. } => value.clone(),
        other => format!("{other:?}"),
    }
}

#[must_use]
pub fn render_dis(instructions: &[Instruction]) -> String {
    let mut out: String = String::with_capacity(instructions.len() * 48);
    for ins in instructions {
        let arg_segment: String = match (ins.arg, ins.argrepr.as_deref()) {
            (Some(a), Some(r)) => format!(" {a:5} ({r})"),
            (Some(a), None) => format!(" {a:5}"),
            (None, _) => String::new(),
        };
        let _: Result<(), std::fmt::Error> = std::fmt::Write::write_fmt(
            &mut out,
            format_args!("{:>6} {:<24}{}\n", ins.offset, ins.opname, arg_segment),
        );
    }
    out
}

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use disrobe_py_marshal::{CodeEra, CodeObject, PyVersion};

    #[test]
    fn empty_code_disassembles_empty() {
        let co: CodeObject = CodeObject::new(CodeEra::Py311Plus);
        let result: Vec<Instruction> = disassemble(&co, PyVersion::PY312);
        assert!(result.is_empty());
    }

    #[test]
    fn legacy_27_decodes_no_arg_op() {
        let mut co: CodeObject = CodeObject::new(CodeEra::Py27);
        co.code = vec![1, 2, 3];
        let result: Vec<Instruction> = disassemble(&co, PyVersion::PY27);
        assert!(!result.is_empty());
    }

    #[test]
    fn render_produces_lines() {
        let ins: Vec<Instruction> = vec![Instruction {
            offset: 0,
            opcode: 0,
            opname: "NOP".to_owned(),
            arg: None,
            argrepr: None,
            line: None,
            is_jump_target: false,
        }];
        let s: String = render_dis(&ins);
        assert!(s.contains("NOP"));
    }

    #[test]
    fn extended_arg_accumulates_high_bits() {
        let mut co: CodeObject = CodeObject::new(CodeEra::Py311Plus);
        co.code = vec![144, 0x12, 100, 0x34];
        let result: Vec<Instruction> = disassemble(&co, PyVersion::PY312);
        assert_eq!(result.len(), 2);
        let load_const: &Instruction = result.last().expect("load_const present");
        assert_eq!(load_const.arg, Some(0x1200u32 | 0x34));
    }

    #[test]
    fn truncated_legacy_does_not_panic() {
        let mut co: CodeObject = CodeObject::new(CodeEra::Py27);
        co.code = vec![100, 0];
        let result: Vec<Instruction> = disassemble(&co, PyVersion::PY27);
        assert!(result.is_empty());
    }
}
