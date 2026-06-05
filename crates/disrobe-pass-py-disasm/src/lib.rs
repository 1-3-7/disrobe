#![forbid(unsafe_code)]
#![allow(clippy::redundant_pub_crate)]

pub mod alt_runtimes;
mod cfg;
#[cfg(feature = "chain")]
pub mod chain_detector;
mod exception_table;
pub mod format_wire;
mod jumps;
mod lines;
#[cfg(feature = "llm-metadata")]
pub mod llm;
mod opcodes;
pub mod pass;
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
    let mut instructions: Vec<Instruction> = if version.is_wordcode() {
        disassemble_wordcode(co, version)
    } else {
        disassemble_legacy(co, version)
    };
    assign_line_numbers(&mut instructions, co, version);
    mark_jump_targets(&mut instructions, version);
    instructions
}

fn assign_line_numbers(instructions: &mut [Instruction], co: &CodeObject, version: PyVersion) {
    let line_map: lines::LineMap = lines::LineMap::build(co, version);
    let mut previous_line: Option<u32> = None;
    for instruction in instructions.iter_mut() {
        let offset: u32 = instruction.offset as u32;
        let resolved: Option<u32> = line_map.line_at(offset);
        instruction.line = line_map.start_line(offset, previous_line);
        if resolved.is_some() {
            previous_line = resolved;
        }
    }
}

fn mark_jump_targets(instructions: &mut [Instruction], version: PyVersion) {
    let mut targets: std::collections::BTreeSet<u32> = std::collections::BTreeSet::new();
    for instruction in instructions.iter() {
        let kind: jumps::JumpKind = jumps::jump_kind(&instruction.opname, version);
        if matches!(kind, jumps::JumpKind::None) {
            continue;
        }
        let Some(arg): Option<u32> = instruction.arg else {
            continue;
        };
        let caches: u32 = u32::from(cache_size(instruction.opcode, version));
        let resolved: Option<u32> =
            jumps::jump_target(kind, instruction.offset as u32, arg, caches, version);
        if let Some(target) = resolved {
            targets.insert(target);
        }
    }
    for instruction in instructions.iter_mut() {
        instruction.is_jump_target = targets.contains(&(instruction.offset as u32));
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
        if is_extended_arg(op, version) {
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
            argrepr: argrepr(co, name, arg, version),
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
            argrepr: argrepr(co, name, Some(arg), version),
            line: None,
            is_jump_target: false,
        });
        cursor += 3;
    }
    out
}

#[inline]
const fn is_extended_arg(op: u8, version: PyVersion) -> bool {
    str_eq_ascii(opname(op, version), "EXTENDED_ARG")
}

#[inline]
const fn str_eq_ascii(lhs: &str, rhs: &str) -> bool {
    let (left, right): (&[u8], &[u8]) = (lhs.as_bytes(), rhs.as_bytes());
    if left.len() != right.len() {
        return false;
    }
    let mut index: usize = 0usize;
    while index < left.len() {
        if left[index] != right[index] {
            return false;
        }
        index += 1;
    }
    true
}

const CMP_OP_MODERN: [&str; 6] = ["<", "<=", "==", "!=", ">", ">="];
const CMP_OP_LEGACY: [&str; 12] = [
    "<",
    "<=",
    "==",
    "!=",
    ">",
    ">=",
    "in",
    "not in",
    "is",
    "is not",
    "exception match",
    "BAD",
];
const FORMAT_VALUE_CONVERSIONS: [&str; 4] = ["", "str", "repr", "ascii"];
const FORMAT_VALUE_HAVE_SPEC: u32 = 0x04;
const FORMAT_VALUE_CONVERSION_MASK: u32 = 0x03;
const COMPARE_OP_TO_BOOL_BIT: u32 = 0x10;
const MAKE_FUNCTION_FLAGS: [(u32, &str); 4] = [
    (0x01, "defaults"),
    (0x02, "kwdefaults"),
    (0x04, "annotations"),
    (0x08, "closure"),
];

fn argrepr(co: &CodeObject, opname: &str, arg: Option<u32>, version: PyVersion) -> Option<String> {
    let arg: u32 = arg?;
    match opname {
        "LOAD_CONST" | "KW_NAMES" | "RETURN_CONST" => {
            co.consts.get(arg as usize).map(|c| format!("{c:?}"))
        }
        "LOAD_GLOBAL" => load_global_repr(co, arg, version),
        "LOAD_ATTR" => load_attr_repr(co, arg, version),
        "LOAD_NAME"
        | "STORE_NAME"
        | "DELETE_NAME"
        | "STORE_GLOBAL"
        | "DELETE_GLOBAL"
        | "STORE_ATTR"
        | "DELETE_ATTR"
        | "IMPORT_NAME"
        | "IMPORT_FROM"
        | "LOAD_METHOD"
        | "LOAD_FROM_DICT_OR_GLOBALS" => co.names.get(arg as usize).map(object_label),
        "LOAD_FAST"
        | "STORE_FAST"
        | "DELETE_FAST"
        | "LOAD_FAST_CHECK"
        | "LOAD_FAST_AND_CLEAR"
        | "LOAD_FAST_BORROW"
        | "MAKE_CELL"
        | "LOAD_DEREF"
        | "STORE_DEREF"
        | "DELETE_DEREF"
        | "LOAD_CLASSDEREF"
        | "LOAD_FROM_DICT_OR_DEREF" => local_name(co, arg as usize, version).map(object_label),
        "COMPARE_OP" => compare_op_repr(arg, version),
        "IS_OP" => is_op_repr(arg, version),
        "CONTAINS_OP" => contains_op_repr(arg, version),
        "FORMAT_VALUE" => Some(format_value_repr(arg)),
        "MAKE_FUNCTION" | "SET_FUNCTION_ATTRIBUTE" => Some(join_function_flags(arg)),
        _ => None,
    }
}

fn load_global_repr(co: &CodeObject, arg: u32, version: PyVersion) -> Option<String> {
    let shifted: bool = version.major == 3 && version.minor >= 11;
    let (index, null_flag): (usize, bool) = if shifted {
        ((arg >> 1) as usize, arg & 1 != 0)
    } else {
        (arg as usize, false)
    };
    let name: String = co.names.get(index).map(object_label)?;
    Some(decorate_null(name, null_flag, "NULL", version))
}

fn load_attr_repr(co: &CodeObject, arg: u32, version: PyVersion) -> Option<String> {
    let shifted: bool = version.major == 3 && version.minor >= 12;
    let (index, self_flag): (usize, bool) = if shifted {
        ((arg >> 1) as usize, arg & 1 != 0)
    } else {
        (arg as usize, false)
    };
    let name: String = co.names.get(index).map(object_label)?;
    Some(decorate_null(name, self_flag, "NULL|self", version))
}

#[inline]
fn decorate_null(name: String, flag: bool, marker: &str, version: PyVersion) -> String {
    if !flag {
        return name;
    }
    if version.major == 3 && version.minor >= 13 {
        format!("{name} + {marker}")
    } else {
        format!("{marker} + {name}")
    }
}

fn local_name(
    co: &CodeObject,
    index: usize,
    version: PyVersion,
) -> Option<&disrobe_py_marshal::Object> {
    if version.major == 3 && version.minor >= 11 {
        co.localsplusnames
            .get(index)
            .or_else(|| co.varnames.get(index))
    } else {
        co.varnames.get(index)
    }
}

fn compare_op_repr(arg: u32, version: PyVersion) -> Option<String> {
    let is_313_plus: bool = version.major > 3 || (version.major == 3 && version.minor >= 13);
    let is_312: bool = version.major == 3 && version.minor == 12;
    let index: usize = if is_313_plus {
        (arg >> 5) as usize
    } else if is_312 {
        (arg >> 4) as usize
    } else {
        arg as usize
    };
    let modern: bool = version.major > 3 || (version.major == 3 && version.minor >= 11);
    let operator: &str = if modern {
        CMP_OP_MODERN.get(index).copied()?
    } else {
        CMP_OP_LEGACY.get(index).copied()?
    };
    if is_313_plus && arg & COMPARE_OP_TO_BOOL_BIT != 0 {
        Some(format!("bool({operator})"))
    } else {
        Some(operator.to_owned())
    }
}

fn is_op_repr(arg: u32, version: PyVersion) -> Option<String> {
    if version.major > 3 || (version.major == 3 && version.minor >= 14) {
        Some(if arg == 0 {
            "is".to_owned()
        } else {
            "is not".to_owned()
        })
    } else {
        None
    }
}

fn contains_op_repr(arg: u32, version: PyVersion) -> Option<String> {
    if version.major > 3 || (version.major == 3 && version.minor >= 14) {
        Some(if arg == 0 {
            "in".to_owned()
        } else {
            "not in".to_owned()
        })
    } else {
        None
    }
}

fn format_value_repr(arg: u32) -> String {
    let conversion: &str = FORMAT_VALUE_CONVERSIONS
        .get((arg & FORMAT_VALUE_CONVERSION_MASK) as usize)
        .copied()
        .unwrap_or("");
    let have_spec: bool = arg & FORMAT_VALUE_HAVE_SPEC != 0;
    match (conversion.is_empty(), have_spec) {
        (true, false) => String::new(),
        (true, true) => "with format".to_owned(),
        (false, false) => conversion.to_owned(),
        (false, true) => format!("{conversion}, with format"),
    }
}

fn join_function_flags(arg: u32) -> String {
    MAKE_FUNCTION_FLAGS
        .iter()
        .filter_map(|(bit, label): &(u32, &str)| (arg & bit != 0).then_some(*label))
        .collect::<Vec<&str>>()
        .join(", ")
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
    fn extended_arg_opcode_version_gated() {
        let cases: [(PyVersion, u8); 4] = [
            (PyVersion::PY311, 144),
            (PyVersion::PY312, 144),
            (PyVersion::PY313, 71),
            (PyVersion::PY314, 69),
        ];
        for (version, op) in cases {
            assert!(
                is_extended_arg(op, version),
                "EXTENDED_ARG op {op} must be recognized on {version:?}"
            );
            assert_eq!(opname(op, version), "EXTENDED_ARG");
        }
    }

    #[test]
    fn extended_arg_accumulates_high_bits_on_313() {
        let mut co: CodeObject = CodeObject::new(CodeEra::Py311Plus);
        co.code = vec![71, 0x12, 83, 0x34];
        let result: Vec<Instruction> = disassemble(&co, PyVersion::PY313);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].opname, "EXTENDED_ARG");
        let load_const: &Instruction = result.last().expect("load_const present");
        assert_eq!(load_const.opname, "LOAD_CONST");
        assert_eq!(load_const.arg, Some(0x1200u32 | 0x34));
    }

    #[test]
    fn truncated_legacy_does_not_panic() {
        let mut co: CodeObject = CodeObject::new(CodeEra::Py27);
        co.code = vec![100, 0];
        let result: Vec<Instruction> = disassemble(&co, PyVersion::PY27);
        assert!(result.is_empty());
    }

    #[test]
    fn is_op_resolves_on_311_through_314() {
        let cases: [(PyVersion, u8); 4] = [
            (PyVersion::PY311, 117),
            (PyVersion::PY312, 117),
            (PyVersion::PY313, 76),
            (PyVersion::PY314, 74),
        ];
        for (version, op) in cases {
            assert_eq!(opname(op, version), "IS_OP", "IS_OP missing on {version:?}");
        }
    }

    #[test]
    fn call_intrinsic_resolves_on_312_through_314() {
        let cases: [(PyVersion, u8, u8); 3] = [
            (PyVersion::PY312, 173, 174),
            (PyVersion::PY313, 55, 56),
            (PyVersion::PY314, 53, 54),
        ];
        for (version, op1, op2) in cases {
            assert_eq!(opname(op1, version), "CALL_INTRINSIC_1", "on {version:?}");
            assert_eq!(opname(op2, version), "CALL_INTRINSIC_2", "on {version:?}");
        }
    }

    #[test]
    fn no_arg_opcodes_report_none_arg_on_wordcode() {
        let mut co: CodeObject = CodeObject::new(CodeEra::Py311Plus);
        co.code = vec![83, 0, 9, 0];
        let result: Vec<Instruction> = disassemble(&co, PyVersion::PY312);
        assert_eq!(result[0].opname, "RETURN_VALUE");
        assert_eq!(result[0].arg, None);
        assert_eq!(result[1].opname, "NOP");
        assert_eq!(result[1].arg, None);
    }

    #[test]
    fn load_global_name_index_shifts_on_311_plus() {
        let mut co: CodeObject = CodeObject::new(CodeEra::Py311Plus);
        co.names = vec![ascii("zzz"), ascii("qqq")];
        co.code = vec![116, 2];
        let result: Vec<Instruction> = disassemble(&co, PyVersion::PY311);
        assert_eq!(result[0].opname, "LOAD_GLOBAL");
        assert_eq!(result[0].arg, Some(2));
        assert_eq!(result[0].argrepr.as_deref(), Some("qqq"));
    }

    #[test]
    fn load_global_null_flag_renders_per_version() {
        let mut co: CodeObject = CodeObject::new(CodeEra::Py311Plus);
        co.names = vec![ascii("range")];
        co.code = vec![116, 1];
        let twelve: Vec<Instruction> = disassemble(&co, PyVersion::PY312);
        assert_eq!(twelve[0].argrepr.as_deref(), Some("NULL + range"));
        let thirteen: Vec<Instruction> = {
            let mut c: CodeObject = CodeObject::new(CodeEra::Py311Plus);
            c.names = vec![ascii("range")];
            c.code = vec![91, 1];
            disassemble(&c, PyVersion::PY313)
        };
        assert_eq!(thirteen[0].opname, "LOAD_GLOBAL");
        assert_eq!(thirteen[0].argrepr.as_deref(), Some("range + NULL"));
    }

    #[test]
    fn compare_op_decodes_operator_per_version() {
        let mut legacy: CodeObject = CodeObject::new(CodeEra::Py38to310);
        legacy.code = vec![107, 8, 0];
        let nine: Vec<Instruction> = disassemble(&legacy, PyVersion::PY39);
        assert_eq!(nine[0].opname, "COMPARE_OP");
        assert_eq!(nine[0].argrepr.as_deref(), Some("is"));

        let mut twelve: CodeObject = CodeObject::new(CodeEra::Py311Plus);
        twelve.code = vec![107, 2];
        let result: Vec<Instruction> = disassemble(&twelve, PyVersion::PY312);
        assert_eq!(result[0].argrepr.as_deref(), Some("<"));

        let mut thirteen: CodeObject = CodeObject::new(CodeEra::Py311Plus);
        thirteen.code = vec![58, 148];
        let bool_cmp: Vec<Instruction> = disassemble(&thirteen, PyVersion::PY313);
        assert_eq!(bool_cmp[0].opname, "COMPARE_OP");
        assert_eq!(bool_cmp[0].argrepr.as_deref(), Some("bool(>)"));
    }

    #[test]
    fn lnotab_assigns_consecutive_line_starts() {
        let mut co: CodeObject = CodeObject::new(CodeEra::Py38to310);
        co.firstlineno = 1;
        co.lnotab = vec![0, 1, 4, 1, 4, 1];
        co.code = vec![9, 0, 9, 0, 9, 0, 9, 0, 9, 0, 9, 0];
        let result: Vec<Instruction> = disassemble(&co, PyVersion::PY38);
        assert_eq!(result[0].line, Some(2));
        assert_eq!(result[1].line, None);
        assert_eq!(result[2].line, Some(3));
        assert_eq!(result[4].line, Some(4));
    }

    #[test]
    fn jump_target_marks_relative_forward_destination() {
        let mut co: CodeObject = CodeObject::new(CodeEra::Py38to310);
        co.code = vec![110, 2, 9, 0, 9, 0];
        let result: Vec<Instruction> = disassemble(&co, PyVersion::PY39);
        assert_eq!(result[0].opname, "JUMP_FORWARD");
        assert!(!result[0].is_jump_target);
        let target: &Instruction = result
            .iter()
            .find(|i: &&Instruction| i.offset == 4)
            .expect("target instruction at offset 4");
        assert!(
            target.is_jump_target,
            "offset 4 (0 + 2 + arg) should be a jump target"
        );
    }

    #[test]
    fn jump_target_marks_backward_destination_on_311() {
        let mut co: CodeObject = CodeObject::new(CodeEra::Py311Plus);
        co.code = vec![9, 0, 9, 0, 140, 3];
        let result: Vec<Instruction> = disassemble(&co, PyVersion::PY311);
        assert_eq!(result[2].opname, "JUMP_BACKWARD");
        let target: &Instruction = result
            .iter()
            .find(|i: &&Instruction| i.offset == 0)
            .expect("target at offset 0");
        assert!(
            target.is_jump_target,
            "JUMP_BACKWARD destination should be marked"
        );
    }

    fn ascii(value: &str) -> disrobe_py_marshal::Object {
        disrobe_py_marshal::Object::ShortAscii {
            value: value.to_owned(),
            interned: false,
        }
    }
}
