#![forbid(unsafe_code)]
#![deny(unreachable_pub)]
#![allow(clippy::redundant_pub_crate)]

pub(crate) fn push_string_fmt(out: &mut String, args: std::fmt::Arguments<'_>) {
    match std::fmt::write(out, args) {
        Ok(()) => {}
        Err(error) => unreachable!("string formatting failed: {error:?}"),
    }
}

pub(crate) fn push_string_line(out: &mut String, args: std::fmt::Arguments<'_>) {
    push_string_fmt(out, args);
    out.push('\n');
}

pub mod alt_runtimes;
mod cfg;
#[cfg(feature = "chain")]
pub mod chain_detector;
mod const_repr;
pub use const_repr::is_python_printable;
pub(crate) mod debug;
mod exception_table;
pub mod format_wire;
mod jumps;
mod lines;
mod listing;
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
pub use listing::render_listing;
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
    let wordcode: bool = version.is_wordcode();
    crate::debug::dbg_kv("code-object", || {
        format!(
            "py{}.{} {} code_len={} consts={} names={} varnames={}",
            version.major,
            version.minor,
            if wordcode { "wordcode" } else { "legacy" },
            co.code.len(),
            co.consts.len(),
            co.names.len(),
            co.varnames.len()
        )
    });
    let mut instructions: Vec<Instruction> = if wordcode {
        disassemble_wordcode(co, version)
    } else {
        disassemble_legacy(co, version)
    };
    assign_line_numbers(&mut instructions, co, version);
    mark_jump_targets(&mut instructions, version);
    let labels: listing::LabelMap = listing::LabelMap::build(&instructions, co, version);
    listing::assign_jump_arrows(&mut instructions, &labels, version);
    crate::debug::dbg_kv("disassembled", || {
        let jump_targets: usize = instructions
            .iter()
            .filter(|i: &&Instruction| i.is_jump_target)
            .count();
        format!(
            "instructions={} jump_targets={}",
            instructions.len(),
            jump_targets
        )
    });
    instructions
}

fn assign_line_numbers(instructions: &mut [Instruction], co: &CodeObject, version: PyVersion) {
    let line_map: lines::LineMap = lines::LineMap::build(co, version);
    let mut cursor: lines::LineCursor<'_> = line_map.cursor();
    for instruction in instructions.iter_mut() {
        let offset: u32 = instruction.offset as u32;
        let resolution: lines::LineResolution = cursor.resolve(offset, None);
        instruction.line = resolution.start_line;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct JumpFitness {
    pub jumps: usize,
    pub resolved: usize,
    pub on_boundary: usize,
}

impl JumpFitness {
    #[must_use]
    pub const fn all_valid(self) -> bool {
        self.jumps == 0 || (self.resolved == self.jumps && self.on_boundary == self.jumps)
    }
}

#[must_use]
pub fn jump_target_fitness(co: &CodeObject, version: PyVersion) -> JumpFitness {
    let instructions: Vec<Instruction> = disassemble(co, version);
    let code_len: u32 = co.code.len() as u32;
    let offsets: std::collections::BTreeSet<u32> = instructions
        .iter()
        .map(|i: &Instruction| i.offset as u32)
        .collect();
    let mut fitness: JumpFitness = JumpFitness {
        jumps: 0,
        resolved: 0,
        on_boundary: 0,
    };
    for instruction in &instructions {
        let kind: jumps::JumpKind = jumps::jump_kind(&instruction.opname, version);
        if matches!(kind, jumps::JumpKind::None) {
            continue;
        }
        let Some(arg): Option<u32> = instruction.arg else {
            continue;
        };
        fitness.jumps += 1;
        let caches: u32 = u32::from(cache_size(instruction.opcode, version));
        let Some(target): Option<u32> =
            jumps::jump_target(kind, instruction.offset as u32, arg, caches, version)
        else {
            continue;
        };
        fitness.resolved += 1;
        if target < code_len && offsets.contains(&target) {
            fitness.on_boundary += 1;
        }
    }
    fitness
}

const MAX_EXTENDED_ARG_PREFIXES: u32 = 3;

fn disassemble_wordcode(co: &CodeObject, version: PyVersion) -> Vec<Instruction> {
    let code: &Vec<u8> = &co.code;
    let mut out: Vec<Instruction> = Vec::with_capacity(code.len() / 2);
    let mut extended_arg: u32 = 0;
    let mut extended_prefixes: u32 = 0;
    let mut cursor: usize = 0usize;
    while cursor + 1 < code.len() {
        let op: u8 = code[cursor];
        let arg_byte: u8 = code[cursor + 1];
        let name: &'static str = opname(op, version);
        if is_extended_arg(op, version) {
            let combined: u32 = extended_arg | u32::from(arg_byte);
            extended_arg = if combined > (u32::MAX >> 8) {
                u32::MAX
            } else {
                combined << 8
            };
            extended_prefixes = extended_prefixes.saturating_add(1);
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
        let argrepr: Option<String> = overlong_extended_arg_note(extended_prefixes)
            .or_else(|| argrepr(co, name, arg, version));
        extended_arg = 0;
        extended_prefixes = 0;
        out.push(Instruction {
            offset: cursor,
            opcode: op,
            opname: name.to_owned(),
            arg,
            argrepr,
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

fn overlong_extended_arg_note(prefixes: u32) -> Option<String> {
    (prefixes > MAX_EXTENDED_ARG_PREFIXES)
        .then(|| format!("EXTENDED_ARG chain of {prefixes} prefixes saturated at 32-bit ceiling"))
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
const FUNCTION_ATTR_FLAGS: [(u32, &str); 5] = [
    (0x01, "defaults"),
    (0x02, "kwdefaults"),
    (0x04, "annotations"),
    (0x08, "closure"),
    (0x10, "annotate"),
];

const INTRINSIC_1_DESCS: [&str; 12] = [
    "INTRINSIC_1_INVALID",
    "INTRINSIC_PRINT",
    "INTRINSIC_IMPORT_STAR",
    "INTRINSIC_STOPITERATION_ERROR",
    "INTRINSIC_ASYNC_GEN_WRAP",
    "INTRINSIC_UNARY_POSITIVE",
    "INTRINSIC_LIST_TO_TUPLE",
    "INTRINSIC_TYPEVAR",
    "INTRINSIC_PARAMSPEC",
    "INTRINSIC_TYPEVARTUPLE",
    "INTRINSIC_SUBSCRIPT_GENERIC",
    "INTRINSIC_TYPEALIAS",
];

const INTRINSIC_2_DESCS_312: [&str; 5] = [
    "INTRINSIC_2_INVALID",
    "INTRINSIC_PREP_RERAISE_STAR",
    "INTRINSIC_TYPEVAR_WITH_BOUND",
    "INTRINSIC_TYPEVAR_WITH_CONSTRAINTS",
    "INTRINSIC_SET_FUNCTION_TYPE_PARAMS",
];

const INTRINSIC_2_DESCS_313: [&str; 6] = [
    "INTRINSIC_2_INVALID",
    "INTRINSIC_PREP_RERAISE_STAR",
    "INTRINSIC_TYPEVAR_WITH_BOUND",
    "INTRINSIC_TYPEVAR_WITH_CONSTRAINTS",
    "INTRINSIC_SET_FUNCTION_TYPE_PARAMS",
    "INTRINSIC_SET_TYPEPARAM_DEFAULT",
];

fn argrepr(co: &CodeObject, opname: &str, arg: Option<u32>, version: PyVersion) -> Option<String> {
    let arg: u32 = arg?;
    match opname {
        "LOAD_CONST" | "KW_NAMES" | "RETURN_CONST" => {
            co.consts.get(arg as usize).map(const_repr::repr_const)
        }
        "LOAD_COMMON_CONSTANT" => common_constant_repr(arg, version),
        "LOAD_FAST_LOAD_FAST"
        | "LOAD_FAST_BORROW_LOAD_FAST_BORROW"
        | "STORE_FAST_LOAD_FAST"
        | "STORE_FAST_STORE_FAST" => dual_local_repr(co, arg, version),
        "LOAD_GLOBAL" => load_global_repr(co, arg, version),
        "LOAD_ATTR" => load_attr_repr(co, arg, version),
        "LOAD_NAME"
        | "STORE_NAME"
        | "DELETE_NAME"
        | "STORE_GLOBAL"
        | "DELETE_GLOBAL"
        | "STORE_ATTR"
        | "DELETE_ATTR"
        | "IMPORT_FROM"
        | "LOAD_METHOD"
        | "LOAD_FROM_DICT_OR_GLOBALS" => co.names.get(arg as usize).map(object_label),
        "IMPORT_NAME" => import_name_repr(co, arg, version),
        "LOAD_SPECIAL" => special_method_repr(arg),
        "LOAD_FAST"
        | "STORE_FAST"
        | "DELETE_FAST"
        | "LOAD_FAST_CHECK"
        | "LOAD_FAST_AND_CLEAR"
        | "LOAD_FAST_BORROW"
        | "MAKE_CELL"
        | "LOAD_CLOSURE"
        | "LOAD_DEREF"
        | "STORE_DEREF"
        | "DELETE_DEREF"
        | "LOAD_CLASSDEREF"
        | "LOAD_FROM_DICT_OR_DEREF" => local_name(co, arg as usize, version).map(object_label),
        "COMPARE_OP" => compare_op_repr(arg, version),
        "BINARY_OP" => binary_op_repr(arg, version),
        "IS_OP" => is_op_repr(arg, version),
        "CONTAINS_OP" => contains_op_repr(arg, version),
        "FORMAT_VALUE" => Some(format_value_repr(arg)),
        "CONVERT_VALUE" => convert_value_repr(arg),
        "MAKE_FUNCTION" => make_function_repr(arg, version),
        "SET_FUNCTION_ATTRIBUTE" => Some(join_function_flags(arg, version)),
        "CALL_INTRINSIC_1" => intrinsic_1_repr(arg),
        "CALL_INTRINSIC_2" => intrinsic_2_repr(arg, version),
        _ => None,
    }
}

fn intrinsic_1_repr(arg: u32) -> Option<String> {
    INTRINSIC_1_DESCS
        .get(arg as usize)
        .map(|name: &&str| (*name).to_owned())
}

fn intrinsic_2_repr(arg: u32, version: PyVersion) -> Option<String> {
    let table: &[&str] = if version.major > 3 || (version.major == 3 && version.minor >= 13) {
        &INTRINSIC_2_DESCS_313
    } else {
        &INTRINSIC_2_DESCS_312
    };
    table
        .get(arg as usize)
        .map(|name: &&str| (*name).to_owned())
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

const SPECIAL_METHOD_NAMES: [&str; 4] = ["__enter__", "__exit__", "__aenter__", "__aexit__"];

fn special_method_repr(arg: u32) -> Option<String> {
    SPECIAL_METHOD_NAMES
        .get(arg as usize)
        .map(|name: &&str| (*name).to_owned())
}

fn import_name_repr(co: &CodeObject, arg: u32, version: PyVersion) -> Option<String> {
    let shifted: bool = version.major > 3 || (version.major == 3 && version.minor >= 15);
    if !shifted {
        return co.names.get(arg as usize).map(object_label);
    }
    let name: String = co.names.get((arg >> 2) as usize).map(object_label)?;
    if arg & 1 != 0 {
        Some(format!("{name} + lazy"))
    } else if arg & 2 != 0 {
        Some(format!("{name} + eager"))
    } else {
        Some(name)
    }
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

const COMMON_CONSTANTS_314: [&str; 5] = [
    "AssertionError",
    "NotImplementedError",
    "tuple",
    "<built-in function all>",
    "<built-in function any>",
];

const COMMON_CONSTANTS_315: [&str; 12] = [
    "AssertionError",
    "NotImplementedError",
    "tuple",
    "<built-in function all>",
    "<built-in function any>",
    "list",
    "set",
    "None",
    "''",
    "True",
    "False",
    "-1",
];

const NB_OPS: [&str; 27] = [
    "+", "&", "//", "<<", "@", "*", "%", "|", "**", ">>", "-", "/", "^", "+=", "&=", "//=", "<<=",
    "@=", "*=", "%=", "|=", "**=", ">>=", "-=", "/=", "^=", "[]",
];

fn binary_op_repr(arg: u32, version: PyVersion) -> Option<String> {
    if version.major != 3 || version.minor < 11 {
        return None;
    }
    let limit: usize = if version.major > 3 || (version.major == 3 && version.minor >= 14) {
        NB_OPS.len()
    } else {
        NB_OPS.len() - 1
    };
    let index: usize = arg as usize;
    if index >= limit {
        return None;
    }
    NB_OPS.get(index).map(|symbol: &&str| (*symbol).to_owned())
}

fn common_constant_repr(arg: u32, version: PyVersion) -> Option<String> {
    let table: &[&str] = if version.major > 3 || (version.major == 3 && version.minor >= 15) {
        &COMMON_CONSTANTS_315
    } else {
        &COMMON_CONSTANTS_314
    };
    table
        .get(arg as usize)
        .map(|entry: &&str| (*entry).to_owned())
}

fn dual_local_repr(co: &CodeObject, arg: u32, version: PyVersion) -> Option<String> {
    let first: usize = (arg >> 4) as usize;
    let second: usize = (arg & 0x0f) as usize;
    let first_name: String = local_name(co, first, version).map(object_label)?;
    let second_name: String = local_name(co, second, version).map(object_label)?;
    Some(format!("{first_name}, {second_name}"))
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

fn convert_value_repr(arg: u32) -> Option<String> {
    let conversions: [&str; 4] = ["", "str", "repr", "ascii"];
    conversions
        .get(arg as usize)
        .filter(|conversion: &&&str| !conversion.is_empty())
        .map(|conversion: &&str| (*conversion).to_owned())
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

fn make_function_repr(arg: u32, version: PyVersion) -> Option<String> {
    let renders_flags: bool = version.major > 3 || (version.major == 3 && version.minor >= 8);
    renders_flags.then(|| join_function_flags(arg, version))
}

fn join_function_flags(arg: u32, version: PyVersion) -> String {
    let has_annotate: bool = version.major > 3 || (version.major == 3 && version.minor >= 14);
    let limit: usize = if has_annotate {
        FUNCTION_ATTR_FLAGS.len()
    } else {
        FUNCTION_ATTR_FLAGS.len() - 1
    };
    FUNCTION_ATTR_FLAGS[..limit]
        .iter()
        .filter_map(|(bit, label): &(u32, &str)| (arg & bit != 0).then_some(*label))
        .collect::<Vec<&str>>()
        .join(", ")
}

fn object_label(obj: &disrobe_py_marshal::Object) -> String {
    match obj {
        disrobe_py_marshal::Object::String { value, .. }
        | disrobe_py_marshal::Object::Unicode { value, .. }
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
        push_string_fmt(
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
    fn extended_arg_two_prefix_chain_matches_cpython_312() {
        let mut co: CodeObject = CodeObject::new(CodeEra::Py311Plus);
        co.code = vec![100, 1, 144, 1, 144, 0, 125, 0];
        let result: Vec<Instruction> = disassemble(&co, PyVersion::PY312);
        assert_eq!(result.len(), 4);
        assert_eq!(result[0].opname, "LOAD_CONST");
        assert_eq!(result[1].opname, "EXTENDED_ARG");
        assert_eq!(result[2].opname, "EXTENDED_ARG");
        let store_fast: &Instruction = result.last().expect("store_fast present");
        assert_eq!(store_fast.opname, "STORE_FAST");
        assert_eq!(store_fast.arg, Some(0x1_0000u32));
    }

    #[test]
    fn overlong_extended_arg_chain_saturates_and_marks() {
        let mut co: CodeObject = CodeObject::new(CodeEra::Py311Plus);
        co.code = vec![
            144, 0xFF, 144, 0xFF, 144, 0xFF, 144, 0xFF, 144, 0xFF, 100, 0xFF,
        ];
        let result: Vec<Instruction> = disassemble(&co, PyVersion::PY312);
        let load_const: &Instruction = result.last().expect("load_const present");
        assert_eq!(load_const.opname, "LOAD_CONST");
        assert_eq!(load_const.arg, Some(u32::MAX));
        let note: &str = load_const
            .argrepr
            .as_deref()
            .expect("overlong note present");
        assert!(
            note.contains("EXTENDED_ARG chain of 5 prefixes"),
            "over-long chain must surface a visible marker, got {note:?}"
        );
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
    fn large_lnotab_line_assignment_is_bounded() {
        let region_pairs: usize = 40_000;
        let mut co: CodeObject = CodeObject::new(CodeEra::Py38to310);
        co.firstlineno = 1;
        co.lnotab = Vec::with_capacity(region_pairs * 2);
        co.code = Vec::with_capacity(region_pairs * 2);
        for _ in 0..region_pairs {
            co.lnotab.push(2u8);
            co.lnotab.push(1u8);
            co.code.extend_from_slice(&[9u8, 0u8]);
        }
        let start: std::time::Instant = std::time::Instant::now();
        let result: Vec<Instruction> = disassemble(&co, PyVersion::PY38);
        let elapsed: std::time::Duration = start.elapsed();
        assert_eq!(result.len(), region_pairs);
        assert_eq!(result.first().and_then(|i: &Instruction| i.line), Some(1));
        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "line assignment took {elapsed:?}, expected sub-quadratic"
        );
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

    #[test]
    fn intrinsic_1_names_match_interpreter_table() {
        assert_eq!(
            intrinsic_1_repr(2).as_deref(),
            Some("INTRINSIC_IMPORT_STAR")
        );
        assert_eq!(
            intrinsic_1_repr(3).as_deref(),
            Some("INTRINSIC_STOPITERATION_ERROR")
        );
        assert_eq!(
            intrinsic_1_repr(4).as_deref(),
            Some("INTRINSIC_ASYNC_GEN_WRAP")
        );
        assert_eq!(
            intrinsic_1_repr(6).as_deref(),
            Some("INTRINSIC_LIST_TO_TUPLE")
        );
        assert_eq!(intrinsic_1_repr(7).as_deref(), Some("INTRINSIC_TYPEVAR"));
        assert_eq!(intrinsic_1_repr(11).as_deref(), Some("INTRINSIC_TYPEALIAS"));
        assert_eq!(intrinsic_1_repr(12), None);
    }

    #[test]
    fn intrinsic_2_table_drifts_between_312_and_313() {
        assert_eq!(
            intrinsic_2_repr(1, PyVersion::PY312).as_deref(),
            Some("INTRINSIC_PREP_RERAISE_STAR")
        );
        assert_eq!(
            intrinsic_2_repr(4, PyVersion::PY312).as_deref(),
            Some("INTRINSIC_SET_FUNCTION_TYPE_PARAMS")
        );
        assert_eq!(intrinsic_2_repr(5, PyVersion::PY312), None);
        assert_eq!(
            intrinsic_2_repr(5, PyVersion::PY313).as_deref(),
            Some("INTRINSIC_SET_TYPEPARAM_DEFAULT")
        );
        assert_eq!(
            intrinsic_2_repr(5, PyVersion::PY315).as_deref(),
            Some("INTRINSIC_SET_TYPEPARAM_DEFAULT")
        );
    }

    #[test]
    fn special_method_names_match_interpreter_table() {
        assert_eq!(special_method_repr(0).as_deref(), Some("__enter__"));
        assert_eq!(special_method_repr(2).as_deref(), Some("__aenter__"));
        assert_eq!(special_method_repr(3).as_deref(), Some("__aexit__"));
        assert_eq!(special_method_repr(4), None);
    }

    #[test]
    fn function_attr_annotate_flag_gated_to_314() {
        assert_eq!(join_function_flags(0x08, PyVersion::PY312), "closure");
        assert_eq!(join_function_flags(0x10, PyVersion::PY313), "");
        assert_eq!(join_function_flags(0x10, PyVersion::PY314), "annotate");
        assert_eq!(join_function_flags(0x10, PyVersion::PY315), "annotate");
    }

    #[test]
    fn import_name_shifts_and_flags_on_315_only() {
        let mut co: CodeObject = CodeObject::new(CodeEra::Py311Plus);
        co.names = vec![ascii("math"), ascii("os"), ascii("sys")];
        assert_eq!(
            import_name_repr(&co, 2, PyVersion::PY314).as_deref(),
            Some("sys")
        );
        assert_eq!(
            import_name_repr(&co, 2, PyVersion::PY315).as_deref(),
            Some("math + eager")
        );
        assert_eq!(
            import_name_repr(&co, 1, PyVersion::PY315).as_deref(),
            Some("math + lazy")
        );
        assert_eq!(
            import_name_repr(&co, 4, PyVersion::PY315).as_deref(),
            Some("os")
        );
    }

    fn ascii(value: &str) -> disrobe_py_marshal::Object {
        disrobe_py_marshal::Object::ShortAscii {
            value: value.to_owned(),
            interned: false,
        }
    }
}
