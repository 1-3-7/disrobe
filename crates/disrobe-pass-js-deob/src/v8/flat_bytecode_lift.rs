//! Lifts a flat-`BytecodeArray` [`Disassembly`] to a JS surface.
//!
//! Its input comes from [`super::flat_bytecode_disasm::disassemble`]. For a real `.jsc`,
//! [`super::code_serializer::parse_code_serializer_graph`] recovers the inline bytecode of each
//! serialized `BytecodeArray` and that disassembly flows through here.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::bytenode::NodeVersion;
use super::code_serializer::ConstantPoolEntry;
use super::flat_bytecode_disasm::{DecodedInstruction, Disassembly, intrinsic_name};

fn push_format(out: &mut String, args: std::fmt::Arguments<'_>) {
    let result: std::result::Result<(), std::fmt::Error> = std::fmt::write(out, args);
    if let Err(error) = result {
        unreachable!("string formatting failed: {error}");
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LiftFidelity {
    Reversible,
    Lossy,
    OpaqueRuntime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiftedLine {
    pub source_offset: usize,
    pub mnemonic: &'static str,
    pub fidelity: LiftFidelity,
    pub js_surface: String,
    pub ir_comment: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiftedFunction {
    pub node_version: NodeVersion,
    pub v8_version_label: &'static str,
    pub lines: Vec<LiftedLine>,
    pub reversible_count: usize,
    pub lossy_count: usize,
    pub opaque_runtime_count: usize,
}

impl LiftedFunction {
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn reversible_fraction(&self) -> f64 {
        let total: usize = self.lines.len();
        if total == 0 {
            return 0.0;
        }
        let total_f: f64 = total as f64;
        let rev_f: f64 = self.reversible_count as f64;
        rev_f / total_f
    }

    #[must_use]
    pub fn render_js(&self, function_name: &str) -> String {
        let mut out: String = String::with_capacity(self.lines.len() * 32usize);
        push_format(&mut out, format_args!("function {function_name}() {{\n"));
        let mut emitted: usize = 0usize;
        for line in &self.lines {
            if line.js_surface.is_empty() {
                continue;
            }
            for stmt in line.js_surface.split('\n') {
                if stmt.is_empty() {
                    continue;
                }
                push_format(&mut out, format_args!("  {stmt}\n"));
                emitted = emitted.saturating_add(1);
            }
        }
        if emitted == 0usize {
            out.push_str("  return undefined;\n");
        }
        out.push_str("}\n");
        out
    }
}

#[must_use]
pub fn lift_disassembly(disasm: &Disassembly) -> LiftedFunction {
    lift_disassembly_with_pool(disasm, &[])
}

#[must_use]
pub fn lift_disassembly_with_pool(
    disasm: &Disassembly,
    constant_pool: &[ConstantPoolEntry],
) -> LiftedFunction {
    let mut lines: Vec<LiftedLine> = Vec::with_capacity(disasm.instructions.len());
    let mut acc_state: String = "undefined".to_owned();
    let mut reg_state: BTreeMap<i64, String> = BTreeMap::new();
    let mut reversible: usize = 0usize;
    let mut lossy: usize = 0usize;
    let mut opaque: usize = 0usize;
    for ins in &disasm.instructions {
        let line: LiftedLine = lift_instruction(ins, constant_pool, &mut acc_state, &mut reg_state);
        match line.fidelity {
            LiftFidelity::Reversible => reversible = reversible.saturating_add(1),
            LiftFidelity::Lossy => lossy = lossy.saturating_add(1),
            LiftFidelity::OpaqueRuntime => opaque = opaque.saturating_add(1),
        }
        lines.push(line);
    }
    LiftedFunction {
        node_version: disasm.node_version,
        v8_version_label: disasm.v8_version_label,
        lines,
        reversible_count: reversible,
        lossy_count: lossy,
        opaque_runtime_count: opaque,
    }
}

fn reg_name(idx: i64) -> String {
    if idx <= -1 {
        format!("p{}", (-idx).saturating_sub(1))
    } else {
        format!("r{idx}")
    }
}

fn const_name(idx: u64) -> String {
    format!("__c{idx}")
}

fn pool_entry(pool: &[ConstantPoolEntry], idx: u64) -> Option<&ConstantPoolEntry> {
    usize::try_from(idx).ok().and_then(|i: usize| pool.get(i))
}

fn js_string_literal(value: &str) -> String {
    let mut out: String = String::with_capacity(value.len() + 2usize);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ => out.push(ch),
        }
    }
    out.push('"');
    out
}

fn const_literal(pool: &[ConstantPoolEntry], idx: u64) -> String {
    pool_entry(pool, idx)
        .and_then(ConstantPoolEntry::resolved_name)
        .map_or_else(|| const_name(idx), js_string_literal)
}

fn property_access(pool: &[ConstantPoolEntry], receiver: &str, idx: u64) -> String {
    match pool_entry(pool, idx).and_then(ConstantPoolEntry::resolved_name) {
        Some(name) if is_identifier(name) => format!("{receiver}.{name}"),
        Some(name) => format!("{receiver}[{}]", js_string_literal(name)),
        None => format!("{receiver}[{}]", const_name(idx)),
    }
}

fn property_name_target(pool: &[ConstantPoolEntry], idx: u64) -> String {
    match pool_entry(pool, idx).and_then(ConstantPoolEntry::resolved_name) {
        Some(name) if is_identifier(name) => format!(".{name}"),
        Some(name) => format!("[{}]", js_string_literal(name)),
        None => format!("[{}]", const_name(idx)),
    }
}

fn global_name(pool: &[ConstantPoolEntry], idx: u64) -> String {
    match pool_entry(pool, idx).and_then(ConstantPoolEntry::resolved_name) {
        Some(name) if is_identifier(name) => name.to_owned(),
        Some(name) => format!("globalThis[{}]", js_string_literal(name)),
        None => format!("globalThis[{}]", const_name(idx)),
    }
}

fn is_identifier(name: &str) -> bool {
    let mut chars: std::str::Chars<'_> = name.chars();
    let Some(first): Option<char> = chars.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == '_' || first == '$') {
        return false;
    }
    chars.all(|c: char| c.is_ascii_alphanumeric() || c == '_' || c == '$')
}

fn ctx_slot_name(depth: u64, slot: u64) -> String {
    if depth == 0 {
        format!("__ctx{slot}")
    } else {
        format!("__ctx{depth}_{slot}")
    }
}

fn module_var_name(cell_index: i64) -> String {
    if cell_index < 0 {
        format!("__import{}", -cell_index)
    } else {
        format!("__export{cell_index}")
    }
}

fn reg_expr(regs: &BTreeMap<i64, String>, idx: i64) -> String {
    regs.get(&idx).cloned().unwrap_or_else(|| reg_name(idx))
}

const fn type_of_literal(flag: u64) -> &'static str {
    match flag {
        0 => "\"number\"",
        1 => "\"string\"",
        2 => "\"symbol\"",
        3 => "\"boolean\"",
        4 => "\"bigint\"",
        5 => "\"undefined\"",
        6 => "\"function\"",
        _ => "\"object\"",
    }
}

fn decode_regexp_flags(bits: u64) -> String {
    let mut s: String = String::with_capacity(8usize);
    if bits & 1 != 0 {
        s.push('g');
    }
    if bits & 2 != 0 {
        s.push('i');
    }
    if bits & 4 != 0 {
        s.push('m');
    }
    if bits & 8 != 0 {
        s.push('y');
    }
    if bits & 16 != 0 {
        s.push('u');
    }
    if bits & 32 != 0 {
        s.push('s');
    }
    if bits & 128 != 0 {
        s.push('d');
    }
    if bits & 256 != 0 {
        s.push('v');
    }
    s
}

fn call_arg_list(
    regs: &BTreeMap<i64, String>,
    first: i64,
    count: i64,
    skip_receiver: bool,
) -> String {
    let start: i64 = if skip_receiver {
        first.saturating_add(1)
    } else {
        first
    };
    let effective: i64 = if skip_receiver {
        count.saturating_sub(1)
    } else {
        count
    };
    let mut parts: Vec<String> = Vec::new();
    let mut taken: i64 = 0i64;
    while taken < effective {
        let reg: i64 = start.saturating_add(taken);
        parts.push(reg_expr(regs, reg));
        taken = taken.saturating_add(1);
    }
    parts.join(", ")
}

#[allow(clippy::too_many_lines)]
fn lift_instruction(
    ins: &DecodedInstruction,
    pool: &[ConstantPoolEntry],
    acc: &mut String,
    regs: &mut BTreeMap<i64, String>,
) -> LiftedLine {
    let mn: &'static str = ins.mnemonic;
    let mut fidelity: LiftFidelity = LiftFidelity::Reversible;
    let mut surface: String = String::new();
    let mut ir_comment: Option<String> = None;
    match mn {
        "LdaZero" => {
            "0".clone_into(acc);
        }
        "LdaUndefined" => {
            "undefined".clone_into(acc);
        }
        "LdaNull" => {
            "null".clone_into(acc);
        }
        "LdaTrue" => {
            "true".clone_into(acc);
        }
        "LdaFalse" => {
            "false".clone_into(acc);
        }
        "LdaTheHole" => {
            "/* hole */ undefined".clone_into(acc);
            fidelity = LiftFidelity::Lossy;
            ir_comment = Some("V8 hole sentinel collapses to undefined at JS surface".to_owned());
        }
        "LdaSmi" => {
            if let Some(v) = ins.operands.first() {
                *acc = format!("{}", v.signed_value);
            }
        }
        "LdaConstant" => {
            if let Some(v) = ins.operands.first() {
                *acc = const_literal(pool, v.unsigned_value);
            }
        }
        "Ldar" => {
            if let Some(v) = ins.operands.first() {
                let name: String = reg_name(v.signed_value);
                *acc = regs.get(&v.signed_value).cloned().unwrap_or(name);
            }
        }
        "Star" | "Star0" | "Star1" | "Star2" | "Star3" | "Star4" | "Star5" | "Star6" | "Star7"
        | "Star8" | "Star9" | "Star10" | "Star11" | "Star12" | "Star13" | "Star14" | "Star15" => {
            let target: i64 = ins.operands.first().map_or_else(
                || {
                    mn.strip_prefix("Star")
                        .and_then(|s: &str| s.parse::<i64>().ok())
                        .unwrap_or(0i64)
                },
                |v| v.signed_value,
            );
            regs.insert(target, acc.clone());
            surface = format!("let {} = {};", reg_name(target), acc);
        }
        "Mov" => {
            if ins.operands.len() >= 2 {
                let src_idx: i64 = ins.operands[0].signed_value;
                let dst_idx: i64 = ins.operands[1].signed_value;
                let src_expr: String = regs
                    .get(&src_idx)
                    .cloned()
                    .unwrap_or_else(|| reg_name(src_idx));
                regs.insert(dst_idx, src_expr.clone());
                surface = format!("let {} = {};", reg_name(dst_idx), src_expr);
            }
        }
        "Add" => binary(acc, regs, ins, "+", &mut surface),
        "Sub" => binary(acc, regs, ins, "-", &mut surface),
        "Mul" => binary(acc, regs, ins, "*", &mut surface),
        "Div" => binary(acc, regs, ins, "/", &mut surface),
        "Mod" => binary(acc, regs, ins, "%", &mut surface),
        "Exp" => binary(acc, regs, ins, "**", &mut surface),
        "BitwiseOr" => binary(acc, regs, ins, "|", &mut surface),
        "BitwiseXor" => binary(acc, regs, ins, "^", &mut surface),
        "BitwiseAnd" => binary(acc, regs, ins, "&", &mut surface),
        "ShiftLeft" => binary(acc, regs, ins, "<<", &mut surface),
        "ShiftRight" => binary(acc, regs, ins, ">>", &mut surface),
        "ShiftRightLogical" => binary(acc, regs, ins, ">>>", &mut surface),
        "AddSmi" => binary_smi(acc, ins, "+"),
        "SubSmi" => binary_smi(acc, ins, "-"),
        "MulSmi" => binary_smi(acc, ins, "*"),
        "DivSmi" => binary_smi(acc, ins, "/"),
        "ModSmi" => binary_smi(acc, ins, "%"),
        "ExpSmi" => binary_smi(acc, ins, "**"),
        "BitwiseOrSmi" => binary_smi(acc, ins, "|"),
        "BitwiseXorSmi" => binary_smi(acc, ins, "^"),
        "BitwiseAndSmi" => binary_smi(acc, ins, "&"),
        "ShiftLeftSmi" => binary_smi(acc, ins, "<<"),
        "ShiftRightSmi" => binary_smi(acc, ins, ">>"),
        "ShiftRightLogicalSmi" => binary_smi(acc, ins, ">>>"),
        "Inc" => {
            *acc = format!("({acc}) + 1");
        }
        "Dec" => {
            *acc = format!("({acc}) - 1");
        }
        "Negate" => {
            *acc = format!("-({acc})");
        }
        "BitwiseNot" => {
            *acc = format!("~({acc})");
        }
        "LogicalNot" | "ToBooleanLogicalNot" => {
            *acc = format!("!({acc})");
        }
        "TypeOf" => {
            *acc = format!("typeof ({acc})");
        }
        "ToBoolean" => {
            *acc = format!("Boolean({acc})");
        }
        "ToString" => {
            *acc = format!("String({acc})");
        }
        "ToNumber" => {
            *acc = format!("Number({acc})");
        }
        "ToNumeric" => {
            *acc = format!("Number({acc})");
            fidelity = LiftFidelity::Lossy;
            ir_comment = Some("ToNumeric covers BigInt+Number; surface uses Number".to_owned());
        }
        "ToName" => {
            *acc = format!("String({acc})");
            fidelity = LiftFidelity::Lossy;
        }
        "ToObject" => {
            if let Some(v) = ins.operands.first() {
                surface = format!("let {} = Object({});", reg_name(v.signed_value), acc);
                regs.insert(v.signed_value, format!("Object({acc})"));
            }
        }
        "TestEqual" => test_binary(acc, regs, ins, "==", &mut surface),
        "TestEqualStrict" => test_binary(acc, regs, ins, "===", &mut surface),
        "TestLessThan" => test_binary(acc, regs, ins, "<", &mut surface),
        "TestGreaterThan" => test_binary(acc, regs, ins, ">", &mut surface),
        "TestLessThanOrEqual" => test_binary(acc, regs, ins, "<=", &mut surface),
        "TestGreaterThanOrEqual" => test_binary(acc, regs, ins, ">=", &mut surface),
        "TestInstanceOf" => test_binary(acc, regs, ins, "instanceof", &mut surface),
        "TestIn" => test_binary(acc, regs, ins, "in", &mut surface),
        "TestNull" => {
            *acc = format!("({acc}) === null");
        }
        "TestUndefined" => {
            *acc = format!("({acc}) === undefined");
        }
        "TestReferenceEqual" => {
            if let Some(r) = ins.operands.first() {
                let other: String = regs
                    .get(&r.signed_value)
                    .cloned()
                    .unwrap_or_else(|| reg_name(r.signed_value));
                *acc = format!("({acc}) === ({other})");
            }
        }
        "GetNamedProperty" => {
            if ins.operands.len() >= 2 {
                let recv_idx: i64 = ins.operands[0].signed_value;
                let name_idx: u64 = ins.operands[1].unsigned_value;
                let recv: String = regs
                    .get(&recv_idx)
                    .cloned()
                    .unwrap_or_else(|| reg_name(recv_idx));
                *acc = property_access(pool, &recv, name_idx);
            }
        }
        "GetKeyedProperty" => {
            if let Some(r) = ins.operands.first() {
                let recv: String = regs
                    .get(&r.signed_value)
                    .cloned()
                    .unwrap_or_else(|| reg_name(r.signed_value));
                *acc = format!("{recv}[{acc}]");
            }
        }
        "SetNamedProperty" | "DefineNamedOwnProperty" => {
            if ins.operands.len() >= 2 {
                let recv_idx: i64 = ins.operands[0].signed_value;
                let name_idx: u64 = ins.operands[1].unsigned_value;
                let recv: String = regs
                    .get(&recv_idx)
                    .cloned()
                    .unwrap_or_else(|| reg_name(recv_idx));
                surface = format!("{recv}{} = {acc};", property_name_target(pool, name_idx));
            }
        }
        "SetKeyedProperty" => {
            if ins.operands.len() >= 2 {
                let recv_idx: i64 = ins.operands[0].signed_value;
                let key_idx: i64 = ins.operands[1].signed_value;
                let recv: String = regs
                    .get(&recv_idx)
                    .cloned()
                    .unwrap_or_else(|| reg_name(recv_idx));
                let key: String = regs
                    .get(&key_idx)
                    .cloned()
                    .unwrap_or_else(|| reg_name(key_idx));
                surface = format!("{recv}[{key}] = {acc};");
            }
        }
        "CallProperty0" => {
            if ins.operands.len() >= 2 {
                let fn_idx: i64 = ins.operands[0].signed_value;
                let recv_idx: i64 = ins.operands[1].signed_value;
                let f: String = regs
                    .get(&fn_idx)
                    .cloned()
                    .unwrap_or_else(|| reg_name(fn_idx));
                let r: String = regs
                    .get(&recv_idx)
                    .cloned()
                    .unwrap_or_else(|| reg_name(recv_idx));
                *acc = format!("{f}.call({r})");
            }
        }
        "CallProperty1" => {
            if ins.operands.len() >= 3 {
                let fn_idx: i64 = ins.operands[0].signed_value;
                let recv_idx: i64 = ins.operands[1].signed_value;
                let a0: i64 = ins.operands[2].signed_value;
                let f: String = regs
                    .get(&fn_idx)
                    .cloned()
                    .unwrap_or_else(|| reg_name(fn_idx));
                let r: String = regs
                    .get(&recv_idx)
                    .cloned()
                    .unwrap_or_else(|| reg_name(recv_idx));
                let arg: String = regs.get(&a0).cloned().unwrap_or_else(|| reg_name(a0));
                *acc = format!("{f}.call({r}, {arg})");
            }
        }
        "CallProperty2" => {
            if ins.operands.len() >= 4 {
                let fn_idx: i64 = ins.operands[0].signed_value;
                let recv_idx: i64 = ins.operands[1].signed_value;
                let a0: i64 = ins.operands[2].signed_value;
                let a1: i64 = ins.operands[3].signed_value;
                let f: String = regs
                    .get(&fn_idx)
                    .cloned()
                    .unwrap_or_else(|| reg_name(fn_idx));
                let r: String = regs
                    .get(&recv_idx)
                    .cloned()
                    .unwrap_or_else(|| reg_name(recv_idx));
                let arg0: String = regs.get(&a0).cloned().unwrap_or_else(|| reg_name(a0));
                let arg1: String = regs.get(&a1).cloned().unwrap_or_else(|| reg_name(a1));
                *acc = format!("{f}.call({r}, {arg0}, {arg1})");
            }
        }
        "CallUndefinedReceiver0" => {
            if let Some(r) = ins.operands.first() {
                let f: String = regs
                    .get(&r.signed_value)
                    .cloned()
                    .unwrap_or_else(|| reg_name(r.signed_value));
                *acc = format!("{f}()");
            }
        }
        "CallUndefinedReceiver1" => {
            if ins.operands.len() >= 2 {
                let fn_idx: i64 = ins.operands[0].signed_value;
                let a0: i64 = ins.operands[1].signed_value;
                let f: String = regs
                    .get(&fn_idx)
                    .cloned()
                    .unwrap_or_else(|| reg_name(fn_idx));
                let arg0: String = regs.get(&a0).cloned().unwrap_or_else(|| reg_name(a0));
                *acc = format!("{f}({arg0})");
            }
        }
        "CallUndefinedReceiver2" => {
            if ins.operands.len() >= 3 {
                let fn_idx: i64 = ins.operands[0].signed_value;
                let a0: i64 = ins.operands[1].signed_value;
                let a1: i64 = ins.operands[2].signed_value;
                let f: String = regs
                    .get(&fn_idx)
                    .cloned()
                    .unwrap_or_else(|| reg_name(fn_idx));
                let arg0: String = regs.get(&a0).cloned().unwrap_or_else(|| reg_name(a0));
                let arg1: String = regs.get(&a1).cloned().unwrap_or_else(|| reg_name(a1));
                *acc = format!("{f}({arg0}, {arg1})");
            }
        }
        "Construct" => {
            if ins.operands.len() >= 3 {
                let f: String = reg_expr(regs, ins.operands[0].signed_value);
                let first: i64 = ins.operands[1].signed_value;
                let count: i64 = ins.operands[2].signed_value;
                let args: String = call_arg_list(regs, first, count, false);
                *acc = format!("new {f}({args})");
                fidelity = LiftFidelity::Lossy;
                ir_comment =
                    Some("Construct: new.target in acc; arg-list from register window".to_owned());
            } else if let Some(r) = ins.operands.first() {
                let f: String = reg_expr(regs, r.signed_value);
                *acc = format!("new {f}()");
                fidelity = LiftFidelity::Lossy;
            }
        }
        "Return" => {
            surface = format!("return {acc};");
        }
        "Throw" | "ReThrow" => {
            surface = format!("throw {acc};");
        }
        "Jump"
        | "JumpConstant"
        | "JumpIfTrue"
        | "JumpIfFalse"
        | "JumpIfTrueConstant"
        | "JumpIfFalseConstant"
        | "JumpIfToBooleanTrue"
        | "JumpIfToBooleanFalse"
        | "JumpIfToBooleanTrueConstant"
        | "JumpIfToBooleanFalseConstant"
        | "JumpIfNull"
        | "JumpIfNotNull"
        | "JumpIfUndefined"
        | "JumpIfNotUndefined"
        | "JumpIfUndefinedOrNull"
        | "JumpIfJSReceiver"
        | "JumpIfForInDone"
        | "JumpIfNullConstant"
        | "JumpIfNotNullConstant"
        | "JumpIfUndefinedConstant"
        | "JumpIfNotUndefinedConstant"
        | "JumpIfUndefinedOrNullConstant"
        | "JumpIfJSReceiverConstant"
        | "JumpIfForInDoneConstant"
        | "JumpLoop" => {
            let delta: i64 = ins.operands.first().map_or(0i64, |v| v.signed_value);
            surface = format!("/* jump mn={mn} delta={delta} */");
            fidelity = LiftFidelity::Lossy;
            ir_comment = Some(format!(
                "control-flow opcode {mn}: lowered to label/goto in MIR; surface JS requires reloop"
            ));
        }
        "CreateClosure" => {
            if let Some(v) = ins.operands.first() {
                let target: String = match pool_entry(pool, v.unsigned_value) {
                    Some(ConstantPoolEntry::InnerFunction { object_index }) => {
                        format!("__fn{object_index}")
                    }
                    _ => const_name(v.unsigned_value),
                };
                *acc = format!("/* closure */ ({target})");
                fidelity = LiftFidelity::Lossy;
                ir_comment = Some(
                    "CreateClosure references SharedFunctionInfo; body lifted separately"
                        .to_owned(),
                );
            }
        }
        "CreateEmptyObjectLiteral" => {
            "{}".clone_into(acc);
        }
        "CreateEmptyArrayLiteral" => {
            "[]".clone_into(acc);
        }
        "CreateMappedArguments" | "CreateUnmappedArguments" => {
            "arguments".clone_into(acc);
        }
        "Debugger" => {
            "debugger;".clone_into(&mut surface);
        }
        "LdaGlobal" | "LdaGlobalInsideTypeof" => {
            if let Some(v) = ins.operands.first() {
                *acc = global_name(pool, v.unsigned_value);
            }
        }
        "StaGlobal" => {
            if let Some(v) = ins.operands.first() {
                surface = format!("{} = {acc};", global_name(pool, v.unsigned_value));
            }
        }
        "InvokeIntrinsic" => {
            if ins.operands.len() >= 3 {
                let id: u64 = ins.operands[0].unsigned_value;
                let first: i64 = ins.operands[1].signed_value;
                let count: i64 = ins.operands[2].signed_value;
                let a0: String = if count >= 1 {
                    reg_expr(regs, first)
                } else {
                    "undefined".to_owned()
                };
                let a1: String = if count >= 2 {
                    reg_expr(regs, first.saturating_add(1))
                } else {
                    "undefined".to_owned()
                };
                let name: &str = intrinsic_name(id).unwrap_or("UnknownIntrinsic");
                match id {
                    11 => {
                        "import.meta".clone_into(acc);
                        fidelity = LiftFidelity::Lossy;
                        ir_comment = Some("GetImportMetaObject".to_owned());
                    }
                    12 => {
                        *acc = format!("{{...({a0})}}");
                        fidelity = LiftFidelity::Lossy;
                        ir_comment = Some(
                            "CopyDataProperties: object/spread copy of own enumerable props"
                                .to_owned(),
                        );
                    }
                    13 => {
                        let excluded: String = call_arg_list(regs, first, count, true);
                        *acc = format!("(({{...{a0}}}) /* excluding [{excluded}] */)");
                        fidelity = LiftFidelity::Lossy;
                        ir_comment = Some(
                            "CopyDataPropertiesWithExcludedPropertiesOnStack: rest spread minus listed keys"
                                .to_owned(),
                        );
                    }
                    14 => {
                        *acc = format!("{{value: {a0}, done: {a1}}}");
                        fidelity = LiftFidelity::Lossy;
                        ir_comment = Some("CreateIterResultObject".to_owned());
                    }
                    _ => {
                        let args_str: String = call_arg_list(regs, first, count, false);
                        *acc = format!("%{name}({args_str})");
                        fidelity = LiftFidelity::OpaqueRuntime;
                        ir_comment = Some(format!(
                            "InvokeIntrinsic %{name} (id={id}) is a V8-internal async/generator helper with no plain-JS surface"
                        ));
                    }
                }
            } else if let Some(v) = ins.operands.first() {
                let id: u64 = v.unsigned_value;
                let name: &str = intrinsic_name(id).unwrap_or("UnknownIntrinsic");
                *acc = format!("%{name}()");
                fidelity = LiftFidelity::OpaqueRuntime;
                ir_comment = Some(format!("InvokeIntrinsic %{name} (id={id})"));
            }
        }
        "CallRuntime" | "CallRuntimeForPair" | "CallJSRuntime" => {
            if let Some(v) = ins.operands.first() {
                *acc = format!("/* runtime#{} */ undefined", v.unsigned_value);
                fidelity = LiftFidelity::OpaqueRuntime;
                ir_comment = Some(format!(
                    "{mn} dispatches to V8 internal runtime; no JS surface equivalent"
                ));
            }
        }
        "LdaContextSlot" | "LdaImmutableContextSlot" | "LdaScriptContextSlot" => {
            if ins.operands.len() >= 3 {
                let slot: u64 = ins.operands[1].unsigned_value;
                let depth: u64 = ins.operands[2].unsigned_value;
                *acc = ctx_slot_name(depth, slot);
            }
        }
        "LdaCurrentContextSlot"
        | "LdaImmutableCurrentContextSlot"
        | "LdaCurrentScriptContextSlot" => {
            if let Some(v) = ins.operands.first() {
                *acc = ctx_slot_name(0, v.unsigned_value);
            }
        }
        "StaContextSlot" | "StaScriptContextSlot" => {
            if ins.operands.len() >= 3 {
                let slot: u64 = ins.operands[1].unsigned_value;
                let depth: u64 = ins.operands[2].unsigned_value;
                surface = format!("{} = {acc};", ctx_slot_name(depth, slot));
            }
        }
        "StaCurrentContextSlot" | "StaCurrentScriptContextSlot" => {
            if let Some(v) = ins.operands.first() {
                surface = format!("{} = {acc};", ctx_slot_name(0, v.unsigned_value));
            }
        }
        "LdaModuleVariable" => {
            if let Some(v) = ins.operands.first() {
                *acc = module_var_name(v.signed_value);
            }
        }
        "StaModuleVariable" => {
            if let Some(v) = ins.operands.first() {
                surface = format!("{} = {acc};", module_var_name(v.signed_value));
            }
        }
        "LdaLookupSlot"
        | "LdaLookupSlotInsideTypeof"
        | "LdaLookupContextSlot"
        | "LdaLookupContextSlotInsideTypeof"
        | "LdaLookupScriptContextSlot"
        | "LdaLookupScriptContextSlotInsideTypeof"
        | "LdaLookupGlobalSlot"
        | "LdaLookupGlobalSlotInsideTypeof" => {
            if let Some(v) = ins.operands.first() {
                *acc = format!("/* lookup */ {}", const_name(v.unsigned_value));
                fidelity = LiftFidelity::Lossy;
                ir_comment = Some(format!("{mn} resolves a name via the dynamic scope chain"));
            }
        }
        "StaLookupSlot" => {
            if let Some(v) = ins.operands.first() {
                surface = format!("{} = {acc};", const_name(v.unsigned_value));
                fidelity = LiftFidelity::Lossy;
                ir_comment = Some("StaLookupSlot stores via the dynamic scope chain".to_owned());
            }
        }
        "PushContext" => {
            if let Some(v) = ins.operands.first() {
                regs.insert(v.signed_value, acc.clone());
                surface = format!("let {} = {acc};", reg_name(v.signed_value));
                ir_comment = Some("PushContext saves the outgoing context register".to_owned());
            }
        }
        "PopContext" => {
            if let Some(v) = ins.operands.first() {
                ir_comment = Some(format!(
                    "PopContext restores context from {}",
                    reg_name(v.signed_value)
                ));
            }
        }
        "GetNamedPropertyFromSuper" => {
            if ins.operands.len() >= 2 {
                let recv: String = reg_expr(regs, ins.operands[0].signed_value);
                let name_idx: u64 = ins.operands[1].unsigned_value;
                *acc = property_access(pool, &recv, name_idx);
                fidelity = LiftFidelity::Lossy;
                ir_comment = Some(
                    "GetNamedPropertyFromSuper reads via the home-object prototype".to_owned(),
                );
            }
        }
        "GetEnumeratedKeyedProperty" => {
            if let Some(r) = ins.operands.first() {
                let recv: String = reg_expr(regs, r.signed_value);
                *acc = format!("{recv}[{acc}]");
            }
        }
        "DefineKeyedOwnProperty" | "DefineKeyedOwnPropertyInLiteral" | "StaInArrayLiteral" => {
            if ins.operands.len() >= 2 {
                let recv: String = reg_expr(regs, ins.operands[0].signed_value);
                let key: String = reg_expr(regs, ins.operands[1].signed_value);
                surface = format!("{recv}[{key}] = {acc};");
            }
        }
        "DeletePropertyStrict" | "DeletePropertySloppy" => {
            if let Some(r) = ins.operands.first() {
                let recv: String = reg_expr(regs, r.signed_value);
                *acc = format!("delete {recv}[{acc}]");
            }
        }
        "GetSuperConstructor" => {
            if let Some(r) = ins.operands.first() {
                regs.insert(
                    r.signed_value,
                    "Object.getPrototypeOf(this.constructor)".to_owned(),
                );
                surface = format!(
                    "let {} = Object.getPrototypeOf(this.constructor);",
                    reg_name(r.signed_value)
                );
                fidelity = LiftFidelity::Lossy;
            }
        }
        "CallProperty" | "CallAnyReceiver" => {
            if ins.operands.len() >= 3 {
                let f: String = reg_expr(regs, ins.operands[0].signed_value);
                let first: i64 = ins.operands[1].signed_value;
                let count: i64 = ins.operands[2].signed_value;
                let recv: String = reg_expr(regs, first);
                let args: String = call_arg_list(regs, first, count, true);
                *acc = if args.is_empty() {
                    format!("{f}.call({recv})")
                } else {
                    format!("{f}.call({recv}, {args})")
                };
            }
        }
        "CallUndefinedReceiver" => {
            if ins.operands.len() >= 3 {
                let f: String = reg_expr(regs, ins.operands[0].signed_value);
                let first: i64 = ins.operands[1].signed_value;
                let count: i64 = ins.operands[2].signed_value;
                let args: String = call_arg_list(regs, first, count, false);
                *acc = format!("{f}({args})");
            }
        }
        "CallWithSpread" => {
            if ins.operands.len() >= 3 {
                let f: String = reg_expr(regs, ins.operands[0].signed_value);
                let first: i64 = ins.operands[1].signed_value;
                let count: i64 = ins.operands[2].signed_value;
                let recv: String = reg_expr(regs, first);
                let args: String = call_arg_list(regs, first, count, true);
                *acc = if args.is_empty() {
                    format!("{f}.apply({recv})")
                } else {
                    format!("{f}.call({recv}, {args})")
                };
                fidelity = LiftFidelity::Lossy;
                ir_comment =
                    Some("CallWithSpread final arg is spread; surface omits `...`".to_owned());
            }
        }
        "ConstructWithSpread" => {
            if ins.operands.len() >= 3 {
                let f: String = reg_expr(regs, ins.operands[0].signed_value);
                let first: i64 = ins.operands[1].signed_value;
                let count: i64 = ins.operands[2].signed_value;
                let args: String = call_arg_list(regs, first, count, false);
                *acc = format!("new {f}({args})");
                fidelity = LiftFidelity::Lossy;
                ir_comment =
                    Some("ConstructWithSpread final arg is spread; surface omits `...`".to_owned());
            }
        }
        "ConstructForwardAllArgs" => {
            if let Some(r) = ins.operands.first() {
                let f: String = reg_expr(regs, r.signed_value);
                *acc = format!("new {f}(...arguments)");
                fidelity = LiftFidelity::Lossy;
            }
        }
        "CreateArrayLiteral" => {
            if let Some(v) = ins.operands.first() {
                *acc = format!("/* array literal */ ({})", const_name(v.unsigned_value));
                fidelity = LiftFidelity::Lossy;
                ir_comment = Some(
                    "CreateArrayLiteral materializes a boilerplate array from the constant pool"
                        .to_owned(),
                );
            }
        }
        "CreateArrayFromIterable" => {
            *acc = format!("[...{acc}]");
        }
        "CreateObjectLiteral" => {
            if let Some(v) = ins.operands.first() {
                *acc = format!("/* object literal */ ({})", const_name(v.unsigned_value));
                fidelity = LiftFidelity::Lossy;
                ir_comment =
                    Some("CreateObjectLiteral materializes a boilerplate object".to_owned());
            }
        }
        "CreateRegExpLiteral" => {
            if ins.operands.len() >= 3 {
                let pattern: String = const_name(ins.operands[0].unsigned_value);
                let flags_str: String = decode_regexp_flags(ins.operands[2].unsigned_value);
                *acc = format!("/{pattern}/{flags_str}");
            } else if let Some(v) = ins.operands.first() {
                *acc = format!("new RegExp({})", const_name(v.unsigned_value));
            }
            fidelity = LiftFidelity::Lossy;
        }
        "CloneObject" => {
            if let Some(r) = ins.operands.first() {
                let src: String = reg_expr(regs, r.signed_value);
                *acc = format!("{{ ...{src} }}");
            }
        }
        "GetTemplateObject" => {
            if let Some(v) = ins.operands.first() {
                *acc = format!("/* template */ ({})", const_name(v.unsigned_value));
                fidelity = LiftFidelity::Lossy;
            }
        }
        "CreateRestParameter" => {
            "[...arguments]".clone_into(acc);
        }
        "CreateBlockContext" | "CreateFunctionContext" | "CreateEvalContext" => {
            ir_comment = Some(format!("{mn} allocates a new context scope"));
        }
        "CreateCatchContext" => {
            if let Some(r) = ins.operands.first() {
                ir_comment = Some(format!(
                    "CreateCatchContext binds the caught exception in {}",
                    reg_name(r.signed_value)
                ));
            }
        }
        "CreateWithContext" => {
            if let Some(r) = ins.operands.first() {
                ir_comment = Some(format!(
                    "CreateWithContext extends scope with {}",
                    reg_name(r.signed_value)
                ));
            }
        }
        "TestTypeOf" => {
            let flag: u64 = ins.operands.first().map_or(0u64, |v| v.unsigned_value);
            *acc = format!("typeof ({acc}) === {}", type_of_literal(flag));
        }
        "TestUndetectable" => {
            *acc = format!("({acc}) == null");
        }
        "GetIterator" => {
            if let Some(r) = ins.operands.first() {
                let recv: String = reg_expr(regs, r.signed_value);
                *acc = format!("{recv}[Symbol.iterator]()");
            }
        }
        "ForInEnumerate" => {
            if let Some(r) = ins.operands.first() {
                let recv: String = reg_expr(regs, r.signed_value);
                *acc = format!("/* for-in keys of */ {recv}");
                fidelity = LiftFidelity::Lossy;
                ir_comment = Some("ForInEnumerate yields the receiver enum cache".to_owned());
            }
        }
        "ForInPrepare" => {
            ir_comment =
                Some("ForInPrepare splits the enum cache into the for-in state triple".to_owned());
        }
        "ForInNext" => {
            if let Some(r) = ins.operands.first() {
                let recv: String = reg_expr(regs, r.signed_value);
                *acc = format!("/* for-in key */ Object.keys({recv})[0]");
                fidelity = LiftFidelity::Lossy;
                ir_comment = Some("ForInNext yields the next enumerable key".to_owned());
            }
        }
        "ForInStep" => {
            if let Some(r) = ins.operands.first() {
                let index: String = reg_expr(regs, r.signed_value);
                *acc = format!("({index}) + 1");
            }
        }
        "ThrowReferenceErrorIfHole" => {
            if let Some(v) = ins.operands.first() {
                surface = format!(
                    "if ({acc} === undefined) throw new ReferenceError({});",
                    const_name(v.unsigned_value)
                );
                fidelity = LiftFidelity::Lossy;
            }
        }
        "ThrowSuperNotCalledIfHole" => {
            "if (this === undefined) throw new ReferenceError(\"super not called\");"
                .clone_into(&mut surface);
            fidelity = LiftFidelity::Lossy;
        }
        "ThrowSuperAlreadyCalledIfNotHole" => {
            "if (this !== undefined) throw new ReferenceError(\"super already called\");"
                .clone_into(&mut surface);
            fidelity = LiftFidelity::Lossy;
        }
        "ThrowIfNotSuperConstructor" => {
            if let Some(r) = ins.operands.first() {
                surface = format!(
                    "if (typeof {0} !== \"function\") throw new TypeError(\"not a constructor\");",
                    reg_expr(regs, r.signed_value)
                );
                fidelity = LiftFidelity::Lossy;
            }
        }
        "SetPendingMessage" => {
            ir_comment =
                Some("SetPendingMessage swaps the pending exception message slot".to_owned());
        }
        "IncBlockCounter" => {
            ir_comment =
                Some("IncBlockCounter is block-coverage instrumentation; no JS effect".to_owned());
        }
        "SwitchOnSmiNoFeedback" | "SwitchOnGeneratorState" => {
            surface = format!("/* switch dispatch mn={mn} */");
            fidelity = LiftFidelity::Lossy;
            ir_comment = Some(format!(
                "{mn} is a jump table; surface JS requires reloop of the case targets"
            ));
        }
        "SuspendGenerator" => {
            surface = format!("yield {acc};");
            fidelity = LiftFidelity::Lossy;
            ir_comment = Some("SuspendGenerator saves register state at a yield point".to_owned());
        }
        "ResumeGenerator" => {
            if let Some(r) = ins.operands.first() {
                *acc = format!("/* resume */ {}", reg_expr(regs, r.signed_value));
                fidelity = LiftFidelity::Lossy;
                ir_comment =
                    Some("ResumeGenerator restores register state after a yield".to_owned());
            }
        }
        "FindNonDefaultConstructorOrConstruct" => {
            if ins.operands.len() >= 2 {
                let f: String = reg_expr(regs, ins.operands[0].signed_value);
                *acc = format!("new {f}(...arguments)");
                fidelity = LiftFidelity::Lossy;
                ir_comment = Some(
                    "FindNonDefaultConstructorOrConstruct walks the derived-class constructor chain"
                        .to_owned(),
                );
            }
        }
        "Abort" => {
            "throw new Error(\"V8 abort\");".clone_into(&mut surface);
            fidelity = LiftFidelity::Lossy;
        }
        "Wide" | "ExtraWide" => {
            ir_comment = Some(format!(
                "{mn} is an operand-scale prefix consumed by the decoder"
            ));
        }
        "Illegal" => {
            surface = format!("/* {mn} */");
            fidelity = LiftFidelity::Lossy;
            ir_comment = Some("Illegal marks an unreachable bytecode slot".to_owned());
        }
        "DebugBreak0"
        | "DebugBreak1"
        | "DebugBreak2"
        | "DebugBreak3"
        | "DebugBreak4"
        | "DebugBreak5"
        | "DebugBreak6"
        | "DebugBreakWide"
        | "DebugBreakExtraWide" => {
            "debugger;".clone_into(&mut surface);
            ir_comment = Some(format!("{mn} is an inserted debugger breakpoint"));
        }
        _ => {
            fidelity = LiftFidelity::Lossy;
            ir_comment = Some(format!(
                "lift rule for {mn} not yet specialized; preserved as comment in surface"
            ));
            surface = format!("/* {mn} */");
        }
    }
    LiftedLine {
        source_offset: ins.offset,
        mnemonic: mn,
        fidelity,
        js_surface: surface,
        ir_comment,
    }
}

fn binary(
    acc: &mut String,
    regs: &BTreeMap<i64, String>,
    ins: &DecodedInstruction,
    op_symbol: &str,
    _surface: &mut String,
) {
    if let Some(r) = ins.operands.first() {
        let lhs: String = regs
            .get(&r.signed_value)
            .cloned()
            .unwrap_or_else(|| reg_name(r.signed_value));
        *acc = format!("({lhs}) {op_symbol} ({acc})");
    }
}

fn binary_smi(acc: &mut String, ins: &DecodedInstruction, op_symbol: &str) {
    if let Some(v) = ins.operands.first() {
        *acc = format!("({acc}) {op_symbol} {imm}", imm = v.signed_value);
    }
}

fn test_binary(
    acc: &mut String,
    regs: &BTreeMap<i64, String>,
    ins: &DecodedInstruction,
    op_symbol: &str,
    _surface: &mut String,
) {
    if let Some(r) = ins.operands.first() {
        let lhs: String = regs
            .get(&r.signed_value)
            .cloned()
            .unwrap_or_else(|| reg_name(r.signed_value));
        *acc = format!("({lhs}) {op_symbol} ({acc})");
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::super::bytecode_opcodes::OpcodeTable;
    use super::super::flat_bytecode_disasm::{disassemble, encode_instruction};
    use super::*;

    fn enc(table: &OpcodeTable, mnemonic: &str, operands: &[i64]) -> Vec<u8> {
        encode_instruction(table, mnemonic, operands).expect("encode")
    }

    #[test]
    fn lifts_lda_smi_return_to_literal_return() {
        let table: OpcodeTable = OpcodeTable::for_node(NodeVersion::Node22);
        let mut stream: Vec<u8> = Vec::new();
        stream.extend(enc(&table, "LdaSmi", &[5i64]));
        stream.extend(enc(&table, "Return", &[]));
        let disasm: Disassembly = disassemble(&stream, NodeVersion::Node22);
        let lifted: LiftedFunction = lift_disassembly(&disasm);
        let js: String = lifted.render_js("hello");
        assert!(js.contains("return 5;"));
        assert!(lifted.reversible_fraction() > 0.5);
    }

    #[test]
    fn lifts_add_smi_chain() {
        let table: OpcodeTable = OpcodeTable::for_node(NodeVersion::Node22);
        let mut stream: Vec<u8> = Vec::new();
        stream.extend(enc(&table, "LdaSmi", &[1i64]));
        stream.extend(enc(&table, "AddSmi", &[2i64, 0i64]));
        stream.extend(enc(&table, "Return", &[]));
        let disasm: Disassembly = disassemble(&stream, NodeVersion::Node22);
        let lifted: LiftedFunction = lift_disassembly(&disasm);
        let js: String = lifted.render_js("add");
        assert!(js.contains("return (1) + 2;"));
    }

    #[test]
    fn lifts_call_undefined_receiver_0() {
        let table: OpcodeTable = OpcodeTable::for_node(NodeVersion::Node22);
        let mut stream: Vec<u8> = Vec::new();
        stream.extend(enc(&table, "LdaGlobal", &[7i64, 0i64]));
        stream.extend(enc(&table, "Star0", &[]));
        stream.extend(enc(&table, "CallUndefinedReceiver0", &[0i64, 0i64]));
        stream.extend(enc(&table, "Return", &[]));
        let disasm: Disassembly = disassemble(&stream, NodeVersion::Node22);
        let lifted: LiftedFunction = lift_disassembly(&disasm);
        let js: String = lifted.render_js("call_global");
        assert!(js.contains("return globalThis[__c7]();"));
    }

    #[test]
    fn jumps_are_marked_lossy_with_ir_comment() {
        let table: OpcodeTable = OpcodeTable::for_node(NodeVersion::Node22);
        let stream: Vec<u8> = enc(&table, "Jump", &[12i64]);
        let disasm: Disassembly = disassemble(&stream, NodeVersion::Node22);
        let lifted: LiftedFunction = lift_disassembly(&disasm);
        assert_eq!(lifted.lossy_count, 1usize);
        assert!(lifted.lines[0].ir_comment.as_deref().is_some());
    }

    #[test]
    fn runtime_calls_are_marked_opaque() {
        let table: OpcodeTable = OpcodeTable::for_node(NodeVersion::Node22);
        let mut stream: Vec<u8> = Vec::new();
        stream.extend(enc(&table, "CallRuntime", &[3i64, 0i64, 0i64]));
        let disasm: Disassembly = disassemble(&stream, NodeVersion::Node22);
        let lifted: LiftedFunction = lift_disassembly(&disasm);
        assert_eq!(lifted.opaque_runtime_count, 1usize);
    }

    fn lift_node24(stream: &[u8]) -> LiftedFunction {
        let disasm: Disassembly = disassemble(stream, NodeVersion::Node24);
        lift_disassembly(&disasm)
    }

    #[test]
    fn lifts_context_slot_load_and_store() {
        let table: OpcodeTable = OpcodeTable::for_node(NodeVersion::Node24);
        let mut stream: Vec<u8> = Vec::new();
        stream.extend(enc(&table, "LdaCurrentContextSlot", &[3i64]));
        stream.extend(enc(&table, "StaContextSlot", &[1i64, 4i64, 2i64]));
        stream.extend(enc(&table, "Return", &[]));
        let js: String = lift_node24(&stream).render_js("ctx");
        assert!(js.contains("__ctx2_4 = __ctx3;"), "{js}");
    }

    #[test]
    fn lifts_module_variable_sign_convention() {
        let table: OpcodeTable = OpcodeTable::for_node(NodeVersion::Node24);
        let mut stream: Vec<u8> = Vec::new();
        stream.extend(enc(&table, "LdaModuleVariable", &[-1i64, 0i64]));
        stream.extend(enc(&table, "StaModuleVariable", &[2i64, 0i64]));
        stream.extend(enc(&table, "Return", &[]));
        let js: String = lift_node24(&stream).render_js("mod");
        assert!(js.contains("__export2 = __import1;"), "{js}");
    }

    #[test]
    fn lifts_call_property_with_reg_range() {
        let table: OpcodeTable = OpcodeTable::for_node(NodeVersion::Node24);
        let mut stream: Vec<u8> = Vec::new();
        stream.extend(enc(&table, "CallProperty", &[0i64, 1i64, 3i64, 0i64]));
        stream.extend(enc(&table, "Return", &[]));
        let js: String = lift_node24(&stream).render_js("callprop");
        assert!(js.contains("return r0.call(r1, r2, r3);"), "{js}");
    }

    #[test]
    fn lifts_call_undefined_receiver_reg_range() {
        let table: OpcodeTable = OpcodeTable::for_node(NodeVersion::Node24);
        let mut stream: Vec<u8> = Vec::new();
        stream.extend(enc(
            &table,
            "CallUndefinedReceiver",
            &[0i64, 1i64, 2i64, 0i64],
        ));
        stream.extend(enc(&table, "Return", &[]));
        let js: String = lift_node24(&stream).render_js("callun");
        assert!(js.contains("return r0(r1, r2);"), "{js}");
    }

    #[test]
    fn lifts_construct_with_spread() {
        let table: OpcodeTable = OpcodeTable::for_node(NodeVersion::Node24);
        let mut stream: Vec<u8> = Vec::new();
        stream.extend(enc(
            &table,
            "ConstructWithSpread",
            &[0i64, 1i64, 2i64, 0i64],
        ));
        stream.extend(enc(&table, "Return", &[]));
        let lifted: LiftedFunction = lift_node24(&stream);
        let js: String = lifted.render_js("ctor");
        assert!(js.contains("return new r0(r1, r2);"), "{js}");
        assert_eq!(lifted.lossy_count, 1usize);
    }

    #[test]
    fn lifts_test_type_of_string() {
        let table: OpcodeTable = OpcodeTable::for_node(NodeVersion::Node24);
        let mut stream: Vec<u8> = Vec::new();
        stream.extend(enc(&table, "Ldar", &[1i64]));
        stream.extend(enc(&table, "TestTypeOf", &[1i64]));
        stream.extend(enc(&table, "Return", &[]));
        let js: String = lift_node24(&stream).render_js("tt");
        assert!(js.contains("return typeof (r1) === \"string\";"), "{js}");
    }

    #[test]
    fn lifts_delete_property() {
        let table: OpcodeTable = OpcodeTable::for_node(NodeVersion::Node24);
        let mut stream: Vec<u8> = Vec::new();
        stream.extend(enc(&table, "LdaConstant", &[2i64]));
        stream.extend(enc(&table, "DeletePropertyStrict", &[1i64]));
        stream.extend(enc(&table, "Return", &[]));
        let js: String = lift_node24(&stream).render_js("del");
        assert!(js.contains("return delete r1[__c2];"), "{js}");
    }

    #[test]
    fn lifts_get_named_property_from_super() {
        let table: OpcodeTable = OpcodeTable::for_node(NodeVersion::Node24);
        let mut stream: Vec<u8> = Vec::new();
        stream.extend(enc(
            &table,
            "GetNamedPropertyFromSuper",
            &[1i64, 5i64, 0i64],
        ));
        stream.extend(enc(&table, "Return", &[]));
        let js: String = lift_node24(&stream).render_js("super");
        assert!(js.contains("return r1[__c5];"), "{js}");
    }

    #[test]
    fn lifts_create_reg_exp_literal() {
        let table: OpcodeTable = OpcodeTable::for_node(NodeVersion::Node24);
        let mut stream: Vec<u8> = Vec::new();
        stream.extend(enc(&table, "CreateRegExpLiteral", &[3i64, 0i64, 0i64]));
        stream.extend(enc(&table, "Return", &[]));
        let js: String = lift_node24(&stream).render_js("re");
        assert!(js.contains("return /__c3/;"), "{js}");
    }

    #[test]
    fn lifts_create_reg_exp_literal_with_flags() {
        let table: OpcodeTable = OpcodeTable::for_node(NodeVersion::Node24);
        let mut stream: Vec<u8> = Vec::new();
        stream.extend(enc(&table, "CreateRegExpLiteral", &[0i64, 0i64, 3i64]));
        stream.extend(enc(&table, "Return", &[]));
        let js: String = lift_node24(&stream).render_js("re");
        assert!(js.contains("/__c0/gi"), "{js}");
    }

    #[test]
    fn lifts_clone_object_spread() {
        let table: OpcodeTable = OpcodeTable::for_node(NodeVersion::Node24);
        let mut stream: Vec<u8> = Vec::new();
        stream.extend(enc(&table, "CloneObject", &[1i64, 0i64, 0i64]));
        stream.extend(enc(&table, "Return", &[]));
        let js: String = lift_node24(&stream).render_js("clone");
        assert!(js.contains("return { ...r1 };"), "{js}");
    }

    #[test]
    fn lifts_create_rest_parameter() {
        let table: OpcodeTable = OpcodeTable::for_node(NodeVersion::Node24);
        let mut stream: Vec<u8> = Vec::new();
        stream.extend(enc(&table, "CreateRestParameter", &[]));
        stream.extend(enc(&table, "Return", &[]));
        let js: String = lift_node24(&stream).render_js("rest");
        assert!(js.contains("return [...arguments];"), "{js}");
    }

    #[test]
    fn lifts_for_in_step() {
        let table: OpcodeTable = OpcodeTable::for_node(NodeVersion::Node24);
        let mut step: Vec<u8> = Vec::new();
        step.extend(enc(&table, "ForInStep", &[1i64]));
        step.extend(enc(&table, "Return", &[]));
        let js_step: String = lift_node24(&step).render_js("step");
        assert!(js_step.contains("return (r1) + 1;"), "{js_step}");
    }

    #[test]
    fn lifts_get_iterator() {
        let table: OpcodeTable = OpcodeTable::for_node(NodeVersion::Node24);
        let mut stream: Vec<u8> = Vec::new();
        stream.extend(enc(&table, "GetIterator", &[1i64, 0i64, 0i64]));
        stream.extend(enc(&table, "Return", &[]));
        let js: String = lift_node24(&stream).render_js("iter");
        assert!(js.contains("return r1[Symbol.iterator]();"), "{js}");
    }

    #[test]
    fn lifts_suspend_generator_as_yield() {
        let table: OpcodeTable = OpcodeTable::for_node(NodeVersion::Node24);
        let mut stream: Vec<u8> = Vec::new();
        stream.extend(enc(&table, "LdaSmi", &[7i64]));
        stream.extend(enc(&table, "SuspendGenerator", &[0i64, 1i64, 1i64, 0i64]));
        let lifted: LiftedFunction = lift_node24(&stream);
        let js: String = lifted.render_js("gen");
        assert!(js.contains("yield 7;"), "{js}");
        assert_eq!(lifted.lossy_count, 1usize);
    }

    #[test]
    fn lifts_throw_reference_error_if_hole() {
        let table: OpcodeTable = OpcodeTable::for_node(NodeVersion::Node24);
        let mut stream: Vec<u8> = Vec::new();
        stream.extend(enc(&table, "LdaContextSlot", &[1i64, 4i64, 0i64]));
        stream.extend(enc(&table, "ThrowReferenceErrorIfHole", &[6i64]));
        stream.extend(enc(&table, "Return", &[]));
        let js: String = lift_node24(&stream).render_js("tdz");
        assert!(
            js.contains("if (__ctx4 === undefined) throw new ReferenceError(__c6);"),
            "{js}"
        );
    }

    #[test]
    fn lifts_lookup_slot_lossy() {
        let table: OpcodeTable = OpcodeTable::for_node(NodeVersion::Node24);
        let mut stream: Vec<u8> = Vec::new();
        stream.extend(enc(&table, "LdaLookupSlot", &[2i64]));
        stream.extend(enc(&table, "Return", &[]));
        let lifted: LiftedFunction = lift_node24(&stream);
        let js: String = lifted.render_js("lookup");
        assert!(js.contains("__c2"), "{js}");
        assert_eq!(lifted.lossy_count, 1usize);
    }

    #[test]
    fn prefixes_and_debug_break_do_not_fall_through_to_generic() {
        let table: OpcodeTable = OpcodeTable::for_node(NodeVersion::Node24);
        let mut stream: Vec<u8> = Vec::new();
        stream.extend(enc(&table, "DebugBreak0", &[]));
        let lifted: LiftedFunction = lift_node24(&stream);
        assert!(lifted.lines[0].js_surface.contains("debugger;"));
        assert!(
            !lifted.lines[0]
                .ir_comment
                .as_deref()
                .unwrap_or_default()
                .contains("not yet specialized")
        );
    }

    #[test]
    fn lifts_realistic_length_plus_one_function() {
        let table: OpcodeTable = OpcodeTable::for_node(NodeVersion::Node24);
        let mut stream: Vec<u8> = Vec::new();
        stream.extend(enc(&table, "GetNamedProperty", &[0i64, 0i64, 0i64]));
        stream.extend(enc(&table, "AddSmi", &[1i64, 2i64]));
        stream.extend(enc(&table, "Return", &[]));
        let js: String = lift_node24(&stream).render_js("len_plus_one");
        assert!(js.contains("return (r0[__c0]) + 1;"), "{js}");
    }

    #[test]
    fn lifts_realistic_method_call_sequence() {
        let table: OpcodeTable = OpcodeTable::for_node(NodeVersion::Node24);
        let mut stream: Vec<u8> = Vec::new();
        stream.extend(enc(&table, "GetNamedProperty", &[0i64, 0i64, 0i64]));
        stream.extend(enc(&table, "Star1", &[]));
        stream.extend(enc(&table, "Ldar", &[0i64]));
        stream.extend(enc(&table, "Star2", &[]));
        stream.extend(enc(&table, "CallProperty1", &[1i64, 2i64, 3i64, 4i64]));
        stream.extend(enc(&table, "Return", &[]));
        let js: String = lift_node24(&stream).render_js("method");
        assert!(js.contains("r0[__c0]"), "{js}");
        assert!(js.contains(".call("), "{js}");
    }

    #[test]
    fn whole_tail_is_specialized_no_generic_fallback() {
        let table: OpcodeTable = OpcodeTable::for_node(NodeVersion::Node24);
        let mut unspecialized: Vec<&'static str> = Vec::new();
        for (_byte, spec) in table.iter_specs() {
            if matches!(spec.mnemonic, "Wide" | "ExtraWide") {
                continue;
            }
            let operands: Vec<i64> = vec![0i64; spec.operand_count as usize];
            let Ok(bytes): Result<Vec<u8>, _> =
                encode_instruction(&table, spec.mnemonic, &operands)
            else {
                continue;
            };
            let disasm: Disassembly = disassemble(&bytes, NodeVersion::Node24);
            let lifted: LiftedFunction = lift_disassembly(&disasm);
            let is_generic: bool = lifted.lines.iter().any(|l: &LiftedLine| {
                l.mnemonic == spec.mnemonic
                    && l.ir_comment
                        .as_deref()
                        .is_some_and(|c: &str| c.contains("not yet specialized"))
            });
            if is_generic {
                unspecialized.push(spec.mnemonic);
            }
        }
        assert!(
            unspecialized.is_empty(),
            "unspecialized opcodes remain: {unspecialized:?}"
        );
    }
}
