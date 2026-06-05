use std::collections::BTreeMap;
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

use super::bytecode_disasm::{DecodedInstruction, Disassembly};
use super::bytenode::NodeVersion;

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
        let _ = writeln!(out, "function {function_name}() {{");
        let mut emitted: usize = 0usize;
        for line in &self.lines {
            if line.js_surface.is_empty() {
                continue;
            }
            for stmt in line.js_surface.split('\n') {
                if stmt.is_empty() {
                    continue;
                }
                let _ = writeln!(out, "  {stmt}");
                emitted = emitted.saturating_add(1);
            }
        }
        if emitted == 0usize {
            let _ = writeln!(out, "  return undefined;");
        }
        let _ = writeln!(out, "}}");
        out
    }
}

#[must_use]
pub fn lift_disassembly(disasm: &Disassembly) -> LiftedFunction {
    let mut lines: Vec<LiftedLine> = Vec::with_capacity(disasm.instructions.len());
    let mut acc_state: String = "undefined".to_owned();
    let mut reg_state: BTreeMap<i64, String> = BTreeMap::new();
    let mut reversible: usize = 0usize;
    let mut lossy: usize = 0usize;
    let mut opaque: usize = 0usize;
    for ins in &disasm.instructions {
        let line: LiftedLine = lift_instruction(ins, &mut acc_state, &mut reg_state);
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

#[allow(clippy::too_many_lines)]
fn lift_instruction(
    ins: &DecodedInstruction,
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
                *acc = const_name(v.unsigned_value);
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
                *acc = format!("{recv}[{}]", const_name(name_idx));
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
                surface = format!("{recv}[{}] = {acc};", const_name(name_idx));
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
            if let Some(r) = ins.operands.first() {
                let f: String = regs
                    .get(&r.signed_value)
                    .cloned()
                    .unwrap_or_else(|| reg_name(r.signed_value));
                *acc = format!("new {f}(...args)");
                fidelity = LiftFidelity::Lossy;
                ir_comment =
                    Some("Construct arg-list elided; recover via RegList walker".to_owned());
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
        | "JumpIfNullConstant"
        | "JumpIfNotNullConstant"
        | "JumpIfUndefinedConstant"
        | "JumpIfNotUndefinedConstant"
        | "JumpIfUndefinedOrNullConstant"
        | "JumpIfJSReceiverConstant"
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
                *acc = format!("/* closure */ ({})", const_name(v.unsigned_value));
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
        "LdaGlobal" => {
            if let Some(v) = ins.operands.first() {
                *acc = format!("globalThis[{}]", const_name(v.unsigned_value));
            }
        }
        "StaGlobal" => {
            if let Some(v) = ins.operands.first() {
                surface = format!("globalThis[{}] = {acc};", const_name(v.unsigned_value));
            }
        }
        "CallRuntime" | "CallRuntimeForPair" | "CallJSRuntime" | "InvokeIntrinsic" => {
            if let Some(v) = ins.operands.first() {
                *acc = format!("/* runtime#{} */ undefined", v.unsigned_value);
                fidelity = LiftFidelity::OpaqueRuntime;
                ir_comment = Some(format!(
                    "{mn} dispatches to V8 internal runtime; no JS surface equivalent"
                ));
            }
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
    use super::super::bytecode_disasm::{disassemble, encode_instruction};
    use super::super::bytecode_opcodes::OpcodeTable;
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
}
