use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use super::bytecode_opcodes::{AccumulatorUse, OperandKind};
use super::bytenode::NodeVersion;
use super::code_serializer::ConstantPoolEntry;
use super::flat_bytecode_disasm::{
    DecodedInstruction, DecodedOperand, Disassembly, V8Register, intrinsic_name,
    register_file_start,
};

const ACCUMULATOR_TEMP: &str = "__acc";
const REGISTER_RANGE_SCAN_LIMIT: i64 = 256;
const MAX_RENDERED_ARGUMENTS: i64 = 65_534;

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
    pub parameter_count: usize,
    pub locals: Vec<String>,
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
        let parameters: Vec<String> = (0..self.parameter_count)
            .map(|index: usize| format!("a{index}"))
            .collect();
        push_format(
            &mut out,
            format_args!("function {function_name}({}) {{\n", parameters.join(", ")),
        );
        if !self.locals.is_empty() {
            push_format(
                &mut out,
                format_args!(
                    "  let {};
",
                    self.locals.join(", ")
                ),
            );
        }
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
    let mut acc: Accumulator = Accumulator {
        expr: "undefined".to_owned(),
        shape: ValueShape::Literal,
        written: false,
        materialized: false,
    };
    let mut regs: Registers = Registers {
        literals: BTreeMap::new(),
        locals: BTreeSet::new(),
        register_file_start: register_file_start(disasm.node_version),
    };
    let mut reversible: usize = 0usize;
    let mut lossy: usize = 0usize;
    let mut opaque: usize = 0usize;
    for (position, ins) in disasm.instructions.iter().enumerate() {
        let next: Option<&DecodedInstruction> = disasm.instructions.get(position.saturating_add(1));
        let (mut prelude, spent): (Vec<String>, bool) =
            prepare_accumulator(ins, next, &mut acc, &mut regs);
        let prior_pending: Option<String> = (acc.shape == ValueShape::Pending
            && reads_accumulator(ins.accumulator_use)
            && replaces_accumulator(ins.accumulator_use))
        .then(|| acc.expr.clone());
        acc.written = false;
        let mut line: LiftedLine = lift_instruction(ins, constant_pool, &mut acc, &mut regs);
        settle_accumulator(ins, &mut acc, prior_pending, spent, &mut prelude);
        if !prelude.is_empty() {
            if !line.js_surface.is_empty() {
                prelude.push(std::mem::take(&mut line.js_surface));
            }
            line.js_surface = prelude.join("\n");
        }
        match line.fidelity {
            LiftFidelity::Reversible => reversible = reversible.saturating_add(1),
            LiftFidelity::Lossy => lossy = lossy.saturating_add(1),
            LiftFidelity::OpaqueRuntime => opaque = opaque.saturating_add(1),
        }
        lines.push(line);
    }
    let mut locals: Vec<String> = regs
        .locals
        .iter()
        .map(|index: &i64| format!("r{index}"))
        .collect();
    if acc.materialized {
        locals.push(ACCUMULATOR_TEMP.to_owned());
    }
    LiftedFunction {
        node_version: disasm.node_version,
        v8_version_label: disasm.v8_version_label,
        parameter_count: referenced_parameter_count(disasm),
        locals,
        lines,
        reversible_count: reversible,
        lossy_count: lossy,
        opaque_runtime_count: opaque,
    }
}

fn referenced_parameter_count(disasm: &Disassembly) -> usize {
    disasm
        .instructions
        .iter()
        .flat_map(|ins: &DecodedInstruction| ins.operands.iter())
        .filter_map(|operand: &DecodedOperand| match operand.register {
            Some(V8Register::Parameter(index)) => Some(index.saturating_add(1)),
            _ => None,
        })
        .max()
        .map_or(0usize, |count: i64| {
            usize::try_from(count.min(MAX_RENDERED_ARGUMENTS)).unwrap_or(0usize)
        })
}

const fn reads_accumulator(usage: AccumulatorUse) -> bool {
    matches!(
        usage,
        AccumulatorUse::Read
            | AccumulatorUse::ReadWrite
            | AccumulatorUse::ReadAndClobber
            | AccumulatorUse::ReadWriteShortStar
    )
}

const fn replaces_accumulator(usage: AccumulatorUse) -> bool {
    matches!(
        usage,
        AccumulatorUse::Write
            | AccumulatorUse::ReadWrite
            | AccumulatorUse::Clobber
            | AccumulatorUse::ReadAndClobber
    )
}

const fn overwrites_unread(usage: AccumulatorUse) -> bool {
    !reads_accumulator(usage) && replaces_accumulator(usage)
}

fn is_star(mnemonic: &str) -> bool {
    mnemonic
        .strip_prefix("Star")
        .is_some_and(|suffix: &str| suffix.bytes().all(|byte: u8| byte.is_ascii_digit()))
}

fn is_terminal(mnemonic: &str) -> bool {
    matches!(mnemonic, "Return" | "Throw" | "ReThrow")
}

fn embeds_accumulator_in_statement(mnemonic: &str) -> bool {
    matches!(
        mnemonic,
        "StaGlobal"
            | "StaContextSlot"
            | "StaScriptContextSlot"
            | "StaCurrentContextSlot"
            | "StaCurrentScriptContextSlot"
            | "StaModuleVariable"
            | "StaLookupSlot"
            | "SetNamedProperty"
            | "DefineNamedOwnProperty"
            | "SetKeyedProperty"
            | "DefineKeyedOwnProperty"
            | "DefineKeyedOwnPropertyInLiteral"
            | "StaInArrayLiteral"
            | "ToObject"
            | "PushContext"
            | "ThrowReferenceErrorIfHole"
            | "SuspendGenerator"
    )
}

fn written_register_ranges(ins: &DecodedInstruction) -> Vec<(i64, i64)> {
    let mut ranges: Vec<(i64, i64)> = Vec::new();
    for (position, operand) in ins.operands.iter().enumerate() {
        let count: i64 = match operand.kind {
            OperandKind::RegOut | OperandKind::RegInOut => 1i64,
            OperandKind::RegOutPair => 2i64,
            OperandKind::RegOutTriple => 3i64,
            OperandKind::RegOutList => ins
                .operands
                .get(position.saturating_add(1))
                .filter(|next: &&DecodedOperand| next.kind == OperandKind::RegCount)
                .map_or(0i64, |next: &DecodedOperand| {
                    i64::try_from(next.unsigned_value).unwrap_or(i64::MAX)
                }),
            _ => 0i64,
        };
        if count > 0 {
            ranges.push((operand.signed_value, count));
        }
    }
    ranges
}

fn prepare_accumulator(
    ins: &DecodedInstruction,
    next: Option<&DecodedInstruction>,
    acc: &mut Accumulator,
    regs: &mut Registers,
) -> (Vec<String>, bool) {
    let mut prelude: Vec<String> = Vec::new();
    let usage: AccumulatorUse = ins.accumulator_use;
    let star: bool = is_star(ins.mnemonic);
    if !star {
        let ranges: Vec<(i64, i64)> = written_register_ranges(ins);
        let tracks_registers: bool = matches!(acc.shape, ValueShape::Name | ValueShape::Pending);
        let stale: bool = tracks_registers
            && ranges.iter().any(|&(first, count): &(i64, i64)| {
                count > REGISTER_RANGE_SCAN_LIMIT
                    || (0..count).any(|step: i64| {
                        mentions(&acc.expr, &regs.label(first.saturating_add(step)))
                    })
            });
        if stale {
            prelude.push(acc.materialize());
        }
        for (first, count) in ranges {
            regs.clobber(first, count);
        }
    }
    let mut spent: bool = false;
    if acc.shape == ValueShape::Pending {
        if overwrites_unread(usage) {
            prelude.push(expression_statement(&acc.expr));
            acc.shape = ValueShape::Opaque;
        } else if reads_accumulator(usage)
            && !replaces_accumulator(usage)
            && !star
            && !is_terminal(ins.mnemonic)
        {
            let dies: bool = next.is_some_and(|following: &DecodedInstruction| {
                overwrites_unread(following.accumulator_use)
            });
            if !dies {
                prelude.push(acc.materialize());
            } else if embeds_accumulator_in_statement(ins.mnemonic) {
                spent = true;
            } else {
                prelude.push(expression_statement(&acc.expr));
                acc.shape = ValueShape::Opaque;
            }
        }
    }
    (prelude, spent)
}

fn settle_accumulator(
    ins: &DecodedInstruction,
    acc: &mut Accumulator,
    prior_pending: Option<String>,
    spent: bool,
    prelude: &mut Vec<String>,
) {
    if spent || is_terminal(ins.mnemonic) {
        acc.shape = ValueShape::Opaque;
        return;
    }
    if !replaces_accumulator(ins.accumulator_use) {
        return;
    }
    if let Some(prior) = prior_pending
        && !(acc.written && acc.expr.contains(prior.as_str()))
    {
        prelude.push(expression_statement(&prior));
    }
    if !acc.written {
        acc.assign(format!("__unlifted_{}", ins.mnemonic), ValueShape::Name);
    }
}

fn expression_statement(expr: &str) -> String {
    if expr.starts_with('{') {
        format!("({expr});")
    } else {
        format!("{expr};")
    }
}

fn mentions(expr: &str, name: &str) -> bool {
    expr.match_indices(name).any(|(at, _): (usize, &str)| {
        let before: Option<char> = expr[..at].chars().next_back();
        let after: Option<char> = expr[at.saturating_add(name.len())..].chars().next();
        !before.is_some_and(is_identifier_char) && !after.is_some_and(is_identifier_char)
    })
}

const fn is_identifier_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '$'
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ValueShape {
    Literal,
    Name,
    Pending,
    Opaque,
}

struct Accumulator {
    expr: String,
    shape: ValueShape,
    written: bool,
    materialized: bool,
}

impl Accumulator {
    fn assign(&mut self, expr: String, shape: ValueShape) {
        self.expr = expr;
        self.shape = shape;
        self.written = true;
    }

    fn set(&mut self, expr: String) {
        self.assign(expr, ValueShape::Pending);
    }

    fn set_literal(&mut self, expr: String) {
        self.assign(expr, ValueShape::Literal);
    }

    fn set_name(&mut self, expr: String) {
        self.assign(expr, ValueShape::Name);
    }

    fn operand(&self) -> String {
        operand_text(&self.expr, self.shape)
    }

    fn materialize(&mut self) -> String {
        let statement: String = format!("{ACCUMULATOR_TEMP} = {};", self.expr);
        self.materialized = true;
        ACCUMULATOR_TEMP.clone_into(&mut self.expr);
        self.shape = ValueShape::Name;
        statement
    }
}

impl std::fmt::Display for Accumulator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.expr)
    }
}

fn operand_text(expr: &str, shape: ValueShape) -> String {
    match shape {
        ValueShape::Name => expr.to_owned(),
        ValueShape::Literal if !expr.starts_with('-') => expr.to_owned(),
        ValueShape::Pending if is_identifier(expr) => expr.to_owned(),
        ValueShape::Literal | ValueShape::Pending | ValueShape::Opaque => format!("({expr})"),
    }
}

struct Registers {
    literals: BTreeMap<i64, String>,
    locals: BTreeSet<i64>,
    register_file_start: i64,
}

impl Registers {
    fn label(&self, index: i64) -> String {
        V8Register::from_index(index, self.register_file_start).to_string()
    }

    fn name(&mut self, index: i64) -> String {
        let register: V8Register = V8Register::from_index(index, self.register_file_start);
        if let V8Register::Local(local) = register {
            self.locals.insert(local);
        }
        register.to_string()
    }

    fn read(&mut self, index: i64) -> String {
        if let Some(literal) = self.literals.get(&index) {
            return literal.clone();
        }
        self.name(index)
    }

    fn operand(&mut self, index: i64) -> String {
        if let Some(literal) = self.literals.get(&index) {
            return operand_text(literal, ValueShape::Literal);
        }
        self.name(index)
    }

    fn receiver(&mut self, index: i64) -> String {
        let text: String = self.operand(index);
        if text.starts_with(|c: char| c.is_ascii_digit()) {
            format!("({text})")
        } else {
            text
        }
    }

    fn store(&mut self, index: i64, value: &str, literal: bool) -> String {
        if literal {
            self.literals.insert(index, value.to_owned());
        } else {
            self.literals.remove(&index);
        }
        let name: String = self.name(index);
        format!("{name} = {value};")
    }

    fn clobber(&mut self, first: i64, count: i64) {
        let end: i64 = first.saturating_add(count);
        self.literals
            .retain(|index: &i64, _value: &mut String| *index < first || *index >= end);
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
    chars.all(is_identifier_char)
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

fn call_arg_list(regs: &mut Registers, first: i64, count: i64, skip_receiver: bool) -> String {
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
    if effective > MAX_RENDERED_ARGUMENTS {
        return format!("/* {effective} registers from {} */", regs.label(start));
    }
    let mut parts: Vec<String> = Vec::new();
    let mut taken: i64 = 0i64;
    while taken < effective {
        let reg: i64 = start.saturating_add(taken);
        parts.push(regs.read(reg));
        taken = taken.saturating_add(1);
    }
    parts.join(", ")
}

#[allow(clippy::too_many_lines)]
fn lift_instruction(
    ins: &DecodedInstruction,
    pool: &[ConstantPoolEntry],
    acc: &mut Accumulator,
    regs: &mut Registers,
) -> LiftedLine {
    let mn: &'static str = ins.mnemonic;
    let mut fidelity: LiftFidelity = LiftFidelity::Reversible;
    let mut surface: String = String::new();
    let mut ir_comment: Option<String> = None;
    let acc_operand: String = acc.operand();
    match mn {
        "LdaZero" => acc.set_literal("0".to_owned()),
        "LdaUndefined" => acc.set_literal("undefined".to_owned()),
        "LdaNull" => acc.set_literal("null".to_owned()),
        "LdaTrue" => acc.set_literal("true".to_owned()),
        "LdaFalse" => acc.set_literal("false".to_owned()),
        "LdaTheHole" => {
            acc.set_literal("/* hole */ undefined".to_owned());
            fidelity = LiftFidelity::Lossy;
            ir_comment = Some("V8 hole sentinel collapses to undefined at JS surface".to_owned());
        }
        "LdaSmi" => {
            if let Some(v) = ins.operands.first() {
                acc.set_literal(v.signed_value.to_string());
            }
        }
        "LdaConstant" => {
            if let Some(v) = ins.operands.first() {
                acc.set_literal(const_literal(pool, v.unsigned_value));
            }
        }
        "Ldar" => {
            if let Some(v) = ins.operands.first() {
                match regs.literals.get(&v.signed_value) {
                    Some(literal) => acc.set_literal(literal.clone()),
                    None => acc.set_name(regs.name(v.signed_value)),
                }
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
            let literal: bool = acc.shape == ValueShape::Literal;
            surface = regs.store(target, &acc.expr, literal);
            if !literal {
                acc.set_name(regs.name(target));
            }
        }
        "Mov" => {
            if ins.operands.len() >= 2 {
                let src_idx: i64 = ins.operands[0].signed_value;
                let dst_idx: i64 = ins.operands[1].signed_value;
                let literal: bool = regs.literals.contains_key(&src_idx);
                let source: String = regs.read(src_idx);
                surface = regs.store(dst_idx, &source, literal);
            }
        }
        "Add" => binary(acc, regs, ins, "+"),
        "Sub" => binary(acc, regs, ins, "-"),
        "Mul" => binary(acc, regs, ins, "*"),
        "Div" => binary(acc, regs, ins, "/"),
        "Mod" => binary(acc, regs, ins, "%"),
        "Exp" => binary(acc, regs, ins, "**"),
        "BitwiseOr" => binary(acc, regs, ins, "|"),
        "BitwiseXor" => binary(acc, regs, ins, "^"),
        "BitwiseAnd" => binary(acc, regs, ins, "&"),
        "ShiftLeft" => binary(acc, regs, ins, "<<"),
        "ShiftRight" => binary(acc, regs, ins, ">>"),
        "ShiftRightLogical" => binary(acc, regs, ins, ">>>"),
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
        "Inc" => acc.set(format!("{acc_operand} + 1")),
        "Dec" => acc.set(format!("{acc_operand} - 1")),
        "Negate" => acc.set(format!("-{acc_operand}")),
        "BitwiseNot" => acc.set(format!("~{acc_operand}")),
        "LogicalNot" | "ToBooleanLogicalNot" => acc.set(format!("!{acc_operand}")),
        "TypeOf" => acc.set(format!("typeof {acc_operand}")),
        "ToBoolean" => acc.set(format!("Boolean({acc})")),
        "ToString" => acc.set(format!("String({acc})")),
        "ToNumber" => acc.set(format!("Number({acc})")),
        "ToNumeric" => {
            acc.set(format!("Number({acc})"));
            fidelity = LiftFidelity::Lossy;
            ir_comment = Some("ToNumeric covers BigInt+Number; surface uses Number".to_owned());
        }
        "ToName" => {
            acc.set(format!("String({acc})"));
            fidelity = LiftFidelity::Lossy;
        }
        "ToObject" => {
            if let Some(v) = ins.operands.first() {
                surface = regs.store(v.signed_value, &format!("Object({acc})"), false);
            }
        }
        "TestEqual" => binary(acc, regs, ins, "=="),
        "TestEqualStrict" => binary(acc, regs, ins, "==="),
        "TestLessThan" => binary(acc, regs, ins, "<"),
        "TestGreaterThan" => binary(acc, regs, ins, ">"),
        "TestLessThanOrEqual" => binary(acc, regs, ins, "<="),
        "TestGreaterThanOrEqual" => binary(acc, regs, ins, ">="),
        "TestInstanceOf" => binary(acc, regs, ins, "instanceof"),
        "TestIn" => binary(acc, regs, ins, "in"),
        "TestNull" => acc.set(format!("{acc_operand} === null")),
        "TestUndefined" => acc.set(format!("{acc_operand} === undefined")),
        "TestReferenceEqual" => {
            if let Some(r) = ins.operands.first() {
                let other: String = regs.operand(r.signed_value);
                acc.set(format!("{acc_operand} === {other}"));
            }
        }
        "GetNamedProperty" => {
            if ins.operands.len() >= 2 {
                let recv: String = regs.receiver(ins.operands[0].signed_value);
                let name_idx: u64 = ins.operands[1].unsigned_value;
                acc.set(property_access(pool, &recv, name_idx));
            }
        }
        "GetKeyedProperty" | "GetEnumeratedKeyedProperty" => {
            if let Some(r) = ins.operands.first() {
                let recv: String = regs.receiver(r.signed_value);
                acc.set(format!("{recv}[{acc}]"));
            }
        }
        "SetNamedProperty" | "DefineNamedOwnProperty" => {
            if ins.operands.len() >= 2 {
                let recv: String = regs.receiver(ins.operands[0].signed_value);
                let name_idx: u64 = ins.operands[1].unsigned_value;
                surface = format!("{recv}{} = {acc};", property_name_target(pool, name_idx));
            }
        }
        "SetKeyedProperty"
        | "DefineKeyedOwnProperty"
        | "DefineKeyedOwnPropertyInLiteral"
        | "StaInArrayLiteral" => {
            if ins.operands.len() >= 2 {
                let recv: String = regs.receiver(ins.operands[0].signed_value);
                let key: String = regs.read(ins.operands[1].signed_value);
                surface = format!("{recv}[{key}] = {acc};");
            }
        }
        "CallProperty0" => {
            if ins.operands.len() >= 2 {
                let f: String = regs.receiver(ins.operands[0].signed_value);
                let r: String = regs.read(ins.operands[1].signed_value);
                acc.set(format!("{f}.call({r})"));
            }
        }
        "CallProperty1" => {
            if ins.operands.len() >= 3 {
                let f: String = regs.receiver(ins.operands[0].signed_value);
                let r: String = regs.read(ins.operands[1].signed_value);
                let arg: String = regs.read(ins.operands[2].signed_value);
                acc.set(format!("{f}.call({r}, {arg})"));
            }
        }
        "CallProperty2" => {
            if ins.operands.len() >= 4 {
                let f: String = regs.receiver(ins.operands[0].signed_value);
                let r: String = regs.read(ins.operands[1].signed_value);
                let arg0: String = regs.read(ins.operands[2].signed_value);
                let arg1: String = regs.read(ins.operands[3].signed_value);
                acc.set(format!("{f}.call({r}, {arg0}, {arg1})"));
            }
        }
        "CallUndefinedReceiver0" => {
            if let Some(r) = ins.operands.first() {
                let f: String = regs.receiver(r.signed_value);
                acc.set(format!("{f}()"));
            }
        }
        "CallUndefinedReceiver1" => {
            if ins.operands.len() >= 2 {
                let f: String = regs.receiver(ins.operands[0].signed_value);
                let arg0: String = regs.read(ins.operands[1].signed_value);
                acc.set(format!("{f}({arg0})"));
            }
        }
        "CallUndefinedReceiver2" => {
            if ins.operands.len() >= 3 {
                let f: String = regs.receiver(ins.operands[0].signed_value);
                let arg0: String = regs.read(ins.operands[1].signed_value);
                let arg1: String = regs.read(ins.operands[2].signed_value);
                acc.set(format!("{f}({arg0}, {arg1})"));
            }
        }
        "Construct" => {
            if ins.operands.len() >= 3 {
                let f: String = regs.receiver(ins.operands[0].signed_value);
                let first: i64 = ins.operands[1].signed_value;
                let count: i64 = ins.operands[2].signed_value;
                let args: String = call_arg_list(regs, first, count, false);
                acc.set(format!("new {f}({args})"));
                fidelity = LiftFidelity::Lossy;
                ir_comment =
                    Some("Construct: new.target in acc; arg-list from register window".to_owned());
            } else if let Some(r) = ins.operands.first() {
                let f: String = regs.receiver(r.signed_value);
                acc.set(format!("new {f}()"));
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
                acc.set(format!("/* closure */ ({target})"));
                fidelity = LiftFidelity::Lossy;
                ir_comment = Some(
                    "CreateClosure references SharedFunctionInfo; body lifted separately"
                        .to_owned(),
                );
            }
        }
        "CreateEmptyObjectLiteral" => acc.set("{}".to_owned()),
        "CreateEmptyArrayLiteral" => acc.set("[]".to_owned()),
        "CreateMappedArguments" | "CreateUnmappedArguments" => {
            acc.set_name("arguments".to_owned());
        }
        "Debugger" => {
            "debugger;".clone_into(&mut surface);
        }
        "LdaGlobal" | "LdaGlobalInsideTypeof" => {
            if let Some(v) = ins.operands.first() {
                acc.set(global_name(pool, v.unsigned_value));
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
                    regs.read(first)
                } else {
                    "undefined".to_owned()
                };
                let a1: String = if count >= 2 {
                    regs.read(first.saturating_add(1))
                } else {
                    "undefined".to_owned()
                };
                let name: &str = intrinsic_name(id).unwrap_or("UnknownIntrinsic");
                match id {
                    11 => {
                        acc.set_name("import.meta".to_owned());
                        fidelity = LiftFidelity::Lossy;
                        ir_comment = Some("GetImportMetaObject".to_owned());
                    }
                    12 => {
                        acc.set(format!("{{...({a0})}}"));
                        fidelity = LiftFidelity::Lossy;
                        ir_comment = Some(
                            "CopyDataProperties: object/spread copy of own enumerable props"
                                .to_owned(),
                        );
                    }
                    13 => {
                        let excluded: String = call_arg_list(regs, first, count, true);
                        acc.set(format!("(({{...{a0}}}) /* excluding [{excluded}] */)"));
                        fidelity = LiftFidelity::Lossy;
                        ir_comment = Some(
                            "CopyDataPropertiesWithExcludedPropertiesOnStack: rest spread minus listed keys"
                                .to_owned(),
                        );
                    }
                    14 => {
                        acc.set(format!("{{value: {a0}, done: {a1}}}"));
                        fidelity = LiftFidelity::Lossy;
                        ir_comment = Some("CreateIterResultObject".to_owned());
                    }
                    _ => {
                        let args_str: String = call_arg_list(regs, first, count, false);
                        acc.assign(format!("%{name}({args_str})"), ValueShape::Opaque);
                        fidelity = LiftFidelity::OpaqueRuntime;
                        ir_comment = Some(format!(
                            "InvokeIntrinsic %{name} (id={id}) is a V8-internal async/generator helper with no plain-JS surface"
                        ));
                    }
                }
            } else if let Some(v) = ins.operands.first() {
                let id: u64 = v.unsigned_value;
                let name: &str = intrinsic_name(id).unwrap_or("UnknownIntrinsic");
                acc.assign(format!("%{name}()"), ValueShape::Opaque);
                fidelity = LiftFidelity::OpaqueRuntime;
                ir_comment = Some(format!("InvokeIntrinsic %{name} (id={id})"));
            }
        }
        "CallRuntime" | "CallRuntimeForPair" | "CallJSRuntime" => {
            if let Some(v) = ins.operands.first() {
                acc.assign(
                    format!("__unlifted_runtime_{}()", v.unsigned_value),
                    ValueShape::Opaque,
                );
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
                acc.set(ctx_slot_name(depth, slot));
            }
        }
        "LdaCurrentContextSlot"
        | "LdaImmutableCurrentContextSlot"
        | "LdaCurrentScriptContextSlot" => {
            if let Some(v) = ins.operands.first() {
                acc.set(ctx_slot_name(0, v.unsigned_value));
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
                acc.set(module_var_name(v.signed_value));
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
                acc.set(format!("/* lookup */ {}", const_name(v.unsigned_value)));
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
                let literal: bool = acc.shape == ValueShape::Literal;
                surface = regs.store(v.signed_value, &acc.expr, literal);
                ir_comment = Some("PushContext saves the outgoing context register".to_owned());
            }
        }
        "PopContext" => {
            if let Some(v) = ins.operands.first() {
                ir_comment = Some(format!(
                    "PopContext restores context from {}",
                    regs.label(v.signed_value)
                ));
            }
        }
        "GetNamedPropertyFromSuper" => {
            if ins.operands.len() >= 2 {
                let recv: String = regs.receiver(ins.operands[0].signed_value);
                let name_idx: u64 = ins.operands[1].unsigned_value;
                acc.set(property_access(pool, &recv, name_idx));
                fidelity = LiftFidelity::Lossy;
                ir_comment = Some(
                    "GetNamedPropertyFromSuper reads via the home-object prototype".to_owned(),
                );
            }
        }
        "DeletePropertyStrict" | "DeletePropertySloppy" => {
            if let Some(r) = ins.operands.first() {
                let recv: String = regs.receiver(r.signed_value);
                acc.set(format!("delete {recv}[{acc}]"));
            }
        }
        "GetSuperConstructor" => {
            if let Some(r) = ins.operands.first() {
                surface = regs.store(
                    r.signed_value,
                    "Object.getPrototypeOf(this.constructor)",
                    false,
                );
                fidelity = LiftFidelity::Lossy;
            }
        }
        "CallProperty" | "CallAnyReceiver" => {
            if ins.operands.len() >= 3 {
                let f: String = regs.receiver(ins.operands[0].signed_value);
                let first: i64 = ins.operands[1].signed_value;
                let count: i64 = ins.operands[2].signed_value;
                let recv: String = regs.read(first);
                let args: String = call_arg_list(regs, first, count, true);
                acc.set(if args.is_empty() {
                    format!("{f}.call({recv})")
                } else {
                    format!("{f}.call({recv}, {args})")
                });
            }
        }
        "CallUndefinedReceiver" => {
            if ins.operands.len() >= 3 {
                let f: String = regs.receiver(ins.operands[0].signed_value);
                let first: i64 = ins.operands[1].signed_value;
                let count: i64 = ins.operands[2].signed_value;
                let args: String = call_arg_list(regs, first, count, false);
                acc.set(format!("{f}({args})"));
            }
        }
        "CallWithSpread" => {
            if ins.operands.len() >= 3 {
                let f: String = regs.receiver(ins.operands[0].signed_value);
                let first: i64 = ins.operands[1].signed_value;
                let count: i64 = ins.operands[2].signed_value;
                let recv: String = regs.read(first);
                let args: String = call_arg_list(regs, first, count, true);
                acc.set(if args.is_empty() {
                    format!("{f}.apply({recv})")
                } else {
                    format!("{f}.call({recv}, {args})")
                });
                fidelity = LiftFidelity::Lossy;
                ir_comment =
                    Some("CallWithSpread final arg is spread; surface omits `...`".to_owned());
            }
        }
        "ConstructWithSpread" => {
            if ins.operands.len() >= 3 {
                let f: String = regs.receiver(ins.operands[0].signed_value);
                let first: i64 = ins.operands[1].signed_value;
                let count: i64 = ins.operands[2].signed_value;
                let args: String = call_arg_list(regs, first, count, false);
                acc.set(format!("new {f}({args})"));
                fidelity = LiftFidelity::Lossy;
                ir_comment =
                    Some("ConstructWithSpread final arg is spread; surface omits `...`".to_owned());
            }
        }
        "ConstructForwardAllArgs" => {
            if let Some(r) = ins.operands.first() {
                let f: String = regs.receiver(r.signed_value);
                acc.set(format!("new {f}(...arguments)"));
                fidelity = LiftFidelity::Lossy;
            }
        }
        "CreateArrayLiteral" => {
            if let Some(v) = ins.operands.first() {
                acc.set(format!(
                    "/* array literal */ ({})",
                    const_name(v.unsigned_value)
                ));
                fidelity = LiftFidelity::Lossy;
                ir_comment = Some(
                    "CreateArrayLiteral materializes a boilerplate array from the constant pool"
                        .to_owned(),
                );
            }
        }
        "CreateArrayFromIterable" => acc.set(format!("[...{acc}]")),
        "CreateObjectLiteral" => {
            if let Some(v) = ins.operands.first() {
                acc.set(format!(
                    "/* object literal */ ({})",
                    const_name(v.unsigned_value)
                ));
                fidelity = LiftFidelity::Lossy;
                ir_comment =
                    Some("CreateObjectLiteral materializes a boilerplate object".to_owned());
            }
        }
        "CreateRegExpLiteral" => {
            if ins.operands.len() >= 3 {
                let pattern: String = const_name(ins.operands[0].unsigned_value);
                let flags_str: String = decode_regexp_flags(ins.operands[2].unsigned_value);
                acc.set(format!("/{pattern}/{flags_str}"));
            } else if let Some(v) = ins.operands.first() {
                acc.set(format!("new RegExp({})", const_name(v.unsigned_value)));
            }
            fidelity = LiftFidelity::Lossy;
        }
        "CloneObject" => {
            if let Some(r) = ins.operands.first() {
                let src: String = regs.read(r.signed_value);
                acc.set(format!("{{ ...{src} }}"));
            }
        }
        "GetTemplateObject" => {
            if let Some(v) = ins.operands.first() {
                acc.set(format!("/* template */ ({})", const_name(v.unsigned_value)));
                fidelity = LiftFidelity::Lossy;
            }
        }
        "CreateRestParameter" => acc.set("[...arguments]".to_owned()),
        "CreateBlockContext" | "CreateFunctionContext" | "CreateEvalContext" => {
            ir_comment = Some(format!("{mn} allocates a new context scope"));
        }
        "CreateCatchContext" => {
            if let Some(r) = ins.operands.first() {
                ir_comment = Some(format!(
                    "CreateCatchContext binds the caught exception in {}",
                    regs.label(r.signed_value)
                ));
            }
        }
        "CreateWithContext" => {
            if let Some(r) = ins.operands.first() {
                ir_comment = Some(format!(
                    "CreateWithContext extends scope with {}",
                    regs.label(r.signed_value)
                ));
            }
        }
        "TestTypeOf" => {
            let flag: u64 = ins.operands.first().map_or(0u64, |v| v.unsigned_value);
            acc.set(format!(
                "typeof {acc_operand} === {}",
                type_of_literal(flag)
            ));
        }
        "TestUndetectable" => acc.set(format!("{acc_operand} == null")),
        "GetIterator" => {
            if let Some(r) = ins.operands.first() {
                let recv: String = regs.receiver(r.signed_value);
                acc.set(format!("{recv}[Symbol.iterator]()"));
            }
        }
        "ForInEnumerate" => {
            if let Some(r) = ins.operands.first() {
                let recv: String = regs.read(r.signed_value);
                acc.set(format!("/* for-in keys of */ {recv}"));
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
                let recv: String = regs.receiver(r.signed_value);
                acc.set(format!("/* for-in key */ Object.keys({recv})[0]"));
                fidelity = LiftFidelity::Lossy;
                ir_comment = Some("ForInNext yields the next enumerable key".to_owned());
            }
        }
        "ForInStep" => {
            if let Some(r) = ins.operands.first() {
                let index: String = regs.operand(r.signed_value);
                acc.set(format!("{index} + 1"));
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
                    regs.operand(r.signed_value)
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
                acc.set(format!("/* resume */ {}", regs.read(r.signed_value)));
                fidelity = LiftFidelity::Lossy;
                ir_comment =
                    Some("ResumeGenerator restores register state after a yield".to_owned());
            }
        }
        "FindNonDefaultConstructorOrConstruct" => {
            if ins.operands.len() >= 2 {
                let f: String = regs.receiver(ins.operands[0].signed_value);
                acc.set(format!("new {f}(...arguments)"));
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

fn binary(acc: &mut Accumulator, regs: &mut Registers, ins: &DecodedInstruction, op_symbol: &str) {
    if let Some(r) = ins.operands.first() {
        let lhs: String = regs.operand(r.signed_value);
        let rhs: String = acc.operand();
        acc.set(format!("{lhs} {op_symbol} {rhs}"));
    }
}

fn binary_smi(acc: &mut Accumulator, ins: &DecodedInstruction, op_symbol: &str) {
    if let Some(v) = ins.operands.first() {
        let lhs: String = acc.operand();
        acc.set(format!("{lhs} {op_symbol} {imm}", imm = v.signed_value));
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
        assert!(js.contains("return 1 + 2;"), "{js}");
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
        assert!(
            js.contains(
                "  let r0;
  r0 = globalThis[__c7];
  return r0();"
            ),
            "{js}"
        );
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
        assert!(
            js.contains(
                "__acc = __ctx3;
  __ctx2_4 = __acc;
  return __acc;"
            ),
            "{js}"
        );
    }

    #[test]
    fn lifts_module_variable_sign_convention() {
        let table: OpcodeTable = OpcodeTable::for_node(NodeVersion::Node24);
        let mut stream: Vec<u8> = Vec::new();
        stream.extend(enc(&table, "LdaModuleVariable", &[-1i64, 0i64]));
        stream.extend(enc(&table, "StaModuleVariable", &[2i64, 0i64]));
        stream.extend(enc(&table, "Return", &[]));
        let js: String = lift_node24(&stream).render_js("mod");
        assert!(
            js.contains(
                "__acc = __import1;
  __export2 = __acc;
  return __acc;"
            ),
            "{js}"
        );
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
        assert!(js.contains("return typeof r1 === \"string\";"), "{js}");
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
        assert!(js_step.contains("return r1 + 1;"), "{js_step}");
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
            js.contains(
                "__acc = __ctx4;
  if (__acc === undefined) throw new ReferenceError(__c6);"
            ),
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

    #[test]
    fn a_call_whose_result_is_discarded_stays_a_statement() {
        let table: OpcodeTable = OpcodeTable::for_node(NodeVersion::Node24);
        let mut stream: Vec<u8> = Vec::new();
        stream.extend(enc(&table, "CallUndefinedReceiver0", &[0i64, 0i64]));
        stream.extend(enc(&table, "LdaSmi", &[1i64]));
        stream.extend(enc(&table, "Return", &[]));
        let js: String = lift_node24(&stream).render_js("effect");
        assert!(
            js.contains(
                "  r0();
  return 1;"
            ),
            "{js}"
        );
    }

    #[test]
    fn a_stored_register_is_read_by_name_not_recomputed() {
        let table: OpcodeTable = OpcodeTable::for_node(NodeVersion::Node24);
        let mut stream: Vec<u8> = Vec::new();
        stream.extend(enc(&table, "CallUndefinedReceiver0", &[1i64, 0i64]));
        stream.extend(enc(&table, "Star0", &[]));
        stream.extend(enc(&table, "Add", &[0i64, 0i64]));
        stream.extend(enc(&table, "Star0", &[]));
        stream.extend(enc(&table, "Return", &[]));
        let js: String = lift_node24(&stream).render_js("twice");
        assert_eq!(
            js,
            "function twice() {
  let r0, r1;
  r0 = r1();
  r0 = r0 + r0;
  return r0;
}
"
        );
    }

    #[test]
    fn a_register_overwritten_under_a_pending_read_is_read_first() {
        let table: OpcodeTable = OpcodeTable::for_node(NodeVersion::Node24);
        let mut stream: Vec<u8> = Vec::new();
        stream.extend(enc(&table, "Ldar", &[1i64]));
        stream.extend(enc(&table, "AddSmi", &[1i64, 0i64]));
        stream.extend(enc(&table, "Mov", &[2i64, 1i64]));
        stream.extend(enc(&table, "Return", &[]));
        let js: String = lift_node24(&stream).render_js("mov");
        assert_eq!(
            js,
            "function mov() {
  let r1, r2, __acc;
  __acc = r1 + 1;
  r1 = r2;
  return __acc;
}
"
        );
    }

    #[test]
    fn parameters_are_declared_as_v8_numbers_them() {
        let table: OpcodeTable = OpcodeTable::for_node(NodeVersion::Node24);
        let a1: i64 = register_file_start(NodeVersion::Node24) - 4i64;
        let mut stream: Vec<u8> = Vec::new();
        stream.extend(enc(&table, "Ldar", &[a1]));
        stream.extend(enc(&table, "Return", &[]));
        let js: String = lift_node24(&stream).render_js("second");
        assert_eq!(
            js,
            "function second(a0, a1) {
  return a1;
}
"
        );
    }
}
