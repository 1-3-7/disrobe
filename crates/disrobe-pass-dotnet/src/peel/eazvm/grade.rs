use std::collections::BTreeMap;

use crate::cil::{FlowControl, Instruction, MethodBody, OperandValue, parse_method_body};
use crate::metadata::{MetadataRoot, parse_metadata_root};
use crate::model::{AssemblyModel, MethodModel, Resolver, TypeModel};
use crate::pe::{ClrHeader, PeImage, parse, parse_clr_header};

use super::lift::{LiftedBody, LiftedInstr, LiftedOperand};
use super::names::NameTable;
use super::opcodes::CilOp;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StructuralScore {
    pub matched: u32,
    pub expected: u32,
}

impl StructuralScore {
    #[must_use]
    pub fn percent(self) -> f64 {
        if self.expected == 0 {
            return 100.0;
        }
        f64::from(self.matched) / f64::from(self.expected) * 100.0
    }

    #[must_use]
    pub const fn is_exact(self) -> bool {
        self.matched == self.expected
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OrderedOperand {
    None,
    Imm(i64),
    Var(u32),
    Branch(usize),
    Member(String),
    StringLit(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrderedInstr {
    pub mnemonic: String,
    pub operand: OrderedOperand,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OrderedScore {
    pub matched: u32,
    pub length: u32,
}

impl OrderedScore {
    #[must_use]
    pub fn percent(self) -> f64 {
        if self.length == 0 {
            return 100.0;
        }
        f64::from(self.matched) / f64::from(self.length) * 100.0
    }

    #[must_use]
    pub const fn is_exact(self) -> bool {
        self.matched == self.length
    }
}

#[must_use]
pub fn known_method_normals(clean_image: &[u8], type_name: &str) -> BTreeMap<String, Vec<String>> {
    let mut result: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let Some((pe, clr, root)): Option<(PeImage, ClrHeader, MetadataRoot)> =
        parse_clean(clean_image)
    else {
        return result;
    };
    let Ok(resolver): Result<Resolver, _> = Resolver::build(clean_image, &pe, &clr, &root) else {
        return result;
    };
    let model: AssemblyModel = resolver.model();
    for ty in &model.types {
        if ty.name != type_name {
            continue;
        }
        for method in &ty.methods {
            if method.name == ".ctor" || method.rva == 0 {
                continue;
            }
            if let Some(normals) = normalize_clean_method(clean_image, &pe, ty, method) {
                result.insert(method.name.clone(), normals);
            }
        }
    }
    result
}

#[must_use]
pub fn known_method_ordered(
    clean_image: &[u8],
    type_name: &str,
) -> BTreeMap<String, Vec<OrderedInstr>> {
    let mut result: BTreeMap<String, Vec<OrderedInstr>> = BTreeMap::new();
    let Some((pe, clr, root)): Option<(PeImage, ClrHeader, MetadataRoot)> =
        parse_clean(clean_image)
    else {
        return result;
    };
    let Ok(resolver): Result<Resolver, _> = Resolver::build(clean_image, &pe, &clr, &root) else {
        return result;
    };
    let model: AssemblyModel = resolver.model();
    for ty in &model.types {
        if ty.name != type_name {
            continue;
        }
        for method in &ty.methods {
            if method.name == ".ctor" || method.rva == 0 {
                continue;
            }
            if let Some(ordered) = ordered_clean_method(clean_image, &pe, &resolver, method) {
                result.insert(method.name.clone(), ordered);
            }
        }
    }
    result
}

fn parse_clean(image: &[u8]) -> Option<(PeImage, ClrHeader, MetadataRoot)> {
    let pe: PeImage = parse(image).ok()?;
    let clr: ClrHeader = parse_clr_header(image, &pe).ok()?;
    let root: MetadataRoot = parse_metadata_root(image, &pe, &clr).ok()?;
    Some((pe, clr, root))
}

fn normalize_clean_method(
    image: &[u8],
    pe: &PeImage,
    _ty: &TypeModel,
    method: &MethodModel,
) -> Option<Vec<String>> {
    let off: usize = pe.rva_to_offset(method.rva)?;
    let body: MethodBody = parse_method_body(image.get(off..)?).ok()?;
    let mut normals: Vec<String> = Vec::new();
    for ins in &body.instructions {
        if let Some(norm) = normalize_clean_instr(ins) {
            normals.push(norm);
        }
    }
    Some(normals)
}

fn ordered_clean_method(
    image: &[u8],
    pe: &PeImage,
    resolver: &Resolver,
    method: &MethodModel,
) -> Option<Vec<OrderedInstr>> {
    let off: usize = pe.rva_to_offset(method.rva)?;
    let body: MethodBody = parse_method_body(image.get(off..)?).ok()?;
    let offset_to_index: BTreeMap<u32, usize> = body
        .instructions
        .iter()
        .enumerate()
        .map(|(i, ins): (usize, &Instruction)| (ins.offset, i))
        .collect();
    let next_offsets: Vec<u32> = next_offsets(&body.instructions, body.code_size);
    let mut ordered: Vec<OrderedInstr> = Vec::with_capacity(body.instructions.len());
    for (i, ins) in body.instructions.iter().enumerate() {
        let mnemonic: String = ins.name.clone();
        let operand: OrderedOperand =
            clean_operand(ins, i, &next_offsets, &offset_to_index, resolver);
        ordered.push(OrderedInstr { mnemonic, operand });
    }
    Some(ordered)
}

fn next_offsets(instructions: &[Instruction], code_size: u32) -> Vec<u32> {
    let mut next: Vec<u32> = Vec::with_capacity(instructions.len());
    for i in 0..instructions.len() {
        let following: u32 = instructions
            .get(i + 1)
            .map_or(code_size, |n: &Instruction| n.offset);
        next.push(following);
    }
    next
}

fn clean_operand(
    ins: &Instruction,
    index: usize,
    next_offsets: &[u32],
    offset_to_index: &BTreeMap<u32, usize>,
    resolver: &Resolver,
) -> OrderedOperand {
    match &ins.operand {
        OperandValue::I32(v) => OrderedOperand::Imm(i64::from(*v)),
        OperandValue::I64(v) => OrderedOperand::Imm(*v),
        OperandValue::U8(v) => {
            if matches!(ins.flow, FlowControl::Branch | FlowControl::CondBranch) {
                resolve_clean_branch(
                    i32::from(v.cast_signed()),
                    index,
                    next_offsets,
                    offset_to_index,
                )
            } else if ins.name == "ldc.i4.s" {
                OrderedOperand::Imm(i64::from(v.cast_signed()))
            } else {
                OrderedOperand::Var(u32::from(*v))
            }
        }
        OperandValue::U16(v) => OrderedOperand::Var(u32::from(*v)),
        OperandValue::F32Bits(v) => OrderedOperand::Imm(i64::from(*v)),
        OperandValue::F64Bits(v) => OrderedOperand::Imm(v.cast_signed()),
        OperandValue::BrTarget(disp) => {
            resolve_clean_branch(*disp, index, next_offsets, offset_to_index)
        }
        OperandValue::Token(token) => member_token_operand(*token, ins, resolver),
        OperandValue::None | OperandValue::Switch(_) => OrderedOperand::None,
    }
}

fn resolve_clean_branch(
    disp: i32,
    index: usize,
    next_offsets: &[u32],
    offset_to_index: &BTreeMap<u32, usize>,
) -> OrderedOperand {
    let Some(base): Option<u32> = next_offsets.get(index).copied() else {
        return OrderedOperand::None;
    };
    let target: i64 = i64::from(base) + i64::from(disp);
    let Ok(target_u32): Result<u32, _> = u32::try_from(target) else {
        return OrderedOperand::None;
    };
    offset_to_index
        .get(&target_u32)
        .copied()
        .map_or(OrderedOperand::None, OrderedOperand::Branch)
}

fn member_token_operand(token: u32, ins: &Instruction, resolver: &Resolver) -> OrderedOperand {
    let resolved: String = resolver.resolve_token(token);
    if ins.name == "ldstr" {
        OrderedOperand::StringLit(resolved)
    } else {
        OrderedOperand::Member(simple_member_name(&resolved))
    }
}

fn simple_member_name(resolved: &str) -> String {
    resolved
        .rsplit_once("::")
        .map_or(resolved, |(_, tail): (&str, &str)| tail)
        .to_string()
}

fn normalize_clean_instr(ins: &Instruction) -> Option<String> {
    let name: &str = ins.name.as_str();
    let norm: String = match name {
        "nop" => return None,
        "ldarg.0" | "ldarg.1" | "ldarg.2" | "ldarg.3" | "ldarg.s" | "ldarg" => "ldarg".to_string(),
        "ldloc.0" | "ldloc.1" | "ldloc.2" | "ldloc.3" | "ldloc.s" | "ldloc" => "ldloc".to_string(),
        "stloc.0" | "stloc.1" | "stloc.2" | "stloc.3" | "stloc.s" | "stloc" => "stloc".to_string(),
        "starg.s" | "starg" => "starg".to_string(),
        "ldc.i4.m1" | "ldc.i4.0" | "ldc.i4.1" | "ldc.i4.2" | "ldc.i4.3" | "ldc.i4.4"
        | "ldc.i4.5" | "ldc.i4.6" | "ldc.i4.7" | "ldc.i4.8" | "ldc.i4.s" | "ldc.i4" => {
            let value: i32 = ldc_const(ins).unwrap_or(0);
            format!("ldc.i4:{value}")
        }
        "br.s" | "br" => "br".to_string(),
        "brtrue.s" | "brtrue" => "brtrue".to_string(),
        "brfalse.s" | "brfalse" => "brfalse".to_string(),
        "beq.s" | "beq" => "beq".to_string(),
        "bge.s" | "bge" => "bge".to_string(),
        "bgt.s" | "bgt" => "bgt".to_string(),
        "ble.s" | "ble" => "ble".to_string(),
        "blt.s" | "blt" => "blt".to_string(),
        "add" | "sub" | "mul" | "div" | "rem" | "dup" | "pop" | "ret" | "ldnull" => {
            name.to_string()
        }
        "call" | "callvirt" => "call".to_string(),
        "ldstr" => "ldstr".to_string(),
        _ => name.to_string(),
    };
    Some(norm)
}

fn ldc_const(ins: &Instruction) -> Option<i32> {
    match ins.name.as_str() {
        "ldc.i4.m1" => Some(-1),
        "ldc.i4.0" => Some(0),
        "ldc.i4.1" => Some(1),
        "ldc.i4.2" => Some(2),
        "ldc.i4.3" => Some(3),
        "ldc.i4.4" => Some(4),
        "ldc.i4.5" => Some(5),
        "ldc.i4.6" => Some(6),
        "ldc.i4.7" => Some(7),
        "ldc.i4.8" => Some(8),
        "ldc.i4.s" | "ldc.i4" => match ins.operand {
            OperandValue::I32(v) => Some(v),
            OperandValue::U8(v) => Some(i32::from(v)),
            _ => None,
        },
        _ => None,
    }
}

#[must_use]
pub fn normalize_lifted(body: &LiftedBody) -> Vec<String> {
    let mut normals: Vec<String> = Vec::new();
    for ins in &body.instrs {
        if let Some(norm) = normalize_lifted_instr(ins) {
            normals.push(norm);
        }
    }
    normals
}

#[must_use]
pub fn ordered_lifted(body: &LiftedBody, names: Option<&NameTable>) -> Vec<OrderedInstr> {
    let mut ordered: Vec<OrderedInstr> = Vec::with_capacity(body.instrs.len());
    for ins in &body.instrs {
        ordered.push(ordered_lifted_instr(ins, names));
    }
    ordered
}

fn ordered_lifted_instr(ins: &LiftedInstr, names: Option<&NameTable>) -> OrderedInstr {
    let mnemonic: String = lifted_mnemonic(ins);
    let operand: OrderedOperand = match &ins.operand {
        LiftedOperand::None => OrderedOperand::None,
        LiftedOperand::I32(v) => OrderedOperand::Imm(i64::from(*v)),
        LiftedOperand::Var(v) => OrderedOperand::Var(u32::from(*v)),
        LiftedOperand::BranchTo(dest) => OrderedOperand::Branch(*dest),
        LiftedOperand::Member(id) => names
            .and_then(|t: &NameTable| t.resolve_member(*id))
            .map_or_else(
                || OrderedOperand::Member(format!("member#{id:08X}")),
                |name: &str| OrderedOperand::Member(name.to_string()),
            ),
        LiftedOperand::StringLit(id) => names
            .and_then(|t: &NameTable| t.resolve_string(*id))
            .map_or_else(
                || OrderedOperand::StringLit(format!("string#{id:08X}")),
                |s: &str| OrderedOperand::StringLit(s.to_string()),
            ),
    };
    OrderedInstr { mnemonic, operand }
}

fn lifted_mnemonic(ins: &LiftedInstr) -> String {
    ins.op.handler_key().to_string()
}

fn normalize_lifted_instr(ins: &LiftedInstr) -> Option<String> {
    let norm: String = match ins.op {
        CilOp::Nop => return None,
        CilOp::LdargN(_) | CilOp::LdargS => "ldarg".to_string(),
        CilOp::StargS => "starg".to_string(),
        CilOp::LdlocN(_) | CilOp::LdlocS => "ldloc".to_string(),
        CilOp::StlocN(_) | CilOp::StlocS => "stloc".to_string(),
        CilOp::Ldnull => "ldnull".to_string(),
        CilOp::LdcI4M1 => "ldc.i4:-1".to_string(),
        CilOp::LdcI4N(n) => format!("ldc.i4:{n}"),
        CilOp::LdcI4S | CilOp::LdcI4 => {
            let value: i32 = match ins.operand {
                LiftedOperand::I32(v) => v,
                _ => 0,
            };
            format!("ldc.i4:{value}")
        }
        CilOp::Dup => "dup".to_string(),
        CilOp::Pop => "pop".to_string(),
        CilOp::Call => "call".to_string(),
        CilOp::Ret => "ret".to_string(),
        CilOp::BrS => "br".to_string(),
        CilOp::BrtrueS => "brtrue".to_string(),
        CilOp::BrfalseS => "brfalse".to_string(),
        CilOp::BeqS => "beq".to_string(),
        CilOp::BgeS => "bge".to_string(),
        CilOp::BgtS => "bgt".to_string(),
        CilOp::BleS => "ble".to_string(),
        CilOp::BltS => "blt".to_string(),
        CilOp::Add => "add".to_string(),
        CilOp::Sub => "sub".to_string(),
        CilOp::Mul => "mul".to_string(),
        CilOp::Div => "div".to_string(),
        CilOp::Rem => "rem".to_string(),
        CilOp::And => "and".to_string(),
        CilOp::Or => "or".to_string(),
        CilOp::Xor => "xor".to_string(),
        CilOp::Ldstr => "ldstr".to_string(),
    };
    Some(norm)
}

#[must_use]
pub fn grade_structural(expected: &[String], lifted: &LiftedBody) -> StructuralScore {
    let recovered: Vec<String> = normalize_lifted(lifted);
    let matched: u32 = multiset_overlap(expected, &recovered);
    StructuralScore {
        matched,
        expected: u32::try_from(expected.len()).unwrap_or(u32::MAX),
    }
}

#[must_use]
pub fn grade_ordered(expected: &[OrderedInstr], recovered: &[OrderedInstr]) -> OrderedScore {
    let length: usize = expected.len().max(recovered.len());
    let common: usize = expected.len().min(recovered.len());
    let mut matched: u32 = 0;
    for i in 0..common {
        if expected.get(i) == recovered.get(i) {
            matched += 1;
        }
    }
    OrderedScore {
        matched,
        length: u32::try_from(length).unwrap_or(u32::MAX),
    }
}

#[must_use]
pub fn grade_ordered_lifted(
    expected: &[OrderedInstr],
    lifted: &LiftedBody,
    names: Option<&NameTable>,
) -> OrderedScore {
    let recovered: Vec<OrderedInstr> = ordered_lifted(lifted, names);
    grade_ordered(expected, &recovered)
}

fn multiset_overlap(expected: &[String], recovered: &[String]) -> u32 {
    let mut want: BTreeMap<&str, u32> = BTreeMap::new();
    for e in expected {
        *want.entry(e.as_str()).or_insert(0) += 1;
    }
    let mut got: BTreeMap<&str, u32> = BTreeMap::new();
    for r in recovered {
        *got.entry(r.as_str()).or_insert(0) += 1;
    }
    let mut matched: u32 = 0;
    for (key, wcount) in &want {
        let gcount: u32 = got.get(key).copied().unwrap_or(0);
        matched += (*wcount).min(gcount);
    }
    matched
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::super::{EazVmMethod, EazVmRecovery, devirtualize, lookup_method};
    use super::*;

    fn images() -> (Vec<u8>, Vec<u8>) {
        let mut base: std::path::PathBuf = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        base.push("../../corpus/dotnet/eazvm");
        let vm: Vec<u8> = std::fs::read(base.join("EazSample.eazvm.dll")).unwrap();
        let clean: Vec<u8> = std::fs::read(base.join("EazSample.clean.dll")).unwrap();
        (vm, clean)
    }

    #[test]
    fn add_recovers_in_order_against_known_cil() {
        let (vm, clean): (Vec<u8>, Vec<u8>) = images();
        let recovery: EazVmRecovery = devirtualize(&vm).expect("devirtualize");
        let known: BTreeMap<String, Vec<OrderedInstr>> = known_method_ordered(&clean, "Compute");
        let add: &EazVmMethod = lookup_method(&recovery, "Add").unwrap();
        let expected: &Vec<OrderedInstr> = known.get("Add").expect("Add in known cil");
        let score: OrderedScore = grade_ordered_lifted(expected, &add.lifted, None);
        assert!(
            score.is_exact(),
            "Add must match known CIL in order: {}/{} recovered={:?} expected={:?}",
            score.matched,
            score.length,
            ordered_lifted(&add.lifted, None),
            expected
        );
    }

    #[test]
    fn all_methods_recover_in_order_against_known_cil() {
        let (vm, clean): (Vec<u8>, Vec<u8>) = images();
        let recovery: EazVmRecovery = devirtualize(&vm).expect("devirtualize");
        let known: BTreeMap<String, Vec<OrderedInstr>> = known_method_ordered(&clean, "Compute");
        let mut total_matched: u32 = 0;
        let mut total_length: u32 = 0;
        for m in &recovery.methods {
            let expected: &Vec<OrderedInstr> = known.get(&m.name).expect("method in known cil");
            let score: OrderedScore = grade_ordered_lifted(expected, &m.lifted, None);
            total_matched += score.matched;
            total_length += score.length;
            assert!(
                score.is_exact(),
                "{} must match known CIL in order: {}/{} recovered={:?} expected={:?}",
                m.name,
                score.matched,
                score.length,
                ordered_lifted(&m.lifted, None),
                expected
            );
        }
        let pct: f64 = f64::from(total_matched) / f64::from(total_length) * 100.0;
        assert!(
            (pct - 100.0).abs() < f64::EPSILON,
            "aggregate ordered recovery must be 100%; got {pct:.2}%"
        );
    }
}
