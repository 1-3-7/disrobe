use std::collections::BTreeMap;

use crate::cil::{Instruction, MethodBody, OperandValue, parse_method_body};
use crate::metadata::MetadataRoot;
use crate::model::{AssemblyModel, MethodModel, Resolver, TypeModel};
use crate::pe::{ClrHeader, PeImage};

use super::opcodes::CilOp;

#[derive(Debug, Clone)]
pub struct OpcodeMap {
    code_to_op: BTreeMap<i32, CilOp>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatchError {
    NoDispatchTable,
    NoHandlers,
}

impl OpcodeMap {
    #[must_use]
    pub fn get(&self, virtual_code: i32) -> Option<CilOp> {
        self.code_to_op.get(&virtual_code).copied()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.code_to_op.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.code_to_op.is_empty()
    }
}

fn fnv_masked(s: &str) -> u32 {
    let mut h: u32 = 2_166_136_261;
    for c in s.chars() {
        h ^= u32::from(c);
        h = h.wrapping_mul(16_777_619);
    }
    h & 0x0FFF_FFFF
}

#[must_use]
pub fn handler_fingerprint(op_name: &str) -> i32 {
    let combined: String = format!("HANDLER:{op_name}");
    (fnv_masked(&combined) | 0x1000_0000).cast_signed()
}

pub(super) fn ldc_i4_value(ins: &Instruction) -> Option<i32> {
    match ins.name.as_str() {
        "ldc.i4.0" => Some(0),
        "ldc.i4.1" => Some(1),
        "ldc.i4.2" => Some(2),
        "ldc.i4.3" => Some(3),
        "ldc.i4.4" => Some(4),
        "ldc.i4.5" => Some(5),
        "ldc.i4.6" => Some(6),
        "ldc.i4.7" => Some(7),
        "ldc.i4.8" => Some(8),
        "ldc.i4.m1" => Some(-1),
        "ldc.i4.s" | "ldc.i4" => match ins.operand {
            OperandValue::I32(v) => Some(v),
            OperandValue::U8(v) => Some(i32::from(v)),
            _ => None,
        },
        _ => None,
    }
}

fn identify_handler(body: &MethodBody) -> Option<CilOp> {
    let target: i32 = body
        .instructions
        .iter()
        .filter_map(ldc_i4_value)
        .find(|v: &i32| (*v & 0x1000_0000) != 0)?;
    HANDLED_OPS
        .into_iter()
        .find(|op: &CilOp| handler_fingerprint(op.handler_key()) == target)
}

fn build_method_index(model: &AssemblyModel) -> BTreeMap<u32, MethodModel> {
    let mut index: BTreeMap<u32, MethodModel> = BTreeMap::new();
    for ty in &model.types {
        for method in &ty.methods {
            index.insert(method.token, method.clone());
        }
    }
    index
}

fn find_dispatch_table(model: &AssemblyModel) -> Option<MethodModel> {
    for ty in &model.types {
        for method in &ty.methods {
            if method.name == "BuildDispatchTable" {
                return Some(method.clone());
            }
        }
    }
    None
}

fn dispatch_pairs(body: &MethodBody) -> Vec<(i32, u32)> {
    let mut pairs: Vec<(i32, u32)> = Vec::new();
    let instrs: &[Instruction] = &body.instructions;
    let mut last_code: Option<i32> = None;
    for ins in instrs {
        if let Some(value) = ldc_i4_value(ins) {
            last_code = Some(value);
            continue;
        }
        if ins.name == "ldftn"
            && let OperandValue::Token(token) = ins.operand
            && let Some(code) = last_code.take()
        {
            pairs.push((code, token));
        }
    }
    pairs
}

pub fn recover_opcode_map(
    image: &[u8],
    pe: &PeImage,
    clr: &ClrHeader,
    root: &MetadataRoot,
) -> Result<OpcodeMap, DispatchError> {
    let resolver: Resolver =
        Resolver::build(image, pe, clr, root).map_err(|_| DispatchError::NoDispatchTable)?;
    let model: AssemblyModel = resolver.model();

    let dispatch: MethodModel =
        find_dispatch_table(&model).ok_or(DispatchError::NoDispatchTable)?;
    let dispatch_body: MethodBody =
        read_body(image, pe, dispatch.rva).ok_or(DispatchError::NoDispatchTable)?;
    let pairs: Vec<(i32, u32)> = dispatch_pairs(&dispatch_body);
    if pairs.is_empty() {
        return Err(DispatchError::NoHandlers);
    }

    let method_index: BTreeMap<u32, MethodModel> = build_method_index(&model);
    let mut code_to_op: BTreeMap<i32, CilOp> = BTreeMap::new();

    for (code, handler_token) in pairs {
        let Some(handler): Option<&MethodModel> = method_index.get(&handler_token) else {
            continue;
        };
        let Some(handler_body): Option<MethodBody> = read_body(image, pe, handler.rva) else {
            continue;
        };
        if let Some(op) = identify_handler(&handler_body) {
            code_to_op.insert(code, op);
        }
    }

    if code_to_op.is_empty() {
        return Err(DispatchError::NoHandlers);
    }
    Ok(OpcodeMap { code_to_op })
}

fn read_body(image: &[u8], pe: &PeImage, rva: u32) -> Option<MethodBody> {
    if rva == 0 {
        return None;
    }
    let off: usize = pe.rva_to_offset(rva)?;
    parse_method_body(image.get(off..)?).ok()
}

#[must_use]
pub fn stub_position_string(
    image: &[u8],
    pe: &PeImage,
    method: &MethodModel,
    resolver: &Resolver,
) -> Option<String> {
    let body: MethodBody = read_body(image, pe, method.rva)?;
    for ins in &body.instructions {
        if ins.name == "ldstr"
            && let OperandValue::Token(token) = ins.operand
        {
            let offset: u32 = token & 0x00FF_FFFF;
            if let Some(text) = resolver.user_string(offset) {
                return Some(text);
            }
        }
    }
    None
}

#[must_use]
pub fn is_vm_stub(image: &[u8], pe: &PeImage, ty: &TypeModel, method: &MethodModel) -> bool {
    let _ = ty;
    let Some(body): Option<MethodBody> = read_body(image, pe, method.rva) else {
        return false;
    };
    let has_ldstr: bool = body
        .instructions
        .iter()
        .any(|i: &Instruction| i.name == "ldstr" && matches!(i.operand, OperandValue::Token(_)));
    let ldc_count: usize = body
        .instructions
        .iter()
        .filter(|i: &&Instruction| ldc_i4_value(i).is_some())
        .count();
    let pop_count: usize = body
        .instructions
        .iter()
        .filter(|i: &&Instruction| i.name == "pop")
        .count();
    has_ldstr && ldc_count >= 2 && pop_count >= 3
}

const HANDLED_OPS: [CilOp; 51] = [
    CilOp::Nop,
    CilOp::LdargN(0),
    CilOp::LdargN(1),
    CilOp::LdargN(2),
    CilOp::LdargN(3),
    CilOp::LdargS,
    CilOp::StargS,
    CilOp::LdlocN(0),
    CilOp::LdlocN(1),
    CilOp::LdlocN(2),
    CilOp::LdlocN(3),
    CilOp::StlocN(0),
    CilOp::StlocN(1),
    CilOp::StlocN(2),
    CilOp::StlocN(3),
    CilOp::LdlocS,
    CilOp::StlocS,
    CilOp::Ldnull,
    CilOp::LdcI4M1,
    CilOp::LdcI4N(0),
    CilOp::LdcI4N(1),
    CilOp::LdcI4N(2),
    CilOp::LdcI4N(3),
    CilOp::LdcI4N(4),
    CilOp::LdcI4N(5),
    CilOp::LdcI4N(6),
    CilOp::LdcI4N(7),
    CilOp::LdcI4N(8),
    CilOp::LdcI4S,
    CilOp::LdcI4,
    CilOp::Dup,
    CilOp::Pop,
    CilOp::Call,
    CilOp::Ret,
    CilOp::BrS,
    CilOp::BrfalseS,
    CilOp::BrtrueS,
    CilOp::BeqS,
    CilOp::BgeS,
    CilOp::BgtS,
    CilOp::BleS,
    CilOp::BltS,
    CilOp::Add,
    CilOp::Sub,
    CilOp::Mul,
    CilOp::Div,
    CilOp::Rem,
    CilOp::And,
    CilOp::Or,
    CilOp::Xor,
    CilOp::Ldstr,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprints_are_distinct_and_tagged() {
        let mut seen: Vec<i32> = Vec::new();
        for op in HANDLED_OPS {
            let fp: i32 = handler_fingerprint(op.handler_key());
            assert!(fp & 0x1000_0000 != 0, "fingerprint must carry tag bit");
            assert!(!seen.contains(&fp), "fingerprints must be distinct");
            seen.push(fp);
        }
    }
}
