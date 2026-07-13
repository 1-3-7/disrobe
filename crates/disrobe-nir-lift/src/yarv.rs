use std::collections::BTreeMap;

use disrobe_nir::{
    BinaryOp, NirFunction, NirInstr, NirModule, NirOp, NirSymbol, SourceLang, SourceRef, SymbolKind,
};
use disrobe_pass_ruby::{
    IbfImage, RubyAnalysis, YarvIbfInstruction, YarvIseqBody, YarvOperand, analyze_bytes,
};

use crate::error::{LiftError, Result};
use crate::usize_to_u32_saturating;

const FUNCTION_STRIDE: u64 = 1 << 20;
const IMPORT_BASE: u64 = 1 << 40;

pub fn lift_ruby_iseq(bytes: &[u8]) -> Result<NirModule> {
    let analysis: RubyAnalysis = analyze_bytes(bytes, "<yarv>")
        .map_err(|e| LiftError::Source(format!("ruby yarv analyze: {e}")))?;
    let image: IbfImage = analysis
        .yarv
        .map(|y| y.ibf)
        .ok_or_else(|| LiftError::Source("input is not a compiled-ruby YARV image".to_owned()))?;
    build_module(bytes, &image)
}

#[must_use]
pub const fn function_address(iseq_index: u32) -> u64 {
    (iseq_index as u64)
        .saturating_add(1)
        .saturating_mul(FUNCTION_STRIDE)
}

fn build_module(source: &[u8], image: &IbfImage) -> Result<NirModule> {
    let source_hash: [u8; 32] = *blake3::hash(source).as_bytes();
    let mut module: NirModule = NirModule::new(source_hash, SourceLang::Yarv);

    if image.iseqs.is_empty() {
        return Err(LiftError::Empty);
    }

    let mut imports: ImportTable = ImportTable::new();

    for body in &image.iseqs {
        register_iseq_symbol(body, &mut module);
        let function: NirFunction = lift_body(body, &mut imports);
        module.functions.push(function);
    }

    for (symbol, address) in imports.into_sorted() {
        module.symbols.push(NirSymbol {
            address,
            name: symbol,
            kind: SymbolKind::Import,
        });
    }

    Ok(module)
}

fn iseq_label(index: u32) -> String {
    if index == 0 {
        "<top>".to_owned()
    } else {
        format!("<iseq:{index}>")
    }
}

fn register_iseq_symbol(body: &YarvIseqBody, module: &mut NirModule) {
    let kind: SymbolKind = if body.index == 0 {
        SymbolKind::Export
    } else {
        SymbolKind::Function
    };
    module.symbols.push(NirSymbol {
        address: function_address(body.index),
        name: iseq_label(body.index),
        kind,
    });
}

struct ImportTable {
    by_name: BTreeMap<String, u64>,
    next: u64,
}

impl ImportTable {
    const fn new() -> Self {
        Self {
            by_name: BTreeMap::new(),
            next: IMPORT_BASE,
        }
    }

    fn address_of(&mut self, symbol: &str) -> u64 {
        if let Some(addr) = self.by_name.get(symbol) {
            return *addr;
        }
        let addr: u64 = self.next;
        self.next = self.next.saturating_add(1);
        self.by_name.insert(symbol.to_owned(), addr);
        addr
    }

    fn into_sorted(self) -> Vec<(String, u64)> {
        let mut out: Vec<(String, u64)> = self.by_name.into_iter().collect();
        out.sort_by_key(|(_, addr): &(String, u64)| *addr);
        out
    }
}

fn runtime_pcs(body: &YarvIseqBody) -> Vec<u32> {
    let mut rt: Vec<u32> = Vec::with_capacity(body.instructions.len());
    let mut pc: u32 = 0;
    for instr in &body.instructions {
        rt.push(pc);
        pc = pc
            .saturating_add(1)
            .saturating_add(operand_slots_u32(instr.operands.len()));
    }
    rt
}

fn operand_slots_u32(count: usize) -> u32 {
    usize_to_u32_saturating(count)
}

const fn signed_i32(value: u32) -> i32 {
    let bytes: [u8; 4] = value.to_ne_bytes();
    i32::from_ne_bytes(bytes)
}

const fn signed_low_i32(value: u64) -> i32 {
    let bytes: [u8; 8] = value.to_le_bytes();
    signed_i32(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn branch_targets(body: &YarvIseqBody, base: u64) -> Vec<Option<u64>> {
    let rt: Vec<u32> = runtime_pcs(body);
    let mut targets: Vec<Option<u64>> = vec![None; body.instructions.len()];
    for (idx, instr) in body.instructions.iter().enumerate() {
        if !matches!(
            instr.mnemonic.as_str(),
            "branchif" | "branchunless" | "branchnil" | "jump"
        ) {
            continue;
        }
        let Some(off): Option<i64> = branch_offset(instr) else {
            continue;
        };
        let Some(here): Option<u32> = rt.get(idx).copied() else {
            continue;
        };
        let operand_slots: i64 = i64::from(operand_slots_u32(instr.operands.len()));
        let next_pc: i64 = i64::from(here)
            .saturating_add(1)
            .saturating_add(operand_slots);
        let target_pc: i64 = next_pc.saturating_add(off);
        if target_pc < 0 {
            continue;
        }
        let Some(target_pc_u32): Option<u32> = u32::try_from(target_pc).ok() else {
            continue;
        };
        if let Some(target_idx) = rt.iter().position(|&p: &u32| p == target_pc_u32)
            && let Some(target_instr) = body.instructions.get(target_idx)
        {
            targets[idx] = Some(base.saturating_add(u64::from(target_instr.pc)));
        }
    }
    targets
}

fn branch_offset(instr: &YarvIbfInstruction) -> Option<i64> {
    instr.operands.iter().find_map(|op: &YarvOperand| match op {
        YarvOperand::Offset(o) => Some(i64::from(signed_i32(*o))),
        YarvOperand::Num(n) => Some(i64::from(signed_low_i32(*n))),
        _ => None,
    })
}

fn lift_body(body: &YarvIseqBody, imports: &mut ImportTable) -> NirFunction {
    let base: u64 = function_address(body.index);
    let targets: Vec<Option<u64>> = branch_targets(body, base);

    let mut instructions: Vec<NirInstr> = Vec::with_capacity(body.instructions.len());
    let mut max_pc: u32 = 0;
    for (idx, instr) in body.instructions.iter().enumerate() {
        let address: u64 = base.saturating_add(u64::from(instr.pc));
        max_pc = max_pc.max(instr.pc);
        let branch_target: Option<u64> = targets.get(idx).copied().flatten();
        let (op, operand_list): (NirOp, Vec<String>) = classify(instr, branch_target, imports);
        let (reads_memory, writes_memory): (bool, bool) = memory_facets(instr.mnemonic.as_str());
        instructions.push(NirInstr {
            address,
            op,
            mnemonic: instr.mnemonic.clone(),
            operands: operand_list,
            reads_memory,
            writes_memory,
            byte_width: false,
            source: SourceRef::new(SourceLang::Yarv, address),
        });
    }

    let end: u64 = base.saturating_add(u64::from(max_pc).saturating_add(1));
    NirFunction {
        name: iseq_label(body.index),
        address: base,
        end,
        is_export: body.index == 0,
        instructions,
        source: SourceRef::labelled(
            SourceLang::Yarv,
            base,
            format!("locals={}", body.local_table.len()),
        ),
    }
}

fn classify(
    instr: &YarvIbfInstruction,
    branch_target: Option<u64>,
    imports: &mut ImportTable,
) -> (NirOp, Vec<String>) {
    let name: &str = instr.mnemonic.as_str();
    if let Some(binary_op) = binary_op(name) {
        return (NirOp::BinOp { op: binary_op }, Vec::new());
    }
    match name {
        "leave" => (NirOp::Return, Vec::new()),
        "throw" => (NirOp::Interrupt, Vec::new()),
        "jump" => (
            NirOp::Branch {
                target: branch_target,
            },
            Vec::new(),
        ),
        "branchif" | "branchunless" | "branchnil" => (
            NirOp::CondBranch {
                target: branch_target,
            },
            Vec::new(),
        ),
        "opt_case_dispatch" => (NirOp::CondBranch { target: None }, Vec::new()),
        "nop" => (NirOp::Nop, Vec::new()),
        _ if is_const(name) => (NirOp::Const, const_operand(instr)),
        _ if is_load(name) => (NirOp::Load, access_operand(instr)),
        _ if is_store(name) => (NirOp::Store, access_operand(instr)),
        _ if is_call(name) => classify_call(instr, imports),
        _ => (
            NirOp::Unmodeled {
                opcode: unmodeled_opcode(instr.opcode),
                offset: instr.pc,
            },
            Vec::new(),
        ),
    }
}

fn unmodeled_opcode(opcode: u32) -> u8 {
    u8::try_from(opcode).unwrap_or(u8::MAX)
}

fn classify_call(instr: &YarvIbfInstruction, imports: &mut ImportTable) -> (NirOp, Vec<String>) {
    let method: Option<String> = call_method(instr);
    match method {
        Some(name) if !name.is_empty() && name != "(call)" => {
            let address: u64 = imports.address_of(&name);
            (
                NirOp::Call {
                    target: Some(address),
                },
                vec![name],
            )
        }
        _ => (NirOp::IndirectCall, Vec::new()),
    }
}

fn call_method(instr: &YarvIbfInstruction) -> Option<String> {
    for op in &instr.operands {
        if let YarvOperand::Call { method, .. } = op {
            return Some(method.clone());
        }
    }
    None
}

fn const_operand(instr: &YarvIbfInstruction) -> Vec<String> {
    match instr.mnemonic.as_str() {
        "putnil" => vec!["nil".to_owned()],
        "putself" => vec!["self".to_owned()],
        "putobject_INT2FIX_0_" => vec!["0".to_owned()],
        "putobject_INT2FIX_1_" => vec!["1".to_owned()],
        _ => instr
            .operands
            .iter()
            .filter_map(literal_text)
            .take(1)
            .collect(),
    }
}

fn access_operand(instr: &YarvIbfInstruction) -> Vec<String> {
    instr
        .operands
        .iter()
        .filter_map(access_name)
        .take(1)
        .collect()
}

fn access_name(op: &YarvOperand) -> Option<String> {
    match op {
        YarvOperand::Id(s)
        | YarvOperand::SymLiteral(s)
        | YarvOperand::Literal(s)
        | YarvOperand::NumLiteral(s)
        | YarvOperand::StrLiteral(s) => Some(s.clone()),
        YarvOperand::ObjectRef(i) => Some(format!("obj[{i}]")),
        _ => None,
    }
}

fn literal_text(op: &YarvOperand) -> Option<String> {
    match op {
        YarvOperand::StrLiteral(s)
        | YarvOperand::NumLiteral(s)
        | YarvOperand::Literal(s)
        | YarvOperand::SymLiteral(s)
        | YarvOperand::Id(s) => Some(s.clone()),
        YarvOperand::Num(n) => Some(n.to_string()),
        _ => None,
    }
}

fn binary_op(name: &str) -> Option<BinaryOp> {
    Some(match name {
        "opt_minus" => BinaryOp::Sub,
        "opt_mult" => BinaryOp::Mul,
        "opt_div" => BinaryOp::Div,
        "opt_mod" => BinaryOp::Rem,
        "opt_and" => BinaryOp::And,
        "opt_or" => BinaryOp::Or,
        "opt_plus" | "opt_aref" => BinaryOp::Add,
        _ => return None,
    })
}

fn is_const(name: &str) -> bool {
    matches!(
        name,
        "putobject"
            | "putstring"
            | "putchilledstring"
            | "putnil"
            | "putself"
            | "putobject_INT2FIX_0_"
            | "putobject_INT2FIX_1_"
            | "duparray"
            | "duphash"
            | "newarray"
            | "newhash"
    )
}

fn is_load(name: &str) -> bool {
    matches!(
        name,
        "getlocal"
            | "getlocal_WC_0"
            | "getlocal_WC_1"
            | "getinstancevariable"
            | "getglobal"
            | "getconstant"
            | "getclassvariable"
            | "getblockparam"
            | "getblockparamproxy"
            | "getspecial"
            | "opt_getconstant_path"
    )
}

fn is_store(name: &str) -> bool {
    matches!(
        name,
        "setlocal"
            | "setlocal_WC_0"
            | "setlocal_WC_1"
            | "setinstancevariable"
            | "setglobal"
            | "setconstant"
            | "setclassvariable"
            | "setblockparam"
            | "setspecial"
    )
}

fn is_call(name: &str) -> bool {
    name == "send"
        || name == "invokesuper"
        || name == "invokeblock"
        || name == "invokebuiltin"
        || name == "opt_str_freeze"
        || name == "objtostring"
        || (name.starts_with("opt_") && binary_op(name).is_none() && name != "opt_case_dispatch")
}

fn memory_facets(name: &str) -> (bool, bool) {
    let reads: bool = matches!(
        name,
        "getinstancevariable"
            | "getglobal"
            | "getclassvariable"
            | "getconstant"
            | "opt_getconstant_path"
            | "opt_aref"
    );
    let writes: bool = matches!(
        name,
        "setinstancevariable" | "setglobal" | "setclassvariable" | "setconstant" | "opt_aset"
    );
    (reads, writes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operand_slots_saturate_to_runtime_width() {
        assert_eq!(operand_slots_u32(0), 0);
        assert_eq!(operand_slots_u32(7), 7);
        assert_eq!(operand_slots_u32(usize::MAX), u32::MAX);
    }

    #[test]
    fn branch_operands_preserve_signed_bits() {
        assert_eq!(signed_i32(0x0000_0007), 7);
        assert_eq!(signed_i32(0xffff_fffc), -4);
        assert_eq!(signed_low_i32(0x0000_0000_0000_0007), 7);
        assert_eq!(signed_low_i32(0xffff_ffff_ffff_fffc), -4);
        assert_eq!(signed_low_i32(0x0000_0001_0000_0002), 2);
    }
}
