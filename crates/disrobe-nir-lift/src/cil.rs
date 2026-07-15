use std::collections::BTreeMap;

use disrobe_nir::{
    BinaryOp, NirFunction, NirInstr, NirModule, NirOp, NirSymbol, SourceLang, SourceRef, SymbolKind,
};
use disrobe_pass_dotnet::{
    ClrHeader, FlowControl, Instruction, MetadataRoot, MethodBody, OperandValue, PeImage, Resolver,
    parse as parse_pe, parse_clr_header, parse_metadata_root, parse_method_body,
};

use crate::error::{LiftError, Result};
use crate::usize_to_u32_saturating;

const FUNCTION_STRIDE: u64 = 1 << 20;
const IMPORT_BASE: u64 = 1 << 40;
const METHOD_STATIC: u16 = 0x0010;
const METHOD_ACCESS_PUBLIC: u16 = 0x0006;
const METHOD_ACCESS_MASK: u16 = 0x0007;

pub fn lift_pe(bytes: &[u8]) -> Result<NirModule> {
    let pe: PeImage =
        parse_pe(bytes).map_err(|e| LiftError::Source(format!("dotnet pe parse: {e}")))?;
    let clr: ClrHeader = parse_clr_header(bytes, &pe)
        .map_err(|e| LiftError::Source(format!("dotnet clr header: {e}")))?;
    let root: MetadataRoot = parse_metadata_root(bytes, &pe, &clr)
        .map_err(|e| LiftError::Source(format!("dotnet metadata root: {e}")))?;
    let resolver: Resolver = Resolver::build(bytes, &pe, &clr, &root)
        .map_err(|e| LiftError::Source(format!("dotnet resolver: {e}")))?;

    let source_hash: [u8; 32] = *blake3::hash(bytes).as_bytes();
    let mut module: NirModule = NirModule::new(source_hash, SourceLang::Cil);

    let methods: Vec<MethodEntry> = enumerate_methods(&resolver);
    let internal_by_token: BTreeMap<u32, u64> = methods
        .iter()
        .enumerate()
        .map(|(index, m): (usize, &MethodEntry)| {
            (m.token, function_address(usize_to_u32_saturating(index)))
        })
        .collect();

    let mut imports: ImportTable = ImportTable::new();

    for (index, method) in methods.iter().enumerate() {
        let method_index: u32 = usize_to_u32_saturating(index);
        register_method_symbol(method, method_index, &mut module);
        if method.rva == 0 {
            continue;
        }
        let body_slice: &[u8] = pe
            .slice_at_rva_to_end(bytes, method.rva)
            .map_err(|e| LiftError::Source(format!("dotnet method rva: {e}")))?;
        let body: MethodBody = match parse_method_body(body_slice) {
            Ok(body) => body,
            Err(_) => continue,
        };
        let function: NirFunction = lift_method(
            method,
            method_index,
            &body,
            &resolver,
            &internal_by_token,
            &mut imports,
        );
        module.functions.push(function);
    }

    for (symbol, address) in imports.into_sorted() {
        module.symbols.push(NirSymbol {
            address,
            name: symbol,
            kind: SymbolKind::Import,
        });
    }

    if module.functions.is_empty() {
        return Err(LiftError::Empty);
    }
    Ok(module)
}

#[must_use]
pub const fn function_address(method_index: u32) -> u64 {
    (method_index as u64)
        .saturating_add(1)
        .saturating_mul(FUNCTION_STRIDE)
}

struct MethodEntry {
    token: u32,
    name: String,
    rva: u32,
    flags: u16,
}

impl MethodEntry {
    const fn is_static(&self) -> bool {
        self.flags & METHOD_STATIC != 0
    }

    const fn is_public(&self) -> bool {
        self.flags & METHOD_ACCESS_MASK == METHOD_ACCESS_PUBLIC
    }
}

fn enumerate_methods(resolver: &Resolver) -> Vec<MethodEntry> {
    resolver
        .model()
        .types
        .iter()
        .flat_map(|t| t.methods.iter())
        .map(|m| MethodEntry {
            token: m.token,
            name: m.name.clone(),
            rva: m.rva,
            flags: m.flags,
        })
        .collect()
}

fn register_method_symbol(method: &MethodEntry, method_index: u32, module: &mut NirModule) {
    let kind: SymbolKind = if method.is_public() {
        SymbolKind::Export
    } else {
        SymbolKind::Function
    };
    module.symbols.push(NirSymbol {
        address: function_address(method_index),
        name: method.name.clone(),
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

fn lift_method(
    method: &MethodEntry,
    method_index: u32,
    body: &MethodBody,
    resolver: &Resolver,
    internal_by_token: &BTreeMap<u32, u64>,
    imports: &mut ImportTable,
) -> NirFunction {
    let base: u64 = function_address(method_index);
    let insns: &[Instruction] = &body.instructions;
    let byte_arith: Vec<bool> = byte_arith_flags(insns);

    let mut instructions: Vec<NirInstr> = Vec::with_capacity(insns.len());
    for (ordinal, insn) in insns.iter().enumerate() {
        let address: u64 = base.saturating_add(u64::from(insn.offset));
        let (op, mut operand_list): (NirOp, Vec<String>) =
            classify(insn, base, resolver, internal_by_token, imports);
        let (reads_memory, writes_memory, mem_byte): (bool, bool, bool) = memory_facets(insn);
        let is_byte_arith: bool = byte_arith.get(ordinal).is_some_and(|value: &bool| *value);
        if is_byte_arith {
            operand_list.push("byte stack".to_owned());
        }
        let mnemonic: String = match &op {
            NirOp::BinOp { op: binary_op } => binary_op.mnemonic().to_owned(),
            _ => insn.name.clone(),
        };
        instructions.push(NirInstr {
            address,
            op,
            mnemonic,
            operands: operand_list,
            reads_memory,
            writes_memory,
            byte_width: mem_byte || is_byte_arith,
            source: SourceRef::new(SourceLang::Cil, address),
        });
    }

    let end: u64 = base.saturating_add(u64::from(body.code_size));
    NirFunction {
        name: method.name.clone(),
        address: base,
        end,
        is_export: method.is_public(),
        instructions,
        source: SourceRef::labelled(
            SourceLang::Cil,
            base,
            if method.is_static() {
                "static".to_owned()
            } else {
                "instance".to_owned()
            },
        ),
    }
}

fn classify(
    insn: &Instruction,
    base: u64,
    resolver: &Resolver,
    internal_by_token: &BTreeMap<u32, u64>,
    imports: &mut ImportTable,
) -> (NirOp, Vec<String>) {
    match insn.flow {
        FlowControl::Call => return classify_call(insn, resolver, internal_by_token, imports),
        FlowControl::Return => return (NirOp::Return, Vec::new()),
        FlowControl::Throw => return (NirOp::Interrupt, Vec::new()),
        FlowControl::Branch => {
            let target: Option<u64> =
                branch_target(insn).map(|t| base.saturating_add(u64::from(t)));
            return (NirOp::Branch { target }, Vec::new());
        }
        FlowControl::CondBranch => {
            if let OperandValue::Switch(_) = insn.operand {
                return (NirOp::CondBranch { target: None }, Vec::new());
            }
            let target: Option<u64> =
                branch_target(insn).map(|t| base.saturating_add(u64::from(t)));
            return (NirOp::CondBranch { target }, Vec::new());
        }
        FlowControl::Next | FlowControl::Break | FlowControl::Meta => {}
    }

    if let Some(binary_op) = binary_op(insn.name.as_str()) {
        return (NirOp::BinOp { op: binary_op }, Vec::new());
    }
    if insn.name == "ldstr" {
        let literal: String = string_operand(insn, resolver);
        return (NirOp::Const, vec![literal]);
    }
    if is_field_load(insn.name.as_str()) {
        return (NirOp::Load, field_operand(insn, resolver));
    }
    if is_field_store(insn.name.as_str()) {
        return (NirOp::Store, field_operand(insn, resolver));
    }
    if is_element_load(insn.name.as_str()) {
        return (NirOp::Load, vec!["[array]".to_owned()]);
    }
    if is_element_store(insn.name.as_str()) {
        return (NirOp::Store, vec!["[array]".to_owned()]);
    }
    if is_const(insn.name.as_str()) {
        return (NirOp::Const, const_operand(insn));
    }
    if insn.opcode == OP_NOP {
        return (NirOp::Nop, Vec::new());
    }
    (
        NirOp::Unmodeled {
            opcode: unmodeled_opcode(insn.opcode),
            offset: insn.offset,
        },
        Vec::new(),
    )
}

const OP_NOP: u16 = 0x00;

const fn unmodeled_opcode(opcode: u16) -> u8 {
    (opcode & 0xFF) as u8
}

fn classify_call(
    insn: &Instruction,
    resolver: &Resolver,
    internal_by_token: &BTreeMap<u32, u64>,
    imports: &mut ImportTable,
) -> (NirOp, Vec<String>) {
    let OperandValue::Token(token) = insn.operand else {
        return (NirOp::IndirectCall, Vec::new());
    };
    let symbol: String = resolver.resolve_token(token);
    if let Some(target) = internal_by_token.get(&token).copied() {
        return (
            NirOp::Call {
                target: Some(target),
            },
            vec![symbol],
        );
    }
    let address: u64 = imports.address_of(&symbol);
    (
        NirOp::Call {
            target: Some(address),
        },
        vec![symbol],
    )
}

fn branch_target(insn: &Instruction) -> Option<u32> {
    let OperandValue::BrTarget(rel) = insn.operand else {
        return None;
    };
    let next: i64 = i64::from(insn.offset).saturating_add(i64::from(instruction_size(insn)));
    let absolute: i64 = next.saturating_add(i64::from(rel));
    u32::try_from(absolute).ok()
}

fn count_u32(count: usize) -> u32 {
    usize_to_u32_saturating(count)
}

fn switch_operand_bytes(target_count: usize) -> u32 {
    4u32.saturating_add(4u32.saturating_mul(count_u32(target_count)))
}

fn instruction_size(insn: &Instruction) -> u32 {
    let opcode_bytes: u32 = if insn.opcode >= 0x100 { 2 } else { 1 };
    let operand_bytes: u32 = match &insn.operand {
        OperandValue::None => 0,
        OperandValue::U8(_) => 1,
        OperandValue::U16(_) => 2,
        OperandValue::I32(_) | OperandValue::F32Bits(_) | OperandValue::Token(_) => 4,
        OperandValue::I64(_) | OperandValue::F64Bits(_) => 8,
        OperandValue::BrTarget(_) => {
            if is_short_branch(insn) {
                1
            } else {
                4
            }
        }
        OperandValue::Switch(targets) => switch_operand_bytes(targets.len()),
    };
    opcode_bytes.saturating_add(operand_bytes)
}

fn is_short_branch(insn: &Instruction) -> bool {
    insn.name.as_bytes().ends_with(b".s")
}

fn string_operand(insn: &Instruction, resolver: &Resolver) -> String {
    match insn.operand {
        OperandValue::Token(token) => resolver.resolve_token(token),
        _ => String::new(),
    }
}

fn field_operand(insn: &Instruction, resolver: &Resolver) -> Vec<String> {
    match insn.operand {
        OperandValue::Token(token) => vec![resolver.resolve_token(token)],
        _ => Vec::new(),
    }
}

fn const_operand(insn: &Instruction) -> Vec<String> {
    match &insn.operand {
        OperandValue::I32(v) => vec![v.to_string()],
        OperandValue::I64(v) => vec![v.to_string()],
        OperandValue::U8(v) => vec![i32::from(v.cast_signed()).to_string()],
        OperandValue::F32Bits(bits) => vec![f32::from_bits(*bits).to_string()],
        OperandValue::F64Bits(bits) => vec![f64::from_bits(*bits).to_string()],
        _ => Vec::new(),
    }
}

const BYTE_ARITH_WINDOW: usize = 6;

fn byte_arith_flags(insns: &[Instruction]) -> Vec<bool> {
    let mut flags: Vec<bool> = vec![false; insns.len()];
    let mut element_load_at: Option<usize> = None;
    for (ordinal, insn) in insns.iter().enumerate() {
        if matches!(
            insn.flow,
            FlowControl::Call | FlowControl::Branch | FlowControl::CondBranch
        ) {
            element_load_at = None;
        }
        if is_byte_element_load(insn.name.as_str()) {
            element_load_at = Some(ordinal);
        }
        if binary_op(insn.name.as_str()).is_some()
            && element_load_at
                .is_some_and(|seen: usize| ordinal.saturating_sub(seen) <= BYTE_ARITH_WINDOW)
            && let Some(flag) = flags.get_mut(ordinal)
        {
            *flag = true;
        }
    }
    flags
}

fn binary_op(name: &str) -> Option<BinaryOp> {
    Some(match name {
        "add" | "add.ovf" | "add.ovf.un" => BinaryOp::Add,
        "sub" | "sub.ovf" | "sub.ovf.un" => BinaryOp::Sub,
        "mul" | "mul.ovf" | "mul.ovf.un" => BinaryOp::Mul,
        "div" | "div.un" => BinaryOp::Div,
        "rem" | "rem.un" => BinaryOp::Rem,
        "and" => BinaryOp::And,
        "or" => BinaryOp::Or,
        "xor" => BinaryOp::Xor,
        "shl" => BinaryOp::Shl,
        "shr" | "shr.un" => BinaryOp::Shr,
        "neg" => BinaryOp::Neg,
        "not" => BinaryOp::Not,
        _ => return None,
    })
}

fn is_const(name: &str) -> bool {
    name.starts_with("ldc.") || name == "ldnull"
}

fn is_field_load(name: &str) -> bool {
    matches!(name, "ldfld" | "ldflda" | "ldsfld" | "ldsflda")
}

fn is_field_store(name: &str) -> bool {
    matches!(name, "stfld" | "stsfld")
}

fn is_element_load(name: &str) -> bool {
    name.starts_with("ldelem")
}

fn is_element_store(name: &str) -> bool {
    name.starts_with("stelem")
}

fn is_byte_element_load(name: &str) -> bool {
    matches!(name, "ldelem.i1" | "ldelem.u1")
}

fn is_byte_element_store(name: &str) -> bool {
    matches!(name, "stelem.i1")
}

fn memory_facets(insn: &Instruction) -> (bool, bool, bool) {
    let name: &str = insn.name.as_str();
    let reads: bool = is_field_load(name) || is_element_load(name) || name.starts_with("ldind");
    let writes: bool = is_field_store(name) || is_element_store(name) || name.starts_with("stind");
    let byte: bool = is_byte_element_load(name)
        || is_byte_element_store(name)
        || matches!(name, "ldind.i1" | "ldind.u1" | "stind.i1");
    (reads, writes, byte)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn switch_operand_size_saturates() {
        assert_eq!(switch_operand_bytes(0), 4);
        assert_eq!(switch_operand_bytes(1), 8);
        assert_eq!(switch_operand_bytes(usize::MAX), u32::MAX);
    }
}
