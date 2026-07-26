use std::collections::{BTreeMap, BTreeSet};

use disrobe_nir::{
    BinaryOp, NirFunction, NirInstr, NirModule, NirOp, NirSymbol, SourceLang, SourceRef, SymbolKind,
};
use disrobe_pass_dotnet::{
    ClrHeader, ExceptionClause, ExceptionClauseKind, FlowControl, Instruction, MetadataRoot,
    MethodBody, OperandValue, PeImage, Resolver, parse as parse_pe, parse_clr_header,
    parse_metadata_root, parse_method_body,
};

use crate::error::{LiftError, Result};
use crate::operand::{f32_operand, f64_operand};
use crate::usize_to_u32_saturating;

const FUNCTION_STRIDE: u64 = 1 << 20;
const IMPORT_BASE: u64 = 1 << 40;
const METHOD_STATIC: u16 = 0x0010;
const METHOD_ACCESS_PUBLIC: u16 = 0x0006;
const METHOD_ACCESS_MASK: u16 = 0x0007;
const METHOD_ABSTRACT: u16 = 0x0400;
const METHOD_PINVOKE_IMPL: u16 = 0x2000;
const METHOD_IMPL_CODE_TYPE_MASK: u16 = 0x0003;
const METHOD_IMPL_UNMANAGED: u16 = 0x0004;
const METHOD_IMPL_FORWARD_REF: u16 = 0x0010;
const METHOD_IMPL_INTERNAL_CALL: u16 = 0x1000;

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
        if !method.has_managed_body()? {
            continue;
        }
        let body_slice: &[u8] = pe
            .slice_at_rva_to_end(bytes, method.rva)
            .map_err(|e| LiftError::Source(format!("dotnet method rva: {e}")))?;
        let body: MethodBody =
            parse_method_body(body_slice).map_err(|error: disrobe_pass_dotnet::Error| {
                LiftError::Source(format!(
                    "dotnet method {} token {:#x} rva {:#x} body decode: {error}",
                    method.name, method.token, method.rva
                ))
            })?;
        let function: NirFunction = lift_method(
            method,
            method_index,
            &body,
            &resolver,
            &internal_by_token,
            &mut imports,
        )?;
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
    impl_flags: u16,
}

impl MethodEntry {
    const fn is_static(&self) -> bool {
        self.flags & METHOD_STATIC != 0
    }

    const fn is_public(&self) -> bool {
        self.flags & METHOD_ACCESS_MASK == METHOD_ACCESS_PUBLIC
    }

    const fn is_managed_il(&self) -> bool {
        self.flags & (METHOD_ABSTRACT | METHOD_PINVOKE_IMPL) == 0
            && self.impl_flags
                & (METHOD_IMPL_CODE_TYPE_MASK
                    | METHOD_IMPL_UNMANAGED
                    | METHOD_IMPL_FORWARD_REF
                    | METHOD_IMPL_INTERNAL_CALL)
                == 0
    }

    fn has_managed_body(&self) -> Result<bool> {
        match (self.rva == 0, self.is_managed_il()) {
            (true, true) => Err(LiftError::Source(format!(
                "dotnet method {} token {:#x} has no managed IL body",
                self.name, self.token
            ))),
            (true, false) => Ok(false),
            (false, true) => Ok(true),
            (false, false) => Err(LiftError::Source(format!(
                "dotnet method {} token {:#x} has an unsupported non-IL body at rva {:#x}",
                self.name, self.token, self.rva
            ))),
        }
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
            impl_flags: m.impl_flags,
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
) -> Result<NirFunction> {
    let base: u64 = function_address(method_index);
    let insns: &[Instruction] = &body.instructions;
    validate_method_control_flow(method, body)?;
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
    Ok(NirFunction {
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
    })
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
    let next: i64 = i64::from(insn.offset).checked_add(i64::from(instruction_size(insn)))?;
    let absolute: i64 = next.checked_add(i64::from(rel))?;
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

fn control_flow_error(method: &MethodEntry, insn: &Instruction, reason: &str) -> LiftError {
    LiftError::Source(format!(
        "dotnet method {} token {:#x} invalid control flow at IL_{:04x}: {reason}",
        method.name, method.token, insn.offset
    ))
}

fn validate_relative_target(
    method: &MethodEntry,
    insn: &Instruction,
    next_offset: u32,
    relative: i32,
    offsets: &BTreeSet<u32>,
) -> Result<()> {
    let target: i64 = i64::from(next_offset)
        .checked_add(i64::from(relative))
        .ok_or_else(|| control_flow_error(method, insn, "target arithmetic overflow"))?;
    let target: u32 = u32::try_from(target)
        .map_err(|_| control_flow_error(method, insn, "target is out of range"))?;
    if !offsets.contains(&target) {
        return Err(control_flow_error(
            method,
            insn,
            "target is not an instruction boundary",
        ));
    }
    Ok(())
}

fn exception_region_error(method: &MethodEntry, label: &str, reason: &str) -> LiftError {
    LiftError::Source(format!(
        "dotnet method {} token {:#x} invalid {label}: {reason}",
        method.name, method.token
    ))
}

fn validate_exception_region(
    method: &MethodEntry,
    label: &str,
    offset: u32,
    length: u32,
    code_size: u32,
    offsets: &BTreeSet<u32>,
) -> Result<()> {
    if length == 0 {
        return Err(exception_region_error(method, label, "length is zero"));
    }
    if offset >= code_size || !offsets.contains(&offset) {
        return Err(exception_region_error(
            method,
            label,
            "start is not an instruction boundary",
        ));
    }
    let end: u32 = offset
        .checked_add(length)
        .ok_or_else(|| exception_region_error(method, label, "end offset overflows"))?;
    if end > code_size || end != code_size && !offsets.contains(&end) {
        return Err(exception_region_error(
            method,
            label,
            "end is not an instruction boundary or method end",
        ));
    }
    Ok(())
}

fn validate_exception_clause(
    method: &MethodEntry,
    clause: &ExceptionClause,
    body: &MethodBody,
    offsets: &BTreeSet<u32>,
) -> Result<()> {
    validate_exception_region(
        method,
        "exception try region",
        clause.try_offset,
        clause.try_length,
        body.code_size,
        offsets,
    )?;
    validate_exception_region(
        method,
        "exception handler region",
        clause.handler_offset,
        clause.handler_length,
        body.code_size,
        offsets,
    )?;
    match clause.kind {
        ExceptionClauseKind::Filter => {
            let filter_offset: u32 = clause.class_token_or_filter;
            if filter_offset >= clause.handler_offset
                || !offsets.contains(&filter_offset)
                || filter_offset >= body.code_size
            {
                return Err(exception_region_error(
                    method,
                    "exception filter",
                    "offset is not a valid instruction boundary before its handler",
                ));
            }
        }
        ExceptionClauseKind::Catch => {
            let table: u8 = (clause.class_token_or_filter >> 24) as u8;
            let row: u32 = clause.class_token_or_filter & 0x00FF_FFFF;
            if row == 0 || !matches!(table, 0x01 | 0x02 | 0x1B) {
                return Err(exception_region_error(
                    method,
                    "exception catch type",
                    "token is not a TypeDef, TypeRef, or TypeSpec",
                ));
            }
        }
        ExceptionClauseKind::Finally | ExceptionClauseKind::Fault => {
            if clause.class_token_or_filter != 0 {
                return Err(exception_region_error(
                    method,
                    "exception handler",
                    "reserved token is nonzero",
                ));
            }
        }
    }
    Ok(())
}

fn validate_method_control_flow(method: &MethodEntry, body: &MethodBody) -> Result<()> {
    let offsets: BTreeSet<u32> = body
        .instructions
        .iter()
        .map(|insn: &Instruction| insn.offset)
        .collect();
    if offsets.len() != body.instructions.len() {
        return Err(LiftError::Source(format!(
            "dotnet method {} token {:#x} has duplicate instruction offsets",
            method.name, method.token
        )));
    }
    for (index, insn) in body.instructions.iter().enumerate() {
        let declared_next_offset: u32 = index
            .checked_add(1)
            .and_then(|next: usize| body.instructions.get(next))
            .map_or(body.code_size, |next: &Instruction| next.offset);
        let next_offset: u32 = insn
            .offset
            .checked_add(instruction_size(insn))
            .ok_or_else(|| control_flow_error(method, insn, "instruction end overflows"))?;
        if insn.offset >= body.code_size {
            return Err(control_flow_error(
                method,
                insn,
                "instruction starts beyond the method code size",
            ));
        }
        if next_offset != declared_next_offset {
            return Err(control_flow_error(
                method,
                insn,
                "instruction layout does not match the method code size",
            ));
        }
        match insn.flow {
            FlowControl::Branch if insn.name == "jmp" => {}
            FlowControl::Branch | FlowControl::CondBranch => match &insn.operand {
                OperandValue::BrTarget(relative) => {
                    validate_relative_target(method, insn, next_offset, *relative, &offsets)?;
                }
                OperandValue::Switch(relatives) => {
                    for relative in relatives {
                        validate_relative_target(method, insn, next_offset, *relative, &offsets)?;
                    }
                }
                _ => {
                    return Err(control_flow_error(
                        method,
                        insn,
                        "branch operand is missing",
                    ));
                }
            },
            FlowControl::Next
            | FlowControl::Call
            | FlowControl::Return
            | FlowControl::Throw
            | FlowControl::Meta
            | FlowControl::Break => {}
        }
    }
    for clause in &body.exception_clauses {
        validate_exception_clause(method, clause, body, &offsets)?;
    }
    Ok(())
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
        OperandValue::F32Bits(bits) => vec![f32_operand(*bits)],
        OperandValue::F64Bits(bits) => vec![f64_operand(*bits)],
        _ => implicit_ldc_i4_operand(insn.opcode),
    }
}

fn implicit_ldc_i4_operand(opcode: u16) -> Vec<String> {
    match opcode {
        0x15 => vec!["-1".to_owned()],
        0x16..=0x1E => vec![(i32::from(opcode) - 0x16).to_string()],
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
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn method(rva: u32, flags: u16, impl_flags: u16) -> MethodEntry {
        MethodEntry {
            token: 0x0600_0001,
            name: "Probe".to_owned(),
            rva,
            flags,
            impl_flags,
        }
    }

    #[test]
    fn body_state_distinguishes_absent_empty_and_invalid_methods() {
        let absent: MethodEntry = method(0, METHOD_ABSTRACT, 0);
        assert!(!absent.has_managed_body().expect("abstract body state"));

        let empty_bytes: [u8; 1] = [0x02];
        let empty: MethodBody = parse_method_body(&empty_bytes).expect("empty managed body");
        let decoded: MethodEntry = method(1, 0, 0);
        assert!(decoded.has_managed_body().expect("managed body state"));
        assert!(empty.instructions.is_empty());

        let invalid: MethodEntry = method(0, 0, 0);
        assert!(invalid.has_managed_body().is_err());
    }

    #[test]
    fn non_il_body_is_refused_instead_of_decoded_as_managed_il() {
        let native: MethodEntry = method(1, 0, 1);
        assert!(native.has_managed_body().is_err());
    }

    #[test]
    fn switch_operand_size_saturates() {
        assert_eq!(switch_operand_bytes(0), 4);
        assert_eq!(switch_operand_bytes(1), 8);
        assert_eq!(switch_operand_bytes(usize::MAX), u32::MAX);
    }

    #[test]
    fn invalid_branch_and_switch_targets_are_refused() {
        let branch_body: MethodBody = MethodBody {
            max_stack: 1,
            code_size: 3,
            local_var_sig_tok: 0,
            init_locals: false,
            instructions: vec![
                Instruction {
                    offset: 0,
                    opcode: 0x2B,
                    name: "br.s".to_owned(),
                    operand: OperandValue::BrTarget(-1),
                    flow: FlowControl::Branch,
                },
                Instruction {
                    offset: 2,
                    opcode: 0x2A,
                    name: "ret".to_owned(),
                    operand: OperandValue::None,
                    flow: FlowControl::Return,
                },
            ],
            exception_clauses: Vec::new(),
        };
        let switch_body: MethodBody = MethodBody {
            max_stack: 1,
            code_size: 10,
            local_var_sig_tok: 0,
            init_locals: false,
            instructions: vec![
                Instruction {
                    offset: 0,
                    opcode: 0x45,
                    name: "switch".to_owned(),
                    operand: OperandValue::Switch(vec![-1]),
                    flow: FlowControl::CondBranch,
                },
                Instruction {
                    offset: 9,
                    opcode: 0x2A,
                    name: "ret".to_owned(),
                    operand: OperandValue::None,
                    flow: FlowControl::Return,
                },
            ],
            exception_clauses: Vec::new(),
        };
        let entry: MethodEntry = method(1, 0, 0);
        assert!(validate_method_control_flow(&entry, &branch_body).is_err());
        assert!(validate_method_control_flow(&entry, &switch_body).is_err());
    }

    #[test]
    fn invalid_exception_regions_are_refused() {
        let instructions: Vec<Instruction> = vec![
            Instruction {
                offset: 0,
                opcode: 0x00,
                name: "nop".to_owned(),
                operand: OperandValue::None,
                flow: FlowControl::Next,
            },
            Instruction {
                offset: 1,
                opcode: 0x2A,
                name: "ret".to_owned(),
                operand: OperandValue::None,
                flow: FlowControl::Return,
            },
        ];
        let cases: [ExceptionClause; 4] = [
            ExceptionClause {
                kind: ExceptionClauseKind::Catch,
                try_offset: 0,
                try_length: 3,
                handler_offset: 1,
                handler_length: 1,
                class_token_or_filter: 0x0100_0001,
            },
            ExceptionClause {
                kind: ExceptionClauseKind::Catch,
                try_offset: 0,
                try_length: 1,
                handler_offset: 2,
                handler_length: 0,
                class_token_or_filter: 0x0100_0001,
            },
            ExceptionClause {
                kind: ExceptionClauseKind::Finally,
                try_offset: 0,
                try_length: 1,
                handler_offset: 1,
                handler_length: 0,
                class_token_or_filter: 0,
            },
            ExceptionClause {
                kind: ExceptionClauseKind::Filter,
                try_offset: 0,
                try_length: 1,
                handler_offset: 1,
                handler_length: 1,
                class_token_or_filter: 2,
            },
        ];
        let entry: MethodEntry = method(1, 0, 0);
        for clause in cases {
            let body: MethodBody = MethodBody {
                max_stack: 1,
                code_size: 2,
                local_var_sig_tok: 0,
                init_locals: false,
                instructions: instructions.clone(),
                exception_clauses: vec![clause],
            };
            assert!(validate_method_control_flow(&entry, &body).is_err());
        }
    }

    #[test]
    fn implicit_ldc_i4_macro_forms_carry_their_value() {
        assert_eq!(implicit_ldc_i4_operand(0x15), vec!["-1".to_owned()]);
        assert_eq!(implicit_ldc_i4_operand(0x16), vec!["0".to_owned()]);
        assert_eq!(implicit_ldc_i4_operand(0x1A), vec!["4".to_owned()]);
        assert_eq!(implicit_ldc_i4_operand(0x1E), vec!["8".to_owned()]);
        assert!(implicit_ldc_i4_operand(0x20).is_empty());
    }
}
