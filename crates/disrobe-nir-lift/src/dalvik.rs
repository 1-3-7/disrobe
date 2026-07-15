use std::collections::BTreeMap;

use disrobe_nir::{
    BinaryOp, NirFunction, NirInstr, NirModule, NirOp, NirSymbol, SourceLang, SourceRef, SymbolKind,
};
use disrobe_pass_jvm::{CodeItem, DalvikInsn, DexFile, decode_method, parse_code_items, parse_dex};

use crate::error::{LiftError, Result};
use crate::usize_to_u32_saturating;

const FUNCTION_STRIDE: u64 = 1 << 20;
const IMPORT_BASE: u64 = 1 << 40;

pub fn lift_dex(bytes: &[u8]) -> Result<NirModule> {
    let dex: DexFile = parse_dex(bytes)
        .map_err(|e: disrobe_pass_jvm::Error| LiftError::Source(format!("dex parse: {e}")))?;
    let items: Vec<CodeItem> = parse_code_items(&dex, bytes);
    if items.is_empty() {
        return Err(LiftError::Empty);
    }

    let source_hash: [u8; 32] = *blake3::hash(bytes).as_bytes();
    let mut module: NirModule = NirModule::new(source_hash, SourceLang::Dalvik);

    let internal_by_key: BTreeMap<(String, String, String), u64> = items
        .iter()
        .enumerate()
        .map(|(index, ci): (usize, &CodeItem)| {
            (
                (
                    ci.class.clone(),
                    ci.method_name.clone(),
                    ci.method_descriptor.clone(),
                ),
                function_address(usize_to_u32_saturating(index)),
            )
        })
        .collect();

    let mut imports: ImportTable = ImportTable::new();

    for (index, ci) in items.iter().enumerate() {
        let method_index: u32 = usize_to_u32_saturating(index);
        register_method_symbol(ci, method_index, &mut module);
        let function: NirFunction =
            lift_method(ci, method_index, &dex, &internal_by_key, &mut imports);
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

#[must_use]
pub const fn function_address(method_index: u32) -> u64 {
    (method_index as u64)
        .saturating_add(1)
        .saturating_mul(FUNCTION_STRIDE)
}

fn qualified_name(class: &str, method: &str) -> String {
    let class: &str = class.trim_start_matches('L').trim_end_matches(';');
    let class: String = class.replace('/', ".");
    format!("{class}.{method}")
}

fn register_method_symbol(ci: &CodeItem, method_index: u32, module: &mut NirModule) {
    let kind: SymbolKind = if ci.is_direct {
        SymbolKind::Function
    } else {
        SymbolKind::Export
    };
    module.symbols.push(NirSymbol {
        address: function_address(method_index),
        name: qualified_name(&ci.class, &ci.method_name),
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
    ci: &CodeItem,
    method_index: u32,
    dex: &DexFile,
    internal_by_key: &BTreeMap<(String, String, String), u64>,
    imports: &mut ImportTable,
) -> NirFunction {
    let base: u64 = function_address(method_index);
    let insns: Vec<DalvikInsn> = decode_method(&ci.insns);
    let byte_arith: Vec<bool> = byte_arith_flags(&insns);

    let mut instructions: Vec<NirInstr> = Vec::with_capacity(insns.len());
    for (ordinal, insn) in insns.iter().enumerate() {
        let address: u64 = base.saturating_add(u64::from(insn.pc));
        let (op, mut operand_list): (NirOp, Vec<String>) =
            classify(insn, base, dex, internal_by_key, imports);
        let (reads_memory, writes_memory, mem_byte): (bool, bool, bool) = memory_facets(insn.op);
        let is_byte_arith: bool = byte_arith.get(ordinal).is_some_and(|value: &bool| *value);
        if is_byte_arith {
            operand_list.push("byte stack".to_owned());
        }
        let mnemonic: String = match &op {
            NirOp::BinOp { op: binary_op } => binary_op.mnemonic().to_owned(),
            _ => insn.mnemonic.to_owned(),
        };
        instructions.push(NirInstr {
            address,
            op,
            mnemonic,
            operands: operand_list,
            reads_memory,
            writes_memory,
            byte_width: mem_byte || is_byte_arith,
            source: SourceRef::new(SourceLang::Dalvik, address),
        });
    }

    let end: u64 = base.saturating_add(ci.insns.len() as u64);
    NirFunction {
        name: qualified_name(&ci.class, &ci.method_name),
        address: base,
        end,
        is_export: !ci.is_direct,
        instructions,
        source: SourceRef::labelled(SourceLang::Dalvik, base, ci.method_descriptor.clone()),
    }
}

fn classify(
    insn: &DalvikInsn,
    base: u64,
    dex: &DexFile,
    internal_by_key: &BTreeMap<(String, String, String), u64>,
    imports: &mut ImportTable,
) -> (NirOp, Vec<String>) {
    if is_invoke(insn.op) {
        return classify_invoke(insn, dex, internal_by_key, imports);
    }
    if insn.is_return() {
        return (NirOp::Return, Vec::new());
    }
    if insn.is_throw() {
        return (NirOp::Interrupt, Vec::new());
    }
    if insn.is_unconditional_goto() {
        let target: Option<u64> = insn
            .branch_target_pc()
            .map(|t: u32| base.saturating_add(u64::from(t)));
        return (NirOp::Branch { target }, Vec::new());
    }
    if insn.is_conditional_branch() {
        let target: Option<u64> = insn
            .branch_target_pc()
            .map(|t: u32| base.saturating_add(u64::from(t)));
        return (NirOp::CondBranch { target }, Vec::new());
    }
    if insn.is_switch() {
        return (NirOp::CondBranch { target: None }, Vec::new());
    }
    if let Some(binary_op) = binary_op(insn.op) {
        return (NirOp::BinOp { op: binary_op }, Vec::new());
    }
    if is_array_get(insn.op) || is_field_get(insn.op) {
        return (NirOp::Load, memory_operands(insn.op));
    }
    if is_array_put(insn.op) || is_field_put(insn.op) {
        return (NirOp::Store, memory_operands(insn.op));
    }
    if is_const(insn.op) {
        return (NirOp::Const, const_operand(insn, dex));
    }
    if insn.op == OP_NOP {
        return (NirOp::Nop, Vec::new());
    }
    (
        NirOp::Unmodeled {
            opcode: insn.op,
            offset: insn.pc,
        },
        Vec::new(),
    )
}

fn classify_invoke(
    insn: &DalvikInsn,
    dex: &DexFile,
    internal_by_key: &BTreeMap<(String, String, String), u64>,
    imports: &mut ImportTable,
) -> (NirOp, Vec<String>) {
    let Some(method_index): Option<u32> = insn.index else {
        return (NirOp::IndirectCall, Vec::new());
    };
    let Some(method_ref): Option<&disrobe_pass_jvm::MethodId> =
        dex.method_ids.get(method_index as usize)
    else {
        return (NirOp::IndirectCall, Vec::new());
    };
    let descriptor: String = proto_descriptor(method_ref);

    if let Some(target) = internal_by_key
        .get(&(
            method_ref.class.clone(),
            method_ref.name.clone(),
            descriptor,
        ))
        .copied()
    {
        let name: String = qualified_name(&method_ref.class, &method_ref.name);
        return (
            NirOp::Call {
                target: Some(target),
            },
            vec![name],
        );
    }

    let symbol: String = qualified_name(&method_ref.class, &method_ref.name);
    let address: u64 = imports.address_of(&symbol);
    (
        NirOp::Call {
            target: Some(address),
        },
        vec![symbol],
    )
}

fn proto_descriptor(method_ref: &disrobe_pass_jvm::MethodId) -> String {
    let params: String = method_ref.proto.parameters.join("");
    format!("({params}){}", method_ref.proto.return_type)
}

const BYTE_ARITH_WINDOW: usize = 6;

fn byte_arith_flags(insns: &[DalvikInsn]) -> Vec<bool> {
    let mut flags: Vec<bool> = vec![false; insns.len()];
    let mut array_load_at: Option<usize> = None;
    for (ordinal, insn) in insns.iter().enumerate() {
        if is_invoke(insn.op) || insn.is_unconditional_goto() || insn.is_conditional_branch() {
            array_load_at = None;
        }
        if is_array_get(insn.op) {
            array_load_at = Some(ordinal);
        }
        if binary_op(insn.op).is_some()
            && array_load_at
                .is_some_and(|seen: usize| ordinal.saturating_sub(seen) <= BYTE_ARITH_WINDOW)
            && let Some(flag) = flags.get_mut(ordinal)
        {
            *flag = true;
        }
    }
    flags
}

const OP_NOP: u8 = 0x00;

const fn is_invoke(op: u8) -> bool {
    matches!(op, 0x6E..=0x72 | 0x74..=0x78 | 0xF8 | 0xF9 | 0xFA..=0xFD)
}

const fn is_array_get(op: u8) -> bool {
    matches!(op, 0x44..=0x4A)
}

const fn is_array_put(op: u8) -> bool {
    matches!(op, 0x4B..=0x51)
}

const fn is_field_get(op: u8) -> bool {
    matches!(op, 0x52..=0x58 | 0x60..=0x66)
}

const fn is_field_put(op: u8) -> bool {
    matches!(op, 0x59..=0x5F | 0x67..=0x6D)
}

const fn is_byte_array_access(op: u8) -> bool {
    matches!(op, 0x48 | 0x4F)
}

const fn is_const(op: u8) -> bool {
    matches!(op, 0x12..=0x1C)
}

const fn memory_facets(op: u8) -> (bool, bool, bool) {
    (
        is_array_get(op) || is_field_get(op),
        is_array_put(op) || is_field_put(op),
        is_byte_array_access(op),
    )
}

fn memory_operands(op: u8) -> Vec<String> {
    if is_byte_array_access(op) {
        vec!["byte [array]".to_owned()]
    } else {
        vec!["[array]".to_owned()]
    }
}

const HIGH16_INT_SHIFT: u32 = 16;
const HIGH16_WIDE_SHIFT: u32 = 48;

fn const_operand(insn: &DalvikInsn, dex: &DexFile) -> Vec<String> {
    match insn.op {
        0x15 => shifted_literal(insn, HIGH16_INT_SHIFT),
        0x19 => shifted_literal(insn, HIGH16_WIDE_SHIFT),
        0x1A | 0x1B => index_operand(insn, &dex.strings),
        0x1C => index_operand(insn, &dex.type_names),
        _ => insn
            .literal
            .map_or_else(Vec::new, |value: i64| vec![value.to_string()]),
    }
}

fn shifted_literal(insn: &DalvikInsn, shift: u32) -> Vec<String> {
    insn.literal.map_or_else(Vec::new, |raw: i64| {
        let value: i64 = raw.wrapping_shl(shift);
        vec![value.to_string()]
    })
}

fn index_operand(insn: &DalvikInsn, pool: &[String]) -> Vec<String> {
    insn.index
        .and_then(|index: u32| pool.get(index as usize))
        .map_or_else(Vec::new, |text: &String| vec![text.clone()])
}

const fn binary_op(op: u8) -> Option<BinaryOp> {
    Some(match op {
        0x7B | 0x7D | 0x7F | 0x80 => BinaryOp::Neg,
        0x7C | 0x7E => BinaryOp::Not,
        _ => return arithmetic_binop(op),
    })
}

const fn arithmetic_binop(op: u8) -> Option<BinaryOp> {
    let kind: u8 = match op {
        0x90..=0x9A => op - 0x90,
        0x9B..=0xA5 => op - 0x9B,
        0xA6..=0xAF => op - 0xA6,
        0xB0..=0xBA => op - 0xB0,
        0xBB..=0xC5 => op - 0xBB,
        0xC6..=0xCF => op - 0xC6,
        0xD0..=0xD7 => return lit16_binop(op),
        0xD8..=0xE2 => return lit8_binop(op),
        _ => return None,
    };
    arith_kind(kind)
}

const fn arith_kind(kind: u8) -> Option<BinaryOp> {
    Some(match kind {
        0 => BinaryOp::Add,
        1 => BinaryOp::Sub,
        2 => BinaryOp::Mul,
        3 => BinaryOp::Div,
        4 => BinaryOp::Rem,
        5 => BinaryOp::And,
        6 => BinaryOp::Or,
        7 => BinaryOp::Xor,
        8 => BinaryOp::Shl,
        9 | 10 => BinaryOp::Shr,
        _ => return None,
    })
}

const fn lit16_binop(op: u8) -> Option<BinaryOp> {
    Some(match op {
        0xD0 => BinaryOp::Add,
        0xD1 => BinaryOp::Sub,
        0xD2 => BinaryOp::Mul,
        0xD3 => BinaryOp::Div,
        0xD4 => BinaryOp::Rem,
        0xD5 => BinaryOp::And,
        0xD6 => BinaryOp::Or,
        0xD7 => BinaryOp::Xor,
        _ => return None,
    })
}

const fn lit8_binop(op: u8) -> Option<BinaryOp> {
    Some(match op {
        0xD8 => BinaryOp::Add,
        0xD9 => BinaryOp::Sub,
        0xDA => BinaryOp::Mul,
        0xDB => BinaryOp::Div,
        0xDC => BinaryOp::Rem,
        0xDD => BinaryOp::And,
        0xDE => BinaryOp::Or,
        0xDF => BinaryOp::Xor,
        0xE0 => BinaryOp::Shl,
        0xE1 | 0xE2 => BinaryOp::Shr,
        _ => return None,
    })
}
