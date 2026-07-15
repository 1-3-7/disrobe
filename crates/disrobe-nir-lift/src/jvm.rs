use std::collections::BTreeMap;

use disrobe_nir::{
    BinaryOp, NirFunction, NirInstr, NirModule, NirOp, NirSymbol, SourceLang, SourceRef, SymbolKind,
};
use disrobe_pass_jvm::{
    Attribute, ClassFile, CodeAttribute, ConstantPoolEntry, Instruction, MethodInfo, Operands,
    branch_target, class_internal_name_at, disassemble, method_name_descriptor_at, parse_classfile,
    parse_code_attribute,
};

use crate::error::{LiftError, Result};
use crate::operand::{f32_operand, f64_operand};
use crate::usize_to_u32_saturating;

const FUNCTION_STRIDE: u64 = 1 << 20;
const IMPORT_BASE: u64 = 1 << 40;
const ACC_PUBLIC: u16 = 0x0001;

pub fn lift_classfile(bytes: &[u8]) -> Result<NirModule> {
    let class: ClassFile = parse_classfile(bytes)
        .map_err(|e: disrobe_pass_jvm::Error| LiftError::Source(format!("classfile parse: {e}")))?;
    let this_class: String = class
        .this_class_name()
        .map_or_else(|_| String::with_capacity(0), str::to_owned);

    let source_hash: [u8; 32] = *blake3::hash(bytes).as_bytes();
    let mut module: NirModule = NirModule::new(source_hash, SourceLang::Jvm);

    let methods: Vec<MethodEntry> = enumerate_methods(&class);
    let internal_by_key: BTreeMap<(String, String), u64> = methods
        .iter()
        .map(|m: &MethodEntry| {
            (
                (m.name.clone(), m.descriptor.clone()),
                function_address(m.index),
            )
        })
        .collect();

    let mut imports: ImportTable = ImportTable::new();

    for method in &methods {
        register_method_symbol(method, &mut module);
        let maybe_code: Option<CodeAttribute> = method.code(&class);
        if let Some(code) = maybe_code {
            let function: NirFunction = lift_method(
                method,
                &code,
                &class,
                &this_class,
                &internal_by_key,
                &mut imports,
            )?;
            module.functions.push(function);
        }
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
    index: u32,
    name: String,
    descriptor: String,
    access_flags: u16,
}

impl MethodEntry {
    fn code(&self, class: &ClassFile) -> Option<CodeAttribute> {
        let info: &MethodInfo = class.methods.get(self.index as usize)?;
        for attribute in &info.attributes {
            let attribute: &Attribute = attribute;
            if class.utf8_at(attribute.name_index).ok() == Some("Code") {
                return parse_code_attribute(&attribute.info).ok();
            }
        }
        None
    }

    const fn is_public(&self) -> bool {
        self.access_flags & ACC_PUBLIC != 0
    }
}

fn enumerate_methods(class: &ClassFile) -> Vec<MethodEntry> {
    class
        .methods
        .iter()
        .enumerate()
        .map(|(index, info): (usize, &MethodInfo)| {
            let name: String = class
                .utf8_at(info.name_index)
                .map_or_else(|_| format!("method_{index}"), str::to_owned);
            let descriptor: String = class
                .utf8_at(info.descriptor_index)
                .map_or_else(|_| String::with_capacity(0), str::to_owned);
            MethodEntry {
                index: usize_to_u32_saturating(index),
                name,
                descriptor,
                access_flags: info.access_flags,
            }
        })
        .collect()
}

fn register_method_symbol(method: &MethodEntry, module: &mut NirModule) {
    let kind: SymbolKind = if method.is_public() {
        SymbolKind::Export
    } else {
        SymbolKind::Function
    };
    module.symbols.push(NirSymbol {
        address: function_address(method.index),
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
    code: &CodeAttribute,
    class: &ClassFile,
    this_class: &str,
    internal_by_key: &BTreeMap<(String, String), u64>,
    imports: &mut ImportTable,
) -> Result<NirFunction> {
    let base: u64 = function_address(method.index);
    let insns: Vec<Instruction> = disassemble(&code.code)
        .map_err(|e: disrobe_pass_jvm::Error| LiftError::Source(format!("disassemble: {e}")))?;

    let byte_arith: Vec<bool> = byte_arith_flags(&insns);

    let mut instructions: Vec<NirInstr> = Vec::with_capacity(insns.len());
    for (ordinal, insn) in insns.iter().enumerate() {
        let address: u64 = base.saturating_add(u64::from(insn.pc));
        let (op, mut operand_list): (NirOp, Vec<String>) =
            classify(insn, base, class, this_class, internal_by_key, imports);
        let (reads_memory, writes_memory, mem_byte): (bool, bool, bool) = memory_facets(insn);
        let is_byte_arith: bool = byte_arith.get(ordinal).is_some_and(|value: &bool| *value);
        if is_byte_arith {
            operand_list.push("byte stack".to_owned());
        }
        let normalized: String = match &op {
            NirOp::BinOp { op: binary_op } => binary_op.mnemonic().to_owned(),
            _ => insn.mnemonic.to_owned(),
        };
        instructions.push(NirInstr {
            address,
            op,
            mnemonic: normalized,
            operands: operand_list,
            reads_memory,
            writes_memory,
            byte_width: mem_byte || is_byte_arith,
            source: SourceRef::new(SourceLang::Jvm, address),
        });
    }

    let end: u64 = base.saturating_add(code.code.len() as u64);
    Ok(NirFunction {
        name: method.name.clone(),
        address: base,
        end,
        is_export: method.is_public(),
        instructions,
        source: SourceRef::labelled(SourceLang::Jvm, base, method.descriptor.clone()),
    })
}

fn classify(
    insn: &Instruction,
    base: u64,
    class: &ClassFile,
    this_class: &str,
    internal_by_key: &BTreeMap<(String, String), u64>,
    imports: &mut ImportTable,
) -> (NirOp, Vec<String>) {
    if is_invoke(insn.opcode) {
        return classify_invoke(insn, class, this_class, internal_by_key, imports);
    }
    if is_return(insn.opcode) {
        return (NirOp::Return, Vec::new());
    }
    if insn.opcode == OP_ATHROW {
        return (NirOp::Interrupt, Vec::new());
    }
    if let Operands::Branch(_) = insn.operands {
        let target: Option<u64> =
            branch_target(insn).map(|t: u32| base.saturating_add(u64::from(t)));
        return if is_conditional_branch(insn.opcode) {
            (NirOp::CondBranch { target }, Vec::new())
        } else {
            (NirOp::Branch { target }, Vec::new())
        };
    }
    if matches!(
        insn.operands,
        Operands::TableSwitch { .. } | Operands::LookupSwitch { .. }
    ) {
        return (NirOp::CondBranch { target: None }, Vec::new());
    }
    if let Some(binary_op) = binary_op(insn.opcode) {
        return (NirOp::BinOp { op: binary_op }, Vec::new());
    }
    if is_load(insn.opcode) {
        return (NirOp::Load, memory_operands(insn));
    }
    if is_store(insn.opcode) {
        return (NirOp::Store, memory_operands(insn));
    }
    if is_const(insn.opcode) {
        return (NirOp::Const, const_operand(insn, class));
    }
    if insn.opcode == OP_NOP {
        return (NirOp::Nop, Vec::new());
    }
    (
        NirOp::Unmodeled {
            opcode: insn.opcode,
            offset: insn.pc,
        },
        Vec::new(),
    )
}

fn classify_invoke(
    insn: &Instruction,
    class: &ClassFile,
    this_class: &str,
    internal_by_key: &BTreeMap<(String, String), u64>,
    imports: &mut ImportTable,
) -> (NirOp, Vec<String>) {
    let pool_index: Option<u16> = match &insn.operands {
        Operands::ConstPool(index)
        | Operands::InvokeDynamic(index)
        | Operands::InvokeInterface { index, .. } => Some(*index),
        _ => None,
    };
    let Some(pool_index): Option<u16> = pool_index else {
        return (NirOp::IndirectCall, Vec::new());
    };
    let Some((name, descriptor)): Option<(String, String)> =
        method_name_descriptor_at(class, pool_index)
    else {
        return (NirOp::IndirectCall, Vec::new());
    };
    let owner: Option<String> = class_internal_name_at(class, pool_index);

    if (owner.as_deref() == Some(this_class) || owner.is_none())
        && let Some(target) = internal_by_key.get(&(name.clone(), descriptor)).copied()
    {
        return (
            NirOp::Call {
                target: Some(target),
            },
            vec![name],
        );
    }

    let symbol: String = owner.map_or_else(
        || name.clone(),
        |class_name: String| format!("{}.{name}", class_name.replace('/', ".")),
    );
    let address: u64 = imports.address_of(&symbol);
    (
        NirOp::Call {
            target: Some(address),
        },
        vec![symbol],
    )
}

const BYTE_ARITH_WINDOW: usize = 6;

fn byte_arith_flags(insns: &[Instruction]) -> Vec<bool> {
    let mut flags: Vec<bool> = vec![false; insns.len()];
    let mut array_load_at: Option<usize> = None;
    for (ordinal, insn) in insns.iter().enumerate() {
        let opcode: u8 = insn.opcode;
        if is_invoke(opcode) || matches!(insn.operands, Operands::Branch(_)) {
            array_load_at = None;
        }
        if is_array_load(opcode) {
            array_load_at = Some(ordinal);
        }
        if binary_op(opcode).is_some()
            && array_load_at
                .is_some_and(|seen: usize| ordinal.saturating_sub(seen) <= BYTE_ARITH_WINDOW)
            && let Some(flag) = flags.get_mut(ordinal)
        {
            *flag = true;
        }
    }
    flags
}

const fn is_array_load(opcode: u8) -> bool {
    matches!(opcode, 0x2E..=0x35)
}

const fn binary_op(opcode: u8) -> Option<BinaryOp> {
    Some(match opcode {
        0x60..=0x63 => BinaryOp::Add,
        0x64..=0x67 => BinaryOp::Sub,
        0x68..=0x6B => BinaryOp::Mul,
        0x6C..=0x6F => BinaryOp::Div,
        0x70..=0x73 => BinaryOp::Rem,
        0x74 | 0x75 => BinaryOp::Neg,
        0x78 | 0x79 => BinaryOp::Shl,
        0x7A..=0x7D => BinaryOp::Shr,
        0x7E | 0x7F => BinaryOp::And,
        0x80 | 0x81 => BinaryOp::Or,
        0x82 | 0x83 => BinaryOp::Xor,
        _ => return None,
    })
}

const fn is_invoke(opcode: u8) -> bool {
    matches!(opcode, 0xB6..=0xBA)
}

const fn is_return(opcode: u8) -> bool {
    matches!(opcode, 0xAC..=0xB1)
}

const OP_ATHROW: u8 = 0xBF;
const OP_NOP: u8 = 0x00;

const fn is_conditional_branch(opcode: u8) -> bool {
    matches!(
        opcode,
        0x99 | 0x9A
            | 0x9B
            | 0x9C
            | 0x9D
            | 0x9E
            | 0x9F
            | 0xA0
            | 0xA1
            | 0xA2
            | 0xA3
            | 0xA4
            | 0xA5
            | 0xA6
            | 0xC6
            | 0xC7
    )
}

const fn is_load(opcode: u8) -> bool {
    matches!(
        opcode,
        0x2E | 0x2F | 0x30 | 0x31 | 0x32 | 0x33 | 0x34 | 0x35 | 0xB2 | 0xB4
    )
}

const fn is_store(opcode: u8) -> bool {
    matches!(
        opcode,
        0x4F | 0x50 | 0x51 | 0x52 | 0x53 | 0x54 | 0x55 | 0x56 | 0xB3 | 0xB5
    )
}

const fn is_byte_array_access(opcode: u8) -> bool {
    matches!(opcode, 0x33 | 0x54)
}

const fn is_const(opcode: u8) -> bool {
    matches!(opcode, 0x01..=0x14)
}

fn const_operand(insn: &Instruction, class: &ClassFile) -> Vec<String> {
    match &insn.operands {
        Operands::Byte(value) | Operands::Short(value) => vec![value.to_string()],
        Operands::ConstPool(index) => ldc_operand(class, *index),
        _ => implicit_const_operand(insn.opcode),
    }
}

fn implicit_const_operand(opcode: u8) -> Vec<String> {
    match opcode {
        0x01 => vec!["null".to_owned()],
        0x02 => vec!["-1".to_owned()],
        0x03..=0x08 => vec![(i32::from(opcode) - 0x03).to_string()],
        0x09 => vec!["0".to_owned()],
        0x0A => vec!["1".to_owned()],
        0x0B => vec![f32_operand(0.0f32.to_bits())],
        0x0C => vec![f32_operand(1.0f32.to_bits())],
        0x0D => vec![f32_operand(2.0f32.to_bits())],
        0x0E => vec![f64_operand(0.0f64.to_bits())],
        0x0F => vec![f64_operand(1.0f64.to_bits())],
        _ => Vec::new(),
    }
}

fn ldc_operand(class: &ClassFile, index: u16) -> Vec<String> {
    match class.constant_pool.get(usize::from(index)) {
        Some(ConstantPoolEntry::Integer(value)) => vec![value.to_string()],
        Some(ConstantPoolEntry::Long(value)) => vec![value.to_string()],
        Some(ConstantPoolEntry::Float(bits)) => vec![f32_operand(*bits)],
        Some(ConstantPoolEntry::Double(bits)) => vec![f64_operand(*bits)],
        Some(ConstantPoolEntry::String { utf8_index }) => class
            .utf8_at(*utf8_index)
            .map_or_else(|_| Vec::new(), |text: &str| vec![text.to_owned()]),
        Some(ConstantPoolEntry::Class { name_index }) => class
            .utf8_at(*name_index)
            .map_or_else(|_| Vec::new(), |text: &str| vec![text.to_owned()]),
        _ => Vec::new(),
    }
}

const fn memory_facets(insn: &Instruction) -> (bool, bool, bool) {
    (
        is_load(insn.opcode),
        is_store(insn.opcode),
        is_byte_array_access(insn.opcode),
    )
}

fn memory_operands(insn: &Instruction) -> Vec<String> {
    if is_byte_array_access(insn.opcode) {
        vec!["byte [array]".to_owned()]
    } else if is_load(insn.opcode) || is_store(insn.opcode) {
        vec!["[array]".to_owned()]
    } else {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn implicit_const_macro_forms_carry_their_value() {
        assert_eq!(implicit_const_operand(0x01), vec!["null".to_owned()]);
        assert_eq!(implicit_const_operand(0x02), vec!["-1".to_owned()]);
        assert_eq!(implicit_const_operand(0x03), vec!["0".to_owned()]);
        assert_eq!(implicit_const_operand(0x08), vec!["5".to_owned()]);
        assert_eq!(implicit_const_operand(0x09), vec!["0".to_owned()]);
        assert_eq!(implicit_const_operand(0x0A), vec!["1".to_owned()]);
        assert_eq!(implicit_const_operand(0x0B), vec!["0".to_owned()]);
        assert_eq!(implicit_const_operand(0x0D), vec!["2".to_owned()]);
        assert_eq!(implicit_const_operand(0x0F), vec!["1".to_owned()]);
        assert!(implicit_const_operand(0x10).is_empty());
    }
}
