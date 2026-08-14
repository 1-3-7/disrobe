use disrobe_ir::payload::{
    DisasmInstruction, DisasmPayload, DisasmSymbol, DisasmSymbolKind, InsnFlow,
};
use disrobe_nir::{
    BinaryOp, NirFunction, NirInstr, NirModule, NirOp, NirSymbol, SourceLang, SourceRef, SymbolKind,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FunctionSymbol<'a> {
    address: u64,
    name: &'a str,
    is_export: bool,
}

fn disasm_function_symbols(symbol_table: &[DisasmSymbol]) -> Vec<FunctionSymbol<'_>> {
    let mut symbols: Vec<FunctionSymbol<'_>> = symbol_table
        .iter()
        .filter_map(|s: &DisasmSymbol| match s.kind {
            DisasmSymbolKind::Function | DisasmSymbolKind::Export => Some(FunctionSymbol {
                address: s.address,
                name: s.name.as_str(),
                is_export: matches!(s.kind, DisasmSymbolKind::Export),
            }),
            DisasmSymbolKind::Data | DisasmSymbolKind::Label | DisasmSymbolKind::Import => None,
        })
        .collect();
    symbols.sort_by_key(|s: &FunctionSymbol<'_>| s.address);
    let mut grouped: Vec<FunctionSymbol<'_>> = Vec::with_capacity(symbols.len());
    for symbol in symbols {
        match grouped.last_mut() {
            Some(existing) if existing.address == symbol.address => {
                existing.is_export |= symbol.is_export;
            }
            _ => grouped.push(symbol),
        }
    }
    grouped
}

fn instruction_end(offset: u64, byte_len: usize) -> u64 {
    u64::try_from(byte_len)
        .ok()
        .and_then(|len: u64| offset.checked_add(len))
        .unwrap_or(offset)
}

#[must_use]
pub fn disasm_to_nir(payload: &DisasmPayload) -> NirModule {
    disasm_to_nir_as(payload, SourceLang::NativeX86)
}

#[must_use]
pub fn disasm_to_nir_as(payload: &DisasmPayload, lang: SourceLang) -> NirModule {
    let function_symbols: Vec<FunctionSymbol<'_>> = disasm_function_symbols(&payload.symbol_table);

    let mut sorted_insns: Vec<&DisasmInstruction> = payload.instructions.iter().collect();
    sorted_insns.sort_by_key(|i: &&DisasmInstruction| i.offset);

    let last_end: u64 = sorted_insns.last().map_or(0, |i: &&DisasmInstruction| {
        instruction_end(i.offset, i.bytes.len())
    });

    let functions: Vec<NirFunction> = function_symbols
        .iter()
        .enumerate()
        .map(|(idx, sym): (usize, &FunctionSymbol<'_>)| {
            let start: u64 = sym.address;
            let end: u64 = function_symbols
                .get(idx + 1)
                .map_or(last_end, |next: &FunctionSymbol<'_>| next.address);
            let lo: usize = sorted_insns.partition_point(|i: &&DisasmInstruction| i.offset < start);
            let hi: usize = if end > start {
                sorted_insns.partition_point(|i: &&DisasmInstruction| i.offset < end)
            } else {
                sorted_insns.partition_point(|i: &&DisasmInstruction| i.offset <= start)
            };
            let instructions: Vec<NirInstr> = sorted_insns[lo..hi]
                .iter()
                .map(|i: &&DisasmInstruction| lift_instruction(i, lang))
                .collect();
            NirFunction {
                name: sym.name.to_owned(),
                address: start,
                end,
                is_export: sym.is_export,
                instructions,
                source: SourceRef::labelled(lang, start, sym.name.to_owned()),
            }
        })
        .collect();

    let symbols: Vec<NirSymbol> = payload
        .symbol_table
        .iter()
        .map(|s: &DisasmSymbol| NirSymbol {
            address: s.address,
            name: s.name.clone(),
            kind: lift_symbol_kind(s.kind),
        })
        .collect();

    NirModule {
        source_hash: payload.source_hash,
        lang,
        functions,
        symbols,
    }
}

fn lift_instruction(insn: &DisasmInstruction, lang: SourceLang) -> NirInstr {
    let op: NirOp = lift_op(insn);
    let (reads_memory, writes_memory): (bool, bool) = memory_access(insn);
    NirInstr {
        address: insn.offset,
        op,
        mnemonic: insn.mnemonic.clone(),
        operands: insn.operands.clone(),
        reads_memory,
        writes_memory,
        byte_width: is_byte_width(insn),
        source: SourceRef::new(lang, insn.offset),
    }
}

fn lift_op(insn: &DisasmInstruction) -> NirOp {
    match insn.flow {
        InsnFlow::Call => NirOp::Call {
            target: insn.branch_target,
        },
        InsnFlow::IndirectCall => NirOp::IndirectCall,
        InsnFlow::UnconditionalBranch | InsnFlow::IndirectBranch => NirOp::Branch {
            target: insn.branch_target,
        },
        InsnFlow::ConditionalBranch => NirOp::CondBranch {
            target: insn.branch_target,
        },
        InsnFlow::Return => NirOp::Return,
        InsnFlow::Interrupt => NirOp::Interrupt,
        InsnFlow::Sequential => sequential_op(insn),
    }
}

fn sequential_op(insn: &DisasmInstruction) -> NirOp {
    if let Some(op) = binary_op(&insn.mnemonic) {
        return NirOp::BinOp { op };
    }
    let (reads, writes): (bool, bool) = memory_access(insn);
    match (reads, writes) {
        (_, true) => NirOp::Store,
        (true, false) => NirOp::Load,
        (false, false) => NirOp::Nop,
    }
}

const fn binary_op(mnemonic: &str) -> Option<BinaryOp> {
    if mnemonic.eq_ignore_ascii_case("add") {
        return Some(BinaryOp::Add);
    }
    if mnemonic.eq_ignore_ascii_case("sub") {
        return Some(BinaryOp::Sub);
    }
    if mnemonic.eq_ignore_ascii_case("imul") || mnemonic.eq_ignore_ascii_case("mul") {
        return Some(BinaryOp::Mul);
    }
    if mnemonic.eq_ignore_ascii_case("idiv") || mnemonic.eq_ignore_ascii_case("div") {
        return Some(BinaryOp::Div);
    }
    if mnemonic.eq_ignore_ascii_case("and") {
        return Some(BinaryOp::And);
    }
    if mnemonic.eq_ignore_ascii_case("or") {
        return Some(BinaryOp::Or);
    }
    if mnemonic.eq_ignore_ascii_case("xor") {
        return Some(BinaryOp::Xor);
    }
    if mnemonic.eq_ignore_ascii_case("shl") || mnemonic.eq_ignore_ascii_case("sal") {
        return Some(BinaryOp::Shl);
    }
    if mnemonic.eq_ignore_ascii_case("shr") || mnemonic.eq_ignore_ascii_case("sar") {
        return Some(BinaryOp::Shr);
    }
    if mnemonic.eq_ignore_ascii_case("rol") {
        return Some(BinaryOp::Rol);
    }
    if mnemonic.eq_ignore_ascii_case("ror") {
        return Some(BinaryOp::Ror);
    }
    if mnemonic.eq_ignore_ascii_case("not") {
        return Some(BinaryOp::Not);
    }
    if mnemonic.eq_ignore_ascii_case("neg") {
        return Some(BinaryOp::Neg);
    }
    None
}

fn memory_access(insn: &DisasmInstruction) -> (bool, bool) {
    let any_mem: bool = insn
        .operands
        .iter()
        .any(|op: &String| op.contains('[') && op.contains(']'));
    if !any_mem {
        return (false, false);
    }
    let first_is_mem: bool = insn
        .operands
        .first()
        .is_some_and(|op: &String| op.contains('[') && op.contains(']'));
    let writes: bool = first_is_mem && writes_first_operand(&insn.mnemonic);
    let reads: bool = !first_is_mem || !writes;
    (reads, writes)
}

const fn writes_first_operand(mnemonic: &str) -> bool {
    !(mnemonic.eq_ignore_ascii_case("cmp")
        || mnemonic.eq_ignore_ascii_case("test")
        || mnemonic.eq_ignore_ascii_case("push")
        || mnemonic.eq_ignore_ascii_case("jmp")
        || mnemonic.eq_ignore_ascii_case("call"))
}

fn is_byte_width(insn: &DisasmInstruction) -> bool {
    insn.operands.iter().any(|op: &String| {
        starts_with_ascii_ignore_case(op, "byte ")
            || contains_ascii_ignore_case(op, "byte ptr")
            || is_byte_register(op)
    })
}

const fn is_byte_register(operand: &str) -> bool {
    matches!(
        operand,
        r if r.eq_ignore_ascii_case("al")
            || r.eq_ignore_ascii_case("ah")
            || r.eq_ignore_ascii_case("bl")
            || r.eq_ignore_ascii_case("bh")
            || r.eq_ignore_ascii_case("cl")
            || r.eq_ignore_ascii_case("ch")
            || r.eq_ignore_ascii_case("dl")
            || r.eq_ignore_ascii_case("dh")
            || r.eq_ignore_ascii_case("sil")
            || r.eq_ignore_ascii_case("dil")
            || r.eq_ignore_ascii_case("bpl")
            || r.eq_ignore_ascii_case("spl")
            || r.eq_ignore_ascii_case("r8b")
            || r.eq_ignore_ascii_case("r9b")
            || r.eq_ignore_ascii_case("r10b")
            || r.eq_ignore_ascii_case("r11b")
            || r.eq_ignore_ascii_case("r12b")
            || r.eq_ignore_ascii_case("r13b")
            || r.eq_ignore_ascii_case("r14b")
            || r.eq_ignore_ascii_case("r15b")
    )
}

fn starts_with_ascii_ignore_case(value: &str, prefix: &str) -> bool {
    let value_bytes: &[u8] = value.as_bytes();
    let prefix_bytes: &[u8] = prefix.as_bytes();
    value_bytes
        .get(..prefix_bytes.len())
        .is_some_and(|head: &[u8]| ascii_eq_ignore_case(head, prefix_bytes))
}

fn contains_ascii_ignore_case(value: &str, needle: &str) -> bool {
    let needle_bytes: &[u8] = needle.as_bytes();
    if needle_bytes.is_empty() {
        return true;
    }
    value
        .as_bytes()
        .windows(needle_bytes.len())
        .any(|window: &[u8]| ascii_eq_ignore_case(window, needle_bytes))
}

fn ascii_eq_ignore_case(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .all(|(l, r): (&u8, &u8)| l.eq_ignore_ascii_case(r))
}

const fn lift_symbol_kind(kind: DisasmSymbolKind) -> SymbolKind {
    match kind {
        DisasmSymbolKind::Function => SymbolKind::Function,
        DisasmSymbolKind::Data => SymbolKind::Data,
        DisasmSymbolKind::Label => SymbolKind::Label,
        DisasmSymbolKind::Export => SymbolKind::Export,
        DisasmSymbolKind::Import => SymbolKind::Import,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn seq(offset: u64, mnemonic: &str, operands: &[&str]) -> DisasmInstruction {
        seq_bytes(offset, vec![0x90], mnemonic, operands)
    }

    fn seq_bytes(
        offset: u64,
        bytes: Vec<u8>,
        mnemonic: &str,
        operands: &[&str],
    ) -> DisasmInstruction {
        DisasmInstruction {
            offset,
            bytes,
            mnemonic: mnemonic.to_owned(),
            operands: operands.iter().map(|s: &&str| (*s).to_owned()).collect(),
            flow: InsnFlow::Sequential,
            branch_target: None,
            ..DisasmInstruction::default()
        }
    }

    fn sym(address: u64, name: &str, kind: DisasmSymbolKind) -> DisasmSymbol {
        DisasmSymbol {
            address,
            name: name.to_owned(),
            kind,
        }
    }

    #[test]
    fn uppercase_mnemonics_lift_to_the_same_nir_ops() {
        let payload: DisasmPayload = DisasmPayload {
            source_hash: [0u8; 32],
            instructions: vec![
                seq(0x10, "XOR", &["AL", "0X5A"]),
                seq(0x11, "MOV", &["BYTE PTR [RAX]", "AL"]),
            ],
            symbol_table: vec![
                sym(0x10, "internal", DisasmSymbolKind::Function),
                sym(0x10, "public", DisasmSymbolKind::Export),
            ],
        };
        let module: NirModule = disasm_to_nir(&payload);
        let function: &NirFunction = module.functions.first().expect("function");
        assert!(function.is_export);
        assert!(matches!(
            function.instructions[0].op,
            NirOp::BinOp { op: BinaryOp::Xor }
        ));
        assert!(function.instructions[0].byte_width);
        assert!(function.instructions[1].writes_memory);
        assert!(function.instructions[1].byte_width);
    }

    #[test]
    fn overflowing_instruction_length_does_not_extend_nir_function() {
        let start: u64 = u64::MAX - 1;
        let payload: DisasmPayload = DisasmPayload {
            source_hash: [0u8; 32],
            instructions: vec![seq_bytes(start, vec![0x90, 0x90, 0x90, 0x90], "nop4", &[])],
            symbol_table: vec![sym(start, "edge", DisasmSymbolKind::Function)],
        };
        let module: NirModule = disasm_to_nir(&payload);
        let function: &NirFunction = module.functions.first().expect("function");
        assert_eq!(function.address, start);
        assert_eq!(function.end, start);
        assert_eq!(function.instructions.len(), 1);
        assert_eq!(function.instructions[0].address, start);
    }
}
