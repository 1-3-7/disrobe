use disrobe_nir::{
    BinaryOp, NirFunction, NirInstr, NirModule, NirOp, NirSymbol, SourceLang, SourceRef, SymbolKind,
};

use crate::disasm::{DisasmInstruction, DisasmListing, FunctionListing};
use crate::functions::{FunctionRecovery, RecoveredFunction};
use crate::image::CodeArch;

const MAX_NIR_FUNCTIONS: usize = 4096;
const MAX_NIR_SYMBOLS: usize = 8192;

#[must_use]
pub fn lift_native_nir(
    bytes: &[u8],
    arch: CodeArch,
    recovery: &FunctionRecovery,
    disasm: &DisasmListing,
) -> NirModule {
    let lang: SourceLang = source_lang(arch);
    let source_hash: [u8; 32] = *blake3::hash(bytes).as_bytes();
    let mut module: NirModule = NirModule::new(source_hash, lang);

    for function in recovery
        .functions
        .iter()
        .filter(|function: &&RecoveredFunction| function.address_assigned)
        .take(MAX_NIR_SYMBOLS)
    {
        module.symbols.push(NirSymbol {
            address: function.start,
            name: function.name.clone(),
            kind: SymbolKind::Function,
        });
    }

    module.functions = disasm
        .listings
        .iter()
        .take(MAX_NIR_FUNCTIONS)
        .map(|listing: &FunctionListing| lift_listing(lang, listing))
        .collect();
    module
}

const fn source_lang(arch: CodeArch) -> SourceLang {
    match arch {
        CodeArch::X86 | CodeArch::X86_64 => SourceLang::NativeX86,
        CodeArch::Aarch64 => SourceLang::NativeArm,
        CodeArch::Other => SourceLang::Unknown,
    }
}

fn lift_listing(lang: SourceLang, listing: &FunctionListing) -> NirFunction {
    let instructions: Vec<NirInstr> = listing
        .instructions
        .iter()
        .map(|instruction: &DisasmInstruction| lift_instruction(lang, instruction))
        .collect();
    NirFunction {
        name: listing.recovered_name.clone(),
        address: listing.start,
        end: listing.end,
        is_export: false,
        instructions,
        source: SourceRef::labelled(lang, listing.start, listing.native_name.clone()),
    }
}

fn lift_instruction(lang: SourceLang, instruction: &DisasmInstruction) -> NirInstr {
    let mnemonic: String = instruction.mnemonic.to_ascii_lowercase();
    let operands: Vec<String> = split_operands(&instruction.operands);
    let op: NirOp = classify(&mnemonic, &instruction.operands, &operands);
    let (reads_memory, writes_memory): (bool, bool) = memory_facets(&mnemonic, &operands);
    let byte_width: bool = instruction.bytes.len() == 2 || mnemonic.ends_with('b');
    NirInstr {
        address: instruction.address,
        op,
        mnemonic,
        operands,
        reads_memory,
        writes_memory,
        byte_width,
        source: SourceRef::new(lang, instruction.address),
    }
}

fn split_operands(operands: &str) -> Vec<String> {
    operands
        .split(',')
        .map(str::trim)
        .filter(|operand: &&str| !operand.is_empty())
        .map(str::to_owned)
        .collect()
}

fn classify(mnemonic: &str, raw_operands: &str, operands: &[String]) -> NirOp {
    if is_return(mnemonic) {
        return NirOp::Return;
    }
    if is_call(mnemonic) {
        return direct_target(raw_operands).map_or(NirOp::IndirectCall, |target: u64| {
            NirOp::Call {
                target: Some(target),
            }
        });
    }
    if is_unconditional_branch(mnemonic) {
        return NirOp::Branch {
            target: direct_target(raw_operands),
        };
    }
    if is_conditional_branch(mnemonic) {
        return NirOp::CondBranch {
            target: direct_target(raw_operands),
        };
    }
    if let Some(op) = binary_op(mnemonic) {
        return NirOp::BinOp { op };
    }
    if is_store(mnemonic, operands) {
        return NirOp::Store;
    }
    if is_load(mnemonic, operands) {
        return NirOp::Load;
    }
    if is_const(mnemonic, operands) {
        return NirOp::Const;
    }
    NirOp::Nop
}

fn direct_target(operands: &str) -> Option<u64> {
    let mut head: &str = operands.split(',').next()?.trim();
    for prefix in [
        "near ", "short ", "far ", "qword ", "dword ", "word ", "ptr ",
    ] {
        head = head.strip_prefix(prefix).unwrap_or(head).trim();
    }
    let stripped: &str = head.strip_prefix("0x").or_else(|| head.strip_suffix('h'))?;
    let cleaned: &str = stripped.strip_prefix("0x").unwrap_or(stripped);
    u64::from_str_radix(cleaned, 16).ok()
}

const fn is_return(mnemonic: &str) -> bool {
    matches!(mnemonic.as_bytes(), b"ret" | b"retf") || starts_with_bytes(mnemonic, b"ret")
}

const fn is_call(mnemonic: &str) -> bool {
    matches!(
        mnemonic.as_bytes(),
        b"call" | b"callq" | b"bl" | b"blr" | b"jal" | b"jalr"
    )
}

const fn is_unconditional_branch(mnemonic: &str) -> bool {
    matches!(
        mnemonic.as_bytes(),
        b"jmp" | b"jmpq" | b"b" | b"br" | b"bra" | b"jr"
    )
}

fn is_conditional_branch(mnemonic: &str) -> bool {
    (mnemonic.starts_with('j') && !is_unconditional_branch(mnemonic) && !is_call(mnemonic))
        || mnemonic.starts_with("b.")
        || matches!(mnemonic, "cbz" | "cbnz" | "tbz" | "tbnz" | "beq" | "bne")
}

const fn starts_with_bytes(value: &str, prefix: &[u8]) -> bool {
    let bytes: &[u8] = value.as_bytes();
    if bytes.len() < prefix.len() {
        return false;
    }
    let mut index: usize = 0;
    while index < prefix.len() {
        if bytes[index] != prefix[index] {
            return false;
        }
        index += 1;
    }
    true
}

const fn binary_op(mnemonic: &str) -> Option<BinaryOp> {
    match mnemonic.as_bytes() {
        b"add" | b"adc" | b"inc" => Some(BinaryOp::Add),
        b"sub" | b"sbb" | b"dec" | b"cmp" => Some(BinaryOp::Sub),
        b"imul" | b"mul" => Some(BinaryOp::Mul),
        b"idiv" | b"div" => Some(BinaryOp::Div),
        b"and" | b"test" => Some(BinaryOp::And),
        b"or" => Some(BinaryOp::Or),
        b"xor" => Some(BinaryOp::Xor),
        b"shl" | b"sal" => Some(BinaryOp::Shl),
        b"shr" | b"sar" => Some(BinaryOp::Shr),
        b"rol" => Some(BinaryOp::Rol),
        b"ror" => Some(BinaryOp::Ror),
        b"not" => Some(BinaryOp::Not),
        b"neg" => Some(BinaryOp::Neg),
        _ => None,
    }
}

fn is_store(mnemonic: &str, operands: &[String]) -> bool {
    let dest_memory: bool = operands
        .first()
        .is_some_and(|operand: &String| is_memory_operand(operand));
    dest_memory
        || matches!(
            mnemonic,
            "stos" | "stosb" | "stosw" | "stosd" | "stosq" | "push" | "pushfq" | "pushfd"
        )
}

fn is_load(mnemonic: &str, operands: &[String]) -> bool {
    let source_memory: bool = operands
        .iter()
        .skip(1)
        .any(|operand: &String| is_memory_operand(operand));
    source_memory
        || matches!(
            mnemonic,
            "lods" | "lodsb" | "lodsw" | "lodsd" | "lodsq" | "pop" | "popfq" | "popfd"
        )
}

fn is_const(mnemonic: &str, operands: &[String]) -> bool {
    mnemonic == "lea"
        || operands
            .iter()
            .any(|operand: &String| immediate_operand(operand).is_some())
}

fn memory_facets(mnemonic: &str, operands: &[String]) -> (bool, bool) {
    let reads_memory: bool = is_load(mnemonic, operands)
        || is_return(mnemonic)
        || operands
            .iter()
            .skip(1)
            .any(|operand: &String| is_memory_operand(operand));
    let writes_memory: bool = is_store(mnemonic, operands)
        || is_call(mnemonic)
        || operands
            .first()
            .is_some_and(|operand: &String| is_memory_operand(operand));
    (reads_memory, writes_memory)
}

fn is_memory_operand(operand: &str) -> bool {
    operand.contains('[')
        || operand.contains(']')
        || operand.starts_with("byte ptr ")
        || operand.starts_with("word ptr ")
        || operand.starts_with("dword ptr ")
        || operand.starts_with("qword ptr ")
}

fn immediate_operand(operand: &str) -> Option<u64> {
    let head: &str = operand.trim_start_matches("0x");
    if head != operand {
        return u64::from_str_radix(head, 16).ok();
    }
    if let Some(hex) = operand.strip_suffix('h') {
        return u64::from_str_radix(hex, 16).ok();
    }
    operand.parse::<u64>().ok()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use disrobe_nir::NirClass;

    use super::*;
    use crate::disasm::{DisasmInstruction, FunctionListing};

    fn instruction(address: u64, mnemonic: &str, operands: &str, bytes: &str) -> DisasmInstruction {
        DisasmInstruction {
            address,
            bytes: bytes.to_owned(),
            mnemonic: mnemonic.to_owned(),
            operands: operands.to_owned(),
        }
    }

    #[test]
    fn x86_listing_lifts_control_flow_to_nir() {
        let listing: FunctionListing = FunctionListing {
            native_name: "sub_1000".to_owned(),
            recovered_name: "sub_1000".to_owned(),
            start: 0x1000,
            end: 0x1010,
            byte_len: 0x10,
            instructions: vec![
                instruction(0x1000, "call", "1010h", "e80b000000"),
                instruction(0x1005, "je", "1020h", "7401"),
                instruction(0x1007, "ret", "", "c3"),
            ],
            truncated: false,
        };
        let function: NirFunction = lift_listing(SourceLang::NativeX86, &listing);
        assert_eq!(function.name, "sub_1000");
        assert_eq!(function.instructions[0].class(), NirClass::Call);
        assert_eq!(function.instructions[0].direct_target(), Some(0x1010));
        assert_eq!(function.instructions[1].class(), NirClass::ConditionalJump);
        assert_eq!(function.instructions[1].direct_target(), Some(0x1020));
        assert_eq!(function.instructions[2].class(), NirClass::Return);
    }

    #[test]
    fn x86_listing_lifts_memory_facets() {
        let store: NirInstr = lift_instruction(
            SourceLang::NativeX86,
            &instruction(0x2000, "mov", "[rsp+8], rax", "4889442408"),
        );
        let load: NirInstr = lift_instruction(
            SourceLang::NativeX86,
            &instruction(0x2005, "mov", "rax, [rsp+8]", "488b442408"),
        );
        assert!(matches!(store.op, NirOp::Store));
        assert!(store.writes_memory);
        assert!(matches!(load.op, NirOp::Load));
        assert!(load.reads_memory);
    }
}
