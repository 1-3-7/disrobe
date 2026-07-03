use crate::types::{NirInstr, NirOp};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DefUse {
    pub defs: Vec<ValueId>,
    pub uses: Vec<ValueId>,
}

impl DefUse {
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.defs.is_empty() && self.uses.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ValueId {
    Register(String),
    Memory(String),
    Stack(u32),
}

impl ValueId {
    #[must_use]
    pub fn register(name: &str) -> Self {
        Self::Register(canonical_register(name))
    }

    #[must_use]
    pub fn memory(expr: &str) -> Self {
        Self::Memory(expr.trim().to_owned())
    }

    #[must_use]
    pub const fn label(&self) -> &str {
        match self {
            Self::Register(name) | Self::Memory(name) => name.as_str(),
            Self::Stack(_) => "stack",
        }
    }
}

const RETURN_REGISTER: &str = "rax";

#[must_use]
pub fn def_use(instr: &NirInstr) -> DefUse {
    match &instr.op {
        NirOp::Call { .. } | NirOp::IndirectCall | NirOp::ExternCall { .. } => call_def_use(instr),
        NirOp::Return => DefUse {
            defs: Vec::new(),
            uses: register_use(instr.operands.first())
                .into_iter()
                .chain(std::iter::once(ValueId::register(RETURN_REGISTER)))
                .collect(),
        },
        NirOp::BinOp { .. } | NirOp::Load | NirOp::Store | NirOp::Const => operand_def_use(instr),
        NirOp::Nop
        | NirOp::Branch { .. }
        | NirOp::CondBranch { .. }
        | NirOp::Phi
        | NirOp::Interrupt => DefUse::default(),
    }
}

fn call_def_use(instr: &NirInstr) -> DefUse {
    let mut uses: Vec<ValueId> = Vec::new();
    for operand in &instr.operands {
        if let Some(value) = operand_to_value(operand)
            && !is_symbol_operand(operand)
        {
            uses.push(value);
        }
    }
    DefUse {
        defs: vec![ValueId::register(RETURN_REGISTER)],
        uses,
    }
}

fn operand_def_use(instr: &NirInstr) -> DefUse {
    let mut operands: std::slice::Iter<'_, String> = instr.operands.iter();
    let Some(first): Option<&String> = operands.next() else {
        return DefUse::default();
    };
    let mut defs: Vec<ValueId> = Vec::new();
    let mut uses: Vec<ValueId> = Vec::new();
    if let Some(value) = operand_to_value(first) {
        if defines_first(instr) {
            defs.push(value.clone());
        }
        if reads_first(instr) {
            uses.push(value);
        }
    }
    for operand in operands {
        if let Some(value) = operand_to_value(operand) {
            uses.push(value);
        }
    }
    DefUse { defs, uses }
}

const fn defines_first(instr: &NirInstr) -> bool {
    matches!(
        instr.op,
        NirOp::Const | NirOp::BinOp { .. } | NirOp::Load | NirOp::Store
    )
}

const fn reads_first(instr: &NirInstr) -> bool {
    matches!(instr.op, NirOp::BinOp { .. })
}

fn register_use(operand: Option<&String>) -> Option<ValueId> {
    operand.and_then(|o: &String| operand_to_value(o))
}

fn operand_to_value(operand: &str) -> Option<ValueId> {
    let trimmed: &str = operand.trim();
    if trimmed.is_empty() {
        return None;
    }
    if is_memory_operand(trimmed) {
        return Some(ValueId::memory(memory_cell(trimmed)));
    }
    if is_immediate(trimmed) || is_symbol_operand(trimmed) {
        return None;
    }
    Some(ValueId::register(trimmed))
}

fn is_memory_operand(operand: &str) -> bool {
    operand.contains('[') && operand.contains(']')
}

fn memory_cell(operand: &str) -> &str {
    let start: usize = operand.find('[').map_or(0, |i: usize| i);
    let end: usize = operand.rfind(']').map_or(operand.len(), |i: usize| i + 1);
    operand.get(start..end).unwrap_or(operand)
}

fn is_immediate(operand: &str) -> bool {
    let body: &str = operand.strip_prefix('-').unwrap_or(operand);
    let body: &str = body.strip_prefix("0x").unwrap_or(body);
    !body.is_empty() && body.bytes().all(|b: u8| b.is_ascii_hexdigit())
}

fn is_symbol_operand(operand: &str) -> bool {
    operand
        .bytes()
        .next()
        .is_some_and(|b: u8| b.is_ascii_alphabetic() || b == b'_' || b == b'.')
        && operand
            .bytes()
            .all(|b: u8| b.is_ascii_alphanumeric() || b == b'_' || b == b'.' || b == b'$')
        && !is_known_register(operand)
}

fn canonical_register(name: &str) -> String {
    let lower: String = name.trim().to_ascii_lowercase();
    canonical_x86(&lower).map_or(lower, str::to_owned)
}

fn is_known_register(name: &str) -> bool {
    canonical_x86(&name.trim().to_ascii_lowercase()).is_some()
}

fn canonical_x86(name: &str) -> Option<&'static str> {
    Some(match name {
        "rax" | "eax" | "ax" | "al" | "ah" => "rax",
        "rbx" | "ebx" | "bx" | "bl" | "bh" => "rbx",
        "rcx" | "ecx" | "cx" | "cl" | "ch" => "rcx",
        "rdx" | "edx" | "dx" | "dl" | "dh" => "rdx",
        "rsi" | "esi" | "si" | "sil" => "rsi",
        "rdi" | "edi" | "di" | "dil" => "rdi",
        "rbp" | "ebp" | "bp" | "bpl" => "rbp",
        "rsp" | "esp" | "sp" | "spl" => "rsp",
        "r8" | "r8d" | "r8w" | "r8b" => "r8",
        "r9" | "r9d" | "r9w" | "r9b" => "r9",
        "r10" | "r10d" | "r10w" | "r10b" => "r10",
        "r11" | "r11d" | "r11w" | "r11b" => "r11",
        "r12" | "r12d" | "r12w" | "r12b" => "r12",
        "r13" | "r13d" | "r13w" | "r13b" => "r13",
        "r14" | "r14d" | "r14w" | "r14b" => "r14",
        "r15" | "r15d" | "r15w" | "r15b" => "r15",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{BinaryOp, SourceLang, SourceRef};

    fn instr(op: NirOp, mnemonic: &str, operands: &[&str]) -> NirInstr {
        let mut nir: NirInstr = NirInstr {
            address: 0,
            op,
            mnemonic: mnemonic.to_owned(),
            operands: operands.iter().map(|s: &&str| (*s).to_owned()).collect(),
            reads_memory: false,
            writes_memory: false,
            byte_width: false,
            source: SourceRef::new(SourceLang::NativeX86, 0),
        };
        if mnemonic == "mov" && nir.operands.first().is_some_and(|o| o.contains('[')) {
            nir.writes_memory = true;
        }
        if nir.operands.iter().any(|o| o.contains('[')) && !nir.writes_memory {
            nir.reads_memory = true;
        }
        nir
    }

    #[test]
    fn binop_defs_destination_uses_both() {
        let du: DefUse = def_use(&instr(
            NirOp::BinOp { op: BinaryOp::Xor },
            "xor",
            &["eax", "ebx"],
        ));
        assert_eq!(du.defs, vec![ValueId::register("rax")]);
        assert_eq!(
            du.uses,
            vec![ValueId::register("rax"), ValueId::register("rbx")]
        );
    }

    #[test]
    fn subregisters_alias_to_full_register() {
        assert_eq!(ValueId::register("al"), ValueId::register("rax"));
        assert_eq!(ValueId::register("eax"), ValueId::register("rax"));
    }

    #[test]
    fn call_defines_return_register() {
        let du: DefUse = def_use(&instr(
            NirOp::ExternCall {
                symbol: "recv".to_owned(),
            },
            "call",
            &["recv"],
        ));
        assert_eq!(du.defs, vec![ValueId::register("rax")]);
        assert!(du.uses.is_empty());
    }

    #[test]
    fn immediate_operands_are_not_values() {
        let du: DefUse = def_use(&instr(NirOp::Const, "mov", &["eax", "0x10"]));
        assert_eq!(du.defs, vec![ValueId::register("rax")]);
        assert!(du.uses.is_empty());
    }

    #[test]
    fn empty_operands_yield_no_def_use() {
        let du: DefUse = def_use(&instr(NirOp::BinOp { op: BinaryOp::Add }, "add", &[]));
        assert!(du.is_empty());
    }
}
