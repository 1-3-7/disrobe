use crate::types::{CallOtherEffect, NirInstr, NirOp};

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
        NirOp::Call { target: None }
        | NirOp::NoReturnCall { target: None }
        | NirOp::TailCall { target: None }
        | NirOp::IndirectCall => native_indirect_call_def_use(instr),
        NirOp::Call { .. }
        | NirOp::NoReturnCall { .. }
        | NirOp::TailCall { .. }
        | NirOp::ExternCall { .. } => call_def_use(instr),
        NirOp::Return => DefUse {
            defs: Vec::new(),
            uses: register_use(instr.operands.first())
                .into_iter()
                .chain(std::iter::once(ValueId::register(RETURN_REGISTER)))
                .collect(),
        },
        NirOp::Branch { .. } | NirOp::CondBranch { .. } => DefUse {
            defs: Vec::new(),
            uses: instr
                .operands
                .first()
                .and_then(|value: &String| native_value(value))
                .into_iter()
                .collect(),
        },
        NirOp::RawLoad { addr, .. } => DefUse {
            defs: instr
                .operands
                .first()
                .map(|value: &String| ValueId::register(value))
                .into_iter()
                .collect(),
            uses: native_value(addr)
                .into_iter()
                .chain(std::iter::once(ValueId::memory(addr)))
                .collect(),
        },
        NirOp::RawStore { addr, value, .. } => DefUse {
            defs: vec![ValueId::memory(addr)],
            uses: native_value(addr)
                .into_iter()
                .chain(native_value(value))
                .collect(),
        },
        NirOp::Subpiece { src, .. } => DefUse {
            defs: instr
                .operands
                .first()
                .map(|value: &String| ValueId::register(value))
                .into_iter()
                .collect(),
            uses: native_value(src).into_iter().collect(),
        },
        NirOp::Deposit {
            cell,
            value,
            zero_upper,
            ..
        } => {
            let mut uses: Vec<ValueId> = Vec::new();
            if !zero_upper {
                uses.push(ValueId::register(cell));
            }
            let input: Option<ValueId> = native_value(value);
            if let Some(input) = input {
                uses.push(input);
            }
            DefUse {
                defs: vec![ValueId::register(cell)],
                uses,
            }
        }
        NirOp::CallOther { effect } => callother_def_use(effect),
        NirOp::Copy { src, .. } => DefUse {
            defs: instr
                .operands
                .first()
                .map(|value: &String| ValueId::register(value))
                .into_iter()
                .collect(),
            uses: native_value(src).into_iter().collect(),
        },
        NirOp::Value { inputs, .. } => DefUse {
            defs: instr
                .operands
                .first()
                .map(|value: &String| ValueId::register(value))
                .into_iter()
                .collect(),
            uses: inputs
                .iter()
                .filter_map(|value: &String| native_value(value))
                .collect(),
        },
        NirOp::Piece { high, low, .. } => DefUse {
            defs: instr
                .operands
                .first()
                .map(|value: &String| ValueId::register(value))
                .into_iter()
                .collect(),
            uses: native_value(high)
                .into_iter()
                .chain(native_value(low))
                .collect(),
        },
        NirOp::BinOp { .. } | NirOp::Load | NirOp::Store | NirOp::Const => operand_def_use(instr),
        NirOp::Nop | NirOp::Phi | NirOp::Interrupt | NirOp::Unmodeled { .. } => DefUse::default(),
    }
}

fn native_value(value: &str) -> Option<ValueId> {
    if is_immediate(value) {
        None
    } else {
        Some(ValueId::register(value))
    }
}

fn callother_def_use(effect: &CallOtherEffect) -> DefUse {
    let mut defs: Vec<ValueId> = effect
        .writes
        .iter()
        .map(|value: &String| ValueId::register(value))
        .collect();
    let mut uses: Vec<ValueId> = effect
        .reads
        .iter()
        .filter_map(|value: &String| native_value(value))
        .collect();
    if effect.unknown_registers {
        defs.push(ValueId::register("*"));
        uses.push(ValueId::register("*"));
    }
    if effect.writes_memory {
        defs.push(ValueId::memory("*"));
    }
    if effect.reads_memory {
        uses.push(ValueId::memory("*"));
    }
    DefUse { defs, uses }
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

fn native_indirect_call_def_use(instr: &NirInstr) -> DefUse {
    DefUse {
        defs: vec![ValueId::register(RETURN_REGISTER)],
        uses: instr
            .operands
            .iter()
            .filter_map(|operand: &String| native_value(operand))
            .collect(),
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
    if let Some(hex) = body.strip_prefix("0x").or_else(|| body.strip_prefix("0X")) {
        return !hex.is_empty() && hex.bytes().all(|byte: u8| byte.is_ascii_hexdigit());
    }
    !body.is_empty() && body.bytes().all(|byte: u8| byte.is_ascii_digit())
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

    #[test]
    fn native_memory_alias_and_effect_ops_expose_exact_def_use() {
        let load: DefUse = def_use(&instr(
            NirOp::RawLoad {
                addr: "rax".to_owned(),
                size: 4,
            },
            "LOAD",
            &["t0"],
        ));
        assert_eq!(load.defs, vec![ValueId::register("t0")]);
        assert_eq!(
            load.uses,
            vec![ValueId::register("rax"), ValueId::memory("rax")]
        );

        let store: DefUse = def_use(&instr(
            NirOp::RawStore {
                addr: "rax".to_owned(),
                value: "t0".to_owned(),
                size: 4,
            },
            "STORE",
            &[],
        ));
        assert_eq!(store.defs, vec![ValueId::memory("rax")]);
        assert_eq!(
            store.uses,
            vec![ValueId::register("rax"), ValueId::register("t0")]
        );

        let deposit: DefUse = def_use(&instr(
            NirOp::Deposit {
                cell: "rax".to_owned(),
                value: "t0".to_owned(),
                offset: 0,
                size: 4,
                cell_size: 8,
                zero_upper: true,
            },
            "DEPOSIT",
            &[],
        ));
        assert_eq!(deposit.defs, vec![ValueId::register("rax")]);
        assert_eq!(deposit.uses, vec![ValueId::register("t0")]);

        let effect: CallOtherEffect = CallOtherEffect {
            name: "x86_probe_reads_writes_mem_v1".to_owned(),
            reads: vec!["rax".to_owned()],
            writes: vec!["rdx".to_owned()],
            reads_memory: true,
            writes_memory: true,
            unknown_registers: false,
        };
        let callother: DefUse = def_use(&instr(NirOp::CallOther { effect }, "CALLOTHER", &[]));
        assert_eq!(
            callother.defs,
            vec![ValueId::register("rdx"), ValueId::memory("*")]
        );
        assert_eq!(
            callother.uses,
            vec![ValueId::register("rax"), ValueId::memory("*")]
        );

        let flags: DefUse = def_use(&instr(
            NirOp::Value {
                op: crate::types::ValueOp::BoolOr,
                inputs: vec!["cf".to_owned(), "af".to_owned()],
                input_sizes: vec![1, 1],
                size: 1,
            },
            "BOOL_OR",
            &["t0"],
        ));
        assert_eq!(
            flags.uses,
            vec![ValueId::register("cf"), ValueId::register("af")]
        );
    }
}
