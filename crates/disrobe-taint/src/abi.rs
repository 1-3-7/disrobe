use disrobe_nir::{DefUse, NirInstr, NirModule, SourceLang, ValueId};

const X86_ARGUMENT_REGISTERS: [&str; 6] = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"];
const X86_RETURN_REGISTER: &str = "rax";

const AARCH64_ARGUMENT_REGISTERS: [&str; 8] = ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"];
const AARCH64_RETURN_REGISTER: &str = "x0";

const AARCH64_HIGHEST_NUMBERED_REGISTER: u8 = 30;

const STACK_POINTER_IS_IN_BOTH_REGISTER_FILES: &str = "sp";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum CallAbi {
    #[default]
    X86,
    Aarch64,
}

impl CallAbi {
    #[must_use]
    pub(crate) fn detect(module: &NirModule) -> Self {
        let mut x86_evidence: usize = 0;
        let mut aarch64_evidence: usize = 0;
        for function in &module.functions {
            for instr in &function.instructions {
                if instr.source.lang == SourceLang::NativeArm {
                    return Self::Aarch64;
                }
                for operand in &instr.operands {
                    match voting_family(operand) {
                        Some(Self::X86) => x86_evidence = x86_evidence.saturating_add(1),
                        Some(Self::Aarch64) => {
                            aarch64_evidence = aarch64_evidence.saturating_add(1);
                        }
                        None => {}
                    }
                }
            }
        }
        if aarch64_evidence > x86_evidence {
            Self::Aarch64
        } else {
            Self::X86
        }
    }

    pub(crate) const fn argument_registers(self) -> &'static [&'static str] {
        match self {
            Self::X86 => &X86_ARGUMENT_REGISTERS,
            Self::Aarch64 => &AARCH64_ARGUMENT_REGISTERS,
        }
    }

    pub(crate) const fn return_register(self) -> &'static str {
        match self {
            Self::X86 => X86_RETURN_REGISTER,
            Self::Aarch64 => AARCH64_RETURN_REGISTER,
        }
    }

    #[must_use]
    pub(crate) fn canonical_register(self, operand: &str) -> Option<String> {
        let name: String = operand.trim().to_ascii_lowercase();
        match self {
            Self::X86 => is_x86_register(&name).then_some(name),
            Self::Aarch64 => canonical_aarch64(&name),
        }
    }

    pub(crate) fn register_value(self, operand: &str) -> Option<ValueId> {
        self.canonical_register(operand)
            .map(|name: String| ValueId::register(&name))
    }

    pub(crate) fn normalize_def_use(self, defuse: DefUse) -> DefUse {
        DefUse {
            defs: defuse
                .defs
                .into_iter()
                .map(|value: ValueId| self.normalize_value(value))
                .collect(),
            uses: defuse
                .uses
                .into_iter()
                .map(|value: ValueId| self.normalize_value(value))
                .collect(),
        }
    }

    fn normalize_value(self, value: ValueId) -> ValueId {
        let ValueId::Register(name) = &value else {
            return value;
        };
        self.canonical_register(name)
            .map_or_else(|| value.clone(), |name: String| ValueId::register(&name))
    }

    pub(crate) fn register_move(self, instr: &NirInstr) -> Option<DefUse> {
        if !is_native(instr.source.lang)
            || !instr.mnemonic.eq_ignore_ascii_case("mov")
            || instr.operands.len() != 2
        {
            return None;
        }
        let destination: ValueId = self.register_value(instr.operands.first()?)?;
        let source: Option<ValueId> = instr
            .operands
            .get(1)
            .and_then(|operand: &String| self.register_value(operand));
        Some(DefUse {
            defs: vec![destination],
            uses: source.into_iter().collect(),
        })
    }
}

pub(crate) const fn is_native(lang: SourceLang) -> bool {
    matches!(lang, SourceLang::NativeX86 | SourceLang::NativeArm)
}

fn voting_family(operand: &str) -> Option<CallAbi> {
    let name: String = operand.trim().to_ascii_lowercase();
    if name.is_empty() || name == STACK_POINTER_IS_IN_BOTH_REGISTER_FILES {
        return None;
    }
    if is_x86_register(&name) {
        return Some(CallAbi::X86);
    }
    canonical_aarch64(&name).map(|_| CallAbi::Aarch64)
}

fn canonical_aarch64(name: &str) -> Option<String> {
    if matches!(name, "sp" | "wsp") {
        return Some(STACK_POINTER_IS_IN_BOTH_REGISTER_FILES.to_owned());
    }
    if matches!(name, "xzr" | "wzr") {
        return Some("xzr".to_owned());
    }
    if name == "lr" {
        return Some("x30".to_owned());
    }
    if name == "fp" {
        return Some("x29".to_owned());
    }
    numbered_aarch64_register(name).map(|number: u8| format!("x{number}"))
}

fn numbered_aarch64_register(name: &str) -> Option<u8> {
    let digits: &str = name
        .strip_prefix('x')
        .or_else(|| name.strip_prefix('w'))
        .filter(|digits: &&str| {
            !digits.is_empty() && digits.bytes().all(|byte: u8| byte.is_ascii_digit())
        })?;
    digits
        .parse::<u8>()
        .ok()
        .filter(|number: &u8| *number <= AARCH64_HIGHEST_NUMBERED_REGISTER)
}

fn is_x86_register(name: &str) -> bool {
    matches!(
        name,
        "rax"
            | "eax"
            | "ax"
            | "al"
            | "ah"
            | "rbx"
            | "ebx"
            | "bx"
            | "bl"
            | "bh"
            | "rcx"
            | "ecx"
            | "cx"
            | "cl"
            | "ch"
            | "rdx"
            | "edx"
            | "dx"
            | "dl"
            | "dh"
            | "rsi"
            | "esi"
            | "si"
            | "sil"
            | "rdi"
            | "edi"
            | "di"
            | "dil"
            | "rbp"
            | "ebp"
            | "bp"
            | "bpl"
            | "rsp"
            | "esp"
            | "sp"
            | "spl"
            | "r8"
            | "r8d"
            | "r8w"
            | "r8b"
            | "r9"
            | "r9d"
            | "r9w"
            | "r9b"
            | "r10"
            | "r10d"
            | "r10w"
            | "r10b"
            | "r11"
            | "r11d"
            | "r11w"
            | "r11b"
            | "r12"
            | "r12d"
            | "r12w"
            | "r12b"
            | "r13"
            | "r13d"
            | "r13w"
            | "r13b"
            | "r14"
            | "r14d"
            | "r14w"
            | "r14b"
            | "r15"
            | "r15d"
            | "r15w"
            | "r15b"
    )
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use disrobe_nir::{NirFunction, NirOp, SourceRef};

    use super::*;

    fn instr(lang: SourceLang, mnemonic: &str, operands: &[&str]) -> NirInstr {
        NirInstr {
            address: 0,
            op: NirOp::Nop,
            mnemonic: mnemonic.to_owned(),
            operands: operands.iter().map(|o: &&str| (*o).to_owned()).collect(),
            reads_memory: false,
            writes_memory: false,
            byte_width: false,
            source: SourceRef::new(lang, 0),
        }
    }

    fn module_of(lang: SourceLang, instructions: Vec<NirInstr>) -> NirModule {
        NirModule {
            source_hash: [0u8; 32],
            lang,
            functions: vec![NirFunction {
                name: "f".to_owned(),
                address: 0,
                end: 4,
                is_export: false,
                instructions,
                source: SourceRef::new(lang, 0),
            }],
            symbols: Vec::new(),
        }
    }

    #[test]
    fn aarch64_subregisters_and_aliases_collapse_onto_one_location() {
        let abi: CallAbi = CallAbi::Aarch64;
        assert_eq!(abi.canonical_register("w0").as_deref(), Some("x0"));
        assert_eq!(abi.canonical_register("X0").as_deref(), Some("x0"));
        assert_eq!(abi.canonical_register("lr").as_deref(), Some("x30"));
        assert_eq!(abi.canonical_register("fp").as_deref(), Some("x29"));
        assert_eq!(abi.canonical_register("wzr").as_deref(), Some("xzr"));
        assert_eq!(abi.canonical_register("x31"), None);
        assert_eq!(abi.canonical_register("x"), None);
        assert_eq!(abi.canonical_register("[x8, #0x10]"), None);
    }

    #[test]
    fn the_x86_register_file_still_folds_subregisters_onto_the_full_register() {
        let abi: CallAbi = CallAbi::X86;
        assert_eq!(
            abi.register_value("eax"),
            Some(ValueId::register("rax")),
            "the nir register canonicalizer already folds x86 subregisters"
        );
        assert_eq!(abi.register_value("sp"), Some(ValueId::register("rsp")));
        assert_eq!(abi.register_value("x0"), None);
    }

    #[test]
    fn an_arm_tagged_instruction_selects_the_aarch64_register_file() {
        let module: NirModule = module_of(
            SourceLang::NativeArm,
            vec![instr(SourceLang::NativeArm, "mov", &["x0", "sp"])],
        );
        assert_eq!(CallAbi::detect(&module), CallAbi::Aarch64);
        assert_eq!(CallAbi::detect(&module).return_register(), "x0");
    }

    #[test]
    fn an_x86_tagged_module_carrying_aarch64_operands_still_selects_aarch64() {
        let module: NirModule = module_of(
            SourceLang::NativeX86,
            vec![
                instr(SourceLang::NativeX86, "mov", &["x0", "sp"]),
                instr(SourceLang::NativeX86, "mov", &["w1", "#0x40"]),
                instr(SourceLang::NativeX86, "ldr", &["x8", "[x8, #0x4e0]"]),
            ],
        );
        assert_eq!(
            CallAbi::detect(&module),
            CallAbi::Aarch64,
            "the native disasm lift tags every architecture as native-x86, so the register file has to come from the operands"
        );
    }

    #[test]
    fn a_lone_stack_pointer_operand_does_not_decide_the_register_file() {
        let module: NirModule = module_of(
            SourceLang::NativeX86,
            vec![instr(SourceLang::NativeX86, "sub", &["sp", "sp"])],
        );
        assert_eq!(
            CallAbi::detect(&module),
            CallAbi::X86,
            "sp names a register in both files, so it must not cast a vote"
        );
    }

    #[test]
    fn an_x86_module_keeps_the_x86_register_file() {
        let module: NirModule = module_of(
            SourceLang::NativeX86,
            vec![
                instr(SourceLang::NativeX86, "mov", &["rdi", "rax"]),
                instr(SourceLang::NativeX86, "xor", &["eax", "eax"]),
            ],
        );
        assert_eq!(CallAbi::detect(&module), CallAbi::X86);
        assert_eq!(CallAbi::detect(&module).return_register(), "rax");
        assert_eq!(CallAbi::detect(&module).argument_registers().len(), 6);
    }

    #[test]
    fn an_operandless_module_keeps_the_x86_default() {
        let module: NirModule =
            module_of(SourceLang::Wasm, vec![instr(SourceLang::Wasm, "call", &[])]);
        assert_eq!(CallAbi::detect(&module), CallAbi::X86);
    }

    #[test]
    fn an_aarch64_register_move_is_recognized_on_an_x86_tagged_instruction() {
        let mov: NirInstr = instr(SourceLang::NativeX86, "mov", &["x0", "x1"]);
        let defuse: DefUse = CallAbi::Aarch64
            .register_move(&mov)
            .expect("aarch64 mov is a register move");
        assert_eq!(defuse.defs, vec![ValueId::register("x0")]);
        assert_eq!(defuse.uses, vec![ValueId::register("x1")]);
    }

    #[test]
    fn a_non_native_move_is_not_treated_as_a_register_move() {
        let mov: NirInstr = instr(SourceLang::Wasm, "mov", &["x0", "x1"]);
        assert!(CallAbi::Aarch64.register_move(&mov).is_none());
    }
}
