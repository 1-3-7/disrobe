#![allow(clippy::expect_used, clippy::unwrap_used)]
use disrobe_pass_py_disasm::alt_runtimes::micropython_native::{
    CodeKind, MicroPythonNativeModule, NativeArch, count_functions, detect, parse,
    total_instructions,
};

const X64_FIXTURE: &[u8] =
    include_bytes!("../../../corpus/python/alt_runtimes/micropython/hello_native_x64.mpy");
const ARMV7M_FIXTURE: &[u8] =
    include_bytes!("../../../corpus/python/alt_runtimes/micropython/hello_native_armv7m.mpy");

#[test]
fn detect_real_x64_and_armv7m_native_mpy() {
    assert!(detect(X64_FIXTURE), "x64 native mpy must detect");
    assert!(detect(ARMV7M_FIXTURE), "armv7m native mpy must detect");
}

#[test]
fn parses_real_x64_native_mpy_header_and_qstrs() {
    let module: MicroPythonNativeModule = parse(X64_FIXTURE).expect("parse x64");
    assert_eq!(module.version, 6);
    assert_eq!(module.arch, NativeArch::X64);
    assert_eq!(module.small_int_bits, 31);
    assert!(
        module.qstrs.iter().any(|q: &String| q == "add"),
        "qstr table should carry the function name `add`: {:?}",
        module.qstrs
    );
    assert!(module.qstrs.iter().any(|q: &String| q == "mul"));
}

#[test]
fn x64_native_module_has_three_functions_native_and_viper() {
    let module: MicroPythonNativeModule = parse(X64_FIXTURE).expect("parse x64");
    assert_eq!(
        count_functions(&module.function),
        3,
        "module + add(native) + mul(viper)"
    );
    assert_eq!(module.function.kind, CodeKind::NativePy);
    let kinds: Vec<CodeKind> = module
        .function
        .children
        .iter()
        .map(|c| c.kind)
        .collect::<Vec<CodeKind>>();
    assert!(kinds.contains(&CodeKind::NativePy), "add is native-py");
    assert!(kinds.contains(&CodeKind::NativeViper), "mul is viper");
}

#[test]
fn x64_machine_code_disassembles_to_real_x86_prologue() {
    let module: MicroPythonNativeModule = parse(X64_FIXTURE).expect("parse x64");
    let add_fn = module
        .function
        .children
        .iter()
        .find(|c| c.kind == CodeKind::NativePy)
        .expect("native-py child");
    assert!(
        add_fn.disasm_note.is_none(),
        "x64 must disassemble cleanly: {:?}",
        add_fn.disasm_note
    );
    assert!(
        !add_fn.disassembly.is_empty(),
        "add() machine code must decode to instructions"
    );
    let mnemonics: Vec<&str> = add_fn
        .disassembly
        .iter()
        .map(|i| i.mnemonic.as_str())
        .collect::<Vec<&str>>();
    assert!(
        mnemonics.contains(&"push"),
        "x86-64 native prologue must contain push; got {mnemonics:?}"
    );
    assert!(
        mnemonics.contains(&"ret"),
        "function body must contain a ret; got first 12: {:?}",
        &mnemonics[..mnemonics.len().min(12)]
    );
}

#[test]
fn armv7m_machine_code_disassembles_as_thumb() {
    let module: MicroPythonNativeModule = parse(ARMV7M_FIXTURE).expect("parse armv7m");
    assert_eq!(module.arch, NativeArch::Armv7m);
    let total: usize = total_instructions(&module.function);
    assert!(
        total > 0,
        "armv7m thumb code must decode to at least one instruction"
    );
    let add_fn = module
        .function
        .children
        .iter()
        .find(|c| c.kind == CodeKind::NativePy)
        .expect("native-py child");
    assert!(
        !add_fn.disassembly.is_empty(),
        "armv7m add() must decode to thumb instructions"
    );
    let mnemonics: Vec<&str> = add_fn
        .disassembly
        .iter()
        .map(|i| i.mnemonic.as_str())
        .collect::<Vec<&str>>();
    assert!(
        mnemonics.iter().any(|m: &&str| m.starts_with("push")),
        "armv7m thumb prologue must contain push; got {mnemonics:?}"
    );
}

#[test]
fn x64_viper_child_machine_code_disassembles() {
    let module: MicroPythonNativeModule = parse(X64_FIXTURE).expect("parse x64");
    let viper_fn = module
        .function
        .children
        .iter()
        .find(|c| c.kind == CodeKind::NativeViper)
        .expect("viper child (mul)");
    assert!(
        !viper_fn.machine_code.is_empty(),
        "viper function must carry extracted machine code"
    );
    assert!(
        viper_fn.disasm_note.is_none(),
        "x64 viper machine code must disassemble cleanly, not wall: {:?}",
        viper_fn.disasm_note
    );
    assert!(
        !viper_fn.disassembly.is_empty(),
        "viper machine code must disassemble to real x86-64 instructions, not just be extracted"
    );
    let mnemonics: Vec<&str> = viper_fn
        .disassembly
        .iter()
        .map(|i| i.mnemonic.as_str())
        .collect::<Vec<&str>>();
    assert!(
        mnemonics
            .iter()
            .any(|m: &&str| *m == "ret" || *m == "imul" || *m == "mov"),
        "viper mul() must decode to real x86-64 mnemonics; got {mnemonics:?}"
    );
}

#[test]
fn armv7m_viper_child_machine_code_disassembles() {
    let module: MicroPythonNativeModule = parse(ARMV7M_FIXTURE).expect("parse armv7m");
    let viper_fn = module
        .function
        .children
        .iter()
        .find(|c| c.kind == CodeKind::NativeViper)
        .expect("viper child (mul)");
    assert!(!viper_fn.machine_code.is_empty());
    assert!(
        !viper_fn.disassembly.is_empty(),
        "armv7m viper machine code must decode to thumb instructions"
    );
}

#[test]
fn machine_code_excludes_python_prelude_tail() {
    let module: MicroPythonNativeModule = parse(X64_FIXTURE).expect("parse x64");
    assert!(
        module.function.prelude_offset > 0,
        "native-py module must record a prelude offset"
    );
    assert_eq!(
        module.function.machine_code.len(),
        module.function.prelude_offset,
        "machine code region is fun_data[..prelude_offset]"
    );
}

#[test]
fn detect_rejects_pure_bytecode_mpy() {
    let bytecode: [u8; 6] = [MPY_MAGIC_BYTE, 6, 0x00, 31, 6, 0];
    assert!(
        !detect(&bytecode),
        "arch=0 is portable bytecode, not native"
    );
}

const MPY_MAGIC_BYTE: u8 = b'M';
