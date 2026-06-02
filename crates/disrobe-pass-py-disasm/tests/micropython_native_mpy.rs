#![allow(clippy::expect_used, clippy::unwrap_used)]

use disrobe_pass_py_disasm::alt_runtimes::micropython_native::{
    MicroPythonNativeModule, NativeArch, NativeKind, detect, parse,
};

const MPY_MAGIC: u8 = b'M';
const NATIVE_FLAG: u8 = 0x02;
const VIPER_FLAG: u8 = 0x03;

fn header(version: u8, flag: u8, arch_id: u8) -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::with_capacity(8);
    bytes.push(MPY_MAGIC);
    bytes.push(version);
    bytes.push(flag | (arch_id << 2));
    bytes.push(31);
    if version >= 5 {
        bytes.extend_from_slice(&[4u8, 0u8]);
    }
    bytes
}

#[test]
fn parses_native_x64_v6() {
    let mut bytes: Vec<u8> = header(6, NATIVE_FLAG, 2);
    bytes.extend_from_slice(&[0x55, 0x48, 0x89, 0xE5, 0xC3]);
    let module: MicroPythonNativeModule = parse(&bytes).expect("parse");
    assert_eq!(module.kind, NativeKind::Native);
    assert_eq!(module.arch, NativeArch::X64);
    assert_eq!(module.native_code.len(), 5);
}

#[test]
fn parses_viper_armv7em_v4() {
    let mut bytes: Vec<u8> = header(4, VIPER_FLAG, 5);
    bytes.extend_from_slice(&[0x70, 0x47]);
    let module: MicroPythonNativeModule = parse(&bytes).expect("parse");
    assert_eq!(module.kind, NativeKind::Viper);
    assert_eq!(module.arch, NativeArch::Armv7em);
}

#[test]
fn detect_accepts_native_v3_through_v6() {
    for v in 3u8..=6u8 {
        let bytes: Vec<u8> = header(v, NATIVE_FLAG, 1);
        assert!(detect(&bytes), "should detect native v{v}");
    }
}

#[test]
fn detect_rejects_pure_bytecode() {
    let bytes: Vec<u8> = header(6, 0x00, 0);
    assert!(!detect(&bytes));
}

#[test]
#[ignore = "requires the uncommitted corpus/python/alt_runtimes/micropython/hello.native.mpy fixture; run with --ignored once present"]
fn parses_real_baked_native_fixture() {
    const FIXTURE: &str = "../../corpus/python/alt_runtimes/micropython/hello.native.mpy";
    let path: std::path::PathBuf = std::env::current_dir().expect("cwd").join(FIXTURE);
    assert!(
        path.exists(),
        "missing micropython native fixture: {}",
        path.display()
    );
    let bytes: Vec<u8> = std::fs::read(&path).expect("read");
    let result: Result<MicroPythonNativeModule, _> =
        disrobe_pass_py_disasm::alt_runtimes::micropython_native::parse(&bytes);
    if let Ok(module) = result {
        assert!(matches!(
            module.kind,
            NativeKind::Native | NativeKind::Viper
        ));
        assert!(!module.native_code.is_empty());
    } else {
        use disrobe_pass_py_disasm::alt_runtimes::micropython::parse as parse_bytecode;
        let bytecode: disrobe_pass_py_disasm::alt_runtimes::micropython::MicroPythonModule =
            parse_bytecode(&bytes)
                .expect("toplevel header bytecode-flagged for module-level native");
        assert_eq!(bytecode.version.raw(), 6);
        assert!(!bytecode.raw_code.is_empty());
    }
}

#[test]
fn all_arch_ids_decode_to_known_or_unknown() {
    for arch_id in 0u8..=15u8 {
        let mut bytes: Vec<u8> = header(6, NATIVE_FLAG, arch_id);
        bytes.extend_from_slice(&[0u8]);
        let result: Result<MicroPythonNativeModule, _> = parse(&bytes);
        if arch_id == 0 || arch_id > 7 {
            assert!(matches!(
                result.expect("parse").arch,
                NativeArch::Unknown | NativeArch::X86
            ));
        } else {
            assert!(result.is_ok());
        }
    }
}
