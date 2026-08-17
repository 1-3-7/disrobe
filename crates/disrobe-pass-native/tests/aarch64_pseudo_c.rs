#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

#[path = "support/object_symbol.rs"]
#[allow(clippy::redundant_pub_crate)]
mod object_symbol;

use disrobe_pass_native::{
    Error, LeafRecovery, PseudoAbi, PseudoReg, ResolvedCall, recover_aarch64_function,
    recover_aarch64_function_with_calls, recover_leaf_function_abi,
    recover_leaf_function_in_object,
};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

use disrobe_core::subprocess::{CapturedOutput, run_captured};

fn find_program(name: &str) -> Option<PathBuf> {
    let path: OsString = std::env::var_os("PATH")?;
    let names: Vec<String> = if cfg!(windows) {
        vec![format!("{name}.exe"), name.to_owned()]
    } else {
        vec![name.to_owned()]
    };
    std::env::split_paths(&path)
        .flat_map(|directory: PathBuf| names.iter().map(move |name: &String| directory.join(name)))
        .find(|candidate: &PathBuf| candidate.is_file())
}

fn run_tool(program: &Path, args: Vec<OsString>) -> CapturedOutput {
    let output: CapturedOutput = run_captured(program, &args, Duration::from_secs(30), 1 << 20)
        .expect("spawn aarch64 ground-truth tool")
        .expect("aarch64 ground-truth tool timeout");
    assert_eq!(
        output.exit_code,
        Some(0),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn compiled_crc32_fixture() -> Vec<u8> {
    let clang: PathBuf = find_program("clang").expect("clang is required for the crc32 fixture");
    let fixture: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("aarch64_crc.c");
    let scratch: tempfile::TempDir = tempfile::tempdir().expect("create crc32 fixture scratch");
    let object_path: PathBuf = scratch.path().join("aarch64_crc.o");
    run_tool(
        &clang,
        vec![
            "--target=aarch64-none-elf".into(),
            "-march=armv8-a+crc".into(),
            "-O2".into(),
            "-ffreestanding".into(),
            "-c".into(),
            fixture.as_os_str().to_owned(),
            "-o".into(),
            object_path.as_os_str().to_owned(),
        ],
    );
    std::fs::read(object_path).expect("read crc32 fixture object")
}

fn assert_crc_execution(
    recovered: &LeafRecovery,
    name: &str,
    c_call: &str,
    rust_call: &str,
    expected: u64,
    compiler: &Path,
    rustc: &Path,
    scratch: &Path,
) {
    let c_source: PathBuf = scratch.join(format!("crc32_width_{name}.c"));
    let c_exe: PathBuf = scratch.join(format!("crc32_width_{name}.exe"));
    let c_driver: String = format!(
        "{}\nint main(void) {{ return {c_call} == 0x{expected:016x}ULL ? 0 : 1; }}\n",
        recovered.source
    );
    std::fs::write(&c_source, c_driver).expect("write crc32 width C grade");
    run_tool(
        compiler,
        vec![
            "-O2".into(),
            c_source.as_os_str().to_owned(),
            "-o".into(),
            c_exe.as_os_str().to_owned(),
        ],
    );
    let no_args: [OsString; 0] = [];
    let c_result: CapturedOutput = run_captured(&c_exe, &no_args, Duration::from_secs(30), 1 << 20)
        .expect("spawn crc32 width C grade")
        .expect("crc32 width C grade timeout");
    assert_eq!(c_result.exit_code, Some(0), "{name}: {}", recovered.source);

    let rust_source: PathBuf = scratch.join(format!("crc32_width_{name}.rs"));
    let rust_exe: PathBuf = scratch.join(format!("crc32_width_{name}_rust.exe"));
    let rust_driver: String = format!(
        "{}\nfn main() {{ assert_eq!({rust_call}, 0x{expected:016x}u64); }}\n",
        recovered
            .rust_source
            .as_deref()
            .unwrap_or_else(|| panic!("{name} produced no pseudo-rust"))
    );
    std::fs::write(&rust_source, rust_driver).expect("write crc32 width Rust grade");
    run_tool(
        rustc,
        vec![
            "-O".into(),
            rust_source.as_os_str().to_owned(),
            "-o".into(),
            rust_exe.as_os_str().to_owned(),
        ],
    );
    let rust_result: CapturedOutput =
        run_captured(&rust_exe, &no_args, Duration::from_secs(30), 1 << 20)
            .expect("spawn crc32 width Rust grade")
            .expect("crc32 width Rust grade timeout");
    assert_eq!(rust_result.exit_code, Some(0), "{name}");
}

#[test]
fn clang_o2_integer_add_lifts_through_shared_ir() {
    let bytes: [u8; 12] = [
        0x28, 0x00, 0x00, 0x8b, 0x00, 0x01, 0x02, 0x8b, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let recovered: LeafRecovery = recover_aarch64_function(&bytes, 0).expect("aarch64 add");
    assert_eq!(
        recovered.signature.observed_integer_registers(),
        vec![PseudoReg::Rax, PseudoReg::A64X1, PseudoReg::A64X2]
    );
    assert!(recovered.source.contains("r_rax = r_a64_tmp"));
    assert!(recovered.source.contains("r_a64_x1"));
    assert!(recovered.source.contains("r_a64_x2"));
    assert!(recovered.rust_source.is_some());
}

#[test]
fn clang_o2_shifted_integer_alu_lifts() {
    let bytes: [u8; 28] = [
        0x48, 0xfc, 0x43, 0x93, 0x29, 0x00, 0x00, 0x8a, 0x4a, 0x00, 0x01, 0xca, 0x49, 0x01, 0x09,
        0xaa, 0x08, 0x09, 0x80, 0x8b, 0x00, 0x0d, 0x09, 0x8b, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let recovered: LeafRecovery = recover_aarch64_function(&bytes, 0).expect("aarch64 alu");
    assert_eq!(recovered.signature.observed_integer_registers().len(), 3);
    assert!(recovered.source.contains(" & "));
    assert!(recovered.source.contains(" | "));
    assert!(recovered.source.contains(" ^ "));
    assert!(recovered.source.contains(" >> "), "{}", recovered.source);
    assert!(recovered.source.contains(" << "), "{}", recovered.source);
}

#[test]
fn clang_o2_madd_and_msub_lift() {
    let madd: [u8; 8] = [0x20, 0x08, 0x00, 0x9b, 0xc0, 0x03, 0x5f, 0xd6];
    let msub: [u8; 8] = [0x20, 0x88, 0x00, 0x9b, 0xc0, 0x03, 0x5f, 0xd6];
    let added: LeafRecovery = recover_aarch64_function(&madd, 0).expect("aarch64 madd");
    let subtracted: LeafRecovery = recover_aarch64_function(&msub, 0).expect("aarch64 msub");
    assert!(added.source.contains(" * ") && added.source.contains(" + "));
    assert!(subtracted.source.contains(" * ") && subtracted.source.contains(" - "));
    assert_eq!(added.signature.observed_integer_registers().len(), 3);
    assert_eq!(subtracted.signature.observed_integer_registers().len(), 3);
}

#[test]
fn clang_crc32_intrinsics_lift_every_scalar_form() {
    let object_bytes: Vec<u8> = compiled_crc32_fixture();
    let cases: [(&str, &str); 8] = [
        ("crc_ieee_b", "disrobe_crc32_ieee"),
        ("crc_ieee_h", "disrobe_crc32_ieee"),
        ("crc_ieee_w", "disrobe_crc32_ieee"),
        ("crc_ieee_x", "disrobe_crc32_ieee"),
        ("crc_castagnoli_b", "disrobe_crc32_castagnoli"),
        ("crc_castagnoli_h", "disrobe_crc32_castagnoli"),
        ("crc_castagnoli_w", "disrobe_crc32_castagnoli"),
        ("crc_castagnoli_x", "disrobe_crc32_castagnoli"),
    ];
    for (symbol, helper) in cases {
        let (bytes, address): (Vec<u8>, u64) = object_symbol::function_code(&object_bytes, symbol)
            .unwrap_or_else(|| panic!("crc32 fixture lacks {symbol}"));
        let recovered: LeafRecovery = recover_aarch64_function(&bytes, address)
            .unwrap_or_else(|error: Error| panic!("{symbol} rejected: {error:?}"));
        assert!(
            recovered.source.contains(helper),
            "{symbol}: {}",
            recovered.source
        );
        let rust: &str = recovered
            .rust_source
            .as_deref()
            .unwrap_or_else(|| panic!("{symbol} produced no pseudo-rust"));
        assert!(rust.contains(helper), "{symbol}: {rust}");
        assert_eq!(
            recovered.signature.observed_integer_registers(),
            vec![PseudoReg::Rax, PseudoReg::A64X1],
            "{symbol}"
        );
    }
}

#[test]
fn crc32_zero_register_operands_recover_without_aliasing_state() {
    let cases: [[u8; 8]; 3] = [
        [0x1f, 0x4c, 0xc1, 0x9a, 0xc0, 0x03, 0x5f, 0xd6],
        [0xe0, 0x4f, 0xc1, 0x9a, 0xc0, 0x03, 0x5f, 0xd6],
        [0x00, 0x4c, 0xdf, 0x9a, 0xc0, 0x03, 0x5f, 0xd6],
    ];
    for bytes in cases {
        let recovered: LeafRecovery = recover_aarch64_function(&bytes, 0)
            .unwrap_or_else(|error: Error| panic!("crc32 zero register rejected: {error:?}"));
        assert!(recovered.source.contains("disrobe_crc32_ieee"));
        assert!(
            recovered
                .rust_source
                .as_deref()
                .is_some_and(|source: &str| source.contains("disrobe_crc32_ieee"))
        );
    }
}

#[test]
fn crc32_width_and_zero_register_vectors_execute_in_c_and_rust() {
    let object_bytes: Vec<u8> = compiled_crc32_fixture();
    let compiler: PathBuf = find_program("cc")
        .or_else(|| find_program("clang"))
        .expect("a native C compiler is required for the crc32 execution grade");
    let rustup: PathBuf =
        find_program("rustup").expect("rustup is required for the crc32 execution grade");
    let rustc_output: CapturedOutput = run_tool(&rustup, vec!["which".into(), "rustc".into()]);
    assert_eq!(rustc_output.exit_code, Some(0), "resolve the Rust compiler");
    let rustc: PathBuf = PathBuf::from(String::from_utf8_lossy(&rustc_output.stdout).trim());
    assert!(rustc.is_file(), "resolved Rust compiler does not exist");
    let scratch: tempfile::TempDir = tempfile::tempdir().expect("create crc32 width scratch");
    let cases: [(&str, u64); 8] = [
        ("crc_ieee_b", 0x96ac_0dd4),
        ("crc_ieee_h", 0x49ff_eb40),
        ("crc_ieee_w", 0xa010_7153),
        ("crc_ieee_x", 0xd72a_f417),
        ("crc_castagnoli_b", 0x2a3c_90de),
        ("crc_castagnoli_h", 0xae59_5b5a),
        ("crc_castagnoli_w", 0x6b4e_fede),
        ("crc_castagnoli_x", 0x7242_bacb),
    ];
    for (symbol, expected) in cases {
        let (bytes, address): (Vec<u8>, u64) = object_symbol::function_code(&object_bytes, symbol)
            .unwrap_or_else(|| panic!("crc32 fixture lacks {symbol}"));
        let recovered: LeafRecovery = recover_aarch64_function(&bytes, address)
            .unwrap_or_else(|error: Error| panic!("{symbol} rejected: {error:?}"));
        assert_crc_execution(
            &recovered,
            symbol,
            "recovered(0xa5a55a5aULL, 0xfedcba9876543210ULL)",
            "recovered(0xa5a55a5au64, 0xfedcba9876543210u64)",
            expected,
            &compiler,
            &rustc,
            scratch.path(),
        );
    }

    let zero_cases: [(&str, [u8; 8], &str, &str, u64); 3] = [
        (
            "destination_zero",
            [0x1f, 0x4c, 0xc1, 0x9a, 0xc0, 0x03, 0x5f, 0xd6],
            "recovered(0xa5a55a5aULL, 0xfedcba9876543210ULL)",
            "recovered(0xa5a55a5au64, 0xfedcba9876543210u64)",
            0xa5a5_5a5a,
        ),
        (
            "accumulator_zero",
            [0xe0, 0x4f, 0xc1, 0x9a, 0xc0, 0x03, 0x5f, 0xd6],
            "recovered(0xfedcba9876543210ULL)",
            "recovered(0xfedcba9876543210u64)",
            0x657f_3d5b,
        ),
        (
            "value_zero",
            [0x00, 0x4c, 0xdf, 0x9a, 0xc0, 0x03, 0x5f, 0xd6],
            "recovered(0xa5a55a5aULL)",
            "recovered(0xa5a55a5au64)",
            0xb255_c94c,
        ),
    ];
    for (name, bytes, c_call, rust_call, expected) in zero_cases {
        let recovered: LeafRecovery = recover_aarch64_function(&bytes, 0)
            .unwrap_or_else(|error: Error| panic!("{name} rejected: {error:?}"));
        assert_crc_execution(
            &recovered,
            name,
            c_call,
            rust_call,
            expected,
            &compiler,
            &rustc,
            scratch.path(),
        );
    }
}

#[test]
fn clang_crc32_check_vectors_execute_in_c_and_rust() {
    let object_bytes: Vec<u8> = compiled_crc32_fixture();
    let compiler: PathBuf = find_program("cc")
        .or_else(|| find_program("clang"))
        .expect("a native C compiler is required for the crc32 execution grade");
    let rustup: PathBuf =
        find_program("rustup").expect("rustup is required for the crc32 execution grade");
    let rustc_output: CapturedOutput = run_tool(&rustup, vec!["which".into(), "rustc".into()]);
    assert_eq!(rustc_output.exit_code, Some(0), "resolve the Rust compiler");
    let rustc: PathBuf = PathBuf::from(String::from_utf8_lossy(&rustc_output.stdout).trim());
    assert!(rustc.is_file(), "resolved Rust compiler does not exist");
    let scratch: tempfile::TempDir = tempfile::tempdir().expect("create crc32 scratch directory");
    let cases: [(&str, &str, u32); 2] = [
        ("ieee", "crc_ieee_check", 0x340b_c6d9),
        ("castagnoli", "crc_castagnoli_check", 0x1cf9_6d7c),
    ];
    for (name, symbol, expected) in cases {
        let (bytes, address): (Vec<u8>, u64) = object_symbol::function_code(&object_bytes, symbol)
            .unwrap_or_else(|| panic!("crc32 fixture lacks {symbol}"));
        let recovered: LeafRecovery = recover_aarch64_function(&bytes, address)
            .unwrap_or_else(|error: Error| panic!("{name} check rejected: {error:?}"));
        assert!(recovered.signature.observed_integer_registers().is_empty());
        let c_source: PathBuf = scratch.path().join(format!("crc32_{name}.c"));
        let c_exe: PathBuf = scratch.path().join(format!("crc32_{name}.exe"));
        let c_driver: String = format!(
            "{}\nint main(void) {{ return recovered() == 0x{expected:08x}u ? 0 : 1; }}\n",
            recovered.source
        );
        std::fs::write(&c_source, c_driver).expect("write crc32 C grade");
        run_tool(
            &compiler,
            vec![
                "-O2".into(),
                c_source.as_os_str().to_owned(),
                "-o".into(),
                c_exe.as_os_str().to_owned(),
            ],
        );
        let no_args: [OsString; 0] = [];
        let c_result: CapturedOutput =
            run_captured(&c_exe, &no_args, Duration::from_secs(30), 1 << 20)
                .expect("spawn crc32 C grade")
                .expect("crc32 C grade timeout");
        assert_eq!(c_result.exit_code, Some(0), "{name}: {}", recovered.source);

        let rust_source: PathBuf = scratch.path().join(format!("crc32_{name}.rs"));
        let rust_exe: PathBuf = scratch.path().join(format!("crc32_{name}_rust.exe"));
        let rust_driver: String = format!(
            "{}\nfn main() {{ assert_eq!(recovered(), 0x{expected:08x}u64); }}\n",
            recovered
                .rust_source
                .as_deref()
                .unwrap_or_else(|| panic!("{name} check produced no pseudo-rust"))
        );
        std::fs::write(&rust_source, rust_driver).expect("write crc32 Rust grade");
        run_tool(
            &rustc,
            vec![
                "-O".into(),
                rust_source.as_os_str().to_owned(),
                "-o".into(),
                rust_exe.as_os_str().to_owned(),
            ],
        );
        let rust_result: CapturedOutput =
            run_captured(&rust_exe, &no_args, Duration::from_secs(30), 1 << 20)
                .expect("spawn crc32 Rust grade")
                .expect("crc32 Rust grade timeout");
        assert_eq!(rust_result.exit_code, Some(0), "{name}");
    }
}

#[test]
fn clang_mov_wide_constant_materialization_lifts() {
    let wide: [u8; 20] = [
        0x00, 0xde, 0x9b, 0xd2, 0x80, 0x57, 0xb3, 0xf2, 0x00, 0xcf, 0xca, 0xf2, 0x80, 0x46, 0xe2,
        0xf2, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let inverted: [u8; 8] = [0x80, 0x46, 0x82, 0x92, 0xc0, 0x03, 0x5f, 0xd6];
    let zero: [u8; 8] = [0xe0, 0x03, 0x1f, 0xaa, 0xc0, 0x03, 0x5f, 0xd6];
    let recovered: LeafRecovery = recover_aarch64_function(&wide, 0).expect("mov wide");
    let recovered_inverted: LeafRecovery =
        recover_aarch64_function(&inverted, 0).expect("mov inverted");
    let recovered_zero: LeafRecovery = recover_aarch64_function(&zero, 0).expect("mov zero");
    assert!(recovered.signature.observed_integer_registers().is_empty());
    assert!(recovered.source.contains("57072"));
    assert!(recovered.source.matches(" | ").count() >= 3);
    assert!(recovered_inverted.source.contains("4661"));
    assert!(recovered_zero.source.contains("r_rax = 0"));
}

#[test]
fn clang_o0_spill_frame_lifts_stack_slots() {
    let bytes: [u8; 44] = [
        0xff, 0x83, 0x00, 0xd1, 0xe0, 0x0f, 0x00, 0xf9, 0xe1, 0x0b, 0x00, 0xf9, 0xe2, 0x07, 0x00,
        0xf9, 0xe8, 0x0f, 0x40, 0xf9, 0xe9, 0x0b, 0x40, 0xf9, 0x08, 0x01, 0x09, 0x8b, 0xe9, 0x07,
        0x40, 0xf9, 0x00, 0x01, 0x09, 0x8b, 0xff, 0x83, 0x00, 0x91, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let recovered: LeafRecovery = recover_aarch64_function(&bytes, 0).expect("aarch64 frame");
    assert_eq!(recovered.signature.observed_integer_registers().len(), 3);
    assert!(recovered.source.contains("stack_frame[32]"));
    assert!(recovered.source.contains("r_rsp"));
    assert!(
        recovered
            .source
            .contains("uint64_t recovered(uint64_t a0, uint64_t a1, uint64_t a2)")
    );
}

#[test]
fn clang_optimized_byte_stack_arguments_stay_outside_the_fixed_local_frame() {
    const AT_ALLOCATION: [u8; 28] = [
        0xff, 0x43, 0x00, 0xd1, 0xe0, 0x33, 0x00, 0x39, 0xe8, 0x43, 0x40, 0x39, 0xe9, 0x33, 0x40,
        0x39, 0x20, 0x01, 0x08, 0x4a, 0xff, 0x43, 0x00, 0x91, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    const ABOVE_ALLOCATION: [u8; 28] = [
        0xff, 0x43, 0x00, 0xd1, 0xe0, 0x33, 0x00, 0x39, 0xe8, 0x63, 0x40, 0x39, 0xe9, 0x33, 0x40,
        0x39, 0x20, 0x01, 0x08, 0x4a, 0xff, 0x43, 0x00, 0x91, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let cases: [(&str, &[u8], i64); 2] = [
        (
            "ninth byte argument at the entry stack pointer",
            &AT_ALLOCATION,
            16,
        ),
        (
            "tenth byte argument above the entry stack pointer",
            &ABOVE_ALLOCATION,
            24,
        ),
    ];
    let mut wrong_recoveries: Vec<String> = Vec::with_capacity(cases.len());
    let mut index: usize = 0;
    while index < cases.len() {
        let (name, bytes, displacement): (&str, &[u8], i64) = cases[index];
        let result: core::result::Result<LeafRecovery, Error> = recover_aarch64_function(bytes, 0);
        result.map_or_else(
            |error: Error| {
                let message: String = format!("{error:?}");
                assert!(
                    message.contains(&format!(
                        "1-byte slot at {displacement} is outside the [0, 16) bytes this frame owns"
                    )) && message.contains(
                        "the entry stack pointer sits at 16 and incoming stack arguments begin there"
                    ),
                    "{name} rejected for the wrong reason: {message}"
                );
            },
            |recovered: LeafRecovery| {
                wrong_recoveries.push(format!("{name}: {}", recovered.source));
            },
        );
        index += 1;
    }
    assert!(
        wrong_recoveries.is_empty(),
        "{} of {} incoming stack-argument reads recovered as fixed locals:\n{}",
        wrong_recoveries.len(),
        cases.len(),
        wrong_recoveries.join("\n")
    );
}

#[test]
fn an_aarch64_slot_whose_width_straddles_the_entry_stack_pointer_is_rejected() {
    const CODE: [u8; 16] = [
        0xff, 0x83, 0x00, 0xd1, 0xe0, 0xf3, 0x41, 0x78, 0xff, 0x83, 0x00, 0x91, 0xc0, 0x03, 0x5f,
        0xd6,
    ];
    let error: Error =
        recover_aarch64_function(&CODE, 0).expect_err("a straddling slot must reject");
    let message: String = format!("{error:?}");
    assert!(
        message.contains("stack access straddles the entry stack pointer"),
        "{message}"
    );
}

#[test]
fn a_negative_aarch64_sp_displacement_below_the_allocation_is_rejected() {
    const CODE: [u8; 16] = [
        0xff, 0x83, 0x00, 0xd1, 0xe0, 0xf3, 0x5f, 0x38, 0xff, 0x83, 0x00, 0x91, 0xc0, 0x03, 0x5f,
        0xd6,
    ];
    let error: Error =
        recover_aarch64_function(&CODE, 0).expect_err("a below-frame slot must reject");
    let message: String = format!("{error:?}");
    assert!(
        message.contains("stack access lands below the allocated frame"),
        "{message}"
    );
}

#[test]
fn clang_optimized_local_slots_below_the_entry_stack_pointer_still_recover() {
    const CODE: [u8; 32] = [
        0xff, 0x43, 0x00, 0xd1, 0x08, 0x04, 0x00, 0x91, 0xe0, 0x07, 0x00, 0xf9, 0xe8, 0x03, 0x00,
        0xf9, 0xe8, 0x07, 0x40, 0xf9, 0xe9, 0x07, 0x41, 0xf8, 0x20, 0x01, 0x08, 0x8b, 0xc0, 0x03,
        0x5f, 0xd6,
    ];
    let recovered: LeafRecovery =
        recover_aarch64_function(&CODE, 0).expect("allocated local slots must recover");
    assert!(
        recovered.source.contains("unsigned char stack_frame[16]"),
        "{}",
        recovered.source
    );
}

#[test]
fn a_pre_indexed_frame_record_allocation_bounds_sp_relative_slots() {
    const CODE: [u8; 24] = [
        0xfd, 0x7b, 0xbe, 0xa9, 0xfd, 0x03, 0x00, 0x91, 0xe0, 0x43, 0x00, 0x39, 0xe0, 0x83, 0x40,
        0x39, 0xfd, 0x7b, 0xc2, 0xa8, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let error: Error =
        recover_aarch64_function(&CODE, 0).expect_err("the entry stack pointer is not a local");
    let message: String = format!("{error:?}");
    assert!(
        message.contains("1-byte slot at 32 is outside the [0, 32) bytes this frame owns")
            && message.contains(
                "the entry stack pointer sits at 32 and incoming stack arguments begin there"
            ),
        "{message}"
    );
}

#[test]
fn a_pre_indexed_frame_record_stays_inside_the_allocation() {
    const CODE: [u8; 24] = [
        0xfd, 0x7b, 0xbe, 0xa9, 0xfd, 0x03, 0x00, 0x91, 0xe0, 0x43, 0x00, 0x39, 0xe0, 0x43, 0x40,
        0x39, 0xfd, 0x7b, 0xc2, 0xa8, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let recovered: LeafRecovery =
        recover_aarch64_function(&CODE, 0).expect("a local above the frame record must recover");
    assert!(
        recovered.source.contains("unsigned char stack_frame[17]"),
        "{}",
        recovered.source
    );
}

#[test]
fn an_x29_relative_local_uses_frame_pointer_coordinates() {
    const CODE: [u8; 32] = [
        0xff, 0x83, 0x00, 0xd1, 0xfd, 0x7b, 0x01, 0xa9, 0xfd, 0x43, 0x00, 0x91, 0xa0, 0x83, 0x1f,
        0xf8, 0xa0, 0x83, 0x5f, 0xf8, 0xfd, 0x7b, 0x41, 0xa9, 0xff, 0x83, 0x00, 0x91, 0xc0, 0x03,
        0x5f, 0xd6,
    ];
    let recovered: LeafRecovery =
        recover_aarch64_function(&CODE, 0).expect("an x29-relative local must recover");
    assert!(
        recovered.source.contains("unsigned char stack_frame[8]"),
        "{}",
        recovered.source
    );
}

#[test]
fn an_x29_relative_incoming_byte_argument_stays_outside_the_fixed_local_frame() {
    const CODE: [u8; 28] = [
        0xff, 0x83, 0x00, 0xd1, 0xfd, 0x7b, 0x01, 0xa9, 0xfd, 0x43, 0x00, 0x91, 0xa0, 0x43, 0x40,
        0x39, 0xfd, 0x7b, 0x41, 0xa9, 0xff, 0x83, 0x00, 0x91, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let error: Error =
        recover_aarch64_function(&CODE, 0).expect_err("the entry stack pointer is not a local");
    let message: String = format!("{error:?}");
    assert!(
        message.contains("1-byte slot at 16 is outside the [-16, 16) bytes this frame owns")
            && message.contains(
                "the entry stack pointer sits at 16 and incoming stack arguments begin there"
            ),
        "{message}"
    );
}

#[test]
fn an_x29_local_survives_a_later_shallower_sp_incoming_argument_load() {
    const CODE: [u8; 44] = [
        0xff, 0x83, 0x00, 0xd1, 0xfd, 0x7b, 0x01, 0xa9, 0xfd, 0x43, 0x00, 0x91, 0xa0, 0x83, 0x1f,
        0xf8, 0xa0, 0x83, 0x5f, 0xf8, 0xff, 0x43, 0x00, 0x91, 0xe1, 0x0b, 0x40, 0xf9, 0x00, 0x00,
        0x01, 0x8b, 0xfd, 0x7b, 0x40, 0xa9, 0xff, 0x43, 0x00, 0x91, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let recovered: LeafRecovery = recover_aarch64_function(&CODE, 0)
        .expect("the maximum allocation must bound x29 coordinates");
    assert!(
        recovered.source.contains("unsigned char stack_frame[8]"),
        "{}",
        recovered.source
    );
}

#[test]
fn clang_o2_pair_load_and_store_lift() {
    let load_pair: [u8; 12] = [
        0x08, 0x24, 0x40, 0xa9, 0x20, 0x01, 0x08, 0x8b, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let store_pair: [u8; 8] = [0x01, 0x08, 0x00, 0xa9, 0xc0, 0x03, 0x5f, 0xd6];
    let loaded: LeafRecovery = recover_aarch64_function(&load_pair, 0).expect("aarch64 ldp");
    let stored: LeafRecovery = recover_aarch64_function(&store_pair, 0).expect("aarch64 stp");
    assert_eq!(
        loaded.signature.observed_integer_registers(),
        vec![PseudoReg::Rax]
    );
    assert_eq!(loaded.source.matches("*(uint64_t*)").count(), 2);
    assert_eq!(stored.signature.observed_integer_registers().len(), 3);
    assert!(stored.source.contains("recovered_struct_0_t"));
    assert!(stored.source.contains("recovered_struct_0->field_0"));
    assert!(stored.source.contains("recovered_struct_0->field_8"));
    let rust: &str = stored.rust_source.as_deref().expect("aarch64 struct rust");
    assert!(rust.contains("struct RecoveredStruct0"));
    assert!(rust.contains("field_0"));
    assert!(rust.contains("field_8"));
}

#[test]
fn clang_o0_cbnz_diamond_structures_if_else() {
    let bytes: [u8; 60] = [
        0xff, 0x43, 0x00, 0xd1, 0xe0, 0x03, 0x00, 0xf9, 0xe8, 0x03, 0x40, 0xf9, 0xa8, 0x00, 0x00,
        0xb5, 0x01, 0x00, 0x00, 0x14, 0xe8, 0x00, 0x80, 0xd2, 0xe8, 0x07, 0x00, 0xf9, 0x05, 0x00,
        0x00, 0x14, 0xe8, 0x03, 0x40, 0xf9, 0x08, 0x05, 0x00, 0x91, 0xe8, 0x07, 0x00, 0xf9, 0x01,
        0x00, 0x00, 0x14, 0xe0, 0x07, 0x40, 0xf9, 0xff, 0x43, 0x00, 0x91, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let recovered: LeafRecovery =
        recover_aarch64_function(&bytes, 0x2c).expect("aarch64 cbnz diamond");
    assert_eq!(
        recovered.signature.observed_integer_registers(),
        vec![PseudoReg::Rax]
    );
    assert!(recovered.source.contains("if ("));
    assert!(recovered.source.contains("else"));
    assert!(recovered.source.contains("== 0") || recovered.source.contains("!= 0"));
}

#[test]
fn clang_o0_tbnz_diamond_structures_bit_test() {
    let bytes: [u8; 64] = [
        0xff, 0x43, 0x00, 0xd1, 0xe0, 0x03, 0x00, 0xf9, 0xe8, 0x03, 0x40, 0xf9, 0xc8, 0x00, 0x28,
        0x37, 0x01, 0x00, 0x00, 0x14, 0xe8, 0x03, 0x40, 0xf9, 0x08, 0x0d, 0x00, 0x91, 0xe8, 0x07,
        0x00, 0xf9, 0x05, 0x00, 0x00, 0x14, 0xe8, 0x03, 0x40, 0xf9, 0x08, 0x11, 0x00, 0xf1, 0xe8,
        0x07, 0x00, 0xf9, 0x01, 0x00, 0x00, 0x14, 0xe0, 0x07, 0x40, 0xf9, 0xff, 0x43, 0x00, 0x91,
        0xc0, 0x03, 0x5f, 0xd6,
    ];
    let recovered: LeafRecovery =
        recover_aarch64_function(&bytes, 0x68).expect("aarch64 tbnz diamond");
    assert!(recovered.source.contains("0x20"));
    assert!(recovered.source.contains("if ("));
    assert!(recovered.source.contains("else"));
}

#[test]
fn clang_o0_nzcv_loop_uses_shared_structurer() {
    let bytes: [u8; 88] = [
        0xff, 0x83, 0x00, 0xd1, 0xe0, 0x0f, 0x00, 0xf9, 0xff, 0x0b, 0x00, 0xf9, 0xff, 0x07, 0x00,
        0xf9, 0x01, 0x00, 0x00, 0x14, 0xe8, 0x07, 0x40, 0xf9, 0xe9, 0x0f, 0x40, 0xf9, 0x08, 0x01,
        0x09, 0xeb, 0x6a, 0x01, 0x00, 0x54, 0x01, 0x00, 0x00, 0x14, 0xe9, 0x07, 0x40, 0xf9, 0xe8,
        0x0b, 0x40, 0xf9, 0x08, 0x01, 0x09, 0x8b, 0xe8, 0x0b, 0x00, 0xf9, 0x01, 0x00, 0x00, 0x14,
        0xe8, 0x07, 0x40, 0xf9, 0x08, 0x05, 0x00, 0x91, 0xe8, 0x07, 0x00, 0xf9, 0xf3, 0xff, 0xff,
        0x17, 0xe0, 0x0b, 0x40, 0xf9, 0xff, 0x83, 0x00, 0x91, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let recovered: LeafRecovery =
        recover_aarch64_function(&bytes, 0xa8).expect("aarch64 nzcv loop");
    assert!(recovered.lifted_loop);
    assert!(recovered.source.contains("while (1)"));
    assert!(recovered.source.contains("break;"));
}

#[test]
fn clang_assembler_cmp_cmn_and_tst_drive_conditions() {
    let cmp: [u8; 24] = [
        0x1f, 0x00, 0x01, 0xeb, 0x6d, 0x00, 0x00, 0x54, 0x00, 0x00, 0x01, 0xcb, 0xc0, 0x03, 0x5f,
        0xd6, 0x00, 0x00, 0x01, 0x8b, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let cmn: [u8; 24] = [
        0x1f, 0x14, 0x00, 0xb1, 0x61, 0x00, 0x00, 0x54, 0x20, 0x00, 0x80, 0xd2, 0xc0, 0x03, 0x5f,
        0xd6, 0x00, 0x00, 0x80, 0xd2, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let tst: [u8; 24] = [
        0x1f, 0x00, 0x01, 0xea, 0x60, 0x00, 0x00, 0x54, 0x40, 0x00, 0x80, 0xd2, 0xc0, 0x03, 0x5f,
        0xd6, 0x60, 0x00, 0x80, 0xd2, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    for (bytes, base) in [(&cmp[..], 0_u64), (&cmn[..], 0x18), (&tst[..], 0x30)] {
        let recovered: LeafRecovery =
            recover_aarch64_function(bytes, base).expect("aarch64 flags branch");
        assert!(recovered.source.contains("if ("));
        assert!(recovered.source.matches("return ").count() >= 2);
    }
}

#[test]
fn clang_o2_direct_call_tracks_aapcs64_and_callee_saved_register() {
    let bytes: [u8; 36] = [
        0xfd, 0x7b, 0xbe, 0xa9, 0xf3, 0x0b, 0x00, 0xf9, 0xfd, 0x03, 0x00, 0x91, 0x33, 0x00, 0x00,
        0x8b, 0x00, 0x00, 0x00, 0x94, 0x60, 0x02, 0x00, 0x8b, 0xf3, 0x0b, 0x40, 0xf9, 0xfd, 0x7b,
        0xc2, 0xa8, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let calls: [ResolvedCall; 1] =
        [
            ResolvedCall::from_integer_arity(
                0x10,
                Some("helper".to_owned()),
                PseudoAbi::Aapcs64,
                1,
            )
            .expect("canonical aapcs64 call"),
        ];
    let recovered: LeafRecovery =
        recover_aarch64_function_with_calls(&bytes, 0, &calls).expect("aarch64 direct call");
    assert_eq!(
        recovered.signature.observed_integer_registers(),
        vec![PseudoReg::Rax, PseudoReg::A64X1]
    );
    assert_eq!(recovered.call_targets, vec![0x10]);
    let expected: &str = "#include <stdint.h>\nextern uint64_t helper(uint64_t);\nuint64_t recovered(uint64_t a0, uint64_t a1) {\n    uint64_t r_rax = a0;\n    uint64_t r_a64_x1 = a1;\n    uint64_t r_a64_tmp = 0;\n    r_a64_tmp = r_a64_x1;\n    r_a64_tmp = r_a64_tmp + (r_rax);\n    r_rax = helper(r_rax);\n    r_a64_tmp = r_a64_tmp + (r_rax);\n    r_rax = r_a64_tmp;\n    return r_rax;\n}\n";
    assert_eq!(recovered.source, expected);
    assert!(
        !recovered.source.contains("stack_frame"),
        "the callee-saved spill slot must stay frame management: {}",
        recovered.source
    );
}

#[test]
fn callee_saved_pair_writeback_lifts() {
    let bytes: [u8; 20] = [
        0xf3, 0x53, 0xbf, 0xa9, 0xf3, 0x03, 0x00, 0xaa, 0xe0, 0x03, 0x13, 0xaa, 0xf3, 0x53, 0xc1,
        0xa8, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let recovered: LeafRecovery =
        recover_aarch64_function(&bytes, 0).expect("aarch64 callee-save pair");
    assert_eq!(
        recovered.signature.observed_integer_registers(),
        vec![PseudoReg::Rax]
    );
    let expected: &str = "#include <stdint.h>\nuint64_t recovered(uint64_t a0) {\n    uint64_t r_rax = a0;\n    return r_rax;\n}\n";
    assert_eq!(recovered.source, expected);
    assert!(
        !recovered.source.contains("stack_frame"),
        "the callee-saved pair writeback must stay frame management: {}",
        recovered.source
    );
}

#[test]
fn frame_pointer_omitted_link_register_frame_lifts() {
    let bytes: [u8; 16] = [
        0xfe, 0x0f, 0x1f, 0xf8, 0x00, 0x00, 0x00, 0x94, 0xfe, 0x07, 0x41, 0xf8, 0xc0, 0x03, 0x5f,
        0xd6,
    ];
    let calls: [ResolvedCall; 1] =
        [
            ResolvedCall::from_integer_arity(4, Some("helper".to_owned()), PseudoAbi::Aapcs64, 0)
                .expect("canonical zero-argument aapcs64 call"),
        ];
    let recovered: LeafRecovery =
        recover_aarch64_function_with_calls(&bytes, 0, &calls).expect("aarch64 lr frame");
    assert!(recovered.signature.observed_integer_registers().is_empty());
    assert!(recovered.source.contains("helper()"));
    assert_eq!(recovered.call_targets, vec![4]);
}

#[test]
fn clang_o2_aapcs64_sret_uses_x8() {
    let bytes: [u8; 12] = [
        0x00, 0x05, 0x00, 0xa9, 0x02, 0x09, 0x00, 0xf9, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let recovered: LeafRecovery = recover_aarch64_function(&bytes, 0x84).expect("aarch64 sret");
    assert_eq!(recovered.signature.observed_integer_registers().len(), 3);
    assert_eq!(recovered.sret.as_ref().map(|sret| sret.size), Some(24));
    assert!(recovered.source.contains("recovered_sret_t"));
    assert!(recovered.source.contains("r_a64_x8"));
    assert!(recovered.rust_source.is_none());
}

#[test]
fn clang_o1_aapcs64_stack_arguments_lift() {
    let bytes: [u8; 20] = [
        0xe8, 0x27, 0x40, 0xa9, 0xea, 0x00, 0x00, 0x8b, 0x48, 0x01, 0x08, 0x8b, 0x00, 0x01, 0x09,
        0x8b, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let recovered: LeafRecovery = recover_aarch64_function(&bytes, 0).expect("aarch64 stack args");
    assert_eq!(recovered.signature.observed_integer_registers().len(), 4);
    assert!(
        recovered
            .signature
            .observed_integer_registers()
            .contains(&PseudoReg::A64Stack0)
    );
    assert!(
        recovered
            .signature
            .observed_integer_registers()
            .contains(&PseudoReg::A64Stack1)
    );
    assert!(recovered.source.contains("r_a64_stack0 = a2"));
    assert!(recovered.source.contains("r_a64_stack1 = a3"));
}

#[test]
fn clang_frame_pointer_and_split_stack_arguments_lift() {
    let frame_pointer: [u8; 24] = [
        0xfd, 0x7b, 0xbf, 0xa9, 0xfd, 0x03, 0x00, 0x91, 0xa8, 0x0b, 0x40, 0xf9, 0xe0, 0x03, 0x08,
        0xaa, 0xfd, 0x7b, 0xc1, 0xa8, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let split_stack: [u8; 32] = [
        0xfd, 0x7b, 0xbf, 0xa9, 0xfd, 0x03, 0x00, 0x91, 0xff, 0x83, 0x00, 0xd1, 0xe8, 0x1b, 0x40,
        0xf9, 0xe0, 0x03, 0x08, 0xaa, 0xff, 0x83, 0x00, 0x91, 0xfd, 0x7b, 0xc1, 0xa8, 0xc0, 0x03,
        0x5f, 0xd6,
    ];
    for bytes in [&frame_pointer[..], &split_stack[..]] {
        let recovered: LeafRecovery =
            recover_aarch64_function(bytes, 0).expect("aarch64 framed stack argument");
        assert_eq!(
            recovered.signature.observed_integer_registers(),
            vec![PseudoReg::A64Stack0]
        );
        assert!(recovered.source.contains("r_a64_stack0 = a0"));
    }
}

#[test]
fn clang_o1_outgoing_stack_argument_lifts() {
    let bytes: [u8; 60] = [
        0xff, 0x83, 0x00, 0xd1, 0xfd, 0x7b, 0x01, 0xa9, 0xfd, 0x43, 0x00, 0x91, 0x28, 0x01, 0x80,
        0x52, 0x62, 0x00, 0x80, 0x52, 0x83, 0x00, 0x80, 0x52, 0xa4, 0x00, 0x80, 0x52, 0xc5, 0x00,
        0x80, 0x52, 0xe6, 0x00, 0x80, 0x52, 0x07, 0x01, 0x80, 0x52, 0xe8, 0x03, 0x00, 0xf9, 0x00,
        0x00, 0x00, 0x94, 0xfd, 0x7b, 0x41, 0xa9, 0xff, 0x83, 0x00, 0x91, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let calls: [ResolvedCall; 1] =
        [
            ResolvedCall::from_integer_arity(44, Some("helper".to_owned()), PseudoAbi::Aapcs64, 9)
                .expect("canonical nine-argument aapcs64 call"),
        ];
    let recovered: LeafRecovery =
        recover_aarch64_function_with_calls(&bytes, 0, &calls).expect("aarch64 call9");
    assert_eq!(
        recovered.signature.observed_integer_registers(),
        vec![PseudoReg::Rax, PseudoReg::A64X1]
    );
    assert!(recovered.source.contains("r_a64_outgoing0 = r_a64_x8"));
    assert!(recovered.source.contains("helper("));
    assert!(recovered.source.contains("r_a64_outgoing0)"));
}

#[test]
fn clang_assembler_pre_and_post_index_writeback_lift() {
    let bytes: [u8; 24] = [
        0x01, 0x8c, 0x40, 0xf8, 0x02, 0x84, 0x00, 0xf8, 0x03, 0x10, 0xc1, 0xa9, 0x05, 0x18, 0x81,
        0xa8, 0xe0, 0x03, 0x01, 0xaa, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let recovered: LeafRecovery =
        recover_aarch64_function(&bytes, 0).expect("aarch64 indexed memory");
    assert_eq!(recovered.signature.observed_integer_registers().len(), 4);
    assert!(recovered.source.matches("r_rax = r_rax +").count() >= 4);
    assert!(recovered.source.matches("*(uint64_t*)").count() >= 4);
}

#[test]
fn clang_d_register_post_index_copy_loop_lifts() {
    let bytes: [u8; 32] = [
        0x5f, 0x04, 0x00, 0x71, 0xcb, 0x00, 0x00, 0x54, 0xe8, 0x03, 0x02, 0x2a, 0x20, 0x84, 0x40,
        0xfc, 0x08, 0x05, 0x00, 0xf1, 0x00, 0x84, 0x00, 0xfc, 0xa1, 0xff, 0xff, 0x54, 0xc0, 0x03,
        0x5f, 0xd6,
    ];
    let recovered: LeafRecovery =
        recover_aarch64_function(&bytes, 0).expect("d-register post-index copy loop");
    assert!(
        recovered.source.contains("recovered_i8x8"),
        "{}",
        recovered.source
    );
    assert!(
        recovered.source.contains("(__typeof__(v0)){0}"),
        "{}",
        recovered.source
    );
    assert!(
        recovered
            .source
            .contains("*(uint64_t *)(&v0) = *(recovered_u64_mem *)(r_a64_x1)"),
        "{}",
        recovered.source
    );
    assert!(
        recovered
            .source
            .contains("*(recovered_u64_mem *)(r_rax) = *(uint64_t *)(&v0)"),
        "{}",
        recovered.source
    );

    let Some(compiler): Option<PathBuf> =
        find_program("cc").or_else(|| find_program("gcc").or_else(|| find_program("clang")))
    else {
        eprintln!("skipping d-register behavioral check: no host C compiler");
        return;
    };
    let scratch: tempfile::TempDir =
        tempfile::tempdir().expect("create d-register scratch directory");
    let source_path: PathBuf = scratch.path().join("dreg_recovered.c");
    let driver_path: PathBuf = scratch.path().join("dreg_driver.c");
    let exe_path: PathBuf = scratch.path().join(if cfg!(windows) {
        "dreg_driver.exe"
    } else {
        "dreg_driver"
    });
    let renamed: String =
        recovered
            .source
            .replacen("uint64_t recovered(", "uint64_t dreg_recovered(", 1);
    std::fs::write(&source_path, renamed).expect("write recovered d-register source");
    std::fs::write(
        &driver_path,
        "#include <stdint.h>\n#include <string.h>\n\
         extern uint64_t dreg_recovered(uint64_t d, uint64_t s, uint64_t n);\n\
         int main(void) {\n\
         \x20   uint64_t src[7]; uint64_t dst[7];\n\
         \x20   for (int i = 0; i < 7; i++) { src[i] = 0x1111111100000000ULL * (i + 1) + i; dst[i] = 0; }\n\
         \x20   dreg_recovered((uint64_t)(uintptr_t)dst, (uint64_t)(uintptr_t)src, 7);\n\
         \x20   return memcmp(dst, src, sizeof(src)) == 0 ? 0 : 1;\n\
         }\n",
    )
    .expect("write d-register driver");
    run_tool(
        &compiler,
        vec![
            "-O1".into(),
            "-fno-strict-aliasing".into(),
            source_path.as_os_str().to_owned(),
            driver_path.as_os_str().to_owned(),
            "-o".into(),
            exe_path.as_os_str().to_owned(),
        ],
    );
    let no_args: [OsString; 0] = [];
    let outcome: CapturedOutput =
        run_captured(&exe_path, &no_args, Duration::from_secs(30), 1 << 20)
            .expect("spawn d-register driver")
            .expect("d-register driver timeout");
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "recovered d-register copy diverged from the reference buffer"
    );
}

#[test]
fn scalar_d_register_post_index_load_and_store_keep_fp_state() {
    let take: [u8; 16] = [
        0x08, 0x00, 0x40, 0xf9, 0x00, 0x85, 0x40, 0xfc, 0x08, 0x00, 0x00, 0xf9, 0xc0, 0x03, 0x5f,
        0xd6,
    ];
    let put: [u8; 16] = [
        0x08, 0x00, 0x40, 0xf9, 0x00, 0x85, 0x00, 0xfc, 0x08, 0x00, 0x00, 0xf9, 0xc0, 0x03, 0x5f,
        0xd6,
    ];

    let recovered_take: LeafRecovery =
        recover_aarch64_function(&take, 0).expect("scalar post-indexed double load");
    assert!(
        recovered_take
            .source
            .contains("x_xmm0 = fp_d_to_bits((double)((*(double*)"),
        "{}",
        recovered_take.source
    );
    assert!(!recovered_take.source.contains("recovered_i8x8"));
    assert!(
        recovered_take.source.contains("r_a64_x8 = r_a64_x8 +"),
        "{}",
        recovered_take.source
    );

    let recovered_put: LeafRecovery =
        recover_aarch64_function(&put, 0).expect("scalar post-indexed double store");
    assert!(
        recovered_put
            .source
            .contains("(*(uint64_t*)(uintptr_t)(r_a64_x8)) = x_xmm0"),
        "{}",
        recovered_put.source
    );
    assert!(!recovered_put.source.contains("recovered_i8x8"));
    assert!(
        recovered_put.source.contains("r_a64_x8 = r_a64_x8 +"),
        "{}",
        recovered_put.source
    );

    let Some(compiler): Option<PathBuf> =
        find_program("cc").or_else(|| find_program("gcc").or_else(|| find_program("clang")))
    else {
        eprintln!("skipping scalar d-register behavioral check: no host C compiler");
        return;
    };
    let scratch: tempfile::TempDir =
        tempfile::tempdir().expect("create scalar d-register scratch directory");
    let take_path: PathBuf = scratch.path().join("scalar_take.c");
    let put_path: PathBuf = scratch.path().join("scalar_put.c");
    let driver_path: PathBuf = scratch.path().join("scalar_driver.c");
    let exe_path: PathBuf = scratch.path().join(if cfg!(windows) {
        "scalar_driver.exe"
    } else {
        "scalar_driver"
    });
    let take_source: String =
        recovered_take
            .source
            .replacen("double recovered(", "double scalar_take(", 1);
    let put_source: String =
        recovered_put
            .source
            .replacen("void recovered(", "void scalar_put(", 1);
    std::fs::write(&take_path, take_source).expect("write scalar take source");
    std::fs::write(&put_path, put_source).expect("write scalar put source");
    std::fs::write(
        &driver_path,
        "#include <stdint.h>\n#include <string.h>\n\
         extern double scalar_take(uint64_t cursor_address);\n\
         extern void scalar_put(double value, uint64_t cursor_address);\n\
         int main(void) {\n\
         \x20   const uint64_t cases[] = {\n\
         \x20       0x0000000000000000ULL, 0x8000000000000000ULL,\n\
         \x20       0x0000000000000001ULL, 0x7ff0000000000000ULL,\n\
         \x20       0xfff0000000000000ULL, 0x7ff8000000001234ULL,\n\
         \x20       0x7ff0000000001234ULL\n\
         \x20   };\n\
         \x20   for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {\n\
         \x20       uint64_t source = cases[i]; uint64_t *read_cursor = &source;\n\
         \x20       double value = scalar_take((uint64_t)(uintptr_t)&read_cursor);\n\
         \x20       uint64_t returned = 0; memcpy(&returned, &value, sizeof(returned));\n\
         \x20       if (returned != cases[i] || read_cursor != &source + 1) return 1;\n\
         \x20       uint64_t destination = 0; uint64_t *write_cursor = &destination;\n\
         \x20       scalar_put(value, (uint64_t)(uintptr_t)&write_cursor);\n\
         \x20       if (destination != cases[i] || write_cursor != &destination + 1) return 2;\n\
         \x20   }\n\
         \x20   return 0;\n\
         }\n",
    )
    .expect("write scalar d-register driver");
    run_tool(
        &compiler,
        vec![
            "-O1".into(),
            "-fno-strict-aliasing".into(),
            take_path.as_os_str().to_owned(),
            put_path.as_os_str().to_owned(),
            driver_path.as_os_str().to_owned(),
            "-o".into(),
            exe_path.as_os_str().to_owned(),
        ],
    );
    let no_args: [OsString; 0] = [];
    let outcome: CapturedOutput =
        run_captured(&exe_path, &no_args, Duration::from_secs(30), 1 << 20)
            .expect("spawn scalar d-register driver")
            .expect("scalar d-register driver timeout");
    assert_eq!(outcome.exit_code, Some(0));

    let Some(rustup): Option<PathBuf> = find_program("rustup") else {
        eprintln!("skipping scalar d-register Rust check: no Rust compiler");
        return;
    };
    let rustc_output: CapturedOutput = run_tool(&rustup, vec!["which".into(), "rustc".into()]);
    let rustc: PathBuf = PathBuf::from(
        String::from_utf8_lossy(&rustc_output.stdout)
            .trim()
            .to_owned(),
    );
    assert!(rustc.is_file(), "{}", rustc.display());
    let rust_path: PathBuf = scratch.path().join("scalar_driver.rs");
    let rust_exe_path: PathBuf = scratch.path().join(if cfg!(windows) {
        "scalar_rust_driver.exe"
    } else {
        "scalar_rust_driver"
    });
    let rust_take: String = recovered_take
        .rust_source
        .as_deref()
        .expect("scalar take must have Rust output")
        .replacen("pub fn recovered(", "pub fn scalar_take(", 1);
    let rust_put: String = recovered_put
        .rust_source
        .as_deref()
        .expect("scalar put must have Rust output")
        .replacen("pub fn recovered(", "pub fn scalar_put(", 1);
    let rust_driver: String = format!(
        "{rust_take}\n{rust_put}\n\
         fn main() {{\n\
         \x20   let cases: [u64; 7] = [\n\
         \x20       0x0000000000000000, 0x8000000000000000, 0x0000000000000001,\n\
         \x20       0x7ff0000000000000, 0xfff0000000000000, 0x7ff8000000001234,\n\
         \x20       0x7ff0000000001234,\n\
         \x20   ];\n\
         \x20   for bits in cases {{\n\
         \x20       let mut source: u64 = bits;\n\
         \x20       let mut read_cursor: *mut u64 = &mut source;\n\
         \x20       let value: f64 = scalar_take((&mut read_cursor as *mut *mut u64) as u64);\n\
         \x20       assert_eq!(value.to_bits(), bits);\n\
         \x20       assert_eq!(read_cursor as usize, (&source as *const u64 as usize) + 8);\n\
         \x20       let mut destination: u64 = 0;\n\
         \x20       let mut write_cursor: *mut u64 = &mut destination;\n\
         \x20       scalar_put(value, (&mut write_cursor as *mut *mut u64) as u64);\n\
         \x20       assert_eq!(destination, bits);\n\
         \x20       assert_eq!(write_cursor as usize, (&destination as *const u64 as usize) + 8);\n\
         \x20   }}\n\
         }}\n"
    );
    std::fs::write(&rust_path, rust_driver).expect("write scalar d-register Rust driver");
    run_tool(
        &rustc,
        vec![
            "-O".into(),
            rust_path.as_os_str().to_owned(),
            "-o".into(),
            rust_exe_path.as_os_str().to_owned(),
        ],
    );
    let rust_outcome: CapturedOutput =
        run_captured(&rust_exe_path, &no_args, Duration::from_secs(30), 1 << 20)
            .expect("spawn scalar d-register Rust driver")
            .expect("scalar d-register Rust driver timeout");
    assert_eq!(rust_outcome.exit_code, Some(0));
}

#[test]
fn post_indexed_d_value_consumed_by_vector_stays_vector() {
    let bytes: [u8; 24] = [
        0x20, 0x84, 0x40, 0xfc, 0x00, 0x84, 0xe0, 0x4e, 0x00, 0x84, 0x00, 0xfc, 0x40, 0x00, 0x00,
        0xf9, 0x41, 0x04, 0x00, 0xf9, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let recovered: LeafRecovery =
        recover_aarch64_function(&bytes, 0).expect("post-indexed vector low lane flow");

    assert!(
        recovered.source.contains("recovered_i64x2"),
        "{}",
        recovered.source
    );
    assert!(recovered.source.contains("v0"), "{}", recovered.source);
    assert!(!recovered.source.contains("x_xmm0"), "{}", recovered.source);

    let Some(compiler): Option<PathBuf> =
        find_program("cc").or_else(|| find_program("gcc").or_else(|| find_program("clang")))
    else {
        eprintln!("skipping vector d-register behavioral check: no host C compiler");
        return;
    };
    let scratch: tempfile::TempDir =
        tempfile::tempdir().expect("create vector d-register scratch directory");
    let recovered_path: PathBuf = scratch.path().join("vector_transfer.c");
    let driver_path: PathBuf = scratch.path().join("vector_driver.c");
    let exe_path: PathBuf = scratch.path().join(if cfg!(windows) {
        "vector_driver.exe"
    } else {
        "vector_driver"
    });
    std::fs::write(&recovered_path, &recovered.source).expect("write vector d-register source");
    std::fs::write(
        &driver_path,
        "#include <stdint.h>\n\
         extern uint64_t recovered(uint64_t destination, uint64_t source, uint64_t cursors);\n\
         struct cursor_pair { uint64_t destination; uint64_t source; };\n\
         int main(void) {\n\
         \x20   const uint64_t cases[] = {\n\
         \x20       0x0000000000000000ULL, 0x0000000000000001ULL,\n\
         \x20       0x0123456789abcdefULL, 0x7ff0000000001234ULL,\n\
         \x20       0xffffffffffffffffULL\n\
         \x20   };\n\
         \x20   for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {\n\
         \x20       uint64_t source = cases[i]; uint64_t destination = 0;\n\
         \x20       struct cursor_pair cursors = {0, 0};\n\
         \x20       uint64_t result = recovered((uint64_t)(uintptr_t)&destination,\n\
         \x20           (uint64_t)(uintptr_t)&source, (uint64_t)(uintptr_t)&cursors);\n\
         \x20       if (destination != cases[i] * 2ULL) return 1;\n\
         \x20       if (cursors.destination != (uint64_t)(uintptr_t)(&destination + 1)) return 2;\n\
         \x20       if (cursors.source != (uint64_t)(uintptr_t)(&source + 1)) return 3;\n\
         \x20       if (result != cursors.destination) return 4;\n\
         \x20   }\n\
         \x20   return 0;\n\
         }\n",
    )
    .expect("write vector d-register driver");
    run_tool(
        &compiler,
        vec![
            "-O1".into(),
            "-fno-strict-aliasing".into(),
            recovered_path.as_os_str().to_owned(),
            driver_path.as_os_str().to_owned(),
            "-o".into(),
            exe_path.as_os_str().to_owned(),
        ],
    );
    let no_args: [OsString; 0] = [];
    let outcome: CapturedOutput =
        run_captured(&exe_path, &no_args, Duration::from_secs(30), 1 << 20)
            .expect("spawn vector d-register driver")
            .expect("vector d-register driver timeout");
    assert_eq!(outcome.exit_code, Some(0));
}

#[test]
fn non_post_indexed_d_value_consumed_by_vector_stays_vector() {
    let bytes: [u8; 16] = [
        0x20, 0x00, 0x40, 0xfd, 0x00, 0x84, 0xe0, 0x4e, 0x00, 0x00, 0x00, 0xfd, 0xc0, 0x03, 0x5f,
        0xd6,
    ];
    let recovered: LeafRecovery =
        recover_aarch64_function(&bytes, 0).expect("non-post-indexed vector low lane flow");

    assert!(recovered.source.contains("v0"), "{}", recovered.source);
    assert!(!recovered.source.contains("x_xmm0"), "{}", recovered.source);
}

#[test]
fn scalar_definition_replaces_an_earlier_d_register_memory_value() {
    let bytes: [u8; 20] = [
        0x00, 0x00, 0x40, 0xfd, 0x00, 0x84, 0xe0, 0x4e, 0x00, 0x10, 0x6e, 0x1e, 0x00, 0x28, 0x61,
        0x1e, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let recovered: LeafRecovery = recover_aarch64_function(&bytes, 0)
        .expect("a later scalar definition starts an independent register value");

    assert!(recovered.source.contains("v0"), "{}", recovered.source);
    assert!(recovered.source.contains("x_xmm0"), "{}", recovered.source);
}

#[test]
fn unscaled_d_register_load_consumed_by_vector_stays_vector() {
    let bytes: [u8; 16] = [
        0x00, 0x00, 0x40, 0xfc, 0x00, 0x84, 0xe0, 0x4e, 0x00, 0x00, 0x00, 0xfc, 0xc0, 0x03, 0x5f,
        0xd6,
    ];
    let recovered: LeafRecovery =
        recover_aarch64_function(&bytes, 0).expect("unscaled vector low lane flow");

    assert!(recovered.source.contains("v0"), "{}", recovered.source);
    assert!(!recovered.source.contains("x_xmm0"), "{}", recovered.source);
}

#[test]
fn paired_d_register_loads_consumed_by_vectors_stay_vector() {
    let bytes: [u8; 16] = [
        0x20, 0x04, 0xc1, 0x6c, 0x00, 0x84, 0xe0, 0x4e, 0x21, 0x84, 0xe1, 0x4e, 0xc0, 0x03, 0x5f,
        0xd6,
    ];
    let recovered: LeafRecovery =
        recover_aarch64_function(&bytes, 0).expect("paired vector low lane flow");

    assert!(recovered.source.contains("v0"), "{}", recovered.source);
    assert!(recovered.source.contains("v1"), "{}", recovered.source);
    assert!(!recovered.source.contains("x_xmm0"), "{}", recovered.source);
    assert!(!recovered.source.contains("x_xmm1"), "{}", recovered.source);
}

#[test]
fn paired_d_register_vector_values_store_through_vector_state() {
    let bytes: [u8; 16] = [
        0x00, 0x84, 0xe0, 0x4e, 0x21, 0x84, 0xe1, 0x4e, 0x00, 0x04, 0x00, 0x6d, 0xc0, 0x03, 0x5f,
        0xd6,
    ];
    let recovered: LeafRecovery =
        recover_aarch64_function(&bytes, 0).expect("paired vector low lane store");

    assert!(recovered.source.contains("v0"), "{}", recovered.source);
    assert!(recovered.source.contains("v1"), "{}", recovered.source);
    assert!(!recovered.source.contains("x_xmm0"), "{}", recovered.source);
    assert!(!recovered.source.contains("x_xmm1"), "{}", recovered.source);
}

#[test]
fn d_register_load_consumed_by_q_store_uses_one_vector_state() {
    let bytes: [u8; 12] = [
        0x00, 0x00, 0x40, 0xfd, 0x20, 0x00, 0x80, 0x3d, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let recovered: LeafRecovery =
        recover_aarch64_function(&bytes, 0).expect("d load feeding q store");

    assert!(recovered.source.contains("v0"), "{}", recovered.source);
    assert!(!recovered.source.contains("x_xmm0"), "{}", recovered.source);
}

#[test]
fn disjoint_scalar_and_vector_register_values_recover_together() {
    let bytes: [u8; 24] = [
        0x08, 0x00, 0x40, 0xf9, 0x00, 0x85, 0x40, 0xfc, 0x08, 0x00, 0x00, 0xf9, 0x01, 0xe4, 0x00,
        0x6f, 0x21, 0x84, 0xe1, 0x4e, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let recovered: LeafRecovery =
        recover_aarch64_function(&bytes, 0).expect("independent scalar and vector values");

    assert!(recovered.source.contains("x_xmm0"), "{}", recovered.source);
    assert!(recovered.source.contains("v1"), "{}", recovered.source);
    assert!(
        recovered.source.contains("recovered_i64x2"),
        "{}",
        recovered.source
    );
}

#[test]
fn one_d_value_used_as_scalar_and_vector_is_refused() {
    let bytes: [u8; 16] = [
        0x20, 0x84, 0x40, 0xfc, 0x00, 0x84, 0xe0, 0x4e, 0x01, 0x28, 0x60, 0x1e, 0xc0, 0x03, 0x5f,
        0xd6,
    ];
    let error: Error = recover_aarch64_function(&bytes, 0)
        .expect_err("one value cannot cross scalar and vector register states");

    assert!(
        error
            .to_string()
            .contains("one d-register value is consumed as both scalar and vector data"),
        "{error:?}"
    );
}

#[test]
fn untyped_d_value_crossing_a_basic_block_is_refused() {
    let bytes: [u8; 20] = [
        0x20, 0x84, 0x40, 0xfc, 0x02, 0x00, 0x00, 0x14, 0x1f, 0x20, 0x03, 0xd5, 0x00, 0x84, 0xe0,
        0x4e, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let error: Error = recover_aarch64_function(&bytes, 0)
        .expect_err("cross-block d-register provenance must not be guessed");

    assert!(
        error
            .to_string()
            .contains("an untyped d-register value crosses a basic-block boundary"),
        "{error:?}"
    );
}

#[test]
fn classified_d_transfer_value_crossing_a_basic_block_is_refused() {
    let bytes: [u8; 24] = [
        0x00, 0x00, 0x40, 0xfd, 0x00, 0x84, 0xe0, 0x4e, 0x02, 0x00, 0x00, 0x14, 0x1f, 0x20, 0x03,
        0xd5, 0x20, 0x00, 0x00, 0xfd, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let error: Error = recover_aarch64_function(&bytes, 0)
        .expect_err("classified d-register transfer provenance must not cross blocks");

    assert!(
        error
            .to_string()
            .contains("a d-register transfer value crosses a basic-block boundary"),
        "{error:?}"
    );
}

#[test]
fn aarch64_cross_width_fmov_zero_extends_the_low_lane() {
    let bytes: [u8; 16] = [
        0x01, 0x00, 0x67, 0x9e, 0x22, 0x40, 0x20, 0x1e, 0x40, 0x40, 0x60, 0x1e, 0xc0, 0x03, 0x5f,
        0xd6,
    ];
    let r: LeafRecovery = recover_aarch64_function(&bytes, 0).expect("cross-width fmov sequence");
    assert!(
        r.source.contains("& 0xffffffffULL") || r.source.contains("(uint32_t)"),
        "the single-precision fmov must zero-extend the low 32 bits, not copy the full register: {}",
        r.source
    );
}

#[test]
fn aarch64_scalar_fmaxnm_and_fminnm_recover_as_ieee_num_helpers() {
    let max_single: [u8; 8] = [0x00, 0x68, 0x21, 0x1e, 0xc0, 0x03, 0x5f, 0xd6];
    let min_double: [u8; 8] = [0x00, 0x78, 0x61, 0x1e, 0xc0, 0x03, 0x5f, 0xd6];
    let single: LeafRecovery =
        recover_aarch64_function(&max_single, 0).expect("aarch64 fmaxnm single");
    assert!(
        single.source.contains("fpx_maxnum_f32("),
        "single-precision fmaxnm must recover as the ieee maxnum helper: {}",
        single.source
    );
    assert_eq!(single.signature.parameter_types().len(), 2);
    assert_eq!(single.return_width_bits, 32);
    let double: LeafRecovery =
        recover_aarch64_function(&min_double, 0).expect("aarch64 fminnm double");
    assert!(
        double.source.contains("fpx_minnum_f64("),
        "double-precision fminnm must recover as the ieee minnum helper: {}",
        double.source
    );
    assert_eq!(double.signature.parameter_types().len(), 2);
    assert_eq!(double.return_width_bits, 64);
}

#[test]
fn aarch64_scalar_fma_recovers_with_correct_input_negations() {
    let ret: [u8; 4] = [0xc0, 0x03, 0x5f, 0xd6];
    let cases: [(u32, &str, bool, bool); 5] = [
        (0x1f01_0800, "fpx_fma_f32(", false, false),
        (0x1f01_8800, "fpx_fma_f32(", true, false),
        (0x1f21_0800, "fpx_fma_f32(", true, true),
        (0x1f21_8800, "fpx_fma_f32(", false, true),
        (0x1f41_0800, "fpx_fma_f64(", false, false),
    ];
    for (word, builtin, neg_mul_lhs, neg_addend) in cases {
        let mut bytes: Vec<u8> = word.to_le_bytes().to_vec();
        bytes.extend_from_slice(&ret);
        let recovered: LeafRecovery =
            recover_aarch64_function(&bytes, 0).expect("aarch64 fused multiply-add");
        assert_eq!(recovered.signature.parameter_types().len(), 3, "{builtin}");
        let call: &str = recovered.source.rsplit_once(builtin).map_or_else(
            || panic!("missing {builtin} in {}", recovered.source),
            |(_, rest): (&str, &str)| rest,
        );
        let mut depth: i32 = 1;
        let mut parts: Vec<String> = vec![String::new()];
        for ch in call.chars() {
            match ch {
                '(' => {
                    depth += 1;
                    parts.last_mut().expect("current arg").push(ch);
                }
                ')' if depth == 1 => break,
                ')' => {
                    depth -= 1;
                    parts.last_mut().expect("current arg").push(ch);
                }
                ',' if depth == 1 => parts.push(String::new()),
                _ => parts.last_mut().expect("current arg").push(ch),
            }
        }
        let parts: Vec<&str> = parts.iter().map(|part: &String| part.trim()).collect();
        assert_eq!(parts.len(), 3, "three fma arguments in `{call}`");
        assert_eq!(
            parts[0].starts_with('-'),
            neg_mul_lhs,
            "multiplicand negation for {word:#010x} in `{}`",
            parts.join(" | ")
        );
        assert_eq!(
            parts[2].starts_with('-'),
            neg_addend,
            "addend negation for {word:#010x} in `{}`",
            parts.join(" | ")
        );
        assert!(
            !parts[1].starts_with('-'),
            "the multiplier must never be negated for {word:#010x} in `{}`",
            parts.join(" | ")
        );
    }
}

#[test]
fn aarch64_scalar_fp_compare_recovers_ordered_unordered_and_select() {
    let ret: [u8; 4] = [0xc0, 0x03, 0x5f, 0xd6];
    let ordered_lt: [u8; 8] = [0x00, 0x20, 0x21, 0x1e, 0xe0, 0x57, 0x9f, 0x1a];
    let unordered_nlt: [u8; 8] = [0x00, 0x20, 0x21, 0x1e, 0xe0, 0x47, 0x9f, 0x1a];
    let is_nan: [u8; 8] = [0x00, 0x20, 0x20, 0x1e, 0xe0, 0x77, 0x9f, 0x1a];
    let select_min: [u8; 8] = [0x00, 0x20, 0x21, 0x1e, 0x00, 0x4c, 0x21, 0x1e];

    let mut lt_bytes: Vec<u8> = ordered_lt.to_vec();
    lt_bytes.extend_from_slice(&ret);
    let lt: LeafRecovery = recover_aarch64_function(&lt_bytes, 0).expect("fcmp + cset mi");
    assert!(
        lt.source.contains('<') && !lt.source.contains("!("),
        "fcmp + cset mi must recover an ordered less-than: {}",
        lt.source
    );

    let mut nlt_bytes: Vec<u8> = unordered_nlt.to_vec();
    nlt_bytes.extend_from_slice(&ret);
    let nlt: LeafRecovery = recover_aarch64_function(&nlt_bytes, 0).expect("fcmp + cset pl");
    assert!(
        nlt.source.contains("!("),
        "fcmp + cset pl must recover the unordered complement of less-than: {}",
        nlt.source
    );

    let mut nan_bytes: Vec<u8> = is_nan.to_vec();
    nan_bytes.extend_from_slice(&ret);
    let nan: LeafRecovery = recover_aarch64_function(&nan_bytes, 0).expect("fcmp x,x + cset vs");
    assert!(
        nan.source.contains("!="),
        "fcmp of a register with itself + cset vs must recover an unordered test: {}",
        nan.source
    );

    let mut sel_bytes: Vec<u8> = select_min.to_vec();
    sel_bytes.extend_from_slice(&ret);
    let sel: LeafRecovery = recover_aarch64_function(&sel_bytes, 0).expect("fcmp + fcsel mi");
    assert!(
        sel.source.contains('?') && sel.source.contains('<'),
        "fcmp + fcsel mi must recover a conditional select on an ordered less-than: {}",
        sel.source
    );
    assert_eq!(sel.signature.parameter_types().len(), 2);
    assert!(sel.returns_fp.is_some());
    assert_eq!(sel.return_width_bits, 32);
}

#[test]
fn aarch64_fp_return_survives_an_incidental_fp_compare_side_effect() {
    let bytes: [u8; 20] = [
        0x00, 0x28, 0x21, 0x1e, 0x08, 0x20, 0x20, 0x1e, 0xe8, 0x57, 0x9f, 0x1a, 0x08, 0x00, 0x00,
        0xb9, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let recovered: LeafRecovery =
        recover_aarch64_function(&bytes, 0).expect("fp add with a compare stored to a pointer");
    assert!(
        recovered.returns_fp.is_some(),
        "a function that returns its fp sum must not be reclassified as int just because it materializes an fp comparison into a stored flag: {}",
        recovered.source
    );
    assert_eq!(recovered.return_width_bits, 32);
}

#[test]
fn atomics_and_out_of_subset_integer_ops_reject_explicitly() {
    let atomics: [u8; 12] = [
        0x01, 0x7c, 0x5f, 0xc8, 0x01, 0x7c, 0x02, 0xc8, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let widening_multiply_accumulate: [u8; 8] = [0x20, 0x08, 0x20, 0x9b, 0xc0, 0x03, 0x5f, 0xd6];
    for bytes in [&atomics[..], &widening_multiply_accumulate[..]] {
        let error = recover_aarch64_function(bytes, 0).expect_err("unsupported aarch64 class");
        assert!(
            format!("{error:?}").contains("aarch64 reject: unsupported instruction"),
            "{error:?}"
        );
    }
}

#[test]
fn neon_register_form_packed_arithmetic_lifts() {
    let cases: [(&[u8], &str, &str); 9] = [
        (
            &[0x00, 0xd4, 0x21, 0x4e, 0xc0, 0x03, 0x5f, 0xd6],
            "recovered_f32x4",
            "v0 = v0 + v1",
        ),
        (
            &[0x00, 0xd4, 0xa1, 0x4e, 0xc0, 0x03, 0x5f, 0xd6],
            "recovered_f32x4",
            "v0 = v0 - v1",
        ),
        (
            &[0x00, 0xdc, 0x21, 0x6e, 0xc0, 0x03, 0x5f, 0xd6],
            "recovered_f32x4",
            "v0 = v0 * v1",
        ),
        (
            &[0x20, 0x84, 0xa0, 0x4e, 0xc0, 0x03, 0x5f, 0xd6],
            "recovered_i32x4",
            "v0 = v1 + v0",
        ),
        (
            &[0x20, 0x9c, 0xa0, 0x4e, 0xc0, 0x03, 0x5f, 0xd6],
            "recovered_i32x4",
            "v0 = v1 * v0",
        ),
        (
            &[0x00, 0x84, 0xa1, 0x6e, 0xc0, 0x03, 0x5f, 0xd6],
            "recovered_i32x4",
            "v0 = v0 - v1",
        ),
        (
            &[0x00, 0xd4, 0x61, 0x4e, 0xc0, 0x03, 0x5f, 0xd6],
            "recovered_f64x2",
            "v0 = v0 + v1",
        ),
        (
            &[0x00, 0xdc, 0x61, 0x6e, 0xc0, 0x03, 0x5f, 0xd6],
            "recovered_f64x2",
            "v0 = v0 * v1",
        ),
        (
            &[0x20, 0x84, 0x60, 0x4e, 0xc0, 0x03, 0x5f, 0xd6],
            "recovered_i16x8",
            "v0 = v1 + v0",
        ),
    ];
    for (bytes, ty, op) in cases {
        let recovered: LeafRecovery = recover_aarch64_function(bytes, 0).expect("neon arithmetic");
        assert!(
            recovered.source.contains(ty),
            "missing {ty} in {}",
            recovered.source
        );
        assert!(
            recovered
                .source
                .contains("__attribute__((vector_size(16)))"),
            "{}",
            recovered.source
        );
        assert!(
            recovered.source.contains(op),
            "missing {op} in {}",
            recovered.source
        );
        assert!(
            recovered.source.contains("return v0;"),
            "{}",
            recovered.source
        );
        assert_eq!(recovered.return_width_bits, 128);
        assert!(recovered.rust_source.is_none());
    }
}

#[test]
fn neon_vector_load_store_and_dup_lift() {
    let store_add: [u8; 20] = [
        0x20, 0x00, 0xc0, 0x3d, 0x41, 0x00, 0xc0, 0x3d, 0x00, 0xd4, 0x21, 0x4e, 0x00, 0x00, 0x80,
        0x3d, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let recovered: LeafRecovery = recover_aarch64_function(&store_add, 0).expect("neon store-add");
    assert!(
        recovered
            .source
            .contains("void recovered(uint64_t a0, uint64_t a1, uint64_t a2)")
    );
    assert_eq!(
        recovered.source.matches("*(recovered_f32x4_mem*)").count(),
        3
    );
    assert!(recovered.source.contains("v0 = v0 + v1;"));
    assert!(recovered.source.contains("return;"));
    assert_eq!(recovered.return_width_bits, 0);

    let copyq: [u8; 12] = [
        0x20, 0x00, 0xc0, 0x3d, 0x00, 0x00, 0x80, 0x3d, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let copy: LeafRecovery = recover_aarch64_function(&copyq, 0).expect("neon copy");
    assert_eq!(copy.source.matches("*(recovered_i8x16_mem*)").count(), 2);
    assert!(copy.source.contains("void recovered("));

    let splat: [u8; 8] = [0x00, 0x0c, 0x04, 0x4e, 0xc0, 0x03, 0x5f, 0xd6];
    let broadcast: LeafRecovery = recover_aarch64_function(&splat, 0).expect("neon dup");
    assert_eq!(
        broadcast.signature.observed_integer_registers(),
        vec![PseudoReg::Rax]
    );
    assert!(
        broadcast.source.contains(
            "(recovered_i32x4){(int32_t)r_rax, (int32_t)r_rax, (int32_t)r_rax, (int32_t)r_rax}"
        ),
        "{}",
        broadcast.source
    );
    assert!(broadcast.source.contains("return v0;"));
}

#[test]
fn neon_out_of_subset_forms_reject_explicitly() {
    let vector_mov: [u8; 8] = [0x20, 0x1c, 0xa1, 0x4e, 0xc0, 0x03, 0x5f, 0xd6];
    let indexed_fmla: [u8; 8] = [0x10, 0x11, 0x80, 0x0f, 0xc0, 0x03, 0x5f, 0xd6];
    let ld1_single: [u8; 8] = [0x68, 0x79, 0x40, 0x4c, 0xc0, 0x03, 0x5f, 0xd6];
    let reduction: [u8; 8] = [0x00, 0x38, 0x30, 0x0e, 0xc0, 0x03, 0x5f, 0xd6];
    for bytes in [
        &vector_mov[..],
        &indexed_fmla[..],
        &ld1_single[..],
        &reduction[..],
    ] {
        let error =
            recover_aarch64_function(bytes, 0).expect_err("out-of-subset neon form must reject");
        assert!(
            format!("{error:?}").contains("aarch64 reject:"),
            "{error:?}"
        );
    }
}

#[test]
fn neon_recovered_sources_recompile_to_matching_words() {
    let Some(clang): Option<PathBuf> = find_program("clang") else {
        eprintln!("skipping neon recompile: clang is unavailable");
        return;
    };
    let Some(objdump): Option<PathBuf> = find_program("llvm-objdump") else {
        eprintln!("skipping neon recompile: llvm-objdump is unavailable");
        return;
    };
    let cases: [(&[u8], &[&str]); 5] = [
        (
            &[0x00, 0xd4, 0x21, 0x4e, 0xc0, 0x03, 0x5f, 0xd6],
            &["4e21d400"],
        ),
        (
            &[0x20, 0x84, 0xa0, 0x4e, 0xc0, 0x03, 0x5f, 0xd6],
            &["4ea08420"],
        ),
        (
            &[0x00, 0x0c, 0x04, 0x4e, 0xc0, 0x03, 0x5f, 0xd6],
            &["4e040c00"],
        ),
        (
            &[
                0x20, 0x00, 0xc0, 0x3d, 0x41, 0x00, 0xc0, 0x3d, 0x00, 0xd4, 0x21, 0x4e, 0x00, 0x00,
                0x80, 0x3d, 0xc0, 0x03, 0x5f, 0xd6,
            ],
            &["3dc00020", "3dc00041", "4e21d400", "3d800000"],
        ),
        (
            &[
                0x20, 0x00, 0xc0, 0x3d, 0x41, 0x00, 0xc0, 0x3d, 0x00, 0xd4, 0x21, 0x4e, 0x61, 0x00,
                0xc0, 0x3d, 0x00, 0xdc, 0x21, 0x6e, 0x00, 0x00, 0x80, 0x3d, 0xc0, 0x03, 0x5f, 0xd6,
            ],
            &["3dc00020", "4e21d400", "6e21dc00", "3d800000"],
        ),
    ];
    let scratch: tempfile::TempDir = tempfile::tempdir().expect("create neon scratch directory");
    for (index, (bytes, expected)) in cases.into_iter().enumerate() {
        let recovered: LeafRecovery =
            recover_aarch64_function(bytes, 0).expect("recover neon function");
        let source_path: PathBuf = scratch.path().join(format!("neon_{index}.c"));
        let object_path: PathBuf = scratch.path().join(format!("neon_{index}.o"));
        std::fs::write(&source_path, recovered.source).expect("write recovered neon source");
        run_tool(
            &clang,
            vec![
                "--target=aarch64-linux-gnu".into(),
                "-O2".into(),
                "-ffreestanding".into(),
                "-c".into(),
                source_path.as_os_str().to_owned(),
                "-o".into(),
                object_path.as_os_str().to_owned(),
            ],
        );
        let listing: CapturedOutput = run_tool(
            &objdump,
            vec!["-d".into(), object_path.as_os_str().to_owned()],
        );
        let listing: String = String::from_utf8(listing.stdout).expect("utf8 neon listing");
        for word in expected {
            assert!(
                listing.contains(word),
                "recompiled neon function {index} is missing {word}\n{listing}"
            );
        }
    }
}

#[test]
fn clang_and_llvm_cross_check_committed_words_and_recompiled_add() {
    let Some(clang): Option<PathBuf> = find_program("clang") else {
        eprintln!("skipping aarch64 compiler cross-check: clang is unavailable");
        return;
    };
    let Some(objdump): Option<PathBuf> = find_program("llvm-objdump") else {
        eprintln!("skipping aarch64 compiler cross-check: llvm-objdump is unavailable");
        return;
    };
    let scratch: tempfile::TempDir = tempfile::tempdir().expect("create aarch64 scratch directory");
    let original_c: PathBuf = scratch.path().join("original.c");
    let original_o: PathBuf = scratch.path().join("original.o");
    let recovered_c: PathBuf = scratch.path().join("recovered.c");
    let recovered_o: PathBuf = scratch.path().join("recovered.o");
    std::fs::write(
        &original_c,
        "long add3(long a,long b,long c){return a+b+c;} struct triple{long a;long b;long c;}; struct triple make3(long a,long b,long c){struct triple x={a,b,c};return x;}",
    )
    .expect("write aarch64 source");
    run_tool(
        &clang,
        vec![
            "--target=aarch64-linux-gnu".into(),
            "-O2".into(),
            "-ffreestanding".into(),
            "-c".into(),
            original_c.as_os_str().to_owned(),
            "-o".into(),
            original_o.as_os_str().to_owned(),
        ],
    );
    let listing: CapturedOutput = run_tool(
        &objdump,
        vec!["-d".into(), original_o.as_os_str().to_owned()],
    );
    let listing: String = String::from_utf8(listing.stdout).expect("utf8 llvm listing");
    for word in ["8b000028", "8b020100", "a9000500", "f9000902"] {
        assert!(listing.contains(word), "missing {word} in {listing}");
    }
    let add3: [u8; 12] = [
        0x28, 0x00, 0x00, 0x8b, 0x00, 0x01, 0x02, 0x8b, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let recovered: LeafRecovery = recover_aarch64_function(&add3, 0).expect("recover add3");
    std::fs::write(&recovered_c, recovered.source).expect("write recovered aarch64 source");
    run_tool(
        &clang,
        vec![
            "--target=aarch64-linux-gnu".into(),
            "-O2".into(),
            "-ffreestanding".into(),
            "-c".into(),
            recovered_c.as_os_str().to_owned(),
            "-o".into(),
            recovered_o.as_os_str().to_owned(),
        ],
    );
    let recovered_listing: CapturedOutput = run_tool(
        &objdump,
        vec!["-d".into(), recovered_o.as_os_str().to_owned()],
    );
    let recovered_listing: String =
        String::from_utf8(recovered_listing.stdout).expect("utf8 recovered listing");
    assert!(
        recovered_listing.contains("8b000028"),
        "{recovered_listing}"
    );
    assert!(
        recovered_listing.contains("8b020100"),
        "{recovered_listing}"
    );
}

#[test]
fn oversized_input_rejects_before_decode() {
    let bytes: Vec<u8> = vec![0xff; 4097 * 4];
    let error = recover_aarch64_function(&bytes, 0).expect_err("oversized aarch64 body");
    assert!(
        format!("{error:?}").contains("aarch64 reject: instruction bytes exceed the bounded lift"),
        "{error:?}"
    );
}

#[test]
fn stack_adjustment_outside_frame_edges_rejects() {
    let bytes: [u8; 12] = [
        0xe0, 0x03, 0x01, 0xaa, 0xff, 0x43, 0x00, 0x91, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let error = recover_aarch64_function(&bytes, 0).expect_err("mid-body stack adjustment");
    assert!(
        format!("{error:?}").contains("stack pointer leaves the bounded aligned frame"),
        "{error:?}"
    );
}

#[test]
fn incomplete_and_negative_stack_epilogues_reject() {
    let missing: [u8; 12] = [
        0xff, 0x83, 0x00, 0xd1, 0xe0, 0x03, 0x01, 0xaa, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let under_restored: [u8; 16] = [
        0xff, 0x83, 0x00, 0xd1, 0xe0, 0x03, 0x01, 0xaa, 0xff, 0x43, 0x00, 0x91, 0xc0, 0x03, 0x5f,
        0xd6,
    ];
    let negative: [u8; 20] = [
        0xfd, 0x7b, 0xbf, 0xa9, 0xfd, 0x03, 0x00, 0x91, 0xe0, 0x03, 0x01, 0xaa, 0xfd, 0x7b, 0xff,
        0xa8, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    for bytes in [&missing[..], &under_restored[..], &negative[..]] {
        let error = recover_aarch64_function(bytes, 0).expect_err("invalid stack epilogue");
        assert!(
            format!("{error:?}")
                .contains("stack pointer does not return to its entry value before the return"),
            "{error:?}"
        );
    }
}

#[test]
fn intervening_write_never_compares_the_overwritten_nzcv_operand() {
    let bytes: [u8; 28] = [
        0x1f, 0x00, 0x01, 0xeb, 0xe0, 0x03, 0x02, 0xaa, 0x6c, 0x00, 0x00, 0x54, 0x00, 0x00, 0x80,
        0xd2, 0xc0, 0x03, 0x5f, 0xd6, 0x20, 0x00, 0x80, 0xd2, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let recovered: LeafRecovery =
        recover_aarch64_function(&bytes, 0).expect("clobbered compare operand recovers");
    let overwrite: usize = recovered
        .source
        .find("r_rax = r_a64_x2;")
        .unwrap_or_else(|| panic!("{}", recovered.source));
    assert!(
        recovered.source[..overwrite]
            .contains("sel_cc_0 = (int64_t)(int64_t)(r_rax) > (int64_t)(int64_t)(r_a64_x1);"),
        "{}",
        recovered.source
    );
    assert!(
        !recovered.source[overwrite..].contains("r_a64_x1"),
        "{}",
        recovered.source
    );
}

#[test]
fn unresolved_call_infers_only_register_arguments() {
    let bytes: [u8; 8] = [0x00, 0x00, 0x00, 0x94, 0xc0, 0x03, 0x5f, 0xd6];
    let recovered: LeafRecovery = recover_aarch64_function(&bytes, 0).expect("unresolved bl");
    assert_eq!(recovered.signature.observed_integer_registers().len(), 8);
    assert!(
        !recovered
            .signature
            .observed_integer_registers()
            .contains(&PseudoReg::A64Stack0)
    );
}

#[test]
fn legacy_x86_entry_rejects_aapcs64() {
    let error = recover_leaf_function_abi(&[0xc3], 0, PseudoAbi::Aapcs64)
        .expect_err("aapcs64 in x86 entry");
    assert!(format!("{error:?}").contains("aapcs64"), "{error:?}");
}

#[test]
fn legacy_x86_object_entry_rejects_aapcs64_before_probing() {
    let error = recover_leaf_function_in_object(&[], &[0xc3], 0, PseudoAbi::Aapcs64, &[])
        .expect_err("aapcs64 in x86 object entry");
    assert!(format!("{error:?}").contains("aapcs64"), "{error:?}");
}

#[test]
fn resolved_call_rejects_arguments_beyond_bounded_stack_slots() {
    let error = ResolvedCall::from_integer_arity(0, None, PseudoAbi::Aapcs64, 17)
        .expect_err("too many resolved aapcs64 arguments");
    assert!(
        format!("{error:?}").contains("resolved call argument count exceeds"),
        "{error:?}"
    );
}

#[test]
fn duplicate_resolved_call_targets_reject() {
    let bytes: [u8; 8] = [0x00, 0x00, 0x00, 0x94, 0xc0, 0x03, 0x5f, 0xd6];
    let calls: [ResolvedCall; 2] = [
        ResolvedCall::from_integer_arity(0, None, PseudoAbi::Aapcs64, 1)
            .expect("one-argument aapcs64 call"),
        ResolvedCall::from_integer_arity(0, None, PseudoAbi::Aapcs64, 9)
            .expect("nine-argument aapcs64 call"),
    ];
    let error = recover_aarch64_function_with_calls(&bytes, 0, &calls)
        .expect_err("duplicate resolved call target");
    assert!(
        format!("{error:?}").contains("resolved call targets contain duplicates"),
        "{error:?}"
    );
}

#[test]
fn subs_branch_uses_pre_subtraction_operands() {
    let bytes: [u8; 24] = [
        0x00, 0x04, 0x00, 0xf1, 0x60, 0x00, 0x00, 0x54, 0x00, 0x00, 0x80, 0xd2, 0xc0, 0x03, 0x5f,
        0xd6, 0x20, 0x00, 0x80, 0xd2, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let recovered: LeafRecovery = recover_aarch64_function(&bytes, 0).expect("subs branch");
    assert!(recovered.source.contains("r_a64_flag_lhs"));
    assert!(recovered.source.contains("r_a64_flag_rhs"));
}

#[test]
fn cmn_and_tst_reject_conditions_that_need_cv() {
    let cmn_lt: [u8; 24] = [
        0x1f, 0x14, 0x00, 0xb1, 0x6b, 0x00, 0x00, 0x54, 0x20, 0x00, 0x80, 0xd2, 0xc0, 0x03, 0x5f,
        0xd6, 0x00, 0x00, 0x80, 0xd2, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let tst_hs: [u8; 24] = [
        0x1f, 0x00, 0x01, 0xea, 0x62, 0x00, 0x00, 0x54, 0x40, 0x00, 0x80, 0xd2, 0xc0, 0x03, 0x5f,
        0xd6, 0x60, 0x00, 0x80, 0xd2, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    for bytes in [&cmn_lt[..], &tst_hs[..]] {
        let error = recover_aarch64_function(bytes, 0).expect_err("condition needs cv flags");
        assert!(
            format!("{error:?}").contains("condition is undefined for the tracked nzcv source"),
            "{error:?}"
        );
    }
}
