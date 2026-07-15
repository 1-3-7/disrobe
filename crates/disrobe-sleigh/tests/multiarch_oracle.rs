use std::env;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use disrobe_core::subprocess::{CapturedOutput, run_captured};
use disrobe_sleigh::coverage::{DecodeReport, decode_block_with_coverage_for_language};
use disrobe_sleigh::lifter::{ArmMode, Language, RiscVWidth};
use disrobe_sleigh::syntax::Endian;

const TOOL_CAPTURE_LIMIT: usize = 4 * 1024 * 1024;
const TOOL_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Debug)]
struct Toolchain {
    gcc: PathBuf,
    objcopy: PathBuf,
    objdump: PathBuf,
}

#[derive(Debug)]
struct CrossCheck {
    reference: Vec<String>,
    report: DecodeReport,
}

#[test]
fn committed_form_matrices_match_gnu_objdump() {
    for (label, language, expected, callother) in [
        ("arm32_a32_forms", Language::Arm32(ArmMode::A32), 20, 0),
        ("arm32_thumb_forms", Language::Arm32(ArmMode::Thumb), 23, 0),
        ("mips32le_forms", Language::Mips32(Endian::Little), 28, 3),
        ("mips32be_forms", Language::Mips32(Endian::Big), 28, 3),
        ("powerpc32_forms", Language::PowerPc32Be, 32, 1),
        ("powerpc64_forms", Language::PowerPc64Be, 30, 2),
        ("riscv32_forms", Language::RiscV(RiscVWidth::Rv32), 31, 6),
        ("riscv64_forms", Language::RiscV(RiscVWidth::Rv64), 33, 6),
        (
            "riscv32c_forms",
            Language::RiscVCompressed(RiscVWidth::Rv32),
            19,
            0,
        ),
        (
            "riscv64c_forms",
            Language::RiscVCompressed(RiscVWidth::Rv64),
            20,
            0,
        ),
        (
            "riscv32a_forms",
            Language::RiscVCompressed(RiscVWidth::Rv32),
            10,
            10,
        ),
        (
            "riscv64a_forms",
            Language::RiscVCompressed(RiscVWidth::Rv64),
            12,
            12,
        ),
    ] {
        let checked: CrossCheck = corpus_cross_check(label, language);
        assert_cross_check(label, &checked, expected, callother);
    }
}

#[test]
fn committed_cross_gcc_functions_match_gnu_objdump() {
    for (label, language, expected) in [
        ("arm32_a32_oracle_o2", Language::Arm32(ArmMode::A32), 19),
        ("arm32_thumb_oracle_o2", Language::Arm32(ArmMode::Thumb), 22),
        ("mips32le_oracle_o2", Language::Mips32(Endian::Little), 20),
        ("mips32be_oracle_o2", Language::Mips32(Endian::Big), 20),
        ("powerpc32_oracle_o2", Language::PowerPc32Be, 11),
        ("riscv32_oracle_o2", Language::RiscV(RiscVWidth::Rv32), 11),
        ("riscv64_oracle_o2", Language::RiscV(RiscVWidth::Rv64), 11),
        (
            "riscv32c_oracle_os",
            Language::RiscVCompressed(RiscVWidth::Rv32),
            11,
        ),
        (
            "riscv64c_oracle_os",
            Language::RiscVCompressed(RiscVWidth::Rv64),
            11,
        ),
    ] {
        let checked: CrossCheck = corpus_cross_check(label, language);
        let callother: usize = if label.starts_with("riscv") && !label.contains("c_oracle") {
            4
        } else if label.starts_with("riscv") {
            1
        } else {
            usize::from(label.starts_with("powerpc"))
        };
        assert_cross_check(label, &checked, expected, callother);
    }
    for (label, language) in [
        (
            "riscv32a_oracle_o2",
            Language::RiscVCompressed(RiscVWidth::Rv32),
        ),
        (
            "riscv64a_oracle_o2",
            Language::RiscVCompressed(RiscVWidth::Rv64),
        ),
    ] {
        let checked: CrossCheck = corpus_cross_check(label, language);
        assert_cross_check_with_unsupported(label, &checked, 18, 6, 1);
    }
}

#[test]
fn live_cross_assemblers_match_gnu_objdump() {
    if let Some(toolchain) = find_arm_toolchain() {
        for (label, source, language, options) in [
            (
                "arm32-a32-live",
                "arm32_a32_forms.s",
                Language::Arm32(ArmMode::A32),
                vec!["-march=armv7-a", "-marm"],
            ),
            (
                "arm32-thumb-live",
                "arm32_thumb_forms.s",
                Language::Arm32(ArmMode::Thumb),
                vec!["-march=armv7-a", "-mthumb"],
            ),
        ] {
            let checked: CrossCheck =
                live_cross_check(&toolchain, label, source, language, &options);
            let expected: usize = if language == Language::Arm32(ArmMode::Thumb) {
                23
            } else {
                20
            };
            assert_cross_check(label, &checked, expected, 0);
        }
    } else {
        println!("ARM cross-toolchain unavailable; set DISROBE_ARM_GNU_BIN or PATH");
    }
    if let Some(toolchain) = find_mips_toolchain() {
        for (label, language, byte_order) in [
            ("mips32le-live", Language::Mips32(Endian::Little), "-EL"),
            ("mips32be-live", Language::Mips32(Endian::Big), "-EB"),
        ] {
            let options: Vec<&str> = vec!["-mips32", "-mno-abicalls", "-fno-pic", byte_order];
            let checked: CrossCheck =
                live_cross_check(&toolchain, label, "mips32_forms.s", language, &options);
            assert_cross_check(label, &checked, 28, 3);
        }
    } else {
        println!("MIPS cross-toolchain unavailable; set DISROBE_MIPS_GNU_BIN or PATH");
    }
    if let Some(toolchain) = find_riscv_toolchain() {
        for (label, source, language, architecture, abi, expected, callother) in [
            (
                "riscv32-live",
                "riscv32_forms.s",
                Language::RiscV(RiscVWidth::Rv32),
                "-march=rv32im",
                "-mabi=ilp32",
                31,
                6,
            ),
            (
                "riscv64-live",
                "riscv64_forms.s",
                Language::RiscV(RiscVWidth::Rv64),
                "-march=rv64im",
                "-mabi=lp64",
                33,
                6,
            ),
            (
                "riscv32c-live",
                "riscv32c_forms.s",
                Language::RiscVCompressed(RiscVWidth::Rv32),
                "-march=rv32imac",
                "-mabi=ilp32",
                19,
                0,
            ),
            (
                "riscv64c-live",
                "riscv64c_forms.s",
                Language::RiscVCompressed(RiscVWidth::Rv64),
                "-march=rv64imac",
                "-mabi=lp64",
                20,
                0,
            ),
            (
                "riscv32a-live",
                "riscv32a_forms.s",
                Language::RiscVCompressed(RiscVWidth::Rv32),
                "-march=rv32imac",
                "-mabi=ilp32",
                10,
                10,
            ),
            (
                "riscv64a-live",
                "riscv64a_forms.s",
                Language::RiscVCompressed(RiscVWidth::Rv64),
                "-march=rv64imac",
                "-mabi=lp64",
                12,
                12,
            ),
        ] {
            let options: Vec<&str> = vec![architecture, abi];
            let checked: CrossCheck =
                live_cross_check(&toolchain, label, source, language, &options);
            assert_cross_check(label, &checked, expected, callother);
        }
    } else {
        println!("RISC-V cross-toolchain unavailable; set DISROBE_RISCV_GNU_BIN or PATH");
    }
    if let Some(toolchain) = find_powerpc_toolchain() {
        let options: Vec<&str> = vec!["-mcpu=powerpc", "-m32", "-mbig"];
        let checked: CrossCheck = live_cross_check(
            &toolchain,
            "powerpc32-live",
            "powerpc32_forms.s",
            Language::PowerPc32Be,
            &options,
        );
        assert_cross_check("powerpc32-live", &checked, 32, 1);
        let ppc64_options: Vec<&str> = vec!["-mcpu=powerpc64", "-m32", "-mbig", "-Wa,-mppc64"];
        let ppc64: CrossCheck = live_cross_check(
            &toolchain,
            "powerpc64-live",
            "powerpc64_forms.s",
            Language::PowerPc64Be,
            &ppc64_options,
        );
        assert_cross_check("powerpc64-live", &ppc64, 30, 2);
    } else {
        println!("PowerPC cross-toolchain unavailable; set DISROBE_POWERPC_GNU_BIN or PATH");
    }
}

#[test]
fn live_cross_gcc_functions_match_gnu_objdump() {
    let common: Vec<&str> = vec![
        "-std=c11",
        "-O2",
        "-fno-asynchronous-unwind-tables",
        "-fno-stack-protector",
        "-fno-unwind-tables",
    ];
    if let Some(toolchain) = find_arm_toolchain() {
        for (label, language, mode, expected) in [
            (
                "arm32-a32-c-live",
                Language::Arm32(ArmMode::A32),
                "-marm",
                19,
            ),
            (
                "arm32-thumb-c-live",
                Language::Arm32(ArmMode::Thumb),
                "-mthumb",
                22,
            ),
        ] {
            let mut options: Vec<&str> = common.clone();
            options.extend(["-march=armv7-a", mode]);
            let checked: CrossCheck =
                live_cross_check(&toolchain, label, "arm32_oracle.c", language, &options);
            assert_cross_check(label, &checked, expected, 0);
        }
    } else {
        println!("ARM cross-toolchain unavailable; set DISROBE_ARM_GNU_BIN or PATH");
    }
    if let Some(toolchain) = find_mips_toolchain() {
        for (label, language, byte_order) in [
            ("mips32le-c-live", Language::Mips32(Endian::Little), "-EL"),
            ("mips32be-c-live", Language::Mips32(Endian::Big), "-EB"),
        ] {
            let mut options: Vec<&str> = common.clone();
            options.extend(["-mips32", "-mno-abicalls", "-fno-pic", byte_order]);
            let checked: CrossCheck =
                live_cross_check(&toolchain, label, "mips32_oracle.c", language, &options);
            assert_cross_check(label, &checked, 20, 0);
        }
    } else {
        println!("MIPS cross-toolchain unavailable; set DISROBE_MIPS_GNU_BIN or PATH");
    }
    if let Some(toolchain) = find_riscv_toolchain() {
        for (label, language, architecture, abi) in [
            (
                "riscv32-c-live",
                Language::RiscV(RiscVWidth::Rv32),
                "-march=rv32im",
                "-mabi=ilp32",
            ),
            (
                "riscv64-c-live",
                Language::RiscV(RiscVWidth::Rv64),
                "-march=rv64im",
                "-mabi=lp64",
            ),
        ] {
            let mut options: Vec<&str> = common.clone();
            options.extend([architecture, abi]);
            let checked: CrossCheck =
                live_cross_check(&toolchain, label, "riscv_oracle.c", language, &options);
            assert_cross_check(label, &checked, 11, 4);
        }
        for (label, language, architecture, abi) in [
            (
                "riscv32-c-compressed-live",
                Language::RiscVCompressed(RiscVWidth::Rv32),
                "-march=rv32imc",
                "-mabi=ilp32",
            ),
            (
                "riscv64-c-compressed-live",
                Language::RiscVCompressed(RiscVWidth::Rv64),
                "-march=rv64imac",
                "-mabi=lp64",
            ),
        ] {
            let mut options: Vec<&str> = common.clone();
            options.push("-Os");
            options.extend([architecture, abi]);
            let checked: CrossCheck =
                live_cross_check(&toolchain, label, "riscv_oracle.c", language, &options);
            assert_cross_check(label, &checked, 11, 1);
        }
        for (label, language, architecture, abi) in [
            (
                "riscv32-c-atomic-live",
                Language::RiscVCompressed(RiscVWidth::Rv32),
                "-march=rv32imac",
                "-mabi=ilp32",
            ),
            (
                "riscv64-c-atomic-live",
                Language::RiscVCompressed(RiscVWidth::Rv64),
                "-march=rv64imac",
                "-mabi=lp64",
            ),
        ] {
            let mut options: Vec<&str> = common.clone();
            options.extend([architecture, abi]);
            let checked: CrossCheck = live_cross_check(
                &toolchain,
                label,
                "riscv_atomic_oracle.c",
                language,
                &options,
            );
            assert_cross_check_with_unsupported(label, &checked, 18, 6, 1);
        }
    } else {
        println!("RISC-V cross-toolchain unavailable; set DISROBE_RISCV_GNU_BIN or PATH");
    }
    if let Some(toolchain) = find_powerpc_toolchain() {
        let options: Vec<&str> = vec![
            "-O2",
            "-ffreestanding",
            "-fno-builtin",
            "-mcpu=powerpc",
            "-m32",
            "-mbig",
        ];
        let checked: CrossCheck = live_cross_check(
            &toolchain,
            "powerpc32-c-live",
            "powerpc_oracle.c",
            Language::PowerPc32Be,
            &options,
        );
        assert_cross_check("powerpc32-c-live", &checked, 11, 1);
    } else {
        println!("PowerPC cross-toolchain unavailable; set DISROBE_POWERPC_GNU_BIN or PATH");
    }
}

fn live_cross_check(
    toolchain: &Toolchain,
    label: &str,
    source_name: &str,
    language: Language,
    options: &[&str],
) -> CrossCheck {
    let directory: PathBuf =
        env::temp_dir().join(format!("disrobe-sleigh-{}-{label}", std::process::id()));
    let create_result: io::Result<()> = fs::create_dir_all(&directory);
    assert!(create_result.is_ok(), "{create_result:?}");
    let object: PathBuf = directory.join("input.o");
    let text: PathBuf = directory.join("input.text");
    let source: PathBuf = fixture_path(source_name);
    let mut compiler_arguments: Vec<OsString> = vec![OsString::from("-c")];
    compiler_arguments.extend(options.iter().map(OsString::from));
    compiler_arguments.extend([
        OsString::from("-o"),
        object.as_os_str().to_owned(),
        source.as_os_str().to_owned(),
    ]);
    let compiler_output: Option<CapturedOutput> = run(&toolchain.gcc, &compiler_arguments);
    assert!(compiler_output.is_some());
    let copy_output: Option<CapturedOutput> = run(
        &toolchain.objcopy,
        &[
            OsString::from("-O"),
            OsString::from("binary"),
            OsString::from("-j"),
            OsString::from(".text"),
            object.as_os_str().to_owned(),
            text.as_os_str().to_owned(),
        ],
    );
    assert!(copy_output.is_some());
    let disassembly_output: Option<CapturedOutput> = run(
        &toolchain.objdump,
        &[
            OsString::from("-d"),
            OsString::from("-z"),
            object.as_os_str().to_owned(),
        ],
    );
    assert!(disassembly_output.is_some());
    let bytes: Vec<u8> = fs::read(&text).unwrap_or_default();
    let report: DecodeReport = decode_block_with_coverage_for_language(language, &bytes, 0);
    let disassembly: String = disassembly_output
        .map(|output: CapturedOutput| String::from_utf8_lossy(&output.stdout).into_owned())
        .unwrap_or_default();
    let reference: Vec<String> = objdump_mnemonics(&disassembly, language);
    let remove_object: io::Result<()> = fs::remove_file(&object);
    let remove_text: io::Result<()> = fs::remove_file(&text);
    let remove_directory: io::Result<()> = fs::remove_dir(&directory);
    assert!(remove_object.is_ok(), "{remove_object:?}");
    assert!(remove_text.is_ok(), "{remove_text:?}");
    assert!(remove_directory.is_ok(), "{remove_directory:?}");
    CrossCheck { reference, report }
}

fn corpus_cross_check(label: &str, language: Language) -> CrossCheck {
    let base: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("corpus")
        .join(label);
    let bytes: Vec<u8> = fs::read(base.with_extension("text")).unwrap_or_default();
    let reference: Vec<String> = fs::read_to_string(base.with_extension("mnemonics"))
        .unwrap_or_default()
        .split_whitespace()
        .map(str::to_owned)
        .collect();
    let report: DecodeReport = decode_block_with_coverage_for_language(language, &bytes, 0);
    CrossCheck { reference, report }
}

fn assert_cross_check(label: &str, checked: &CrossCheck, expected: usize, callother: usize) {
    assert_cross_check_with_unsupported(label, checked, expected, callother, 0);
}

fn assert_cross_check_with_unsupported(
    label: &str,
    checked: &CrossCheck,
    expected: usize,
    callother: usize,
    unsupported: usize,
) {
    let decoded: Vec<String> = checked
        .report
        .instructions
        .iter()
        .map(|instruction| instruction.mnemonic.clone())
        .collect();
    assert_eq!(checked.reference.len(), expected, "{label}");
    assert_eq!(decoded, checked.reference, "{label}");
    assert!((checked.report.coverage.decode_coverage_percent() - 100.0).abs() < f64::EPSILON);
    assert_eq!(checked.report.coverage.callother, callother, "{label}");
    assert_eq!(checked.report.coverage.unsupported, unsupported, "{label}");
}

fn objdump_mnemonics(disassembly: &str, language: Language) -> Vec<String> {
    disassembly
        .lines()
        .filter_map(|line: &str| {
            let (address, body): (&str, &str) = line.split_once(':')?;
            let indented: bool = line.as_bytes().first().is_some_and(u8::is_ascii_whitespace);
            let valid_address: bool = indented
                && !address.trim().is_empty()
                && address
                    .trim()
                    .chars()
                    .all(|character: char| character.is_ascii_hexdigit());
            if !valid_address {
                return None;
            }
            let mnemonic: Option<&str> = body
                .split('\t')
                .filter(|column: &&str| !column.trim().is_empty())
                .nth(1)
                .and_then(|column: &str| column.split_whitespace().next());
            mnemonic.map(|value: &str| {
                if matches!(language, Language::Arm32(_)) {
                    value
                        .strip_suffix(".n")
                        .or_else(|| value.strip_suffix(".w"))
                        .unwrap_or(value)
                        .to_owned()
                } else {
                    value.to_owned()
                }
            })
        })
        .collect()
}

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

fn find_arm_toolchain() -> Option<Toolchain> {
    find_toolchain(
        "arm-linux-androideabi-4.9",
        "arm-linux-androideabi",
        "DISROBE_ARM_GNU_BIN",
    )
}

fn find_mips_toolchain() -> Option<Toolchain> {
    find_toolchain(
        "mipsel-linux-android-4.9",
        "mipsel-linux-android",
        "DISROBE_MIPS_GNU_BIN",
    )
}

fn find_riscv_toolchain() -> Option<Toolchain> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(configured) = env::var_os("DISROBE_RISCV_GNU_BIN") {
        candidates.push(PathBuf::from(configured));
    }
    if let Some(path) = env::var_os("PATH") {
        candidates.extend(env::split_paths(&path));
    }
    if let Some(local_data) = env::var_os("LOCALAPPDATA") {
        candidates.push(
            PathBuf::from(local_data)
                .join("disrobe-tools")
                .join("msys64-riscv")
                .join("ucrt64")
                .join("bin"),
        );
    }
    candidates
        .into_iter()
        .find_map(|candidate: PathBuf| toolchain_in_directory(&candidate, "riscv64-unknown-elf"))
}

fn find_powerpc_toolchain() -> Option<Toolchain> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(configured) = env::var_os("DISROBE_POWERPC_GNU_BIN") {
        candidates.push(PathBuf::from(configured));
    }
    if let Some(path) = env::var_os("PATH") {
        candidates.extend(env::split_paths(&path));
    }
    if let Some(local_data) = env::var_os("LOCALAPPDATA") {
        candidates.push(
            PathBuf::from(local_data)
                .join("disrobe-tools")
                .join("powerpc-eabi-gcc-4.9.0")
                .join("bin"),
        );
    }
    candidates.into_iter().find_map(|candidate: PathBuf| {
        toolchain_in_directory(&candidate, "powerpc-linux-gnu")
            .or_else(|| toolchain_in_directory(&candidate, "powerpc-eabi"))
    })
}

fn find_toolchain(directory: &str, prefix: &str, override_name: &str) -> Option<Toolchain> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(configured) = env::var_os(override_name) {
        candidates.push(PathBuf::from(configured));
    }
    if let Some(path) = env::var_os("PATH") {
        candidates.extend(env::split_paths(&path));
    }
    if let Some(local_data) = env::var_os("LOCALAPPDATA") {
        candidates.push(
            PathBuf::from(local_data)
                .join("disrobe-tools")
                .join("android-ndk-r16b-cross")
                .join("android-ndk-r16b")
                .join("toolchains")
                .join(directory)
                .join("prebuilt")
                .join("windows-x86_64")
                .join("bin"),
        );
    }
    candidates
        .into_iter()
        .find_map(|candidate: PathBuf| toolchain_in_directory(&candidate, prefix))
}

fn toolchain_in_directory(directory: &Path, prefix: &str) -> Option<Toolchain> {
    Some(Toolchain {
        gcc: find_executable(directory, &format!("{prefix}-gcc"))?,
        objcopy: find_executable(directory, &format!("{prefix}-objcopy"))?,
        objdump: find_executable(directory, &format!("{prefix}-objdump"))?,
    })
}

fn find_executable(directory: &Path, stem: &str) -> Option<PathBuf> {
    let plain: PathBuf = directory.join(stem);
    if plain.is_file() {
        return Some(plain);
    }
    let windows: PathBuf = directory.join(format!("{stem}.exe"));
    windows.is_file().then_some(windows)
}

fn run(program: &Path, arguments: &[OsString]) -> Option<CapturedOutput> {
    let result: io::Result<Option<CapturedOutput>> =
        run_captured(program, arguments, TOOL_TIMEOUT, TOOL_CAPTURE_LIMIT);
    assert!(result.is_ok(), "{result:?}");
    let output: Option<CapturedOutput> = result.ok().flatten();
    assert!(output.is_some(), "{} timed out", program.display());
    let output: CapturedOutput = output?;
    assert!(
        output.exit_code == Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    (output.exit_code == Some(0)).then_some(output)
}
