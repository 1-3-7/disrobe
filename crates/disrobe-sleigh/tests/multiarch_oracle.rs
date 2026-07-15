use std::env;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use disrobe_core::subprocess::{CapturedOutput, run_captured};
use disrobe_sleigh::coverage::{DecodeReport, decode_block_with_coverage_for_language};
use disrobe_sleigh::lifter::{ArmMode, Language};
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
    ] {
        let checked: CrossCheck = corpus_cross_check(label, language);
        assert_cross_check(label, &checked, expected, 0);
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
    let reference: Vec<String> = objdump_mnemonics(&disassembly);
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
    assert_eq!(checked.report.coverage.unsupported, 0, "{label}");
}

fn objdump_mnemonics(disassembly: &str) -> Vec<String> {
    disassembly
        .lines()
        .filter_map(|line: &str| {
            let mut parts: std::str::SplitWhitespace<'_> = line.split_whitespace();
            let address: &str = parts.next()?;
            let valid_address: bool = address.ends_with(':')
                && address[..address.len().saturating_sub(1)]
                    .chars()
                    .all(|character: char| character.is_ascii_hexdigit());
            if !valid_address {
                return None;
            }
            let mut mnemonic: Option<&str> = None;
            for part in parts {
                let encoding: bool = matches!(part.len(), 4 | 8)
                    && part
                        .chars()
                        .all(|character: char| character.is_ascii_hexdigit());
                if !encoding {
                    mnemonic = Some(part);
                    break;
                }
            }
            mnemonic.map(|value: &str| {
                value
                    .strip_suffix(".n")
                    .or_else(|| value.strip_suffix(".w"))
                    .unwrap_or(value)
                    .to_owned()
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
