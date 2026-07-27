use std::env;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use disrobe_core::scratch::ScratchDir;
use disrobe_core::subprocess::{CapturedOutput, run_captured};
use disrobe_sleigh::coverage::{DecodeReport, decode_block_with_coverage};

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
fn cross_gcc_text_matches_gnu_objdump_at_o0_and_o2() {
    let toolchain: Option<Toolchain> = find_toolchain();
    for optimization in ["-O0", "-O2"] {
        grade_optimization(toolchain.as_ref(), optimization);
    }
}

#[test]
fn assembled_form_matrix_matches_gnu_objdump() {
    let committed: CrossCheck = corpus_cross_check("aarch64_forms");
    assert_cross_check("committed forms", &committed);
    assert_eq!(committed.reference.len(), 64);
    if let Some(toolchain) = find_toolchain() {
        let source: PathBuf = fixture_path("aarch64_forms.s");
        let options: [OsString; 0] = [];
        let live: CrossCheck = cross_check(&toolchain, "assembler", &options, &source, "forms");
        assert_cross_check("live forms", &live);
    }
}

fn grade_optimization(toolchain: Option<&Toolchain>, optimization: &str) {
    let suffix: &str = optimization.trim_start_matches('-');
    let corpus_label: String = format!("aarch64_oracle_{}", suffix.to_ascii_lowercase());
    let committed: CrossCheck = corpus_cross_check(&corpus_label);
    assert_cross_check(&format!("committed {optimization}"), &committed);
    let Some(toolchain) = toolchain else {
        return;
    };
    let source: PathBuf = fixture_path("aarch64_oracle.c");
    let options: [OsString; 4] = [
        OsString::from(optimization),
        OsString::from("-fno-asynchronous-unwind-tables"),
        OsString::from("-fno-stack-protector"),
        OsString::from("-fno-optimize-sibling-calls"),
    ];
    let live: CrossCheck = cross_check(toolchain, "c", &options, &source, suffix);
    assert_cross_check(&format!("live {optimization}"), &live);
}

#[allow(clippy::expect_used)]
fn cross_check(
    toolchain: &Toolchain,
    language: &str,
    options: &[OsString],
    source: &Path,
    label: &str,
) -> CrossCheck {
    let purpose: String = format!("disrobe-sleigh-{label}");
    let scratch: ScratchDir = ScratchDir::create(&purpose).expect("create scratch directory");
    let directory: PathBuf = scratch.path().to_path_buf();
    let object: PathBuf = directory.join("input.o");
    let text: PathBuf = directory.join("input.text");
    let mut compiler_arguments: Vec<OsString> = vec![
        OsString::from("-x"),
        OsString::from(language),
        OsString::from("-c"),
    ];
    compiler_arguments.extend_from_slice(options);
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
        &[OsString::from("-d"), object.as_os_str().to_owned()],
    );
    assert!(disassembly_output.is_some());
    let bytes_result: io::Result<Vec<u8>> = fs::read(&text);
    assert!(bytes_result.is_ok(), "{bytes_result:?}");
    let bytes: Vec<u8> = bytes_result.unwrap_or_default();
    let report: DecodeReport = decode_block_with_coverage(&bytes, 0);
    let reference_text: String = disassembly_output
        .map(|output: CapturedOutput| String::from_utf8_lossy(&output.stdout).into_owned())
        .unwrap_or_default();
    let reference: Vec<String> = objdump_mnemonics(&reference_text);
    let checked: CrossCheck = CrossCheck { reference, report };
    let close_result: io::Result<()> = scratch.close();
    assert!(close_result.is_ok(), "{close_result:?}");
    checked
}

fn assert_cross_check(label: &str, checked: &CrossCheck) {
    let decoded: Vec<String> = checked
        .report
        .instructions
        .iter()
        .map(|instruction| instruction.mnemonic.clone())
        .collect();
    assert!(!checked.reference.is_empty());
    let mismatches: Vec<String> = checked
        .report
        .instructions
        .iter()
        .zip(&checked.reference)
        .enumerate()
        .filter(|(_, (instruction, reference))| instruction.mnemonic != **reference)
        .map(|(index, (instruction, reference))| {
            format!(
                "{index}: expected {reference}, got {} {}",
                instruction.mnemonic, instruction.operands
            )
        })
        .collect();
    assert_eq!(decoded, checked.reference, "{label}: {mismatches:#?}");
    assert!((checked.report.coverage.decode_coverage_percent() - 100.0).abs() < f64::EPSILON);
    assert_eq!(checked.report.coverage.callother, 0);
    assert_eq!(checked.report.coverage.unsupported, 0);
}

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

fn corpus_cross_check(label: &str) -> CrossCheck {
    let base: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("corpus")
        .join(label);
    let text: PathBuf = base.with_extension("text");
    let mnemonics: PathBuf = base.with_extension("mnemonics");
    let bytes_result: io::Result<Vec<u8>> = fs::read(&text);
    assert!(bytes_result.is_ok(), "{bytes_result:?}");
    let bytes: Vec<u8> = bytes_result.unwrap_or_default();
    let reference_result: io::Result<String> = fs::read_to_string(&mnemonics);
    assert!(reference_result.is_ok(), "{reference_result:?}");
    let reference: Vec<String> = reference_result
        .unwrap_or_default()
        .split_whitespace()
        .map(str::to_owned)
        .collect();
    let report: DecodeReport = decode_block_with_coverage(&bytes, 0);
    CrossCheck { reference, report }
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

fn objdump_mnemonics(disassembly: &str) -> Vec<String> {
    disassembly
        .lines()
        .filter_map(|line: &str| {
            let mut parts: std::str::SplitWhitespace<'_> = line.split_whitespace();
            let address: &str = parts.next()?;
            let encoding: &str = parts.next()?;
            let mnemonic: &str = parts.next()?;
            let valid_address: bool = address.ends_with(':')
                && address[..address.len().saturating_sub(1)]
                    .chars()
                    .all(|character: char| character.is_ascii_hexdigit());
            let valid_encoding: bool = encoding.len() == 8
                && encoding
                    .chars()
                    .all(|character: char| character.is_ascii_hexdigit());
            (valid_address && valid_encoding).then(|| mnemonic.to_owned())
        })
        .collect()
}

fn find_toolchain() -> Option<Toolchain> {
    Some(Toolchain {
        gcc: find_tool(
            "AARCH64_GCC",
            &["aarch64-linux-gnu-gcc", "aarch64-none-linux-gnu-gcc"],
        )?,
        objcopy: find_tool(
            "AARCH64_OBJCOPY",
            &[
                "aarch64-linux-gnu-objcopy",
                "aarch64-none-linux-gnu-objcopy",
            ],
        )?,
        objdump: find_tool(
            "AARCH64_OBJDUMP",
            &[
                "aarch64-linux-gnu-objdump",
                "aarch64-none-linux-gnu-objdump",
            ],
        )?,
    })
}

fn find_tool(variable: &str, names: &[&str]) -> Option<PathBuf> {
    if let Some(value) = env::var_os(variable) {
        let path: PathBuf = PathBuf::from(value);
        if path.is_file() {
            return Some(path);
        }
    }
    if let Some(path_value) = env::var_os("PATH") {
        for directory in env::split_paths(&path_value) {
            for name in names {
                for suffix in ["", ".exe"] {
                    let candidate: PathBuf = directory.join(format!("{name}{suffix}"));
                    if candidate.is_file() {
                        return Some(candidate);
                    }
                }
            }
        }
    }
    let local_data: PathBuf = PathBuf::from(env::var_os("LOCALAPPDATA")?);
    let directory: PathBuf = local_data
        .join("disrobe-tools")
        .join("arm-gnu-toolchain-15.2-aarch64-linux")
        .join("bin");
    for name in names {
        let candidate: PathBuf = directory.join(format!("{name}.exe"));
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}
