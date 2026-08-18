#![cfg(feature = "chain")]
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::unwrap_used
)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use disrobe_core::scratch::ScratchDir;
use disrobe_core::subprocess::{CapturedOutput, wait_with_direct_process_output_timeout};
use disrobe_ir::payload::DisasmPayload;
use disrobe_pass_native::{Arch, FunctionSpan, build_disasm_payload, function_spans};
use serde_json::Value;

const MAX_CAPTURE_BYTES: usize = 1 << 20;

fn run_bounded(command: &mut Command, seconds: u64) -> CapturedOutput {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let child: std::process::Child = command.spawn().expect("spawn bounded process");
    wait_with_direct_process_output_timeout(child, Duration::from_secs(seconds), MAX_CAPTURE_BYTES)
        .expect("bounded process must complete")
}

fn find_file_named(root: &Path, target: &str) -> Option<PathBuf> {
    for entry in std::fs::read_dir(root).ok()?.flatten() {
        let path: PathBuf = entry.path();
        if path.is_dir() {
            if let Some(found) = find_file_named(&path, target) {
                return Some(found);
            }
        } else if entry.file_name().to_string_lossy() == target {
            return Some(path);
        }
    }
    None
}

#[test]
fn auto_recovers_an_authored_x86_64_direct_trap_guard() {
    let scratch: ScratchDir = ScratchDir::create("auto-native-trap-guard").expect("scratch");
    let source_path: PathBuf = scratch.path().join("direct_trap_guard.c");
    let image_path: PathBuf = scratch.path().join("direct_trap_guard.elf");
    let out_path: PathBuf = scratch.path().join("out");
    let second_out_path: PathBuf = scratch.path().join("out-second");
    std::fs::write(
        &source_path,
        "__attribute__((noinline)) long long direct_trap_guard(long long x){ if (x < 0) __builtin_trap(); return x + 1; }",
    )
    .expect("authored source");
    let compiled: CapturedOutput = run_bounded(
        Command::new("clang")
            .arg("--target=x86_64-linux-gnu")
            .arg("-fuse-ld=lld")
            .arg("-O1")
            .arg("-fno-stack-protector")
            .arg("-nostdlib")
            .arg("-static")
            .arg("-Wl,--build-id=none")
            .arg("-Wl,-e,direct_trap_guard")
            .arg(&source_path)
            .arg("-o")
            .arg(&image_path),
        30,
    );
    assert_eq!(
        compiled.exit_code,
        Some(0),
        "clang/lld failed: {}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let image: Vec<u8> = std::fs::read(&image_path).expect("authored x86-64 ELF");
    let payload: DisasmPayload = build_disasm_payload(&image).expect("disassemble authored ELF");
    let span: FunctionSpan = function_spans(&payload, Arch::X86_64)
        .into_iter()
        .find(|span: &FunctionSpan| span.name == "direct_trap_guard")
        .expect("authored function symbol");
    assert!(
        payload.instructions.iter().any(|instruction| {
            instruction.offset >= span.address
                && instruction.offset < span.end
                && instruction.mnemonic == "ud2"
        }),
        "authored function must carry decoded UD2 evidence"
    );
    let auto: CapturedOutput = run_bounded(
        Command::new(env!("CARGO_BIN_EXE_disrobe"))
            .arg("auto")
            .arg(&image_path)
            .arg("--out")
            .arg(&out_path),
        30,
    );
    assert_eq!(
        auto.exit_code,
        Some(0),
        "disrobe auto failed: {}",
        String::from_utf8_lossy(&auto.stderr)
    );
    let report_path: PathBuf =
        find_file_named(&out_path, "pseudo-source.json").expect("pseudo-source output");
    let report_text: String = std::fs::read_to_string(&report_path).expect("pseudo-source text");
    let report: Value = serde_json::from_str(&report_text).expect("pseudo-source JSON");
    assert_eq!(report["run"], true);
    assert_eq!(report["functions_recovered"], 1);
    assert_eq!(report["functions_unrecovered"], 0);
    let recovered: &Value = &report["recovered"][0];
    assert_eq!(recovered["name"], "direct_trap_guard");
    let c_source: &str = recovered["source"].as_str().expect("C source");
    let rust_source: &str = recovered["rust_source"].as_str().expect("Rust source");
    assert!(c_source.contains("__builtin_trap();"), "{c_source}");
    assert!(!c_source.contains("goto "), "{c_source}");
    assert!(
        rust_source.contains("std::process::abort();"),
        "{rust_source}"
    );
    let second_auto: CapturedOutput = run_bounded(
        Command::new(env!("CARGO_BIN_EXE_disrobe"))
            .arg("auto")
            .arg(&image_path)
            .arg("--out")
            .arg(&second_out_path),
        30,
    );
    assert_eq!(second_auto.exit_code, Some(0));
    let second_report_path: PathBuf = find_file_named(&second_out_path, "pseudo-source.json")
        .expect("second pseudo-source output");
    let second_report_text: String =
        std::fs::read_to_string(second_report_path).expect("second pseudo-source text");
    assert_eq!(report_text, second_report_text);
}
