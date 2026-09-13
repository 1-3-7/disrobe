use std::ffi::OsStr;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use disrobe_core::subprocess::{CapturedOutput, run_captured};
use disrobe_pass_native::PseudoAbi;

#[path = "../../../disrobe-pass-native/tests/support/x86_compiler.rs"]
pub mod x86_compiler;

pub(crate) use x86_compiler::assert_x86_artifact;

pub(crate) fn command(compiler: &str) -> Command {
    if cfg!(target_arch = "x86_64") {
        let mut command: Command = Command::new(compiler);
        if cfg!(windows) && compiler == "clang" {
            command.args(["-target", "x86_64-w64-mingw32"]);
        }
        return command;
    }
    let (program, flags): (String, Vec<&str>) =
        x86_compiler::object_compiler(compiler, PseudoAbi::SysV);
    let mut command: Command = Command::new(program);
    command.args(flags).args([
        "-ffreestanding",
        "-fno-stack-protector",
        "-nostdlib",
        "-static",
        "-Wl,-e,main",
    ]);
    if compiler == "clang" {
        command.arg("-fuse-ld=lld");
    }
    command
}

pub(crate) fn run(command: &Command, timeout: Duration) -> std::io::Result<CapturedOutput> {
    let args: Vec<&OsStr> = command.get_args().collect();
    run_captured(
        Path::new(command.get_program()),
        &args,
        timeout,
        4 * 1024 * 1024,
    )?
    .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::TimedOut, "compiler timed out"))
}

pub(crate) fn compiler_available(compiler: &str) -> bool {
    let mut command: Command = command(compiler);
    command.arg("--version");
    let output: CapturedOutput = run(&command, Duration::from_secs(10))
        .unwrap_or_else(|error| panic!("the x86 oracle requires {compiler}: {error}"));
    assert_eq!(
        output.exit_code,
        Some(0),
        "{compiler} must answer --version"
    );
    let version: String = String::from_utf8_lossy(&output.stdout).to_ascii_lowercase();
    let expected_family: bool = match compiler {
        "gcc" => {
            !version.contains("clang")
                && (version.contains("gcc") || version.contains("free software foundation"))
        }
        "clang" => version.contains("clang"),
        other => panic!("unsupported oracle compiler: {other}"),
    };
    assert!(
        expected_family,
        "{compiler} must identify its real compiler family: {version}"
    );
    true
}

pub(crate) fn strip_tool(native: Option<&'static str>) -> Option<&'static str> {
    if cfg!(target_arch = "x86_64") {
        return native;
    }
    let mut command: Command = Command::new("llvm-strip");
    command.arg("--version");
    let output: CapturedOutput = run(&command, Duration::from_secs(10))
        .expect("llvm-strip is required for the cross-compiled ELF oracle");
    assert_eq!(
        output.exit_code,
        Some(0),
        "llvm-strip must answer --version"
    );
    Some("llvm-strip")
}
