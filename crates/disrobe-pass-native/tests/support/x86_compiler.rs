use std::path::Path;
use std::sync::OnceLock;
use std::time::Duration;

use disrobe_core::subprocess::{CapturedOutput, run_captured};
use disrobe_pass_native::PseudoAbi;
use object::Object as _;

fn cc_family() -> &'static str {
    static FAMILY: OnceLock<&'static str> = OnceLock::new();
    FAMILY.get_or_init(|| {
        let output: CapturedOutput = run_captured(
            Path::new("cc"),
            &["--version"],
            Duration::from_secs(10),
            4 * 1024 * 1024,
        )
        .expect("probe the cc compiler family")
        .expect("cc version probe must finish");
        assert_eq!(output.exit_code, Some(0), "cc must answer --version");
        let version: String = String::from_utf8_lossy(&output.stdout).to_ascii_lowercase();
        if version.contains("clang") {
            "clang"
        } else {
            assert!(
                version.contains("gcc") || version.contains("free software foundation"),
                "cc must identify its GNU or Clang family: {version}"
            );
            "gcc"
        }
    })
}

pub(crate) fn object_compiler(compiler: &str, abi: PseudoAbi) -> (String, Vec<&'static str>) {
    let ms_abi: bool = match abi {
        PseudoAbi::MsX64 => true,
        PseudoAbi::SysV => false,
        PseudoAbi::Aapcs64 => panic!("AAPCS64 is not an x86 oracle ABI"),
    };
    let family: &str = if compiler == "cc" {
        cc_family()
    } else {
        compiler
    };
    match family {
        "gcc" => {
            let variable: &str = if ms_abi {
                "DISROBE_SIMILARITY_GCC"
            } else {
                "DISROBE_GCC_BIN"
            };
            let program: String = match std::env::var(variable) {
                Ok(program) => program,
                Err(std::env::VarError::NotPresent) if cfg!(target_arch = "x86_64") => {
                    compiler.to_owned()
                }
                Err(error) => panic!("{variable} must name an x86 GNU compiler: {error}"),
            };
            let abi_flag: &str = if ms_abi { "-mabi=ms" } else { "-mabi=sysv" };
            (program, vec![abi_flag])
        }
        "clang" => {
            let target: &str = if ms_abi {
                "--target=x86_64-w64-windows-gnu"
            } else {
                "--target=x86_64-unknown-linux-gnu"
            };
            (compiler.to_owned(), vec![target])
        }
        other => panic!("unsupported x86 oracle compiler: {other}"),
    }
}

pub(crate) fn assert_x86_artifact(bytes: &[u8]) {
    let file: object::File<'_> = object::File::parse(bytes).expect("parse compiler artifact");
    assert_eq!(
        file.architecture(),
        object::Architecture::X86_64,
        "an x86 recovery oracle must consume an x86-64 compiler artifact"
    );
}
