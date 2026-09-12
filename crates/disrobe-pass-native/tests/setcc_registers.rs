#![allow(clippy::expect_used, clippy::panic)]

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

use disrobe_core::scratch::ScratchDir;
use disrobe_core::subprocess::{CapturedOutput, run_captured};
use disrobe_pass_native::{LeafRecovery, PseudoAbi, recover_leaf_function_abi};

#[path = "support/compiler_toolchain.rs"]
#[allow(clippy::redundant_pub_crate)]
mod compiler_toolchain;

enum Language {
    C,
    Rust,
}

fn rust_compiler() -> String {
    let rustup: String = compiler_toolchain::probe_one("rustup").expect("Rust toolchain required");
    let resolved: CapturedOutput = run_captured(
        Path::new(&rustup),
        &["which", "rustc"],
        Duration::from_secs(30),
        4096,
    )
    .expect("resolve Rust compiler")
    .expect("Rust compiler resolution timeout");
    assert_eq!(resolved.exit_code, Some(0), "Rust compiler required");
    let compiler: String = String::from_utf8(resolved.stdout)
        .expect("Rust compiler path")
        .trim()
        .to_owned();
    assert!(Path::new(&compiler).is_file(), "Rust compiler must exist");
    compiler
}

fn compile_and_run(source: &str, language: Language) -> Vec<u64> {
    let scratch: ScratchDir = ScratchDir::create("disrobe-setcc-registers").expect("scratch");
    let (compiler, extension, mut arguments): (String, &str, Vec<OsString>) = match language {
        Language::C => (
            compiler_toolchain::probe_any(&["gcc", "clang", "cc"]).expect("C compiler required"),
            "c",
            vec!["-std=c11".into(), "-O1".into()],
        ),
        Language::Rust => (
            rust_compiler(),
            "rs",
            vec![
                "--edition=2024".into(),
                "-C".into(),
                "overflow-checks=on".into(),
            ],
        ),
    };
    let input: PathBuf = scratch.path().join(format!("recovered.{extension}"));
    let executable: PathBuf = scratch.path().join(if cfg!(windows) {
        "recovered.exe"
    } else {
        "recovered"
    });
    std::fs::write(&input, source).expect("write recovered source");
    arguments.extend([
        "-o".into(),
        executable.as_os_str().to_owned(),
        input.as_os_str().to_owned(),
    ]);
    let compiled: CapturedOutput = run_captured(
        Path::new(&compiler),
        &arguments,
        Duration::from_mins(1),
        1024 * 1024,
    )
    .expect("start compiler")
    .expect("compiler timeout");
    assert_eq!(
        compiled.exit_code,
        Some(0),
        "compiler failed: {}{}\n{source}",
        String::from_utf8_lossy(&compiled.stdout),
        String::from_utf8_lossy(&compiled.stderr)
    );
    let output: CapturedOutput =
        run_captured(&executable, &[] as &[&str], Duration::from_secs(5), 4096)
            .expect("start recovered program")
            .expect("recovered program timeout");
    assert_eq!(
        output.exit_code,
        Some(0),
        "recovered program failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("UTF-8 results")
        .lines()
        .map(|line: &str| line.parse().expect("integer result"))
        .collect()
}

#[test]
fn extended_low_byte_setcc_preserves_the_other_register_bytes() {
    let encodings: [(u8, u8, u8); 6] = [
        (0xbb, 0xc3, 0xd8),
        (0xba, 0xc2, 0xd0),
        (0xbc, 0xc4, 0xe0),
        (0xbd, 0xc5, 0xe8),
        (0xbe, 0xc6, 0xf0),
        (0xbf, 0xc7, 0xf8),
    ];
    for (load_opcode, set_destination, return_source) in encodings {
        let mut code: Vec<u8> = Vec::with_capacity(26);
        let callee_saved: bool = load_opcode >= 0xbc;
        if callee_saved {
            code.extend_from_slice(&[0x41, 0x50 + (set_destination & 7)]);
        }
        code.extend_from_slice(&[
            0x49,
            load_opcode,
            0x11,
            0x22,
            0x33,
            0x44,
            0x55,
            0x66,
            0x77,
            0x88,
            0x48,
            0x83,
            0xff,
            0x1f,
            0x41,
            0x0f,
            0x93,
            set_destination,
            0x4c,
            0x89,
            return_source,
        ]);
        if callee_saved {
            code.extend_from_slice(&[0x41, 0x58 + (set_destination & 7)]);
        }
        code.push(0xc3);
        let recovered: LeafRecovery = recover_leaf_function_abi(&code, 0x1000, PseudoAbi::SysV)
            .expect("recover an extended low-byte conditional write");
        assert_eq!(recovered.signature.callable_arity(), 1);
        let expected: Vec<u64> = vec![
            0x8877_6655_4433_2200,
            0x8877_6655_4433_2200,
            0x8877_6655_4433_2201,
            0x8877_6655_4433_2201,
            0x8877_6655_4433_2201,
        ];
        let c_source: String = format!(
            "#include <stdint.h>\n#include <stdio.h>\n{}\nint main(void){{const uint64_t inputs[5]={{0,30,31,32,UINT64_MAX}};for(unsigned i=0;i<5;i++)printf(\"%llu\\n\",(unsigned long long)recovered(inputs[i]));return 0;}}",
            recovered.source
        );
        let rust_source: String = format!(
            "{}\nfn main(){{for input in [0u64,30,31,32,u64::MAX]{{println!(\"{{}}\",recovered(input));}}}}",
            recovered
                .rust_source
                .expect("Rust extended low-byte source")
        );
        assert_eq!(compile_and_run(&c_source, Language::C), expected);
        assert_eq!(compile_and_run(&rust_source, Language::Rust), expected);
    }
}
