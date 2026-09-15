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

fn compile_and_run(compiler: &str, source: &str, extension: &str) -> Vec<u64> {
    let scratch: ScratchDir = ScratchDir::create("disrobe-nested-follow").expect("scratch");
    let input: PathBuf = scratch.path().join(format!("recovered.{extension}"));
    let executable: PathBuf = scratch.path().join(if cfg!(windows) {
        "recovered.exe"
    } else {
        "recovered"
    });
    std::fs::write(&input, source).expect("write recovered source");
    let mut arguments: Vec<OsString> = match extension {
        "rs" => vec![
            "--edition=2024".into(),
            "-C".into(),
            "overflow-checks=on".into(),
        ],
        "c" => vec!["-std=c11".into(), "-O1".into()],
        _ => panic!("unsupported source extension"),
    };
    arguments.extend([
        "-o".into(),
        executable.as_os_str().to_owned(),
        input.as_os_str().to_owned(),
    ]);
    let compiled: CapturedOutput = run_captured(
        Path::new(compiler),
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
            .expect("recovered loop did not terminate");
    assert_eq!(
        output.exit_code,
        Some(0),
        "recovered program failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("UTF-8 results")
        .lines()
        .map(|line| line.parse().expect("integer result"))
        .collect()
}

#[test]
fn nested_loop_return_values_survive_an_unconditional_outer_latch() {
    let original: [u8; 44] = [
        0x31, 0xc0, 0x31, 0xd2, 0xeb, 0x00, 0x83, 0xc0, 0x01, 0xeb, 0x00, 0x39, 0xc8, 0x74, 0x11,
        0x83, 0xc2, 0x01, 0x83, 0xfa, 0x0a, 0x7c, 0xf4, 0x83, 0xf8, 0x07, 0x7d, 0x0a, 0x31, 0xd2,
        0xeb, 0xe6, 0xb8, 0x65, 0x00, 0x00, 0x00, 0xc3, 0xb8, 0xca, 0x00, 0x00, 0x00, 0xc3,
    ];
    let mut reordered: [u8; 44] = original;
    reordered[14] = 0x17;
    reordered[27] = 0x04;
    reordered[33] = 202;
    reordered[39] = 101;
    let c_compiler: String =
        compiler_toolchain::probe_any(&["gcc", "clang", "cc"]).expect("C compiler required");
    let rustup: String = compiler_toolchain::probe_one("rustup").expect("Rust toolchain required");
    let rust_path: CapturedOutput = run_captured(
        Path::new(&rustup),
        &["which", "rustc"],
        Duration::from_secs(30),
        4096,
    )
    .expect("resolve Rust compiler")
    .expect("Rust compiler resolution timeout");
    assert_eq!(
        rust_path.exit_code,
        Some(0),
        "Rust compiler required: {}{}",
        String::from_utf8_lossy(&rust_path.stdout),
        String::from_utf8_lossy(&rust_path.stderr)
    );
    let rust_compiler: String = String::from_utf8(rust_path.stdout)
        .expect("Rust compiler path")
        .trim()
        .to_owned();
    assert!(
        Path::new(&rust_compiler).is_file(),
        "resolved Rust compiler must exist"
    );
    let expected: Vec<u64> = (-2i64..=10)
        .map(|input| if (1..=7).contains(&input) { 101 } else { 202 })
        .collect();
    for code in [original, reordered] {
        let recovered: LeafRecovery = recover_leaf_function_abi(&code, 0x1000, PseudoAbi::MsX64)
            .expect("recover nested loops with distinct early and normal returns");
        assert_eq!(recovered.signature.callable_arity(), 1);
        assert_eq!(recovered.source.matches("while (").count(), 2);
        let rust: String = recovered.rust_source.expect("Rust loop source");
        assert_eq!(
            rust.lines()
                .filter(|line| {
                    let line: &str = line.trim_start();
                    line.starts_with("loop {") || line.starts_with("while ")
                })
                .count(),
            2
        );
        let c_source: String = format!(
            "#include <stdint.h>\n#include <stdio.h>\n{}\nint main(void){{for(int64_t n=-2;n<=10;n++)printf(\"%llu\\n\",(unsigned long long)recovered((uint64_t)n));return 0;}}",
            recovered.source
        );
        let rust_source: String = format!(
            "#![allow(unused)]\n{rust}\nfn main(){{for n in -2i64..=10{{println!(\"{{}}\",recovered(n as u64));}}}}"
        );
        assert_eq!(compile_and_run(&c_compiler, &c_source, "c"), expected);
        assert_eq!(
            compile_and_run(&rust_compiler, &rust_source, "rs"),
            expected
        );
    }
}
