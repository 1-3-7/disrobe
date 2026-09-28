#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use disrobe_binfmt::containers::bun::{
    BunModule, BunStandalone, detect_bun, module_contents, parse_bun, sanitize_bun_name,
};

use common::requirement::{BUN, locate, unmeasured};

const MAIN_JS: &str = include_str!("fixtures/bun_compile/main.js");
const LIB_JS: &str = include_str!("fixtures/bun_compile/lib.js");

fn run_bun(bun: &Path, dir: &Path, arguments: &[&str]) {
    let output: Output = Command::new(bun)
        .args(arguments)
        .current_dir(dir)
        .env_remove("FORCE_COLOR")
        .output()
        .expect("run bun");
    assert!(
        output.status.success(),
        "bun {} failed\nstdout:\n{}\nstderr:\n{}",
        arguments.join(" "),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn work_dir(target: &str) -> PathBuf {
    let root: PathBuf = Path::new(env!("CARGO_TARGET_TMPDIR")).join("bun_compile");
    let sources: PathBuf = root.join(target);
    std::fs::create_dir_all(&sources).expect("create bun work directory");
    std::fs::write(sources.join("main.js"), MAIN_JS).expect("write main.js");
    std::fs::write(sources.join("lib.js"), LIB_JS).expect("write lib.js");
    root
}

fn compiled_module_matches_the_bundle(target: &str, outfile: &str) {
    let bun: PathBuf = match locate(&BUN) {
        Ok(path) => path,
        Err(reason) => {
            unmeasured(
                &BUN,
                &format!(
                    "module recovery from a real `bun build --compile --target={target}` binary"
                ),
                &reason,
            );
            return;
        }
    };
    let root: PathBuf = work_dir(target);
    let entry: String = format!("./{target}/main.js");
    let bundle_name: String = format!("./{target}/bundle.js");
    run_bun(
        &bun,
        &root,
        &["build", "--target=bun", &entry, "--outfile", &bundle_name],
    );
    let reference: Vec<u8> =
        std::fs::read(root.join(target).join("bundle.js")).expect("read reference bundle");
    let target_flag: String = format!("--target={target}");
    let binary_name: String = format!("./{target}/{outfile}");
    run_bun(
        &bun,
        &root,
        &[
            "build",
            "--compile",
            &target_flag,
            &entry,
            "--outfile",
            &binary_name,
        ],
    );
    let dir: PathBuf = root.join(target);
    let binary_path: PathBuf = if dir.join(outfile).is_file() {
        dir.join(outfile)
    } else {
        dir.join(format!("{outfile}.exe"))
    };
    let binary: Vec<u8> = std::fs::read(&binary_path).expect("read compiled binary");
    std::fs::remove_file(&binary_path).expect("remove compiled binary");

    assert!(
        detect_bun(&binary).is_some(),
        "{target}: not detected as bun"
    );
    let archive: BunStandalone = parse_bun(&binary).expect("parse compiled binary");
    assert_eq!(archive.modules.len(), 1, "{target}: {:?}", archive.modules);
    let module: &BunModule = &archive.modules[0];
    assert!(module.is_entry);
    let name: String = sanitize_bun_name(&module.name);
    assert!(
        name == outfile || name == format!("{outfile}.exe"),
        "{target}: module name {} sanitizes to {name}",
        module.name
    );
    let contents: &[u8] = module_contents(&binary, &archive, module).expect("module contents");
    assert_eq!(
        contents,
        reference.as_slice(),
        "{target}: the embedded module must equal `bun build --target=bun` output"
    );
}

#[test]
fn a_windows_bun_binary_yields_its_bundle() {
    compiled_module_matches_the_bundle("bun-windows-x64", "hello-windows");
}

#[test]
fn a_linux_bun_binary_yields_its_bundle() {
    compiled_module_matches_the_bundle("bun-linux-x64", "hello-linux");
}

#[test]
fn a_macos_bun_binary_yields_its_bundle() {
    compiled_module_matches_the_bundle("bun-darwin-arm64", "hello-darwin");
}
