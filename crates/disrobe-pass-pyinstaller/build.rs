use std::env;
use std::path::Path;

fn main() {
    let target_os: Option<String> = env::var("CARGO_CFG_TARGET_OS").ok();
    let target_env: Option<String> = env::var("CARGO_CFG_TARGET_ENV").ok();
    let manifest_dir: Option<String> = env::var("CARGO_MANIFEST_DIR").ok();
    let (Some(os), Some(env_kind), Some(dir)): (Option<String>, Option<String>, Option<String>) =
        (target_os, target_env, manifest_dir)
    else {
        return;
    };
    if os != "windows" || env_kind != "msvc" {
        return;
    }
    let manifest_path: std::path::PathBuf =
        Path::new(&dir).join("disrobe-pass-pyinstaller.manifest");
    println!("cargo:rerun-if-changed={}", manifest_path.display());
    let path_str: std::path::Display<'_> = manifest_path.display();
    println!("cargo:rustc-link-arg=/MANIFEST:EMBED");
    println!("cargo:rustc-link-arg=/MANIFESTINPUT:{path_str}");
    println!("cargo:rustc-link-arg=/MANIFESTUAC:level='asInvoker'");
}
