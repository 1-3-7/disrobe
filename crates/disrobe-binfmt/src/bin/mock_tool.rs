#![deny(unreachable_pub)]
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

#[allow(
    clippy::print_stderr,
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used
)]
fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!("mock_tool: no mode given");
        return ExitCode::from(2);
    }
    let mode: &str = args[0].as_str();
    match mode {
        "unrar" => mock_unrar(&args[1..]),
        "unrar-fail" => mock_unrar_fail(&args[1..]),
        "sevenz" => mock_sevenz(&args[1..]),
        "sleep" => mock_sleep(&args[1..]),
        other => {
            eprintln!("mock_tool: unknown mode `{other}`");
            ExitCode::from(2)
        }
    }
}

#[allow(clippy::print_stderr)]
fn mock_unrar(rest: &[String]) -> ExitCode {
    let Some(last) = rest.last() else {
        eprintln!("mock_unrar: missing dest");
        return ExitCode::from(2);
    };
    let dest: PathBuf = PathBuf::from(last);
    write_marker(&dest, "mock.txt", b"extracted\n", "mock_unrar")
}

#[allow(clippy::print_stderr)]
fn mock_unrar_fail(rest: &[String]) -> ExitCode {
    let Some(archive): Option<&String> = rest.get(3) else {
        eprintln!("mock_unrar_fail: missing archive");
        return ExitCode::from(2);
    };
    let archive_path: &Path = Path::new(archive);
    let parent_is_scratch: bool = archive_path
        .parent()
        .and_then(Path::file_name)
        .is_some_and(|name: &std::ffi::OsStr| name == "disrobe-scratch");
    if parent_is_scratch {
        ExitCode::from(2)
    } else {
        eprintln!("mock_unrar_fail: archive was not staged under disrobe-scratch");
        ExitCode::from(3)
    }
}

#[allow(clippy::print_stderr)]
fn mock_sevenz(rest: &[String]) -> ExitCode {
    let out_dir: Option<PathBuf> = rest
        .iter()
        .find_map(|a: &String| a.strip_prefix("-o").map(PathBuf::from));
    let Some(dest): Option<PathBuf> = out_dir else {
        eprintln!("mock_sevenz: missing -o<dir>");
        return ExitCode::from(2);
    };
    write_marker(&dest, "iso.txt", b"seveniso\n", "mock_sevenz")
}

#[allow(clippy::print_stderr)]
fn write_marker(dest: &Path, name: &str, body: &[u8], tag: &str) -> ExitCode {
    if let Err(e) = std::fs::create_dir_all(dest) {
        eprintln!("{tag}: mkdir {} failed: {e}", dest.display());
        return ExitCode::from(3);
    }
    let target: PathBuf = dest.join(name);
    if let Err(e) = std::fs::write(&target, body) {
        eprintln!("{tag}: write {} failed: {e}", target.display());
        return ExitCode::from(4);
    }
    ExitCode::SUCCESS
}

fn mock_sleep(rest: &[String]) -> ExitCode {
    let secs: u64 = rest
        .first()
        .and_then(|s: &String| s.parse::<u64>().ok())
        .map_or(60, |value: u64| value);
    std::thread::sleep(Duration::from_secs(secs));
    ExitCode::SUCCESS
}
