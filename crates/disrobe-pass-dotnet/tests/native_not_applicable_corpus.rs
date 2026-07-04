#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::disallowed_methods,
    clippy::missing_panics_doc
)]

use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use disrobe_pass_dotnet::protectors::{DetectionReport, detect_all, is_dotnet_assembly};

fn tool_available(tool: &str) -> bool {
    Command::new(tool)
        .arg("--version")
        .output()
        .is_ok_and(|o: std::process::Output| o.status.success())
}

fn first_c_compiler() -> Option<&'static str> {
    ["cc", "gcc", "clang"]
        .into_iter()
        .find(|c: &&'static str| tool_available(c))
}

fn scratch_dir() -> PathBuf {
    let stamp: u128 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_nanos();
    let dir: PathBuf =
        std::env::temp_dir().join(format!("disrobe-dn-corpus-{}-{stamp}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

fn exe_name(stem: &str) -> String {
    if cfg!(windows) {
        format!("{stem}.exe")
    } else {
        stem.to_string()
    }
}

const NATIVE_SRC: &str = r#"
#include <stdio.h>
int main(void){ const char* s = "Themida .themida .vmp0 WinLicense ConfuserEx"; puts(s); return 0; }
"#;

#[test]
fn native_benign_is_not_a_dotnet_assembly() {
    let Some(cc): Option<&'static str> = first_c_compiler() else {
        eprintln!("SKIP: no C compiler available");
        return;
    };
    let dir: PathBuf = scratch_dir();
    let src: PathBuf = dir.join("nat.c");
    std::fs::write(&src, NATIVE_SRC).expect("write native source");
    let out: PathBuf = dir.join(exe_name("nat"));
    let built: bool = Command::new(cc)
        .arg("-O2")
        .arg(&src)
        .arg("-o")
        .arg(&out)
        .status()
        .is_ok_and(|s: std::process::ExitStatus| s.success());
    if !built {
        eprintln!("SKIP: {cc} build failed");
        let _ = std::fs::remove_dir_all(&dir);
        return;
    }
    let bytes: Vec<u8> = std::fs::read(&out).expect("read native binary");
    assert!(
        !is_dotnet_assembly(&bytes),
        "a native binary that merely contains protector name strings must not be treated as a \
         .NET assembly"
    );
    let report: DetectionReport = detect_all(&bytes);
    assert!(
        report.matches.is_empty() && report.primary.is_none(),
        "the .NET protector classifier must return not-applicable on a native benign; got {:?}",
        report.matches.keys().collect::<Vec<_>>()
    );
    let _ = std::fs::remove_dir_all(&dir);
}
