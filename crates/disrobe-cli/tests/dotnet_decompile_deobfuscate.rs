#![cfg(feature = "dotnet")]
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static SEQ: AtomicU64 = AtomicU64::new(0);

fn workspace_root() -> PathBuf {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p
}

fn corpus(rel: &str) -> PathBuf {
    workspace_root().join("corpus").join("dotnet").join(rel)
}

fn cli_binary() -> PathBuf {
    let exe: PathBuf = std::env::current_exe().expect("current exe");
    let mut dir: PathBuf = exe.parent().expect("exe dir").to_path_buf();
    while dir.file_name().and_then(|s| s.to_str()) != Some("debug")
        && dir.file_name().and_then(|s| s.to_str()) != Some("release")
    {
        if !dir.pop() {
            break;
        }
    }
    dir.push(if cfg!(windows) {
        "disrobe.exe"
    } else {
        "disrobe"
    });
    dir
}

fn out_dir(stem: &str) -> PathBuf {
    let pid: u32 = std::process::id();
    let seq: u64 = SEQ.fetch_add(1, Ordering::Relaxed);
    let p: PathBuf = std::env::temp_dir().join(format!("disrobe-dotnet-it-{stem}-{pid}-{seq}"));
    let _ = std::fs::remove_dir_all(&p);
    p
}

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
}

fn run(args: &[&str]) -> Run {
    let bin: PathBuf = cli_binary();
    assert!(
        bin.exists(),
        "disrobe binary not built at {} - run `cargo build -p disrobe-cli` first",
        bin.display()
    );
    let output: std::process::Output = Command::new(&bin)
        .args(args)
        .env_remove("RUST_LOG")
        .env_remove("DISROBE_LOG")
        .output()
        .expect("spawn disrobe");
    Run {
        code: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

#[test]
fn decompile_normal_assembly_emits_real_native_csharp() {
    let input: PathBuf = corpus("HelloApp.dll");
    let out: PathBuf = out_dir("decompile-normal");
    let r: Run = run(&[
        "dotnet",
        "decompile",
        input.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ]);
    assert_eq!(r.code, 0, "stdout:\n{}\nstderr:\n{}", r.stdout, r.stderr);
    let native: PathBuf = out.join("HelloApp.native.cs");
    let text: String = std::fs::read_to_string(&native)
        .unwrap_or_else(|e| panic!("native .cs missing at {}: {e}", native.display()));
    assert!(
        text.contains("Hello, World!"),
        "native decompilation did not recover the WriteLine literal:\n{text}"
    );
    assert!(
        out.join("manifest.json").exists(),
        "manifest must be written"
    );
    let _ = std::fs::remove_dir_all(&out);
}

#[test]
fn decompile_does_not_panic_on_truncated_managed_pe() {
    let mut base: Vec<u8> = std::fs::read(corpus("HelloApp.dll")).expect("fixture");
    base.truncate(base.len() / 2);
    let input: PathBuf = std::env::temp_dir().join(format!(
        "disrobe-dotnet-trunc-{}-{}.dll",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::write(&input, &base).expect("write truncated fixture");
    let out: PathBuf = out_dir("decompile-truncated");
    let r: Run = run(&[
        "dotnet",
        "decompile",
        input.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ]);
    assert!(
        r.code == 0 || r.code == 1,
        "must fail soft, not crash (code={}). stderr:\n{}",
        r.code,
        r.stderr
    );
    assert!(
        !r.stderr.contains("panicked") && !r.stdout.contains("panicked"),
        "decompile panicked on truncated PE. stderr:\n{}",
        r.stderr
    );
    let _ = std::fs::remove_file(&input);
    let _ = std::fs::remove_dir_all(&out);
}

#[test]
fn deobfuscate_confuserex2_recovers_real_data() {
    let input: PathBuf = corpus("SampleConstants.confuserex2.dll");
    let out: PathBuf = out_dir("peel-cx2");
    let r: Run = run(&[
        "dotnet",
        "deobfuscate",
        input.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ]);
    assert_eq!(r.code, 0, "stdout:\n{}\nstderr:\n{}", r.stdout, r.stderr);
    assert!(
        r.stdout.contains("ConfuserEx2"),
        "expected ConfuserEx2 detection:\n{}",
        r.stdout
    );
    let report: String = std::fs::read_to_string(out.join("peel.json")).expect("peel.json");
    assert!(
        report.contains("DISROBE_CONFUSER_CONSTANT_PROOF_8842"),
        "decrypted constant string not surfaced in report:\n{report}"
    );
    let strings: String =
        std::fs::read_to_string(out.join("SampleConstants.confuserex2.recovered-strings.txt"))
            .expect("recovered-strings.txt");
    assert!(
        strings.contains("DISROBE_CONFUSER_CONSTANT_PROOF_8842"),
        "decrypted constant string not written to disk:\n{strings}"
    );
    let _ = std::fs::remove_dir_all(&out);
}

#[test]
fn deobfuscate_obfuscar_classifies_renamable_identifiers() {
    let input: PathBuf = corpus("HelloAppLegacy.obfuscar.dll");
    let out: PathBuf = out_dir("peel-obfuscar");
    let r: Run = run(&[
        "dotnet",
        "deobfuscate",
        input.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ]);
    assert_eq!(r.code, 0, "stdout:\n{}\nstderr:\n{}", r.stdout, r.stderr);
    assert!(
        r.stdout.contains("Obfuscar"),
        "expected Obfuscar detection:\n{}",
        r.stdout
    );
    let report: String = std::fs::read_to_string(out.join("peel.json")).expect("peel.json");
    assert!(
        report.contains("\"detected\": \"Obfuscar\""),
        "peel.json must record the detected protector:\n{report}"
    );
    assert!(
        report.contains("renamable_identifiers"),
        "peel.json must record renamable identifier classification:\n{report}"
    );
    let _ = std::fs::remove_dir_all(&out);
}

#[test]
fn deobfuscate_forced_themida_surfaces_honest_wall() {
    let input: PathBuf = corpus("HelloApp.dll");
    let out: PathBuf = out_dir("peel-wall");
    let r: Run = run(&[
        "dotnet",
        "deobfuscate",
        input.to_str().unwrap(),
        "--protector",
        "themida-dotnet",
        "--out",
        out.to_str().unwrap(),
    ]);
    assert_eq!(r.code, 0, "stdout:\n{}\nstderr:\n{}", r.stdout, r.stderr);
    assert!(
        r.stdout.contains("WALL") && r.stdout.contains("not fabricated"),
        "wall must be surfaced honestly, not as fake success:\n{}",
        r.stdout
    );
    let report: String = std::fs::read_to_string(out.join("peel.json")).expect("peel.json");
    assert!(
        report.contains("\"walled\": true") && report.contains("detect-only-native-or-vm"),
        "peel.json must mark the native-VM wall:\n{report}"
    );
    let _ = std::fs::remove_dir_all(&out);
}

#[test]
fn deobfuscate_rejects_malformed_pe_without_panic() {
    let input: PathBuf = std::env::temp_dir().join(format!(
        "disrobe-dotnet-junk-{}-{}.bin",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::write(&input, b"MZ\x00\x00 not a real portable executable at all")
        .expect("write junk");
    let out: PathBuf = out_dir("peel-junk");
    let r: Run = run(&[
        "dotnet",
        "deobfuscate",
        input.to_str().unwrap(),
        "--protector",
        "obfuscar",
        "--out",
        out.to_str().unwrap(),
    ]);
    assert_eq!(
        r.code, 1,
        "malformed input must fail soft with an error exit"
    );
    assert!(
        !r.stderr.contains("panicked"),
        "must not panic on malformed PE. stderr:\n{}",
        r.stderr
    );
    let _ = std::fs::remove_file(&input);
    let _ = std::fs::remove_dir_all(&out);
}
