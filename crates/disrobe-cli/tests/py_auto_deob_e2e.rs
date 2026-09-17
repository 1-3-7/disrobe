#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::path::{Path, PathBuf};
use std::process::Command;

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

fn corpus_fixture(rel: &str) -> Option<PathBuf> {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.push("corpus");
    for seg in rel.split('/') {
        p.push(seg);
    }
    p.exists().then_some(p)
}

fn temp_path(stem: &str, ext: &str) -> (disrobe_core::scratch::ScratchDir, PathBuf) {
    let purpose: String = format!("disrobe-py-auto-{stem}");
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch directory");
    let path: PathBuf = scratch.path().join(format!("payload.{ext}"));
    (scratch, path)
}

#[derive(Debug)]
struct Run {
    code: i32,
    stdout: String,
    stderr: String,
}

fn run_disrobe(args: &[&str]) -> Run {
    let bin: PathBuf = cli_binary();
    assert!(
        bin.exists(),
        "disrobe binary not built at {} - run `cargo build -p disrobe-cli` before tests",
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
fn py_decompile_list_enumerates_supported_obfuscators() {
    let r: Run = run_disrobe(&["py", "decompile", "--list"]);
    assert_eq!(r.code, 0, "stderr: {}", r.stderr);
    for kw in ["BlankOBF", "Kramer", "Oxyry", "pyminifier"] {
        assert!(
            r.stdout.contains(kw),
            "--list output missing `{kw}`:\n{}",
            r.stdout
        );
    }
}

#[test]
fn py_deob_list_enumerates_supported_obfuscators() {
    let r: Run = run_disrobe(&["py", "deob", "--list"]);
    assert_eq!(r.code, 0, "stderr: {}", r.stderr);
    assert!(r.stdout.contains("BlankOBF"), "stdout:\n{}", r.stdout);
    assert!(
        r.stdout.contains("disrobe py decompile"),
        "stdout:\n{}",
        r.stdout
    );
}

#[test]
fn py_decompile_auto_deobfuscates_real_obfuscated_fixture() {
    let Some(fixture): Option<PathBuf> =
        corpus_fixture("python/obfuscators/blankobf/edge-cases/real_hello_world.py")
    else {
        eprintln!("skip: blankobf real_hello_world fixture absent");
        return;
    };
    let (_out_dir_scratch, out_dir): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("blankobf", "out");
    let _ = std::fs::remove_dir_all(&out_dir);
    let r: Run = run_disrobe(&[
        "py",
        "decompile",
        fixture.to_str().unwrap(),
        "--out",
        out_dir.to_str().unwrap(),
    ]);
    assert_eq!(
        r.code, 0,
        "auto-deob decompile must succeed; stdout={} stderr={}",
        r.stdout, r.stderr
    );
    assert!(
        r.stdout.contains("auto-deobfuscated"),
        "stdout must report the auto-deob route:\n{}",
        r.stdout
    );
    assert!(
        r.stdout.contains("detected") && r.stdout.contains("deobfuscated"),
        "stdout must surface the detect -> deobfuscate chain:\n{}",
        r.stdout
    );
    let produced: PathBuf = out_dir.join("real_hello_world.py");
    let recovered: String = std::fs::read_to_string(&produced)
        .unwrap_or_else(|e| panic!("expected recovered source at {}: {e}", produced.display()));
    assert!(
        recovered.contains("print") || recovered.contains("def ") || recovered.contains('='),
        "recovered source not recognizable:\n{recovered}"
    );
    let original: Vec<u8> = std::fs::read(&fixture).expect("read fixture");
    assert_ne!(
        recovered.as_bytes(),
        original.as_slice(),
        "recovered source must differ from the obfuscated input"
    );
    let _ = std::fs::remove_dir_all(&out_dir);
}

fn py_deob_status_for(recovery_json: &str) -> Option<String> {
    let key: &str = "\"name\": \"py.deob\"";
    let name_pos: usize = recovery_json.find(key)?;
    let tail: &str = &recovery_json[name_pos..];
    let status_pos: usize = tail.find("\"status\":")?;
    let after: &str = &tail[status_pos + "\"status\":".len()..];
    let open: usize = after.find('"')?;
    let rest: &str = &after[open + 1..];
    let close: usize = rest.find('"')?;
    Some(rest[..close].to_owned())
}

fn find_extracted_ending_with(out_dir: &Path, suffix: &str) -> Option<PathBuf> {
    let mut stack: Vec<PathBuf> = vec![out_dir.join("extracted")];
    while let Some(dir) = stack.pop() {
        let Ok(entries): std::io::Result<std::fs::ReadDir> = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path: PathBuf = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path
                .file_name()
                .and_then(|n: &std::ffi::OsStr| n.to_str())
                .is_some_and(|n: &str| n.ends_with(suffix))
            {
                return Some(path);
            }
        }
    }
    None
}

const NEWLY_WIRED_CHAIN_FAMILIES: &[(&str, &str)] = &[
    (
        "blankobf",
        "python/obfuscators/blankobf/edge-cases/real_hello_world.py",
    ),
    (
        "kramer",
        "python/obfuscators/kramer/edge-cases/real_hello_world_pre_compile.py",
    ),
    (
        "pyminifier",
        "python/obfuscators/pyminifier/edge-cases/real_hello_world.py",
    ),
    (
        "manglify",
        "python/obfuscators/manglify/edge-cases/real_hello_world.py",
    ),
    (
        "plusobf",
        "python/obfuscators/plusobf/edge-cases/real_hello_world.py",
    ),
    (
        "patchwork",
        "python/obfuscators/patchwork/real_hello_world.py",
    ),
];

#[test]
fn auto_chain_recovers_newly_wired_python_families() {
    let mut proved: usize = 0;
    for (family, rel) in NEWLY_WIRED_CHAIN_FAMILIES {
        let Some(fixture): Option<PathBuf> = corpus_fixture(rel) else {
            eprintln!("skip: {family} fixture absent at {rel}");
            continue;
        };
        let (_out_dir_scratch, out_dir): (disrobe_core::scratch::ScratchDir, PathBuf) =
            temp_path(family, "out");
        let _ = std::fs::remove_dir_all(&out_dir);
        let r: Run = run_disrobe(&[
            "auto",
            fixture.to_str().unwrap(),
            "--out",
            out_dir.to_str().unwrap(),
        ]);
        assert_eq!(
            r.code, 0,
            "auto must exit 0 for {family}; stdout={} stderr={}",
            r.stdout, r.stderr
        );
        let recovery_path: PathBuf = out_dir.join("recovery.json");
        let recovery: String = std::fs::read_to_string(&recovery_path).unwrap_or_else(|e| {
            panic!(
                "expected recovery.json for {family} at {}: {e}",
                recovery_path.display()
            )
        });
        let status: String = py_deob_status_for(&recovery).unwrap_or_else(|| {
            panic!(
                "auto chain did not run py.deob on {family}; the obfuscator-family registry is \
                 not wired through the chain. recovery.json:\n{recovery}"
            )
        });
        assert!(
            status == "advanced" || status == "recovered",
            "auto chain must REALLY drive {family} through py.deob (not detect-only, not failed); \
             got status={status}. recovery.json:\n{recovery}"
        );
        let recovered_src: PathBuf = find_extracted_ending_with(&out_dir, ".deobfuscated.py")
            .unwrap_or_else(|| {
                panic!(
                    "py.deob must fan out the recovered source as a child under extracted/ for \
                     {family}; recovery.json:\n{recovery}"
                )
            });
        let recovered: String =
            std::fs::read_to_string(&recovered_src).expect("read recovered source child");
        let original: Vec<u8> = std::fs::read(&fixture).expect("read fixture");
        assert_ne!(
            recovered.as_bytes(),
            original.as_slice(),
            "recovered source child must differ from the obfuscated input for {family}"
        );
        let manifest_path: PathBuf = find_extracted_ending_with(&out_dir, ".manifest.json")
            .unwrap_or_else(|| {
                panic!(
                    "py.deob auto/chain must emit the manifest.json sidecar (PeelResult \
                     provenance) to reach parity with `disrobe py deob` for {family}"
                )
            });
        let manifest: String =
            std::fs::read_to_string(&manifest_path).expect("read py.deob manifest sidecar");
        assert!(
            manifest.contains("\"peel\"") && manifest.contains("\"steps\""),
            "manifest sidecar must carry the full PeelResult (steps/converged/recovered) for \
             {family}; got:\n{manifest}"
        );
        let _ = std::fs::remove_dir_all(&out_dir);
        proved += 1;
    }
    assert!(
        proved > 0,
        "no newly-wired family fixture was present; expected at least one of \
         {NEWLY_WIRED_CHAIN_FAMILIES:?}"
    );
}

#[test]
fn auto_chain_does_not_fabricate_recovery_for_garbage() {
    let (_garbage_scratch, garbage): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("auto-garbage", "py");
    std::fs::write(
        &garbage,
        b"\x00\x01\x02\x03\xff\xfe not pyc not a known obfuscator \x80\x81\x82",
    )
    .expect("write garbage");
    let (_out_dir_scratch, out_dir): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("auto-garbage", "out");
    let _ = std::fs::remove_dir_all(&out_dir);
    let _ = run_disrobe(&[
        "auto",
        garbage.to_str().unwrap(),
        "--out",
        out_dir.to_str().unwrap(),
    ]);
    let recovery_path: PathBuf = out_dir.join("recovery.json");
    if let Ok(recovery) = std::fs::read_to_string(&recovery_path)
        && let Some(status) = py_deob_status_for(&recovery)
    {
        assert_ne!(
            status, "recovered",
            "py.deob must not claim garbage as recovered. recovery.json:\n{recovery}"
        );
    }
    let _ = std::fs::remove_file(&garbage);
    let _ = std::fs::remove_dir_all(&out_dir);
}

#[test]
fn py_decompile_unknown_input_prints_guidance_and_does_not_fabricate() {
    let (_garbage_scratch, garbage): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("garbage", "py");
    std::fs::write(
        &garbage,
        b"\x00\x01\x02\x03\xff\xfe not pyc not a known obfuscator \x80\x81\x82",
    )
    .expect("write garbage");
    let (_out_dir_scratch, out_dir): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("garbage", "out");
    let _ = std::fs::remove_dir_all(&out_dir);
    let r: Run = run_disrobe(&[
        "py",
        "decompile",
        garbage.to_str().unwrap(),
        "--out",
        out_dir.to_str().unwrap(),
    ]);
    assert_ne!(
        r.code, 0,
        "unknown input must not exit 0 with fabricated source; stdout={} stderr={}",
        r.stdout, r.stderr
    );
    let combined: String = format!("{}{}", r.stdout, r.stderr);
    assert!(
        combined.contains("supports these Python obfuscators") || combined.contains("supported"),
        "must print the supported-obfuscator guidance:\nstdout={}\nstderr={}",
        r.stdout,
        r.stderr
    );
    for kw in ["BlankOBF", "Kramer"] {
        assert!(
            combined.contains(kw),
            "guidance must list `{kw}`:\nstdout={}\nstderr={}",
            r.stdout,
            r.stderr
        );
    }
    let produced: PathBuf = out_dir.join("garbage.py");
    assert!(
        !produced.exists(),
        "no fabricated source file must be written for unknown input"
    );
    let _ = std::fs::remove_file(&garbage);
    let _ = std::fs::remove_dir_all(&out_dir);
}
