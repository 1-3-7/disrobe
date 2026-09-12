#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::path::{Path, PathBuf};
use std::process::Command;

const GUARDED_WITH: &str = "def f(a, m, p):\n\
                            \x20   if a:\n\
                            \x20       a = a.strip()\n\
                            \x20   if m is None:\n\
                            \x20       with open(p) as h:\n\
                            \x20           m = h.read()\n\
                            \x20   return m\n";

const PLAIN: &str = "def g(x):\n\x20   return x + 1\n";

fn cli_binary() -> PathBuf {
    let exe: PathBuf = std::env::current_exe().expect("current exe");
    let mut dir: PathBuf = exe.parent().expect("exe dir").to_path_buf();
    while dir
        .file_name()
        .and_then(|name: &std::ffi::OsStr| name.to_str())
        != Some("debug")
        && dir
            .file_name()
            .and_then(|name: &std::ffi::OsStr| name.to_str())
            != Some("release")
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

fn locate_python() -> Option<PathBuf> {
    let path_var: std::ffi::OsString = std::env::var_os("PATH")?;
    for name in ["python3", "python"] {
        for dir in std::env::split_paths(&path_var) {
            for variant in [name.to_owned(), format!("{name}.exe")] {
                let candidate: PathBuf = dir.join(&variant);
                if candidate.is_file()
                    && Command::new(&candidate)
                        .args(["-c", "pass"])
                        .output()
                        .is_ok_and(|out: std::process::Output| out.status.success())
                {
                    return Some(candidate);
                }
            }
        }
    }
    None
}

fn compile_to_pyc(python: &Path, source: &str, dir: &Path, stem: &str) -> PathBuf {
    let src: PathBuf = dir.join(format!("{stem}.py"));
    let dst: PathBuf = dir.join(format!("{stem}.pyc"));
    std::fs::write(&src, source.as_bytes()).expect("write source fixture");
    let script: String = format!(
        "import py_compile;py_compile.compile(r'{}', cfile=r'{}', doraise=True)",
        src.display(),
        dst.display()
    );
    let out: std::process::Output = Command::new(python)
        .args(["-c", &script])
        .output()
        .expect("spawn py_compile");
    assert!(
        out.status.success(),
        "py_compile failed for {stem}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    dst
}

struct Run {
    stdout: String,
    code: i32,
}

fn decompile(pyc: &Path, out_dir: &Path) -> Run {
    let bin: PathBuf = cli_binary();
    assert!(
        bin.exists(),
        "disrobe binary not built at {} - run `cargo build -p disrobe-cli` before tests",
        bin.display()
    );
    let out: std::process::Output = Command::new(&bin)
        .args([
            "py",
            "decompile",
            &pyc.display().to_string(),
            "--out",
            &out_dir.display().to_string(),
        ])
        .env_remove("RUST_LOG")
        .env_remove("DISROBE_LOG")
        .output()
        .expect("spawn disrobe");
    Run {
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        code: out.status.code().unwrap_or(-1),
    }
}

fn verdict_of(stdout: &str) -> String {
    let Some(rest): Option<&str> = stdout
        .lines()
        .find_map(|line: &str| line.trim_start().strip_prefix("roundtrip:"))
    else {
        panic!("the output must carry a roundtrip line: {stdout}");
    };
    rest.trim().to_owned()
}

fn headline_of(stdout: &str) -> &str {
    stdout
        .lines()
        .next()
        .unwrap_or_else(|| panic!("the output must carry a headline: {stdout}"))
}

fn expected_headline(verdict: &str) -> &'static str {
    match verdict {
        "code-diff" => {
            "py decompile: recovered, but the recompiled bytecode does not match the original, so \
             the source below is not equivalent to the input"
        }
        "recompile-failed" => {
            "py decompile: recovered, but the recovered source does not compile, so it cannot be \
             equivalent to the input"
        }
        "no-interpreter" => {
            "py decompile: recovered, not verified: no interpreter was available to recompile with"
        }
        "perfect" | "semantic" | "skipped" => "py decompile: OK",
        other => panic!("unhandled roundtrip verdict {other}; the headline mapping must cover it"),
    }
}

fn scratch(stem: &str) -> disrobe_core::scratch::ScratchDir {
    disrobe_core::scratch::ScratchDir::create(&format!("disrobe-headline-{stem}"))
        .expect("create scratch directory")
}

#[test]
fn the_headline_never_says_ok_when_the_roundtrip_did_not_establish_equivalence() {
    let Some(python): Option<PathBuf> = locate_python() else {
        panic!(
            "no python interpreter on PATH; this case grades what the command tells a caller \
             about equivalence and cannot be established without one"
        );
    };
    let dir: disrobe_core::scratch::ScratchDir = scratch("mapping");
    let root: &Path = dir.path();
    let mut seen: Vec<String> = Vec::new();
    for (stem, source) in [("guarded_with", GUARDED_WITH), ("plain", PLAIN)] {
        let pyc: PathBuf = compile_to_pyc(&python, source, root, stem);
        let out_dir: PathBuf = root.join(format!("{stem}-out"));
        let run: Run = decompile(&pyc, &out_dir);
        assert_eq!(run.code, 0, "decompile failed for {stem}: {}", run.stdout);
        let verdict: String = verdict_of(&run.stdout);
        assert_eq!(
            headline_of(&run.stdout),
            expected_headline(&verdict),
            "the headline for {stem} must state what the roundtrip verdict {verdict} means, \
             because a caller reading only the first line otherwise reads a mismatch as success"
        );
        if verdict != "perfect" && verdict != "semantic" && verdict != "skipped" {
            assert!(
                !run.stdout.starts_with("py decompile: OK"),
                "a verdict of {verdict} must not be headlined OK: {}",
                run.stdout
            );
        }
        seen.push(verdict);
    }
    assert_eq!(
        seen.len(),
        2,
        "both inputs must have produced a verdict: {seen:?}"
    );
}

#[test]
fn a_guard_dropped_from_the_recovered_source_is_reported_rather_than_headlined_ok() {
    let Some(python): Option<PathBuf> = locate_python() else {
        panic!("no python interpreter on PATH; this case cannot be established without one");
    };
    let dir: disrobe_core::scratch::ScratchDir = scratch("guard");
    let root: &Path = dir.path();
    let pyc: PathBuf = compile_to_pyc(&python, GUARDED_WITH, root, "guarded_with");
    let out_dir: PathBuf = root.join("out");
    let run: Run = decompile(&pyc, &out_dir);
    assert_eq!(run.code, 0, "decompile failed: {}", run.stdout);
    let recovered: String =
        std::fs::read_to_string(out_dir.join("guarded_with.py")).expect("recovered source");
    let guards_kept: bool = recovered.contains("if a:") && recovered.contains("if m is None:");
    let verdict: String = verdict_of(&run.stdout);
    if guards_kept {
        assert!(
            matches!(verdict.as_str(), "perfect" | "semantic"),
            "when both guards are recovered the roundtrip must establish byte or normalized \
             equivalence; verdict={verdict} recovered={recovered}"
        );
    } else {
        assert_ne!(
            verdict, "perfect",
            "the recovered source dropped a guard, so the roundtrip cannot be perfect; \
             recovered={recovered}"
        );
        assert!(
            !run.stdout.starts_with("py decompile: OK"),
            "a recovery that dropped a guard must not be headlined OK, because the source reads \
             as valid python and nothing else warns the caller; recovered={recovered} \
             stdout={}",
            run.stdout
        );
    }
}
