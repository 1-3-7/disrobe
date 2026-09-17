#![allow(dead_code)]

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Answer {
    Sat,
    Unsat,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SolverKind {
    Z3,
    Bitwuzla,
}

#[derive(Debug, Clone)]
pub(crate) struct Solver {
    pub(crate) program: &'static str,
    pub(crate) kind: SolverKind,
    pub(crate) version: String,
}

fn probe_version(program: &str) -> Option<String> {
    let output: std::process::Output = Command::new(program).arg("--version").output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&output.stdout);
    let first: String = text.lines().next().unwrap_or("").trim().to_owned();
    if first.is_empty() {
        Some(program.to_owned())
    } else {
        Some(first)
    }
}

pub(crate) fn detect() -> Option<Solver> {
    const CANDIDATES: [(&str, SolverKind); 2] =
        [("z3", SolverKind::Z3), ("bitwuzla", SolverKind::Bitwuzla)];
    CANDIDATES
        .into_iter()
        .find_map(|(program, kind): (&'static str, SolverKind)| {
            probe_version(program).map(|version: String| Solver {
                program,
                kind,
                version,
            })
        })
}

static QUERY_COUNTER: AtomicUsize = AtomicUsize::new(0);

pub(crate) fn parse_answer(text: &str) -> Answer {
    for line in text.lines() {
        match line.trim() {
            "unsat" => return Answer::Unsat,
            "sat" => return Answer::Sat,
            "unknown" | "timeout" => return Answer::Unknown,
            _ => {}
        }
    }
    panic!("solver produced no sat/unsat/unknown verdict: {text:?}");
}

pub(crate) fn run(solver: &Solver, script: &str) -> Answer {
    run_bounded(solver, script, None)
}

pub(crate) fn run_bounded(solver: &Solver, script: &str, seconds: Option<u32>) -> Answer {
    let unique: usize = QUERY_COUNTER.fetch_add(1, Ordering::Relaxed);
    let purpose: String = format!("disrobe_mba_query_{}_{}", std::process::id(), unique);
    let (scratch, mut file): (disrobe_core::scratch::ScratchFile, std::fs::File) =
        disrobe_core::scratch::ScratchFile::create(&purpose, "smt2")
            .expect("write smt2 query to a temp file");
    let path: PathBuf = scratch.path().to_path_buf();
    std::io::Write::write_all(&mut file, script.as_bytes())
        .expect("write smt2 query to a temp file");
    drop(file);
    let mut command: Command = Command::new(solver.program);
    match solver.kind {
        SolverKind::Z3 => {
            if let Some(limit) = seconds {
                command.arg(format!("-T:{limit}"));
            }
            command.arg("-smt2").arg(&path);
        }
        SolverKind::Bitwuzla => {
            if let Some(limit) = seconds {
                command
                    .arg("--time-limit-per")
                    .arg((limit.saturating_mul(1000)).to_string());
            }
            command.arg(&path);
        }
    }
    let output: std::process::Output = command.output().expect("invoke the external solver");
    let stdout: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&output.stdout);
    if stdout.trim().is_empty() {
        return Answer::Unknown;
    }
    parse_answer(&stdout)
}
