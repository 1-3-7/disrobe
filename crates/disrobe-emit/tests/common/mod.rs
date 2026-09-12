#![allow(
    dead_code,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::pedantic,
    clippy::nursery
)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::OnceLock;

use disrobe_core::scratch::ScratchDir;
use disrobe_emit::c::ast::{CBaseType, CExpr, CParam, CTypeSpec, DeclaratorChain};

pub(crate) const WIDE: usize = 1_000_000;

const INT_SIZE: u64 = 4;
const POINTER_SIZE: u64 = 8;
const MAX_SOURCE_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Debug)]
pub(crate) struct Compiler {
    command: String,
    banner: String,
    suppressions: Vec<String>,
}

const OPTIONAL_SUPPRESSIONS: [&str; 3] = [
    "-Wno-parentheses",
    "-Wno-constant-logical-operand",
    "-Wno-tautological-constant-compare",
];

const FLAG_PROBE_SOURCE: &str = "int probe(void) { int unused = 0; return 0; }\n";

const UNKNOWN_FLAG_MARKERS: [&str; 3] =
    ["unrecognized", "unknown warning option", "unknown argument"];

fn supported_suppressions(command: &str) -> Vec<String> {
    let Ok(dir): std::io::Result<ScratchDir> = ScratchDir::create("disrobe-emit-flags") else {
        return Vec::new();
    };
    let path: PathBuf = dir.path().join("flags.c");
    if std::fs::write(&path, FLAG_PROBE_SOURCE).is_err() {
        return Vec::new();
    }
    OPTIONAL_SUPPRESSIONS
        .into_iter()
        .filter(|flag: &&str| {
            let Ok(output): Result<Output, std::io::Error> = Command::new(command)
                .args(["-std=c11", "-Wall", "-fsyntax-only"])
                .arg(flag)
                .arg(&path)
                .output()
            else {
                return false;
            };
            let stderr: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&output.stderr);
            !UNKNOWN_FLAG_MARKERS
                .iter()
                .any(|marker: &&str| stderr.contains(marker))
        })
        .map(str::to_owned)
        .collect()
}

fn dedup_key(banner: &str) -> String {
    banner
        .split_whitespace()
        .skip(1)
        .collect::<Vec<&str>>()
        .join(" ")
}

fn discover_compilers() -> Vec<Compiler> {
    const CANDIDATES: [&str; 3] = ["cc", "gcc", "clang"];
    let mut found: Vec<Compiler> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for candidate in CANDIDATES {
        let Ok(output): Result<Output, std::io::Error> =
            Command::new(candidate).arg("--version").output()
        else {
            continue;
        };
        if !output.status.success() {
            continue;
        }
        let banner: String = String::from_utf8_lossy(&output.stdout)
            .lines()
            .next()
            .unwrap_or_default()
            .trim()
            .to_owned();
        if banner.is_empty() || !seen.insert(dedup_key(&banner)) {
            continue;
        }
        let suppressions: Vec<String> = supported_suppressions(candidate);
        found.push(Compiler {
            command: candidate.to_owned(),
            banner,
            suppressions,
        });
    }
    found
}

static COMPILERS: OnceLock<Vec<Compiler>> = OnceLock::new();

pub(crate) fn required_compilers() -> &'static [Compiler] {
    let found: &'static Vec<Compiler> = COMPILERS.get_or_init(discover_compilers);
    assert!(
        !found.is_empty(),
        "the disrobe-emit c printer is graded against a real c compiler and none was reachable; \
         none of cc, gcc or clang answered --version on PATH, so this run proves nothing about \
         the emitted source and must not report success"
    );
    found
}

const BASE_FLAGS: [&str; 3] = ["-std=c11", "-Wall", "-Werror"];

fn stage(dir: &Path, source: &str, label: &str) -> PathBuf {
    assert!(
        source.len() <= MAX_SOURCE_BYTES,
        "the {label} probe is {} bytes, over the {MAX_SOURCE_BYTES} byte ceiling",
        source.len()
    );
    let path: PathBuf = dir.join("probe.c");
    std::fs::write(&path, source).expect("write probe source");
    path
}

pub(crate) fn syntax_check(compiler: &Compiler, source: &str, label: &str) {
    let dir: ScratchDir = ScratchDir::create("disrobe-emit-grade").expect("scratch dir");
    let path: PathBuf = stage(dir.path(), source, label);
    let output: Output = Command::new(&compiler.command)
        .args(BASE_FLAGS)
        .args(&compiler.suppressions)
        .arg("-fsyntax-only")
        .arg(&path)
        .output()
        .expect("run c compiler");
    assert!(
        output.status.success(),
        "{} rejected the {label} probe\n--- stderr ---\n{}\n--- source ---\n{source}",
        compiler.banner,
        String::from_utf8_lossy(&output.stderr)
    );
}

pub(crate) fn build_and_run(compiler: &Compiler, source: &str, label: &str) {
    let dir: ScratchDir = ScratchDir::create("disrobe-emit-grade").expect("scratch dir");
    let path: PathBuf = stage(dir.path(), source, label);
    let binary: PathBuf = dir.path().join("probe.exe");
    let built: Output = Command::new(&compiler.command)
        .args(BASE_FLAGS)
        .args(&compiler.suppressions)
        .arg("-o")
        .arg(&binary)
        .arg(&path)
        .output()
        .expect("run c compiler");
    assert!(
        built.status.success(),
        "{} could not build the {label} probe\n--- stderr ---\n{}\n--- source ---\n{source}",
        compiler.banner,
        String::from_utf8_lossy(&built.stderr)
    );
    let run: Output = Command::new(&binary).output().expect("run built probe");
    assert_eq!(
        run.status.code(),
        Some(0),
        "{} built the {label} probe but its case {:?} disagreed with the tree\n--- source \
         ---\n{source}",
        compiler.banner,
        run.status.code()
    );
}

pub(crate) fn int_param() -> CParam {
    CParam {
        base: CBaseType::plain(CTypeSpec::Int),
        name: None,
        declarator: DeclaratorChain::Terminal,
    }
}

fn chain_size(chain: &DeclaratorChain) -> Option<u64> {
    match chain {
        DeclaratorChain::Terminal => Some(INT_SIZE),
        DeclaratorChain::Pointer { .. } => Some(POINTER_SIZE),
        DeclaratorChain::Array { of, size } => {
            let extent: u64 = match size.as_deref()? {
                CExpr::Int { value, .. } => *value,
                _ => return None,
            };
            extent.checked_mul(chain_size(of)?)
        }
        DeclaratorChain::Function { .. } => None,
    }
}

pub(crate) fn walk_assertions(
    chain: &DeclaratorChain,
    access: &str,
    label: &str,
    out: &mut Vec<String>,
) {
    if let Some(size) = chain_size(chain) {
        out.push(format!(
            "_Static_assert(sizeof({access}) == {size}, \"{label}\");"
        ));
    }
    match chain {
        DeclaratorChain::Terminal => {}
        DeclaratorChain::Pointer { to, .. } => {
            walk_assertions(to, &format!("(*{access})"), label, out);
        }
        DeclaratorChain::Array { of, .. } => {
            walk_assertions(of, &format!("({access})[0]"), label, out);
        }
        DeclaratorChain::Function {
            returns, params, ..
        } => {
            let args: String = vec!["0"; params.len()].join(", ");
            walk_assertions(returns, &format!("({access})({args})"), label, out);
        }
    }
}
