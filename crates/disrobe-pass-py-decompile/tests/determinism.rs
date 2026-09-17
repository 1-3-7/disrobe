#![cfg(feature = "chain")]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::missing_panics_doc,
    clippy::missing_errors_doc,
    clippy::unnecessary_debug_formatting
)]

use std::path::PathBuf;

use disrobe_core::Artifact;
use disrobe_core::Rung;
use disrobe_core::chain::Pass;
use disrobe_pass_py_decompile::chain_detector::PY_DECOMPILE_PASS;

fn workspace_root() -> PathBuf {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p
}

fn load_edge_cases_3_12_pyc() -> Vec<u8> {
    let mut path: PathBuf = workspace_root();
    path.push("corpus");
    path.push("python");
    path.push("decompile");
    path.push("playground");
    path.push("__pycache__");
    path.push("edge_cases_3_12.cpython-312.pyc");
    std::fs::read(&path).unwrap_or_else(|e: std::io::Error| panic!("read fixture {path:?}: {e}"))
}

fn run_once(seed: &[u8]) -> Vec<u8> {
    let artifact: Artifact = Artifact::new(Rung::Raw, seed.to_vec(), [0u8; 32]);
    let out: Artifact = PY_DECOMPILE_PASS
        .run(&artifact)
        .expect("py.decompile pass must succeed on edge_cases_3_12.cpython-312.pyc");
    out.envelope
}

fn first_divergence_index(a: &[u8], b: &[u8]) -> Option<usize> {
    a.iter().zip(b.iter()).position(|(x, y): (&u8, &u8)| x != y)
}

#[test]
#[ignore = "manual: dumps the chain pass output to target/ for cross-process determinism inspection"]
fn dump_edge_cases_3_12_pyc_decompile() {
    let seed: Vec<u8> = load_edge_cases_3_12_pyc();
    let out: Vec<u8> = run_once(&seed);
    let target: PathBuf = workspace_root()
        .join("target")
        .join("pydec-determinism-dump.py");
    std::fs::write(&target, &out).expect("write dump");
    eprintln!("WROTE {target:?} len={len}", len = out.len());
}

#[test]
fn edge_cases_3_12_pyc_decompile_is_byte_identical_across_ten_runs() {
    let seed: Vec<u8> = load_edge_cases_3_12_pyc();
    let first: Vec<u8> = run_once(&seed);
    let first_len: usize = first.len();
    let mut size_set: std::collections::BTreeSet<usize> = std::collections::BTreeSet::new();
    size_set.insert(first_len);
    for run_index in 1..10_u32 {
        let out: Vec<u8> = run_once(&seed);
        size_set.insert(out.len());
        if out != first {
            let diverge: Option<usize> = first_divergence_index(&first, &out);
            let around: usize = diverge.unwrap_or(0);
            let lo: usize = around.saturating_sub(64);
            let hi_a: usize = (around + 64).min(first.len());
            let hi_b: usize = (around + 64).min(out.len());
            let snippet_a: String = String::from_utf8_lossy(&first[lo..hi_a]).into_owned();
            let snippet_b: String = String::from_utf8_lossy(&out[lo..hi_b]).into_owned();
            panic!(
                "run {run_index} diverged: first_len={first_len} this_len={this_len} \
                 first_diff_byte={diverge:?}\n--- first ---\n{snippet_a}\n--- this ---\n{snippet_b}",
                this_len = out.len(),
            );
        }
    }
    assert_eq!(size_set.len(), 1, "observed sizes: {size_set:?}");
}
