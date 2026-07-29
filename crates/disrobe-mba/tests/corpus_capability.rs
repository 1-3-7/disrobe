#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

#[path = "data/mba_corpus.rs"]
#[allow(clippy::redundant_pub_crate)]
mod mba_corpus;

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

use disrobe_mba::{Expr, Simplification, Width, equivalence_query, simplify};
use mba_corpus::{CorpusEntry, corpus};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Answer {
    Sat,
    Unsat,
    Unknown,
}

#[derive(Debug, Clone, Copy)]
enum SolverKind {
    Z3,
    Bitwuzla,
}

#[derive(Debug, Clone)]
struct Solver {
    program: &'static str,
    kind: SolverKind,
    version: String,
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

fn detect_solver() -> Option<Solver> {
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

fn parse_answer(text: &str) -> Answer {
    for line in text.lines() {
        match line.trim() {
            "unsat" => return Answer::Unsat,
            "sat" => return Answer::Sat,
            "unknown" => return Answer::Unknown,
            _ => {}
        }
    }
    panic!("solver produced no sat/unsat/unknown verdict: {text:?}");
}

fn run_solver(solver: &Solver, script: &str) -> Answer {
    let unique: usize = QUERY_COUNTER.fetch_add(1, Ordering::Relaxed);
    let purpose: String = format!("disrobe_mba_corpus_{}_{}", std::process::id(), unique);
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
            command.arg("-smt2").arg(&path);
        }
        SolverKind::Bitwuzla => {
            command.arg(&path);
        }
    }
    let output: std::process::Output = command.output().expect("invoke the external solver");
    let stdout: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&output.stdout);
    parse_answer(&stdout)
}

struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    const fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z: u64 = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

const RANDOM_SAMPLES: usize = 512;

fn max_var(entry: &CorpusEntry, simplified: &Expr) -> u32 {
    let mut highest: Option<u32> = entry.e_obf.max_var();
    for candidate in [entry.e_src.max_var(), simplified.max_var()] {
        highest = match (highest, candidate) {
            (Some(current), Some(other)) => Some(current.max(other)),
            (Some(current), None) => Some(current),
            (None, other) => other,
        };
    }
    highest.map_or(0, |index: u32| index + 1)
}

fn input_vectors(var_count: u32, width: Width) -> Vec<Vec<u64>> {
    let count: usize = var_count as usize;
    let mask: u64 = width.mask();
    let mut vectors: Vec<Vec<u64>> = Vec::new();
    let structured: [u64; 6] = [
        0,
        mask,
        1,
        mask >> 1,
        0x5555_5555_5555_5555 & mask,
        0xAAAA_AAAA_AAAA_AAAA & mask,
    ];
    for fill in structured {
        vectors.push(vec![fill; count]);
    }
    for slot in 0..count {
        let mut vector: Vec<u64> = vec![0; count];
        vector[slot] = mask;
        vectors.push(vector);
    }
    let mut rng: SplitMix64 =
        SplitMix64::new(0xD150_B5ED_5EED_1234 ^ (u64::from(width.bits()) << 8));
    for _ in 0..RANDOM_SAMPLES {
        let vector: Vec<u64> = (0..count).map(|_| rng.next_u64() & mask).collect();
        vectors.push(vector);
    }
    vectors
}

fn behavioral_equiv(lhs: &Expr, rhs: &Expr, width: Width, vectors: &[Vec<u64>]) -> bool {
    vectors
        .iter()
        .all(|env: &Vec<u64>| lhs.eval(env, width) == rhs.eval(env, width))
}

#[derive(Debug, Clone)]
struct Row {
    name: &'static str,
    provenance: &'static str,
    reduces: bool,
    src_nodes: usize,
    obf_nodes: usize,
    simplified_nodes: usize,
    verification: String,
    smt_confirmed: bool,
}

#[test]
fn corpus_reduces_or_survives_under_behavioral_and_smt_grading() {
    const REDUCE_FLOOR: usize = 22;
    const PROVEN_FLOOR: usize = 28;
    let solver: Option<Solver> = detect_solver();
    match &solver {
        Some(found) => eprintln!(
            "corpus_capability: grading with the external solver {} ({})",
            found.program, found.version
        ),
        None => eprintln!(
            "corpus_capability: no external solver on PATH; running the behavioral differential only"
        ),
    }

    let entries: Vec<CorpusEntry> = corpus();
    let mut rows: Vec<Row> = Vec::with_capacity(entries.len());
    let mut reduced: usize = 0;
    let mut survived: usize = 0;
    let mut proven: usize = 0;

    for entry in &entries {
        let simplification: Simplification = simplify(&entry.e_obf, entry.width);
        let simplified: &Expr = &simplification.simplified;
        if simplification.verification.is_proven() {
            proven += 1;
        }
        assert!(
            simplification.verification.is_proven() || !simplification.changed(),
            "{}: a rewrite was emitted without an independently established proof",
            entry.name
        );
        let var_count: u32 = max_var(entry, simplified);
        let vectors: Vec<Vec<u64>> = input_vectors(var_count, entry.width);

        assert!(
            behavioral_equiv(&entry.e_src, &entry.e_obf, entry.width, &vectors),
            "{}: the corpus triple is not a valid identity, e_src disagrees with e_obf",
            entry.name
        );
        assert!(
            behavioral_equiv(&entry.e_obf, simplified, entry.width, &vectors),
            "{}: simplify(e_obf) diverges from e_obf on a sampled input, a WRONG rewrite\nsimplified = {simplified}",
            entry.name
        );
        assert!(
            behavioral_equiv(&entry.e_src, simplified, entry.width, &vectors),
            "{}: simplify(e_obf) diverges from the ground-truth e_src, a WRONG rewrite\nsimplified = {simplified}",
            entry.name
        );

        let smt_confirmed: bool = solver.as_ref().is_some_and(|active: &Solver| {
            let preserves: String = equivalence_query(&entry.e_obf, simplified, entry.width);
            assert_eq!(
                run_solver(active, &preserves),
                Answer::Unsat,
                "{}: solver did not prove simplify(e_obf) equivalent to e_obf",
                entry.name
            );
            let identity: String = equivalence_query(&entry.e_src, &entry.e_obf, entry.width);
            assert_eq!(
                run_solver(active, &identity),
                Answer::Unsat,
                "{}: solver did not confirm the corpus identity e_src == e_obf",
                entry.name
            );
            let recovered: String = equivalence_query(&entry.e_src, simplified, entry.width);
            assert_eq!(
                run_solver(active, &recovered),
                Answer::Unsat,
                "{}: solver did not prove simplify(e_obf) equivalent to e_src",
                entry.name
            );
            true
        });

        let src_nodes: usize = entry.e_src.node_count();
        let reduces: bool = simplified.node_count() <= src_nodes;
        if reduces {
            reduced += 1;
        } else {
            survived += 1;
        }

        rows.push(Row {
            name: entry.name,
            provenance: entry.provenance,
            reduces,
            src_nodes,
            obf_nodes: entry.e_obf.node_count(),
            simplified_nodes: simplified.node_count(),
            verification: format!("{:?}", simplification.verification),
            smt_confirmed,
        });
    }

    eprintln!(
        "corpus_capability reduce/survive table ({} pairs, {reduced} reduce, {survived} survive):",
        entries.len()
    );
    eprintln!(
        "  {:<28} {:>6} {:>4} {:>4} {:>5} {:>4}  {:<26} provenance",
        "shape", "state", "src", "obf", "simp", "smt", "verification"
    );
    for row in &rows {
        eprintln!(
            "  {:<28} {:>6} {:>4} {:>4} {:>5} {:>4}  {:<26} {}",
            row.name,
            if row.reduces { "REDUCE" } else { "SURVIVE" },
            row.src_nodes,
            row.obf_nodes,
            row.simplified_nodes,
            if row.smt_confirmed { "yes" } else { "n/a" },
            row.verification,
            row.provenance,
        );
    }

    assert!(
        reduced >= REDUCE_FLOOR,
        "capability regression: only {reduced} of {} corpus pairs reduced to the source form, floor is {REDUCE_FLOOR}",
        entries.len()
    );
    assert!(
        proven >= PROVEN_FLOOR,
        "capability regression: only {proven} of {} corpus pairs carry an independently established proof, floor is {PROVEN_FLOOR}",
        entries.len()
    );

    if let Some(active) = &solver {
        let clean: Expr = Expr::add(Expr::var(0), Expr::var(1));
        let wrong: Expr = Expr::sub(Expr::var(0), Expr::var(1));
        let refutation: String = equivalence_query(&clean, &wrong, Width::W8);
        assert_eq!(
            run_solver(active, &refutation),
            Answer::Sat,
            "the solver leg must refute a non-equivalent rewrite (x+y vs x-y), otherwise the grading is vacuous"
        );
    }
}
