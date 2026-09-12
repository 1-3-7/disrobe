use super::lift::{BinOp, LiftedMethod, LiftedOp};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroundOp {
    LoadArg,
    LoadLocal,
    StoreLocal,
    Add,
    Mul,
    CompareAndBranch,
    Return,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryScore {
    pub matched: u32,
    pub expected: u32,
}

impl RecoveryScore {
    #[must_use]
    pub fn percent(self) -> f64 {
        if self.expected == 0 {
            return 100.0;
        }
        f64::from(self.matched) / f64::from(self.expected) * 100.0
    }

    #[must_use]
    pub const fn is_full(self) -> bool {
        self.matched >= self.expected
    }
}

#[must_use]
pub fn project(ops: &[LiftedOp]) -> Vec<GroundOp> {
    let mut out: Vec<GroundOp> = Vec::new();
    let mut i: usize = 0;
    while i < ops.len() {
        match &ops[i] {
            LiftedOp::LoadArg(_) => out.push(GroundOp::LoadArg),
            LiftedOp::LoadLocal(_) => out.push(GroundOp::LoadLocal),
            LiftedOp::StoreLocal(_) => out.push(GroundOp::StoreLocal),
            LiftedOp::Binary(BinOp::Add) => out.push(GroundOp::Add),
            LiftedOp::Binary(BinOp::Mul) => out.push(GroundOp::Mul),
            LiftedOp::Compare(_) => {
                let next_is_branch: bool = ops.get(i + 1).is_some_and(|o: &LiftedOp| {
                    matches!(o, LiftedOp::BranchTrue(_) | LiftedOp::BranchFalse(_))
                });
                if next_is_branch {
                    out.push(GroundOp::CompareAndBranch);
                    i += 1;
                }
            }
            LiftedOp::Return => out.push(GroundOp::Return),
            _ => {}
        }
        i += 1;
    }
    out
}

#[must_use]
pub fn ground_truth(method: &str) -> Option<&'static [GroundOp]> {
    let ops: &'static [GroundOp] = match method {
        "Add" => &[
            GroundOp::LoadArg,
            GroundOp::LoadArg,
            GroundOp::Add,
            GroundOp::Return,
        ],
        "Square" => &[
            GroundOp::LoadArg,
            GroundOp::LoadArg,
            GroundOp::Mul,
            GroundOp::Return,
        ],
        "SumTo" => &[
            GroundOp::StoreLocal,
            GroundOp::StoreLocal,
            GroundOp::LoadLocal,
            GroundOp::Add,
            GroundOp::StoreLocal,
            GroundOp::LoadLocal,
            GroundOp::Add,
            GroundOp::StoreLocal,
            GroundOp::CompareAndBranch,
            GroundOp::LoadLocal,
            GroundOp::Return,
        ],
        "Factorial" => &[
            GroundOp::StoreLocal,
            GroundOp::LoadLocal,
            GroundOp::Mul,
            GroundOp::StoreLocal,
            GroundOp::CompareAndBranch,
            GroundOp::LoadLocal,
            GroundOp::Return,
        ],
        "Classify" => &[
            GroundOp::LoadArg,
            GroundOp::CompareAndBranch,
            GroundOp::Return,
            GroundOp::LoadArg,
            GroundOp::CompareAndBranch,
            GroundOp::Return,
            GroundOp::Return,
        ],
        "Max3" => &[
            GroundOp::LoadArg,
            GroundOp::StoreLocal,
            GroundOp::LoadArg,
            GroundOp::CompareAndBranch,
            GroundOp::LoadArg,
            GroundOp::StoreLocal,
            GroundOp::LoadArg,
            GroundOp::CompareAndBranch,
            GroundOp::LoadArg,
            GroundOp::StoreLocal,
            GroundOp::LoadLocal,
            GroundOp::Return,
        ],
        _ => return None,
    };
    Some(ops)
}

#[must_use]
pub fn grade(method: &str, lifted: &LiftedMethod) -> Option<RecoveryScore> {
    let expected: &[GroundOp] = ground_truth(method)?;
    let recovered: Vec<GroundOp> = project(&lifted.ops);
    let matched: u32 = count_multiset_overlap(expected, &recovered);
    Some(RecoveryScore {
        matched,
        expected: u32::try_from(expected.len()).unwrap_or(u32::MAX),
    })
}

fn count_multiset_overlap(expected: &[GroundOp], recovered: &[GroundOp]) -> u32 {
    let kinds: [GroundOp; 7] = [
        GroundOp::LoadArg,
        GroundOp::LoadLocal,
        GroundOp::StoreLocal,
        GroundOp::Add,
        GroundOp::Mul,
        GroundOp::CompareAndBranch,
        GroundOp::Return,
    ];
    let mut matched: u32 = 0;
    for kind in kinds {
        let want: usize = expected.iter().filter(|o: &&GroundOp| **o == kind).count();
        let got: usize = recovered.iter().filter(|o: &&GroundOp| **o == kind).count();
        matched += u32::try_from(want.min(got)).unwrap_or(u32::MAX);
    }
    matched
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::super::{KoiVmMethod, KoiVmRecovery, devirtualize};
    use super::*;

    fn recovery() -> KoiVmRecovery {
        let mut path: std::path::PathBuf = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("../../corpus/dotnet/koivm/KoiSample.koivm.exe");
        let image: Vec<u8> = std::fs::read(path).unwrap();
        devirtualize(&image).expect("devirtualize")
    }

    #[test]
    fn add_recovers_fully_against_known_original() {
        let rec: KoiVmRecovery = recovery();
        let add: &KoiVmMethod = rec
            .methods
            .iter()
            .find(|m: &&KoiVmMethod| m.method_name == "Add")
            .unwrap();
        let score: RecoveryScore = grade("Add", &add.lifted).unwrap();
        assert!(
            score.is_full(),
            "Add must recover fully vs known original; matched {}/{} ({:?})",
            score.matched,
            score.expected,
            project(&add.lifted.ops)
        );
    }

    #[test]
    fn square_recovers_fully() {
        let rec: KoiVmRecovery = recovery();
        let sq: &KoiVmMethod = rec
            .methods
            .iter()
            .find(|m: &&KoiVmMethod| m.method_name == "Square")
            .unwrap();
        let score: RecoveryScore = grade("Square", &sq.lifted).unwrap();
        assert!(
            score.is_full(),
            "Square matched {}/{} ({:?})",
            score.matched,
            score.expected,
            project(&sq.lifted.ops)
        );
    }

    #[test]
    fn aggregate_recovery_is_high_against_known_originals() {
        let rec: KoiVmRecovery = recovery();
        let mut total_matched: u32 = 0;
        let mut total_expected: u32 = 0;
        for m in &rec.methods {
            if let Some(score) = grade(&m.method_name, &m.lifted) {
                total_matched += score.matched;
                total_expected += score.expected;
                println!(
                    "{}: {}/{} ({:.1}%) ops={:?}",
                    m.method_name,
                    score.matched,
                    score.expected,
                    score.percent(),
                    project(&m.lifted.ops)
                );
            }
        }
        let pct: f64 = f64::from(total_matched) / f64::from(total_expected) * 100.0;
        println!("AGGREGATE: {total_matched}/{total_expected} = {pct:.1}%");
        assert!(
            pct >= 75.0,
            "aggregate structural recovery against known originals must be >= 75%; got {pct:.1}%"
        );
    }
}
