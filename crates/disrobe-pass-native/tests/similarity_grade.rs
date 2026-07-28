#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::redundant_pub_crate
)]

#[path = "similarity_grade/corpus.rs"]
mod corpus;
#[path = "similarity_grade/grade.rs"]
mod grade;
#[path = "similarity_grade/truth.rs"]
mod truth;

use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

use corpus::{Artifact, BuildKey, Compiler, Flavor, Toolchain};
use grade::{Emission, Grade, Outcome, Stage, Tally, WrongMatch};
use truth::{Address, ImageSymbols, SizeBand, TruthTable};

use disrobe_pass_native::extract_function_features;
use disrobe_similarity::{
    FunctionFeatures, FunctionVerdict, MatchReport, Verdict, match_functions,
};

const TRUTH_SOURCE: &str = include_str!("similarity_grade/truth.rs");

const GRADE_SOURCE: &str = include_str!("similarity_grade/grade.rs");

const CORPUS_SOURCE: &str = include_str!("similarity_grade/corpus.rs");

const CORRESPONDENCE_FLOOR: usize = 500;

const RECALL_FLOOR_PERMILLE: u64 = 400;

const PRECISION_FLOOR_PERMILLE: u64 = 980;

const CHANGED_PRECISION_FLOOR_PERMILLE: u64 = 800;

const WRONG_CEILING_PERMILLE: u64 = 10;

const PAIR_PRECISION_FLOOR_PERMILLE: u64 = 900;

const PAIR_PRECISION_SAMPLE: usize = 8;

const WRONG_REPORT_LIMIT: usize = 40;

#[derive(Debug, Clone, Copy)]
struct Leg {
    compiler: Compiler,
    level: &'static str,
    variant: bool,
}

#[derive(Debug, Clone, Copy)]
struct Recipe {
    axis: &'static str,
    flavor: Flavor,
    left: Leg,
    right: Leg,
}

const RECIPES: [Recipe; 7] = [
    Recipe {
        axis: "optimisation level",
        flavor: Flavor::Hosted,
        left: Leg {
            compiler: Compiler::Gcc,
            level: "O0",
            variant: false,
        },
        right: Leg {
            compiler: Compiler::Gcc,
            level: "O2",
            variant: false,
        },
    },
    Recipe {
        axis: "compiler",
        flavor: Flavor::Hosted,
        left: Leg {
            compiler: Compiler::Gcc,
            level: "O2",
            variant: false,
        },
        right: Leg {
            compiler: Compiler::Clang,
            level: "O2",
            variant: false,
        },
    },
    Recipe {
        axis: "source version",
        flavor: Flavor::Hosted,
        left: Leg {
            compiler: Compiler::Gcc,
            level: "O2",
            variant: false,
        },
        right: Leg {
            compiler: Compiler::Gcc,
            level: "O2",
            variant: true,
        },
    },
    Recipe {
        axis: "optimisation level",
        flavor: Flavor::FreestandingElf64,
        left: Leg {
            compiler: Compiler::Clang,
            level: "O0",
            variant: false,
        },
        right: Leg {
            compiler: Compiler::Clang,
            level: "O2",
            variant: false,
        },
    },
    Recipe {
        axis: "optimisation level",
        flavor: Flavor::FreestandingElf64,
        left: Leg {
            compiler: Compiler::Clang,
            level: "O2",
            variant: false,
        },
        right: Leg {
            compiler: Compiler::Clang,
            level: "Os",
            variant: false,
        },
    },
    Recipe {
        axis: "source version",
        flavor: Flavor::FreestandingElf64,
        left: Leg {
            compiler: Compiler::Clang,
            level: "O2",
            variant: false,
        },
        right: Leg {
            compiler: Compiler::Clang,
            level: "O2",
            variant: true,
        },
    },
    Recipe {
        axis: "optimisation level",
        flavor: Flavor::FreestandingAarch64,
        left: Leg {
            compiler: Compiler::Clang,
            level: "O0",
            variant: false,
        },
        right: Leg {
            compiler: Compiler::Clang,
            level: "O2",
            variant: false,
        },
    },
];

#[derive(Debug)]
struct Prepared {
    symbols: ImageSymbols,
    features: Vec<FunctionFeatures>,
}

#[derive(Debug)]
struct Bench {
    tools: Toolchain,
    cache: BTreeMap<BuildKey, Option<Rc<Prepared>>>,
    built: usize,
    unbuildable: BTreeSet<String>,
}

impl Bench {
    const fn new(tools: Toolchain) -> Self {
        Self {
            tools,
            cache: BTreeMap::new(),
            built: 0,
            unbuildable: BTreeSet::new(),
        }
    }

    fn prepared(&mut self, key: &BuildKey) -> Option<Rc<Prepared>> {
        if let Some(hit) = self.cache.get(key) {
            return hit.clone();
        }
        let value: Option<Rc<Prepared>> =
            self.tools
                .build(key)
                .and_then(|artifact: Artifact| -> Option<Rc<Prepared>> {
                    let symbols: ImageSymbols = ImageSymbols::read(&artifact.symbols)?;
                    let features: Vec<FunctionFeatures> =
                        extract_function_features(&artifact.stripped).ok()?;
                    Some(Rc::new(Prepared { symbols, features }))
                });
        if value.is_some() {
            self.built += 1;
        } else {
            self.unbuildable.insert(key.describe());
        }
        self.cache.insert(key.clone(), value.clone());
        value
    }
}

#[derive(Debug)]
struct PairOutcome {
    label: String,
    axis: &'static str,
    flavor: Flavor,
    grade: Grade,
    truth_total: usize,
    changed_total: usize,
    folded_total: usize,
    dropped_left: usize,
    dropped_right: usize,
    folded_left: usize,
    folded_right: usize,
    left_functions: usize,
    right_functions: usize,
    left_names: usize,
    right_names: usize,
    subjects: usize,
    control_wrong: usize,
    control_recovered: usize,
}

fn emissions_of(report: &MatchReport) -> Vec<Emission> {
    report
        .left
        .iter()
        .map(|entry: &FunctionVerdict| Emission {
            subject: entry.subject.0,
            outcome: match &entry.verdict {
                Verdict::Exact { counterpart, .. } => Outcome::Paired {
                    counterpart: counterpart.0,
                    stage: Stage::DataReference,
                },
                Verdict::Structural { counterpart, .. } => Outcome::Paired {
                    counterpart: counterpart.0,
                    stage: Stage::ControlFlow,
                },
                Verdict::Propagated { counterpart, .. } => Outcome::Paired {
                    counterpart: counterpart.0,
                    stage: Stage::Propagation,
                },
                Verdict::Ambiguous { .. } | Verdict::Unmatched { .. } => Outcome::Declined,
            },
        })
        .collect()
}

fn rotated(emissions: &[Emission]) -> Vec<Emission> {
    let counterparts: Vec<Address> = emissions
        .iter()
        .filter_map(|entry: &Emission| match entry.outcome {
            Outcome::Paired { counterpart, .. } => Some(counterpart),
            Outcome::Declined => None,
        })
        .collect();
    if counterparts.len() < 2 {
        return emissions.to_vec();
    }
    let mut position: usize = 0;
    emissions
        .iter()
        .map(|entry: &Emission| match entry.outcome {
            Outcome::Paired { stage, .. } => {
                let next: usize = (position + 1) % counterparts.len();
                position += 1;
                Emission {
                    subject: entry.subject,
                    outcome: Outcome::Paired {
                        counterpart: counterparts[next],
                        stage,
                    },
                }
            }
            Outcome::Declined => *entry,
        })
        .collect()
}

fn run_pair(
    bench: &mut Bench,
    program: &str,
    right_program: &str,
    recipe: &Recipe,
) -> Option<PairOutcome> {
    let left_key: BuildKey = BuildKey {
        program: program.to_owned(),
        compiler: recipe.left.compiler,
        flavor: recipe.flavor,
        level: recipe.left.level,
    };
    let right_key: BuildKey = BuildKey {
        program: right_program.to_owned(),
        compiler: recipe.right.compiler,
        flavor: recipe.flavor,
        level: recipe.right.level,
    };
    let (Some(left), Some(right)): (Option<Rc<Prepared>>, Option<Rc<Prepared>>) =
        (bench.prepared(&left_key), bench.prepared(&right_key))
    else {
        return None;
    };
    if left.symbols.is_empty() || right.symbols.is_empty() {
        return None;
    }

    let table: TruthTable = TruthTable::derive(&left.symbols, &right.symbols);
    let report: MatchReport = match_functions(&left.features, &right.features);
    let emitted: Vec<Emission> = emissions_of(&report);
    let outcome: Grade = grade::grade(&emitted, &table);
    let control: Grade = grade::grade(&rotated(&emitted), &table);

    Some(PairOutcome {
        label: format!(
            "{program} {} {} {} -{} vs {} -{}",
            recipe.flavor.label(),
            left.symbols.format(),
            recipe.left.compiler.label(),
            recipe.left.level,
            recipe.right.compiler.label(),
            recipe.right.level
        ),
        axis: recipe.axis,
        flavor: recipe.flavor,
        truth_total: table.len(),
        changed_total: table.changed_len(),
        folded_total: table.folded_correspondences(),
        dropped_left: table.dropped_left_names,
        dropped_right: table.dropped_right_names,
        folded_left: table.folded_left_addresses,
        folded_right: table.folded_right_addresses,
        left_functions: table.left_functions,
        right_functions: table.right_functions,
        left_names: table.left_names,
        right_names: table.right_names,
        subjects: emitted.len(),
        control_wrong: control.overall.wrong,
        control_recovered: control.overall.recovered,
        grade: outcome,
    })
}

fn print_pair(outcome: &PairOutcome) {
    let tally: Tally = outcome.grade.overall;
    println!(
        "pair {}: truth {} ({} changed, {} folded), {} subjects, recovered {}, wrong {}, refused {}, missed {}, unbacked {}, unjudged {}, precision {} per mille, recall {} per mille",
        outcome.label,
        outcome.truth_total,
        outcome.changed_total,
        outcome.folded_total,
        outcome.subjects,
        tally.recovered,
        tally.wrong,
        tally.refused,
        tally.missed,
        tally.unbacked,
        tally.unjudged,
        tally.precision_permille(),
        tally.recall_permille()
    );
}

fn print_stage_rows(label: &str, total: &Grade) {
    for stage in Stage::ALL {
        let tally: Tally = total.stage(stage);
        println!(
            "{label} [{}]: recovered {}, WRONG {}, unbacked {}, unjudged {}, precision {} per mille",
            stage.label(),
            tally.recovered,
            tally.wrong,
            tally.unbacked,
            tally.unjudged,
            tally.precision_permille()
        );
    }
}

fn print_band_rows(label: &str, total: &Grade) {
    for band in SizeBand::ALL {
        let tally: Tally = total.band(band);
        if tally.expected() == 0 && tally.unbacked == 0 {
            continue;
        }
        println!(
            "{label} [{}]: expected {}, recovered {}, WRONG {}, refused {}, missed {}, unbacked {}, precision {} per mille, recall {} per mille",
            band.label(),
            tally.expected(),
            tally.recovered,
            tally.wrong,
            tally.refused,
            tally.missed,
            tally.unbacked,
            tally.precision_permille(),
            tally.recall_permille()
        );
    }
}

fn print_axis_rows(outcomes: &[PairOutcome]) {
    let mut by_axis: BTreeMap<(&str, &str), Grade> = BTreeMap::new();
    for outcome in outcomes {
        by_axis
            .entry((outcome.axis, outcome.flavor.label()))
            .or_default()
            .absorb(&outcome.grade);
    }
    for ((axis, flavor), total) in &by_axis {
        let tally: Tally = total.overall;
        println!(
            "axis {axis} on {flavor}: expected {}, recovered {}, WRONG {}, refused {}, missed {}, unbacked {}, unjudged {}, precision {} per mille, recall {} per mille",
            tally.expected(),
            tally.recovered,
            tally.wrong,
            tally.refused,
            tally.missed,
            tally.unbacked,
            tally.unjudged,
            tally.precision_permille(),
            tally.recall_permille()
        );
    }
}

fn print_wrong_matches(total: &Grade) {
    if total.wrong_matches.is_empty() {
        println!("wrong matches: none in the whole corpus");
        return;
    }
    println!("wrong matches: {}", total.wrong_matches.len());
    for wrong in total.wrong_matches.iter().take(WRONG_REPORT_LIMIT) {
        let wrong: &WrongMatch = wrong;
        let names: Vec<&str> = wrong.names.iter().map(String::as_str).collect();
        println!(
            "  WRONG [{}]: {:#x} ({}) paired with {:#x}",
            wrong.stage.label(),
            wrong.subject,
            names.join(", "),
            wrong.produced
        );
    }
}

#[test]
fn the_truth_and_the_grader_never_reach_into_the_matcher() {
    let forbidden: [&str; 5] = [
        "disrobe_similarity",
        "disrobe_pass_native",
        "extract_function_features",
        "match_functions",
        "FunctionFeatures",
    ];
    let modules: [(&str, &str); 3] = [
        ("truth.rs", TRUTH_SOURCE),
        ("grade.rs", GRADE_SOURCE),
        ("corpus.rs", CORPUS_SOURCE),
    ];
    for (name, body) in modules {
        for token in forbidden {
            assert!(
                !body.contains(token),
                "{name} names {token}: ground truth and grading must stay outside the matcher"
            );
        }
    }
}

#[test]
fn a_deliberately_wrong_matching_is_graded_as_wrong() {
    let mut table: TruthTable = TruthTable::default();
    for index in 0..4_u64 {
        let left: Address = 0x1000 + index * 0x40;
        let right: Address = 0x9000 + index * 0x30;
        table.band_of.insert(left, SizeBand::Medium);
        table.entries.insert(
            left,
            truth::Correspondence {
                left,
                accepted: BTreeSet::from([right]),
                names: BTreeSet::from([format!("function_{index}")]),
                band: SizeBand::Medium,
                unchanged: false,
                folded: false,
            },
        );
    }

    let honest: Vec<Emission> = (0..4_u64)
        .map(|index: u64| Emission {
            subject: 0x1000 + index * 0x40,
            outcome: Outcome::Paired {
                counterpart: 0x9000 + index * 0x30,
                stage: Stage::DataReference,
            },
        })
        .collect();
    let straight: Grade = grade::grade(&honest, &table);
    assert_eq!(straight.overall.recovered, 4);
    assert_eq!(straight.overall.wrong, 0);

    let wrong: Vec<Emission> = rotated(&honest);
    let broken: Grade = grade::grade(&wrong, &table);
    assert_eq!(
        broken.overall.wrong, 4,
        "a rotated matching must be reported as four wrong pairs"
    );
    assert_eq!(broken.overall.recovered, 0);
    assert_eq!(broken.overall.precision_permille(), 0);
    println!(
        "grader self check: straight matching {} recovered {} wrong, rotated matching {} recovered {} wrong",
        straight.overall.recovered,
        straight.overall.wrong,
        broken.overall.recovered,
        broken.overall.wrong
    );
}

#[test]
fn the_corpus_grades_the_matcher_against_compiler_produced_ground_truth() {
    let Some(tools): Option<Toolchain> = Toolchain::discover() else {
        eprintln!("skipping: the corpus fixture directory is absent");
        return;
    };
    if !tools.can_strip() {
        eprintln!("skipping: neither llvm-strip nor strip is on PATH");
        return;
    }
    if !tools.has_gcc() && !tools.has_clang() {
        eprintln!("skipping: neither gcc nor clang is on PATH");
        return;
    }
    for (name, version) in tools.versions() {
        println!("toolchain {name}: {version}");
    }
    if !tools.has_gcc() {
        eprintln!("note: gcc absent, every hosted PE pair will skip");
    }
    if !tools.has_clang() {
        eprintln!("note: clang absent, every freestanding ELF pair will skip");
    }

    println!(
        "verdicts: recovered is a correspondence the matcher paired with the right counterpart, wrong is one it paired with something else, refused is one where it returned Ambiguous or Unmatched, missed is one whose left address never entered its subject list, unbacked is a pair it emitted for a function that exists only in the left image, unjudged is a pair whose left address carries no name in the unstripped build"
    );

    let programs: Vec<String> = tools.programs();
    assert!(!programs.is_empty(), "the corpus must carry programs");
    let mut bench: Bench = Bench::new(tools);
    let mut outcomes: Vec<PairOutcome> = Vec::new();
    let mut skipped: Vec<String> = Vec::new();

    for program in &programs {
        for recipe in &RECIPES {
            let right_program: String = if recipe.right.variant {
                let Some(variant): Option<String> = bench.tools.variant_of(program) else {
                    continue;
                };
                variant
            } else {
                program.clone()
            };
            match run_pair(&mut bench, program, &right_program, recipe) {
                Some(outcome) => outcomes.push(outcome),
                None => skipped.push(format!(
                    "{program} {} {} -{} vs {} -{}",
                    recipe.flavor.label(),
                    recipe.left.compiler.label(),
                    recipe.left.level,
                    recipe.right.compiler.label(),
                    recipe.right.level
                )),
            }
        }
    }

    if outcomes.is_empty() {
        eprintln!("skipping: no corpus pair built with the toolchain present here");
        return;
    }

    let mut total: Grade = Grade::default();
    let mut truth_total: usize = 0;
    let mut changed_total: usize = 0;
    let mut folded_total: usize = 0;
    let mut dropped_left: usize = 0;
    let mut dropped_right: usize = 0;
    let mut folded_left: usize = 0;
    let mut folded_right: usize = 0;
    let mut named_functions: usize = 0;
    let mut named_symbols: usize = 0;
    let mut subjects: usize = 0;
    let mut control_wrong: usize = 0;
    let mut control_recovered: usize = 0;
    for outcome in &outcomes {
        print_pair(outcome);
        total.absorb(&outcome.grade);
        truth_total += outcome.truth_total;
        changed_total += outcome.changed_total;
        folded_total += outcome.folded_total;
        dropped_left += outcome.dropped_left;
        dropped_right += outcome.dropped_right;
        folded_left += outcome.folded_left;
        folded_right += outcome.folded_right;
        named_functions += outcome.left_functions + outcome.right_functions;
        named_symbols += outcome.left_names + outcome.right_names;
        subjects += outcome.subjects;
        control_wrong += outcome.control_wrong;
        control_recovered += outcome.control_recovered;
    }

    println!();
    println!(
        "corpus: {} programs, {} graded pairs, {} pairs skipped, {} images built, {} function correspondences",
        programs.len(),
        outcomes.len(),
        skipped.len(),
        bench.built,
        truth_total
    );
    println!(
        "corpus: {changed_total} correspondences over code the two builds do not share instruction for instruction, {folded_total} where the linker put more than one name on one address"
    );
    println!(
        "excluded: {dropped_left} named functions present only in the left image and {dropped_right} present only in the right image, which is what inlining and a source edit produce"
    );
    println!(
        "ground truth read {named_functions} addressed functions carrying {named_symbols} names, {folded_left} left and {folded_right} right addresses carrying more than one name"
    );
    println!("matcher: {subjects} function subjects across the stripped left images");
    for entry in &bench.unbuildable {
        println!("unbuildable: {entry}");
    }
    for entry in skipped.iter().take(WRONG_REPORT_LIMIT) {
        println!("skipped pair: {entry}");
    }

    println!();
    print_stage_rows("stage", &total);
    println!();
    print_band_rows("size", &total);
    println!();
    print_axis_rows(&outcomes);

    println!();
    let overall: Tally = total.overall;
    println!(
        "overall: expected {}, recovered {}, WRONG {}, refused {}, missed {}, unbacked {}, unjudged {}",
        overall.expected(),
        overall.recovered,
        overall.wrong,
        overall.refused,
        overall.missed,
        overall.unbacked,
        overall.unjudged
    );
    println!(
        "overall: precision {} per mille, recall {} per mille, {} of the recovered correspondences carry more than one name on one address",
        overall.precision_permille(),
        overall.recall_permille(),
        total.folded_recovered
    );
    let changed: Tally = total.changed;
    println!(
        "changed code only: expected {}, recovered {}, WRONG {}, refused {}, missed {}, unbacked {}, precision {} per mille, recall {} per mille",
        changed.expected(),
        changed.recovered,
        changed.wrong,
        changed.refused,
        changed.missed,
        changed.unbacked,
        changed.precision_permille(),
        changed.recall_permille()
    );
    let identical: Tally = total.identical;
    println!(
        "code the two builds share instruction for instruction: expected {}, recovered {}, WRONG {}, refused {}, missed {}, precision {} per mille, recall {} per mille",
        identical.expected(),
        identical.recovered,
        identical.wrong,
        identical.refused,
        identical.missed,
        identical.precision_permille(),
        identical.recall_permille()
    );
    for outcome in &outcomes {
        if outcome.subjects == 0 {
            println!(
                "note: {} exposes no function start to the matcher once stripped, so all {} of its correspondences grade as missed",
                outcome.label, outcome.truth_total
            );
        }
    }
    println!();
    print_wrong_matches(&total);
    println!();
    println!(
        "control: rotating every emitted counterpart turns {} recovered into {} recovered and {} wrong",
        overall.recovered, control_recovered, control_wrong
    );

    assert!(
        overall.expected() >= CORRESPONDENCE_FLOOR,
        "the corpus produced {} correspondences, below the pinned floor of {CORRESPONDENCE_FLOOR}",
        overall.expected()
    );
    assert!(
        control_wrong > overall.wrong,
        "a rotated matching must grade worse than the real one, otherwise the grader cannot fail"
    );
    assert!(
        overall.recall_permille() >= RECALL_FLOOR_PERMILLE,
        "recall fell from the pinned floor of {RECALL_FLOOR_PERMILLE} per mille to {} per mille",
        overall.recall_permille()
    );
    assert!(
        overall.precision_permille() >= PRECISION_FLOOR_PERMILLE,
        "precision fell from the pinned floor of {PRECISION_FLOOR_PERMILLE} per mille to {} per mille",
        overall.precision_permille()
    );
    assert!(
        changed.precision_permille() >= CHANGED_PRECISION_FLOOR_PERMILLE,
        "precision over changed code fell from the pinned floor of {CHANGED_PRECISION_FLOOR_PERMILLE} per mille to {} per mille",
        changed.precision_permille()
    );
    let wrong_rate: u64 = grade::rate(overall.wrong, overall.judged_emissions());
    assert!(
        wrong_rate <= WRONG_CEILING_PERMILLE,
        "wrong matches rose to {wrong_rate} per mille of the judged pairs, above the pinned ceiling of {WRONG_CEILING_PERMILLE}"
    );
    for outcome in &outcomes {
        let tally: Tally = outcome.grade.overall;
        if tally.judged_emissions() < PAIR_PRECISION_SAMPLE {
            continue;
        }
        assert!(
            tally.precision_permille() >= PAIR_PRECISION_FLOOR_PERMILLE,
            "pair {} fell to {} per mille precision, below the pinned per pair floor of {PAIR_PRECISION_FLOOR_PERMILLE}",
            outcome.label,
            tally.precision_permille()
        );
    }
}
