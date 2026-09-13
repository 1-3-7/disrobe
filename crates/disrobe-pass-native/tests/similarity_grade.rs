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
use std::path::PathBuf;
use std::rc::Rc;

use corpus::{Artifact, BuildKey, Compiler, Flavor, Toolchain};
use grade::{Emission, Grade, Outcome, Stage, Tally, WrongMatch};
use truth::{Address, ImageSymbols, SizeBand, TruthTable};

use disrobe_pass_native::extract_function_features;
use disrobe_similarity::{
    BasicBlock, ControlFlowGraph, DataReference, FunctionFeatures, FunctionId, FunctionVerdict,
    InstructionCategory, MatchReport, Verdict, body_of, match_functions,
};
use object::{Object as _, ObjectSymbol as _, SymbolKind as ObjectSymbolKind};

const TRUTH_SOURCE: &str = include_str!("similarity_grade/truth.rs");

const GRADE_SOURCE: &str = include_str!("similarity_grade/grade.rs");

const CORPUS_SOURCE: &str = include_str!("similarity_grade/corpus.rs");

const CORRESPONDENCE_FLOOR: usize = 500;

const RECALL_FLOOR_PERMILLE: u64 = 600;

const PRECISION_FLOOR_PERMILLE: u64 = 980;

const CHANGED_PRECISION_FLOOR_PERMILLE: u64 = 800;

const WRONG_CEILING_PERMILLE: u64 = 10;

const PAIR_PRECISION_FLOOR_PERMILLE: u64 = 900;

const PAIR_PRECISION_SAMPLE: usize = 8;

const WRONG_REPORT_LIMIT: usize = 40;

const AARCH64_BASELINE_MISSED: usize = 23;

const DYNAMIC_SYMBOL_STRIPPED_ELF: &[u8] =
    include_bytes!("../../../corpus/native/discovery/disc_aarch64_shared.stripped.elf");

const AARCH64_CORRESPONDENCE_IDENTITIES: [&str; 97] = [
    "base32::_start",
    "base32::b32_decode",
    "base32::b32_encode",
    "base32::b64_decode",
    "base32::b64_encode",
    "base32::codec_report",
    "base32::corpus_main",
    "base32::memcmp",
    "base32::memcpy",
    "base32::memset",
    "bignum::_start",
    "bignum::bn_add",
    "bignum::bn_compare",
    "bignum::bn_div_small",
    "bignum::bn_format_hex",
    "bignum::bn_mul_small",
    "bignum::bn_shift_left",
    "bignum::bn_status",
    "bignum::bn_sub",
    "bignum::corpus_main",
    "bignum::memcmp",
    "bignum::memcpy",
    "bignum::memset",
    "crc_hash::_start",
    "crc_hash::adler32",
    "crc_hash::corpus_main",
    "crc_hash::crc32_build_table",
    "crc_hash::crc32_update",
    "crc_hash::digest_label",
    "crc_hash::djb2",
    "crc_hash::fnv1a64",
    "crc_hash::memcmp",
    "crc_hash::memcpy",
    "crc_hash::memset",
    "crc_hash::murmur3_32",
    "crc_hash::splitmix64",
    "json_scan::_start",
    "json_scan::corpus_main",
    "json_scan::json_diagnosis",
    "json_scan::json_scan_literal",
    "json_scan::json_scan_number",
    "json_scan::json_scan_string",
    "json_scan::json_skip_space",
    "json_scan::json_validate",
    "json_scan::memcmp",
    "json_scan::memcpy",
    "json_scan::memset",
    "matrix::_start",
    "matrix::corpus_main",
    "matrix::matrix_determinant",
    "matrix::matrix_identity",
    "matrix::matrix_minor",
    "matrix::matrix_multiply",
    "matrix::matrix_power",
    "matrix::matrix_shape",
    "matrix::matrix_trace",
    "matrix::matrix_transpose",
    "matrix::memcmp",
    "matrix::memcpy",
    "matrix::memset",
    "sortsearch::_start",
    "sortsearch::binary_search",
    "sortsearch::corpus_main",
    "sortsearch::heapsort",
    "sortsearch::hoare_partition",
    "sortsearch::insertion_sort",
    "sortsearch::is_sorted",
    "sortsearch::memcmp",
    "sortsearch::memcpy",
    "sortsearch::memset",
    "sortsearch::merge_runs",
    "sortsearch::ordering_report",
    "sortsearch::quicksort",
    "sortsearch::sift_down",
    "text_util::_start",
    "text_util::corpus_main",
    "text_util::memcmp",
    "text_util::memcpy",
    "text_util::memset",
    "text_util::text_case_fold",
    "text_util::text_length",
    "text_util::text_levenshtein",
    "text_util::text_run_length",
    "text_util::text_summary",
    "text_util::text_tokens",
    "text_util::text_trim",
    "text_util::text_wrap_lines",
    "vm_interp::_start",
    "vm_interp::corpus_main",
    "vm_interp::memcmp",
    "vm_interp::memcpy",
    "vm_interp::memset",
    "vm_interp::vm_build_program",
    "vm_interp::vm_opcode_name",
    "vm_interp::vm_reset",
    "vm_interp::vm_run",
    "vm_interp::vm_verify",
];

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
    stripped_symbol_free: bool,
}

fn stripped_image_has_no_function_symbols(bytes: &[u8]) -> Option<bool> {
    let file: object::File<'_> = object::File::parse(bytes).ok()?;
    let has_defined_function_symbol: bool =
        file.symbols()
            .chain(file.dynamic_symbols())
            .any(|symbol: object::Symbol<'_, '_>| {
                !symbol.is_undefined()
                    && matches!(
                        symbol.kind(),
                        ObjectSymbolKind::Text | ObjectSymbolKind::Label
                    )
                    && symbol.section_index().is_some()
            });
    Some(!has_defined_function_symbol)
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
                    Some(Rc::new(Prepared {
                        symbols,
                        features,
                        stripped_symbol_free: stripped_image_has_no_function_symbols(
                            &artifact.stripped,
                        )?,
                    }))
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
    correspondence_identities: BTreeSet<String>,
    missed_identities: BTreeSet<String>,
    left_stripped_symbol_free: bool,
}

fn correspondence_identities(program: &str, table: &TruthTable) -> BTreeMap<Address, String> {
    table
        .entries
        .iter()
        .map(
            |(address, correspondence): (&Address, &truth::Correspondence)| {
                let names: Vec<&str> = correspondence.names.iter().map(String::as_str).collect();
                (*address, format!("{program}::{}", names.join("|")))
            },
        )
        .collect()
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
    let emitted_subjects: BTreeSet<Address> = emitted
        .iter()
        .map(|entry: &Emission| entry.subject)
        .collect();
    let identities: BTreeMap<Address, String> = correspondence_identities(program, &table);
    let correspondence_identities: BTreeSet<String> = identities.values().cloned().collect();
    let missed_identities: BTreeSet<String> = identities
        .iter()
        .filter(|(address, _): &(&Address, &String)| !emitted_subjects.contains(address))
        .map(|(_, identity): (&Address, &String)| identity.clone())
        .collect();
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
        correspondence_identities,
        missed_identities,
        left_stripped_symbol_free: left.stripped_symbol_free,
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
fn a_dynamic_function_symbol_disqualifies_a_stripped_grade_input() {
    assert_eq!(
        stripped_image_has_no_function_symbols(DYNAMIC_SYMBOL_STRIPPED_ELF),
        Some(false)
    );
}

fn single_block_features(
    id: u64,
    references: &[DataReference],
    categories: &[InstructionCategory],
) -> FunctionFeatures {
    FunctionFeatures::with_structure(
        FunctionId(id),
        references.iter().cloned(),
        ControlFlowGraph::new(0, [BasicBlock::new([], categories.iter().copied())])
            .expect("the single block fixture has no invalid successor"),
    )
}

#[test]
fn reference_and_small_shape_together_distinguish_wrappers_from_import_thunks() {
    let wrapper: [InstructionCategory; 3] = [
        InstructionCategory::Load,
        InstructionCategory::Call,
        InstructionCategory::Return,
    ];
    let thunk: [InstructionCategory; 1] = [InstructionCategory::Branch];
    let format: [DataReference; 1] = [DataReference::imported_call("format")];
    let scan: [DataReference; 1] = [DataReference::imported_call("scan")];
    let left: [FunctionFeatures; 4] = [
        single_block_features(10, &format, &wrapper),
        single_block_features(11, &format, &thunk),
        single_block_features(12, &scan, &wrapper),
        single_block_features(13, &scan, &thunk),
    ];
    let right: [FunctionFeatures; 4] = [
        single_block_features(20, &format, &wrapper),
        single_block_features(21, &format, &thunk),
        single_block_features(22, &scan, &wrapper),
        single_block_features(23, &scan, &thunk),
    ];
    let report: MatchReport = match_functions(&left, &right);
    assert_eq!(report.exact_count(), 0);
    assert_eq!(
        report.matched_pairs(),
        vec![
            (FunctionId(10), FunctionId(20)),
            (FunctionId(11), FunctionId(21)),
            (FunctionId(12), FunctionId(22)),
            (FunctionId(13), FunctionId(23)),
        ]
    );
    for (left, right) in report.matched_pairs() {
        assert_eq!(
            report.right_verdict(right).and_then(Verdict::counterpart),
            Some(left)
        );
    }
    for (subject, name) in [(10, "format"), (11, "format"), (12, "scan"), (13, "scan")] {
        let verdict: &Verdict = report
            .left_verdict(FunctionId(subject))
            .expect("every fixture subject has a verdict");
        let rendered: serde_json::Value =
            serde_json::to_value(body_of(verdict)).expect("verdict evidence serializes");
        assert_eq!(
            rendered["shared_references"],
            serde_json::json!([{ "kind": "imported-call", "name": name }])
        );
    }
}

#[test]
fn reference_and_small_shape_still_refuse_duplicate_holders() {
    let references: [DataReference; 1] = [DataReference::imported_call("format")];
    let categories: [InstructionCategory; 1] = [InstructionCategory::Branch];
    let left: [FunctionFeatures; 2] = [
        single_block_features(10, &references, &categories),
        single_block_features(11, &references, &categories),
    ];
    let right: [FunctionFeatures; 2] = [
        single_block_features(20, &references, &categories),
        single_block_features(21, &references, &categories),
    ];
    assert_eq!(match_functions(&left, &right).matched_count(), 0);
    assert_eq!(match_functions(&left, &right[..1]).matched_count(), 0);
}

#[test]
fn inferred_import_thunks_keep_duplicate_import_names_ambiguous() {
    let references: [DataReference; 1] = [DataReference::imported_call("shared_import")];
    let categories: [InstructionCategory; 1] = [InstructionCategory::Branch];
    let left: [FunctionFeatures; 2] = [10, 11].map(|id| {
        single_block_features(id, &references, &categories).requiring_reference_corroboration()
    });
    let right: [FunctionFeatures; 2] = [20, 21].map(|id| {
        single_block_features(id, &references, &categories).requiring_reference_corroboration()
    });
    for candidates in [right.as_slice(), &right[..1]] {
        let report: MatchReport = match_functions(&left, candidates);
        assert_eq!(report.matched_count(), 0);
        for subject in &left {
            assert!(matches!(
                report.left_verdict(subject.id()),
                Some(Verdict::Ambiguous { .. })
            ));
            assert_eq!(subject.references(), &BTreeSet::from(references.clone()));
        }
    }
}

#[test]
fn a_small_shape_without_a_reference_still_cannot_anchor_a_match() {
    let categories: [InstructionCategory; 2] =
        [InstructionCategory::Arithmetic, InstructionCategory::Return];
    let left: [FunctionFeatures; 1] = [single_block_features(10, &[], &categories)];
    let right: [FunctionFeatures; 1] = [single_block_features(20, &[], &categories)];
    assert_eq!(match_functions(&left, &right).matched_count(), 0);
}

#[test]
fn a_single_import_call_without_structure_cannot_anchor_a_match() {
    let references: [DataReference; 1] = [DataReference::imported_call("shared_service")];
    let left: [FunctionFeatures; 1] = [FunctionFeatures::new(FunctionId(10), references.clone())];
    let right: [FunctionFeatures; 1] = [FunctionFeatures::new(FunctionId(20), references)];
    let report: MatchReport = match_functions(&left, &right);
    assert_eq!(report.exact_count(), 0);
    assert_eq!(report.matched_count(), 0);
    assert_eq!(
        report.left_verdict(FunctionId(10)),
        Some(&Verdict::Ambiguous {
            candidates: BTreeSet::from([FunctionId(20)]),
            own_side: 1,
            other_side: 1,
        })
    );
    assert_eq!(
        report.right_verdict(FunctionId(20)),
        Some(&Verdict::Ambiguous {
            candidates: BTreeSet::from([FunctionId(10)]),
            own_side: 1,
            other_side: 1,
        })
    );
}

fn callback_loop_shape(operation: InstructionCategory) -> ControlFlowGraph {
    ControlFlowGraph::new(
        0,
        [
            BasicBlock::new(
                [3, 1],
                [
                    InstructionCategory::Arithmetic,
                    InstructionCategory::Load,
                    InstructionCategory::Load,
                    InstructionCategory::Compare,
                    InstructionCategory::Branch,
                ],
            ),
            BasicBlock::new(
                [2],
                [InstructionCategory::Other, InstructionCategory::Other],
            ),
            BasicBlock::new(
                [2, 3],
                [
                    operation,
                    InstructionCategory::Load,
                    InstructionCategory::Move,
                    InstructionCategory::Load,
                    InstructionCategory::Store,
                    InstructionCategory::Compare,
                    InstructionCategory::Branch,
                ],
            ),
            BasicBlock::new(
                [],
                [InstructionCategory::Arithmetic, InstructionCategory::Return],
            ),
        ],
    )
    .expect("the callback loop graph is closed")
}

#[test]
fn an_uncorroborated_callback_loop_keeps_shape_candidates_without_matching() {
    let shape: ControlFlowGraph = callback_loop_shape(InstructionCategory::Call);
    let left: [FunctionFeatures; 1] = [FunctionFeatures::with_structure(
        FunctionId(10),
        [],
        shape.clone(),
    )];
    let right: [FunctionFeatures; 1] =
        [FunctionFeatures::with_structure(FunctionId(20), [], shape)];
    let report: MatchReport = match_functions(&left, &right);
    assert_eq!(report.matched_count(), 0);
    assert_eq!(
        report.left_verdict(FunctionId(10)),
        Some(&Verdict::Ambiguous {
            candidates: BTreeSet::from([FunctionId(20)]),
            own_side: 1,
            other_side: 1,
        })
    );
    assert_eq!(
        report.right_verdict(FunctionId(20)),
        Some(&Verdict::Ambiguous {
            candidates: BTreeSet::from([FunctionId(10)]),
            own_side: 1,
            other_side: 1,
        })
    );
}

#[test]
fn a_callback_loop_uses_import_references_with_structural_corroboration() {
    let shape: ControlFlowGraph = callback_loop_shape(InstructionCategory::Call);
    let references: [DataReference; 1] = [DataReference::imported_call("shared_service")];
    let left: [FunctionFeatures; 1] = [FunctionFeatures::with_structure(
        FunctionId(10),
        references.clone(),
        shape.clone(),
    )];
    let right: [FunctionFeatures; 1] = [FunctionFeatures::with_structure(
        FunctionId(20),
        references.clone(),
        shape,
    )];
    let report: MatchReport = match_functions(&left, &right);
    assert_eq!(report.exact_count(), 0);
    assert_eq!(report.structural_count(), 1);
    assert!(matches!(
        report.left_verdict(FunctionId(10)),
        Some(Verdict::Structural { shared_references, .. })
            if shared_references == &BTreeSet::from(references.clone())
    ));
    let inferred: [FunctionFeatures; 1] =
        left.map(FunctionFeatures::requiring_reference_corroboration);
    let report: MatchReport = match_functions(&inferred, &right);
    assert_eq!(report.structural_count(), 1);
    assert!(matches!(
        report.left_verdict(FunctionId(10)),
        Some(Verdict::Structural { shared_references, .. })
            if shared_references == &BTreeSet::from(references)
    ));

    let shape: ControlFlowGraph = callback_loop_shape(InstructionCategory::Arithmetic);
    let left: [FunctionFeatures; 1] = [FunctionFeatures::with_structure(
        FunctionId(10),
        [],
        shape.clone(),
    )];
    let right: [FunctionFeatures; 1] =
        [FunctionFeatures::with_structure(FunctionId(20), [], shape)];
    assert_eq!(match_functions(&left, &right).structural_count(), 1);
}

#[test]
fn inferred_reference_anchors_require_symmetric_structural_corroboration() {
    let references: [DataReference; 1] = [DataReference::string_literal("a shared diagnostic")];
    let left: [FunctionFeatures; 1] = [single_block_features(
        10,
        &references,
        &[InstructionCategory::Load, InstructionCategory::Return],
    )
    .requiring_reference_corroboration()];
    let right: [FunctionFeatures; 1] = [single_block_features(
        20,
        &references,
        &[InstructionCategory::Call, InstructionCategory::Return],
    )];
    let report: MatchReport = match_functions(&left, &right);
    assert_eq!(report.matched_count(), 0);
    assert_eq!(
        report.left_verdict(FunctionId(10)),
        Some(&Verdict::Ambiguous {
            candidates: BTreeSet::from([FunctionId(20)]),
            own_side: 1,
            other_side: 1,
        })
    );
    assert_eq!(
        report.right_verdict(FunctionId(20)),
        Some(&Verdict::Ambiguous {
            candidates: BTreeSet::from([FunctionId(10)]),
            own_side: 1,
            other_side: 1,
        })
    );
}

#[test]
fn an_inferred_leaf_matches_its_relocated_leaf_with_references_and_shape() {
    let references: [DataReference; 1] = [DataReference::string_literal("a shared diagnostic")];
    let categories: [InstructionCategory; 2] =
        [InstructionCategory::Load, InstructionCategory::Return];
    let left: [FunctionFeatures; 1] =
        [single_block_features(10, &references, &categories).requiring_reference_corroboration()];
    for require_corroboration in [false, true] {
        let right: FunctionFeatures = single_block_features(20, &references, &categories);
        let right: [FunctionFeatures; 1] = [if require_corroboration {
            right.requiring_reference_corroboration()
        } else {
            right
        }];
        let report: MatchReport = match_functions(&left, &right);
        assert_eq!(report.exact_count(), 0);
        assert_eq!(
            report.structural_pairs(),
            vec![(FunctionId(10), FunctionId(20))]
        );
        for entry in report.left.iter().chain(&report.right) {
            let Verdict::Structural {
                shared_references, ..
            } = &entry.verdict
            else {
                panic!("both sides retain the corroborated match");
            };
            assert_eq!(shared_references, &BTreeSet::from(references.clone()));
        }
    }
}

#[test]
fn established_reference_anchors_keep_their_existing_exact_admission() {
    let references: [DataReference; 1] = [DataReference::string_literal("a shared diagnostic")];
    let left: [FunctionFeatures; 1] = [single_block_features(
        10,
        &references,
        &[InstructionCategory::Load, InstructionCategory::Return],
    )];
    let right: [FunctionFeatures; 1] = [single_block_features(
        20,
        &references,
        &[InstructionCategory::Call, InstructionCategory::Return],
    )];
    let report: MatchReport = match_functions(&left, &right);
    assert_eq!(report.exact_pairs(), vec![(FunctionId(10), FunctionId(20))]);
    assert_eq!(
        report
            .right_verdict(FunctionId(20))
            .and_then(Verdict::counterpart),
        Some(FunctionId(10))
    );
}

#[test]
fn inferred_reference_holders_cannot_manufacture_standalone_uniqueness() {
    let references: [DataReference; 1] = [DataReference::string_literal("a shared diagnostic")];
    let left: [FunctionFeatures; 2] = [
        FunctionFeatures::new(FunctionId(10), references.clone()),
        FunctionFeatures::new(FunctionId(11), references.clone())
            .requiring_reference_corroboration(),
    ];
    let right: [FunctionFeatures; 1] = [FunctionFeatures::new(FunctionId(20), references)];
    let report: MatchReport = match_functions(&left, &right);
    assert_eq!(report.matched_count(), 0);
    assert_eq!(report.left.len(), 2);
    assert_eq!(
        report.right_verdict(FunctionId(20)),
        Some(&Verdict::Ambiguous {
            candidates: BTreeSet::from([FunctionId(10), FunctionId(11)]),
            own_side: 1,
            other_side: 2,
        })
    );
}

#[test]
fn standalone_shape_evidence_keeps_its_existing_json_fields() {
    let structure: ControlFlowGraph = ControlFlowGraph::new(
        0,
        [
            BasicBlock::new([1], [InstructionCategory::Load]),
            BasicBlock::new([2], [InstructionCategory::Arithmetic]),
            BasicBlock::new([], [InstructionCategory::Return]),
        ],
    )
    .expect("all successors remain inside the fixture");
    let left: [FunctionFeatures; 1] = [FunctionFeatures::with_structure(
        FunctionId(10),
        [],
        structure.clone(),
    )];
    let right: [FunctionFeatures; 1] = [FunctionFeatures::with_structure(
        FunctionId(20),
        [],
        structure.clone(),
    )];
    let report: MatchReport = match_functions(&left, &right);
    assert_eq!(report.structural_count(), 1);
    let verdict: &Verdict = report
        .left_verdict(FunctionId(10))
        .expect("the fixture subject has a verdict");
    let rendered: serde_json::Value =
        serde_json::to_value(body_of(verdict)).expect("verdict evidence serializes");
    assert_eq!(
        rendered,
        serde_json::json!({
            "verdict": "control-flow",
            "counterpart": 20,
            "fingerprint": structure.fingerprint().value(),
            "instructions": 3,
            "instruction_mix": [
                { "category": "arithmetic", "count": 1 },
                { "category": "load", "count": 1 },
                { "category": "return", "count": 1 }
            ]
        })
    );
}

#[test]
fn a_stripped_optimized_elf_keeps_its_prologue_free_string_function() {
    let tools: Toolchain = Toolchain::discover().expect("the compiler corpus is available");
    let key: BuildKey = BuildKey {
        program: "base32".to_owned(),
        compiler: Compiler::Clang,
        flavor: Flavor::FreestandingElf64,
        level: "O2",
    };
    let artifact: Artifact = tools
        .build(&key)
        .expect("Clang builds the freestanding corpus");
    assert_eq!(
        stripped_image_has_no_function_symbols(&artifact.stripped),
        Some(true)
    );
    let symbols: ImageSymbols = ImageSymbols::read(&artifact.symbols)
        .expect("the unstripped compiler output supplies independent symbols");
    let truth: TruthTable = TruthTable::derive(&symbols, &symbols);
    let (&address, _): (&Address, &truth::Correspondence) = truth
        .entries
        .iter()
        .find(|(_, entry)| entry.names.contains("codec_report"))
        .expect("the compiler emitted codec_report");
    let features: Vec<FunctionFeatures> =
        extract_function_features(&artifact.stripped).expect("the stripped ELF decodes");
    let recovered: &FunctionFeatures = features
        .iter()
        .find(|features: &&FunctionFeatures| features.id().0 == address)
        .expect("the stripped caller discovers the prologue-free function");
    assert!(recovered.requires_reference_corroboration());
    assert_eq!(
        recovered.references(),
        &BTreeSet::from([
            DataReference::string_literal("the round trip lost bytes on the way back"),
            DataReference::string_literal("the encoder produced an empty block"),
            DataReference::string_literal("the round trip returned every byte it was given"),
        ])
    );
}

#[test]
fn an_inferred_leaf_does_not_match_its_inlined_callers_references_alone() {
    let tools: Toolchain = Toolchain::discover().expect("the compiler corpus is available");
    let mut bench: Bench = Bench::new(tools);
    let [left, right]: [Rc<Prepared>; 2] = ["O2", "Os"].map(|level: &'static str| {
        bench
            .prepared(&BuildKey {
                program: "base32".to_owned(),
                compiler: Compiler::Clang,
                flavor: Flavor::FreestandingElf64,
                level,
            })
            .expect("Clang builds the stripped freestanding corpus")
    });
    assert!(left.stripped_symbol_free && right.stripped_symbol_free);
    let truth: TruthTable = TruthTable::derive(&left.symbols, &right.symbols);
    let (&subject, expected): (&Address, &truth::Correspondence) = truth
        .entries
        .iter()
        .find(|(_, entry)| entry.names.contains("codec_report"))
        .expect("both compilers emitted codec_report");
    assert!(
        left.features
            .iter()
            .any(|features| features.id().0 == subject)
    );
    let report: MatchReport = match_functions(&left.features, &right.features);
    let verdict: &Verdict = report
        .left_verdict(FunctionId(subject))
        .expect("the inferred leaf remains a reported subject");
    if let Some(counterpart) = verdict.counterpart() {
        assert!(
            expected.accepted.contains(&counterpart.0),
            "the leaf cannot match a caller merely because its inlined copy shares the references: {verdict:?}"
        );
    }
}

#[test]
#[cfg(target_os = "windows")]
fn stripped_pe_keeps_unreferenced_import_thunks_as_corroborated_subjects() {
    use object::ObjectSection as _;

    let tools: Toolchain = Toolchain::discover().expect("the compiler corpus is available");
    let artifact: Artifact = tools
        .build_forced_import_thunk()
        .expect("GCC links the authored forced-import PE fixture");
    assert_eq!(
        stripped_image_has_no_function_symbols(&artifact.stripped),
        Some(true)
    );
    let reference: object::File<'_> = object::File::parse(artifact.symbols.as_slice())
        .expect("the linker supplies an independent symbol table");
    let symbol: object::Symbol<'_, '_> = reference
        .symbols()
        .find(|symbol| symbol.name() == Ok("Sleep") && symbol.is_definition())
        .expect("the linker retains the forced Sleep import thunk");
    let section: object::Section<'_, '_> = reference
        .section_by_index(symbol.section_index().expect("the thunk has a section"))
        .expect("the thunk section exists");
    assert_eq!(section.kind(), object::SectionKind::Text);
    let address: Address = symbol.address();
    assert_ne!(address, 0);
    let features: Vec<FunctionFeatures> =
        extract_function_features(&artifact.stripped).expect("the stripped PE decodes");
    let recovered: &FunctionFeatures = features
        .iter()
        .find(|features: &&FunctionFeatures| features.id().0 == address)
        .unwrap_or_else(|| panic!("the stripped caller omitted forced import thunk Sleep"));
    assert!(recovered.requires_reference_corroboration());
    assert_eq!(
        recovered.references(),
        &BTreeSet::from([DataReference::imported_call("Sleep")])
    );
}

#[test]
#[cfg(target_os = "windows")]
fn stripped_pe_keeps_a_constructor_tail_before_undecodable_data() {
    let tools: Toolchain = Toolchain::discover().expect("the compiler corpus is available");
    let artifact: Artifact = tools
        .build(&BuildKey {
            program: "base32".to_owned(),
            compiler: Compiler::Gcc,
            flavor: Flavor::Hosted,
            level: "O2",
        })
        .expect("GCC builds the hosted PE corpus");
    assert_eq!(
        stripped_image_has_no_function_symbols(&artifact.stripped),
        Some(true)
    );
    let symbols: ImageSymbols = ImageSymbols::read(&artifact.symbols)
        .expect("the compiler supplies independent function symbols");
    let truth: TruthTable = TruthTable::derive(&symbols, &symbols);
    let address_of = |name: &str| -> Address {
        *truth
            .entries
            .iter()
            .find(|(_, entry)| entry.names.contains(name))
            .unwrap_or_else(|| panic!("the runtime emitted {name}"))
            .0
    };
    let address: Address = address_of("register_frame_ctor");
    let callee: Address = address_of("__gcc_register_frame");
    let features: Vec<FunctionFeatures> =
        extract_function_features(&artifact.stripped).expect("the stripped PE decodes");
    let recovered: &FunctionFeatures = features
        .iter()
        .find(|features: &&FunctionFeatures| features.id().0 == address)
        .expect("the stripped caller discovers the constructor tail");
    let structure: &ControlFlowGraph = recovered
        .structure()
        .expect("unreachable constructor data cannot erase the resolved tail jump");
    assert_eq!(structure.instruction_mix().total(), 1);
    assert_eq!(
        recovered.call_targets(),
        &BTreeSet::from([FunctionId(callee)])
    );
}

#[test]
fn stripped_elf_keeps_an_interior_prefix_function_without_seeding_the_section_head() {
    let tools: Toolchain = Toolchain::discover().expect("the compiler corpus is available");
    let artifact: Artifact = tools
        .build(&BuildKey {
            program: "text_util".to_owned(),
            compiler: Compiler::Clang,
            flavor: Flavor::FreestandingElf64,
            level: "O2",
        })
        .expect("Clang builds the freestanding ELF corpus");
    assert_eq!(
        stripped_image_has_no_function_symbols(&artifact.stripped),
        Some(true)
    );
    let symbols: ImageSymbols = ImageSymbols::read(&artifact.symbols)
        .expect("the compiler supplies independent function symbols");
    let truth: TruthTable = TruthTable::derive(&symbols, &symbols);
    let address_of = |name: &str| -> Address {
        *truth
            .entries
            .iter()
            .find(|(_, entry)| entry.names.contains(name))
            .unwrap_or_else(|| panic!("the compiler emitted {name}"))
            .0
    };
    let head: Address = address_of("text_length");
    let interior: Address = address_of("text_trim");
    let anchor: Address = address_of("corpus_main");
    assert!(head < interior && interior < anchor);
    let features: Vec<FunctionFeatures> =
        extract_function_features(&artifact.stripped).expect("the stripped ELF decodes");
    assert!(
        features.iter().all(|features| features.id().0 != head),
        "a section head alone cannot establish a function"
    );
    let recovered: &FunctionFeatures = features
        .iter()
        .find(|features| features.id().0 == interior)
        .expect("a closed padded body separates the interior prefix function");
    assert!(recovered.requires_reference_corroboration());
    assert!(recovered.structure().is_some());
    assert!(
        recovered
            .references()
            .contains(&DataReference::UnusualConstant(0x1_0000_0600))
    );
}

#[test]
fn compiler_alignment_nops_do_not_break_a_corroborated_correspondence() {
    let tools: Toolchain = Toolchain::discover().expect("the compiler corpus is available");
    let mut bench: Bench = Bench::new(tools);
    let [left, right]: [Rc<Prepared>; 2] = ["O2", "Os"].map(|level: &'static str| {
        bench
            .prepared(&BuildKey {
                program: "base32".to_owned(),
                compiler: Compiler::Clang,
                flavor: Flavor::FreestandingElf64,
                level,
            })
            .expect("Clang builds the freestanding compiler corpus")
    });
    assert!(left.stripped_symbol_free && right.stripped_symbol_free);
    let truth: TruthTable = TruthTable::derive(&left.symbols, &right.symbols);
    let (&subject, expected): (&Address, &truth::Correspondence) = truth
        .entries
        .iter()
        .find(|(_, entry)| entry.names.contains("b64_encode"))
        .expect("both compiler outputs identify b64_encode");
    let report: MatchReport = match_functions(&left.features, &right.features);
    let counterpart: FunctionId = report
        .left_verdict(FunctionId(subject))
        .and_then(Verdict::counterpart)
        .expect("alignment NOPs cannot erase the shared references and control flow");
    assert!(expected.accepted.contains(&counterpart.0));
}

#[test]
fn compiler_stack_data_immediates_survive_memory_spilling() {
    let tools: Toolchain = Toolchain::discover().expect("the compiler corpus is available");
    let mut bench: Bench = Bench::new(tools);
    let [left, right]: [Rc<Prepared>; 2] = ["O0", "O2"].map(|level: &'static str| {
        bench
            .prepared(&BuildKey {
                program: "crc_hash".to_owned(),
                compiler: Compiler::Gcc,
                flavor: Flavor::Hosted,
                level,
            })
            .expect("GCC builds the hosted compiler corpus")
    });
    assert!(left.stripped_symbol_free && right.stripped_symbol_free);
    let truth: TruthTable = TruthTable::derive(&left.symbols, &right.symbols);
    let (&subject, expected): (&Address, &truth::Correspondence) = truth
        .entries
        .iter()
        .find(|(_, entry)| entry.names.contains("digest_label"))
        .expect("both compiler outputs identify digest_label");
    for (image, addresses) in [
        (&left, BTreeSet::from([subject])),
        (&right, expected.accepted.clone()),
    ] {
        for address in addresses {
            let features: &FunctionFeatures = image
                .features
                .iter()
                .find(|features| features.id().0 == address)
                .expect("the stripped caller discovers digest_label");
            assert!(
                features
                    .references()
                    .contains(&DataReference::UnusualConstant(0xdead_beef)),
                "the compared data remains the same when its operand is spilled to the stack: {features:?}"
            );
        }
    }
    let report: MatchReport = match_functions(&left.features, &right.features);
    let counterpart: FunctionId = report
        .left_verdict(FunctionId(subject))
        .and_then(Verdict::counterpart)
        .expect("the complete independent references identify the compiled function");
    assert!(expected.accepted.contains(&counterpart.0));
}

#[test]
fn the_corpus_grades_the_matcher_against_compiler_produced_ground_truth() {
    let corpus_path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("similarity_corpus");
    assert!(
        corpus_path.is_dir(),
        "required similarity corpus fixture directory is absent: {}",
        corpus_path.display()
    );
    let Some(tools): Option<Toolchain> = Toolchain::discover() else {
        panic!("required writable scratch directory for the similarity corpus is unavailable");
    };
    assert!(
        tools.can_strip(),
        "required similarity corpus stripper is absent from PATH: need llvm-strip or strip"
    );
    assert!(
        tools.has_gcc(),
        "required similarity corpus compiler is absent from PATH: gcc"
    );
    assert!(
        tools.has_clang(),
        "required similarity corpus compiler is absent from PATH: clang"
    );
    for (name, version) in tools.versions() {
        println!("toolchain {name}: {version}");
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

    assert!(
        !outcomes.is_empty(),
        "required compiler-backed similarity corpus outcomes are absent: no corpus pair built"
    );

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
    let mut aarch64_correspondence_identities: BTreeSet<String> = BTreeSet::new();
    let mut aarch64_missed_identities: BTreeSet<String> = BTreeSet::new();
    let mut aarch64_symbol_bearing_inputs: BTreeSet<String> = BTreeSet::new();
    let mut aarch64_total: Grade = Grade::default();
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
        if matches!(outcome.flavor, Flavor::FreestandingAarch64) {
            aarch64_total.absorb(&outcome.grade);
            aarch64_correspondence_identities
                .extend(outcome.correspondence_identities.iter().cloned());
            aarch64_missed_identities.extend(outcome.missed_identities.iter().cloned());
            if !outcome.left_stripped_symbol_free {
                aarch64_symbol_bearing_inputs.insert(outcome.label.clone());
            }
        }
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
        !aarch64_correspondence_identities.is_empty(),
        "required AArch64 compiler-backed similarity corpus outcomes are absent"
    );
    assert!(
        aarch64_missed_identities.is_empty(),
        "the AArch64 discovery caller missed compiler-backed correspondences: {aarch64_missed_identities:?}; the measured population was {aarch64_correspondence_identities:?}"
    );
    let expected_aarch64_identities: BTreeSet<String> = AARCH64_CORRESPONDENCE_IDENTITIES
        .into_iter()
        .map(str::to_owned)
        .collect();
    assert_eq!(
        aarch64_correspondence_identities, expected_aarch64_identities,
        "the compiler-backed AArch64 correspondence membership changed"
    );
    assert!(
        aarch64_symbol_bearing_inputs.is_empty(),
        "the AArch64 recovery grade was given inputs whose symbol tables already expose function starts: {aarch64_symbol_bearing_inputs:?}"
    );
    let aarch64: Tally = aarch64_total.overall;
    assert_eq!(
        (
            aarch64.expected(),
            aarch64.recovered,
            aarch64.wrong,
            aarch64.refused,
            aarch64.missed,
        ),
        (97, 0, 0, 97, 0),
        "AArch64 candidates must present all 97 compiler-backed correspondences while every match remains refused"
    );
    let presented_gain: usize = AARCH64_BASELINE_MISSED.saturating_sub(aarch64.missed);
    assert_eq!(
        presented_gain, AARCH64_BASELINE_MISSED,
        "AArch64 candidate presentation did not retain the measured +{AARCH64_BASELINE_MISSED} starts"
    );
    println!(
        "AArch64 candidate presentation: +{presented_gain} starts, {} presented, {} recovered, {} wrong, {} refused",
        aarch64.expected().saturating_sub(aarch64.missed),
        aarch64.recovered,
        aarch64.wrong,
        aarch64.refused
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
    for stage in Stage::ALL {
        let tally: Tally = total.stage(stage);
        assert_eq!(
            tally.wrong,
            0,
            "the {} stage paired {} correspondences with the wrong counterpart, and every stage \
             carries a standing claim of none",
            stage.label(),
            tally.wrong
        );
        if tally.judged_emissions() > 0 {
            assert_eq!(
                tally.precision_permille(),
                1000,
                "the {} stage fell to {} per mille precision over {} judged pairs",
                stage.label(),
                tally.precision_permille(),
                tally.judged_emissions()
            );
        }
    }
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
