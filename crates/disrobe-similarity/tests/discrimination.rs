#![allow(clippy::expect_used, clippy::panic)]

use disrobe_similarity::{
    BasicBlock, ControlFlowGraph, DataReference, FunctionFeatures, FunctionId, FunctionVerdict,
    InstructionCategory, MatchReport, MatchStage, UnmatchedCause, Verdict, match_functions,
};

const IMAGE_DELTA: u64 = 0x10_000;

fn block<const N: usize, const M: usize>(
    successors: [usize; N],
    categories: [InstructionCategory; M],
) -> BasicBlock {
    BasicBlock::new(successors, categories)
}

fn graph(entry: usize, blocks: Vec<BasicBlock>) -> ControlFlowGraph {
    ControlFlowGraph::new(entry, blocks).expect("the fixture graph is well formed")
}

fn leaf(category: InstructionCategory) -> ControlFlowGraph {
    graph(0, vec![block([], [category, InstructionCategory::Return])])
}

fn diamond(arm: InstructionCategory) -> ControlFlowGraph {
    graph(
        0,
        vec![
            block(
                [1, 2],
                [InstructionCategory::Compare, InstructionCategory::Branch],
            ),
            block([3], [arm]),
            block([3], [InstructionCategory::Store]),
            block([], [InstructionCategory::Return]),
        ],
    )
}

fn triangle(arm: InstructionCategory) -> ControlFlowGraph {
    graph(
        0,
        vec![
            block(
                [1, 2],
                [InstructionCategory::Compare, InstructionCategory::Branch],
            ),
            block([2], [arm]),
            block([], [InstructionCategory::Return]),
        ],
    )
}

fn counted_loop(arm: InstructionCategory) -> ControlFlowGraph {
    graph(
        0,
        vec![
            block([1], [InstructionCategory::Stack, InstructionCategory::Move]),
            block(
                [2, 4],
                [InstructionCategory::Compare, InstructionCategory::Branch],
            ),
            block([3], [arm, arm]),
            block(
                [1, 4],
                [InstructionCategory::Arithmetic, InstructionCategory::Branch],
            ),
            block([], [InstructionCategory::Return]),
        ],
    )
}

#[derive(Debug, Clone, Copy)]
struct Plan {
    slot: u64,
    text: Option<&'static str>,
    constant: Option<u64>,
    import: Option<&'static str>,
    shape: Shape,
    calls: &'static [u64],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shape {
    None,
    Leaf(InstructionCategory),
    Triangle(InstructionCategory),
    Diamond(InstructionCategory),
    Loop(InstructionCategory),
}

impl Shape {
    fn build(self) -> Option<ControlFlowGraph> {
        match self {
            Self::None => None,
            Self::Leaf(category) => Some(leaf(category)),
            Self::Triangle(category) => Some(triangle(category)),
            Self::Diamond(category) => Some(diamond(category)),
            Self::Loop(category) => Some(counted_loop(category)),
        }
    }
}

fn build(plans: &[Plan], base: u64) -> Vec<FunctionFeatures> {
    plans
        .iter()
        .map(|plan: &Plan| {
            let id: FunctionId = FunctionId(base + plan.slot);
            let mut references: Vec<DataReference> = Vec::new();
            if let Some(text) = plan.text {
                references.push(DataReference::string_literal(text));
            }
            if let Some(value) = plan.constant {
                references.push(DataReference::UnusualConstant(value));
            }
            if let Some(name) = plan.import {
                references.push(DataReference::imported_call(name));
            }
            let features: FunctionFeatures = match plan.shape.build() {
                Some(structure) => FunctionFeatures::with_structure(id, references, structure),
                None => FunctionFeatures::new(id, references),
            };
            features.calling(
                plan.calls
                    .iter()
                    .copied()
                    .map(|slot: u64| FunctionId(base + slot)),
            )
        })
        .collect()
}

const PARSER: [Plan; 10] = [
    Plan {
        slot: 0x000,
        text: Some("unsupported archive member"),
        constant: None,
        import: Some("inflateInit2"),
        shape: Shape::Diamond(InstructionCategory::Load),
        calls: &[0x100, 0x200],
    },
    Plan {
        slot: 0x100,
        text: None,
        constant: None,
        import: None,
        shape: Shape::Leaf(InstructionCategory::Arithmetic),
        calls: &[0x300],
    },
    Plan {
        slot: 0x200,
        text: None,
        constant: None,
        import: None,
        shape: Shape::Leaf(InstructionCategory::Logic),
        calls: &[],
    },
    Plan {
        slot: 0x300,
        text: None,
        constant: None,
        import: None,
        shape: Shape::Leaf(InstructionCategory::Shift),
        calls: &[],
    },
    Plan {
        slot: 0x400,
        text: Some("frame header too short"),
        constant: None,
        import: None,
        shape: Shape::Triangle(InstructionCategory::Move),
        calls: &[],
    },
    Plan {
        slot: 0x500,
        text: None,
        constant: Some(0x9e37_79b9),
        import: None,
        shape: Shape::Loop(InstructionCategory::Vector),
        calls: &[],
    },
    Plan {
        slot: 0x600,
        text: None,
        constant: Some(0x811c_9dc5),
        import: None,
        shape: Shape::Triangle(InstructionCategory::Compare),
        calls: &[],
    },
    Plan {
        slot: 0x700,
        text: None,
        constant: None,
        import: None,
        shape: Shape::Loop(InstructionCategory::System),
        calls: &[],
    },
    Plan {
        slot: 0x800,
        text: Some("checksum mismatch in member %s"),
        constant: None,
        import: None,
        shape: Shape::None,
        calls: &[],
    },
    Plan {
        slot: 0x900,
        text: None,
        constant: None,
        import: None,
        shape: Shape::Diamond(InstructionCategory::FloatingPoint),
        calls: &[],
    },
];

const UNRELATED: [Plan; 5] = [
    Plan {
        slot: 0xa00,
        text: Some("tls handshake aborted"),
        constant: None,
        import: Some("BCryptGenRandom"),
        shape: Shape::Diamond(InstructionCategory::Other),
        calls: &[0xb00],
    },
    Plan {
        slot: 0xb00,
        text: None,
        constant: Some(0x6a09_e667),
        import: None,
        shape: Shape::Loop(InstructionCategory::Call),
        calls: &[],
    },
    Plan {
        slot: 0xc00,
        text: Some("no route to host"),
        constant: None,
        import: None,
        shape: Shape::Triangle(InstructionCategory::Store),
        calls: &[],
    },
    Plan {
        slot: 0xd00,
        text: None,
        constant: Some(0xd76a_a478),
        import: None,
        shape: Shape::Leaf(InstructionCategory::FloatingPoint),
        calls: &[],
    },
    Plan {
        slot: 0xe00,
        text: Some("certificate pin rejected"),
        constant: None,
        import: None,
        shape: Shape::None,
        calls: &[],
    },
];

const FOREIGN: [Plan; 5] = [
    Plan {
        slot: 0xa00,
        text: Some("device queue overrun"),
        constant: None,
        import: Some("DeviceIoControl"),
        shape: Shape::Loop(InstructionCategory::Stack),
        calls: &[0xb00],
    },
    Plan {
        slot: 0xb00,
        text: None,
        constant: Some(0x0100_0193),
        import: None,
        shape: Shape::Diamond(InstructionCategory::Shift),
        calls: &[],
    },
    Plan {
        slot: 0xc00,
        text: Some("firmware slot is locked"),
        constant: None,
        import: None,
        shape: Shape::Triangle(InstructionCategory::Logic),
        calls: &[],
    },
    Plan {
        slot: 0xd00,
        text: None,
        constant: Some(0xfeed_face),
        import: None,
        shape: Shape::Leaf(InstructionCategory::System),
        calls: &[],
    },
    Plan {
        slot: 0xe00,
        text: Some("battery telemetry unavailable"),
        constant: None,
        import: None,
        shape: Shape::None,
        calls: &[],
    },
];

fn joined(first: &[Plan], second: &[Plan]) -> Vec<Plan> {
    first.iter().chain(second.iter()).copied().collect()
}

fn shuffled(features: &[FunctionFeatures]) -> Vec<FunctionFeatures> {
    let mut out: Vec<FunctionFeatures> = Vec::with_capacity(features.len());
    let (head, tail): (&[FunctionFeatures], &[FunctionFeatures]) =
        features.split_at(features.len() / 2);
    for pair in tail.iter().zip(head.iter()) {
        out.push(pair.0.clone());
        out.push(pair.1.clone());
    }
    while out.len() < features.len() {
        let missing: &FunctionFeatures = features
            .get(out.len())
            .expect("every input function is placed exactly once");
        out.push(missing.clone());
    }
    out
}

fn wrong_pairs(report: &MatchReport, delta: u64) -> Vec<(FunctionId, FunctionId)> {
    report
        .matched_pairs()
        .into_iter()
        .filter(|(subject, counterpart): &(FunctionId, FunctionId)| {
            counterpart.0 != subject.0.wrapping_add(delta)
        })
        .collect()
}

#[test]
fn a_rebuilt_image_matches_every_function_that_carries_evidence_to_its_own_counterpart() {
    let left: Vec<FunctionFeatures> = build(&PARSER, 0x40_0000);
    let right: Vec<FunctionFeatures> = shuffled(&build(&PARSER, 0x40_0000 + IMAGE_DELTA));

    let report: MatchReport = match_functions(&left, &right);

    assert_eq!(
        wrong_pairs(&report, IMAGE_DELTA),
        Vec::new(),
        "every pair in a rebuilt image must join a function to the same function at the new base"
    );
    assert_eq!(
        report.matched_count(),
        PARSER.len(),
        "all {} functions carry either a reference anchor, a distinguishing shape or a forced call \
         position, so the rebuild must be resolved in full: {:?}",
        PARSER.len(),
        report
            .left
            .iter()
            .filter(|entry: &&FunctionVerdict| entry.verdict.counterpart().is_none())
            .collect::<Vec<&FunctionVerdict>>()
    );
    assert_eq!(
        report.exact_count(),
        5,
        "five functions carry a string, a constant or an import that occurs once on each side"
    );
    assert_eq!(
        report.structural_count(),
        2,
        "two functions reach the block floor with a shape unique on each side; the three leaves do \
         not and must be left to the call positions"
    );
    assert_eq!(
        report.propagated_count(),
        3,
        "the three leaves are resolved only by their forced position around a matched caller"
    );
}

#[test]
fn a_related_pair_outscores_an_unrelated_pair_on_the_same_left_side() {
    let left: Vec<FunctionFeatures> = build(&PARSER, 0x40_0000);
    let related: Vec<FunctionFeatures> = build(&PARSER, 0x40_0000 + IMAGE_DELTA);
    let unrelated: Vec<FunctionFeatures> = build(&UNRELATED, 0x40_0000 + IMAGE_DELTA);

    let close: MatchReport = match_functions(&left, &related);
    let apart: MatchReport = match_functions(&left, &unrelated);

    assert_eq!(close.matched_count(), PARSER.len());
    assert_eq!(
        apart.matched_count(),
        0,
        "two programs that share no string, no constant, no import and no shape must produce no \
         pair at all, and instead produced {:?}",
        apart.matched_pairs()
    );
    assert!(
        close.matched_count() > apart.matched_count(),
        "the related pair must be separated from the unrelated pair by the count of pairs the \
         matcher is willing to assert"
    );
}

#[test]
fn mixing_a_foreign_program_into_both_sides_never_pairs_across_it() {
    let left_plans: Vec<Plan> = joined(&PARSER, &UNRELATED);
    let right_plans: Vec<Plan> = joined(&PARSER, &FOREIGN);
    let left: Vec<FunctionFeatures> = build(&left_plans, 0x40_0000);
    let right: Vec<FunctionFeatures> = shuffled(&build(&right_plans, 0x40_0000 + IMAGE_DELTA));

    let report: MatchReport = match_functions(&left, &right);

    assert_eq!(
        wrong_pairs(&report, IMAGE_DELTA),
        Vec::new(),
        "the two programs share nothing, so no pair may cross from one into the other"
    );
    assert_eq!(
        report.matched_count(),
        PARSER.len(),
        "only the shared program may be resolved, and all of it must be"
    );
    for plan in UNRELATED {
        let subject: FunctionId = FunctionId(0x40_0000 + plan.slot);
        assert_eq!(
            report.left_verdict(subject).and_then(Verdict::counterpart),
            None,
            "{subject:?} belongs to a program the other side does not contain, so naming a \
             counterpart for it is a false positive"
        );
    }
}

#[test]
fn a_function_the_other_side_lost_is_refused_rather_than_forced_onto_a_neighbour() {
    let left: Vec<FunctionFeatures> = build(&PARSER, 0x40_0000);
    let mut kept: Vec<Plan> = PARSER.to_vec();
    let removed: Plan = kept.remove(4);
    let right: Vec<FunctionFeatures> = build(&kept, 0x40_0000 + IMAGE_DELTA);

    let report: MatchReport = match_functions(&left, &right);

    let orphan: FunctionId = FunctionId(0x40_0000 + removed.slot);
    assert_eq!(
        report.left_verdict(orphan),
        Some(&Verdict::Unmatched {
            cause: UnmatchedCause::NoCandidate,
        }),
        "the function whose counterpart was dropped carries a unique string, so it must report \
         that nothing answered it rather than take the nearest shape"
    );
    assert_eq!(
        wrong_pairs(&report, IMAGE_DELTA),
        Vec::new(),
        "removing one function must not shift any other pair onto a wrong counterpart"
    );
    assert_eq!(report.matched_count(), PARSER.len() - 1);
}

#[test]
fn recompiling_one_function_moves_only_that_function_out_of_reach() {
    let left: Vec<FunctionFeatures> = build(&PARSER, 0x40_0000);
    let mut rebuilt: Vec<Plan> = PARSER.to_vec();
    let slot: usize = 9;
    let changed: &mut Plan = rebuilt
        .get_mut(slot)
        .expect("the plan under change is present");
    assert_eq!(
        changed.shape,
        Shape::Diamond(InstructionCategory::FloatingPoint)
    );
    assert_eq!(changed.text, None);
    changed.shape = Shape::Loop(InstructionCategory::Move);
    let right: Vec<FunctionFeatures> = build(&rebuilt, 0x40_0000 + IMAGE_DELTA);

    let report: MatchReport = match_functions(&left, &right);

    let moved: FunctionId = FunctionId(
        0x40_0000
            + PARSER
                .get(slot)
                .expect("the plan under change is present")
                .slot,
    );
    assert_eq!(
        report.left_verdict(moved).and_then(Verdict::stage),
        None,
        "a function whose only evidence was its shape must not be paired once that shape changes"
    );
    assert_eq!(
        wrong_pairs(&report, IMAGE_DELTA),
        Vec::new(),
        "one rewritten function must not drag any other pair onto a wrong counterpart"
    );
    assert_eq!(report.matched_count(), PARSER.len() - 1);
}

#[test]
fn an_image_matched_against_itself_resolves_every_function_it_can_and_names_no_other() {
    let left: Vec<FunctionFeatures> = build(&joined(&PARSER, &UNRELATED), 0x40_0000);

    let report: MatchReport = match_functions(&left, &left);

    assert_eq!(
        wrong_pairs(&report, 0),
        Vec::new(),
        "an image compared with itself must map every function to its own address"
    );
    assert_eq!(
        report.matched_count(),
        left.len(),
        "self comparison is the documented maximum, so every function must be resolved: {:?}",
        report
            .left
            .iter()
            .filter(|entry: &&FunctionVerdict| entry.verdict.counterpart().is_none())
            .map(|entry: &FunctionVerdict| entry.subject)
            .collect::<Vec<FunctionId>>()
    );
    assert_eq!(report.left, report.right);
}

#[test]
fn every_stage_reports_the_pairs_it_asserted_and_no_pair_twice() {
    let left: Vec<FunctionFeatures> = build(&PARSER, 0x40_0000);
    let right: Vec<FunctionFeatures> = build(&PARSER, 0x40_0000 + IMAGE_DELTA);

    let report: MatchReport = match_functions(&left, &right);

    let staged: usize =
        report.exact_count() + report.structural_count() + report.propagated_count();
    assert_eq!(
        staged,
        report.matched_count(),
        "a pair belongs to exactly one stage"
    );
    for (stage, pairs) in [
        (MatchStage::DataReference, report.exact_pairs()),
        (MatchStage::ControlFlow, report.structural_pairs()),
        (MatchStage::Propagation, report.propagated_pairs()),
    ] {
        for (subject, counterpart) in pairs {
            assert_eq!(
                report.left_verdict(subject).and_then(Verdict::stage),
                Some(stage),
                "{subject:?} was listed under {stage:?}"
            );
            assert_eq!(
                report
                    .right_verdict(counterpart)
                    .and_then(Verdict::counterpart),
                Some(subject),
                "{counterpart:?} must name {subject:?} back"
            );
        }
    }
}
