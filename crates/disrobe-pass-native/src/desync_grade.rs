#![allow(
    dead_code,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::print_stdout,
    clippy::redundant_pub_crate
)]

#[path = "../tests/similarity_grade/corpus.rs"]
mod corpus;

use std::collections::{BTreeMap, BTreeSet};

use crate::build_disasm_payload;
use crate::desync::{
    Bitness, CodeWindow, DirectCallTargetEvidence, DiscoveryInput, direct_call_target_evidence,
};
use corpus::{Artifact, BuildKey, Compiler, Flavor, Toolchain};
use disrobe_ir::payload::{DisasmPayload, DisasmSymbol, DisasmSymbolKind};
use object::{
    Object as _, ObjectSection as _, ObjectSymbol as _, SymbolKind as ObjSymbolKind, SymbolSection,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DiscoveryGrade {
    true_starts: usize,
    discovered: usize,
    false_starts: usize,
    missed: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CallEvidenceGrade {
    decoded_candidates: usize,
    decoded_false_starts: usize,
    multiple_independent_call_candidates: usize,
    multiple_independent_call_false_starts: usize,
    linearly_validated_candidates: usize,
    linearly_validated_false_starts: usize,
}

fn true_text_starts(bytes: &[u8]) -> BTreeSet<u64> {
    let file: object::File<'_> = object::File::parse(bytes).expect("parse unstripped image");
    let text_indices: BTreeSet<usize> = file
        .sections()
        .filter(|section: &object::Section<'_, '_>| {
            matches!(section.kind(), object::SectionKind::Text)
        })
        .map(|section: object::Section<'_, '_>| section.index().0)
        .collect();
    let mut starts: BTreeSet<u64> = BTreeSet::new();
    for symbol in file.symbols() {
        if !matches!(symbol.kind(), ObjSymbolKind::Text) {
            continue;
        }
        if let SymbolSection::Section(index) = symbol.section()
            && text_indices.contains(&index.0)
        {
            starts.insert(symbol.address());
        }
    }
    starts
}

fn discovered_text_starts(bytes: &[u8]) -> BTreeSet<u64> {
    let payload: DisasmPayload = build_disasm_payload(bytes).expect("build stripped payload");
    payload
        .symbol_table
        .iter()
        .filter(|symbol: &&DisasmSymbol| {
            matches!(
                symbol.kind,
                DisasmSymbolKind::Function | DisasmSymbolKind::Export
            )
        })
        .map(|symbol: &DisasmSymbol| symbol.address)
        .collect()
}

fn grade_discovery(artifact: &Artifact) -> DiscoveryGrade {
    let truth: BTreeSet<u64> = true_text_starts(&artifact.symbols);
    let discovered: BTreeSet<u64> = discovered_text_starts(&artifact.stripped);
    let false_starts: usize = discovered.difference(&truth).count();
    let missed: usize = truth.difference(&discovered).count();
    DiscoveryGrade {
        true_starts: truth.len(),
        discovered: discovered.len(),
        false_starts,
        missed,
    }
}

fn grade_call_evidence(artifact: &Artifact) -> CallEvidenceGrade {
    let truth: BTreeSet<u64> = true_text_starts(&artifact.symbols);
    let file: object::File<'_> =
        object::File::parse(&*artifact.stripped).expect("parse stripped image");
    let mut code: Vec<CodeWindow<'_>> = file
        .sections()
        .filter(|section: &object::Section<'_, '_>| {
            matches!(section.kind(), object::SectionKind::Text)
        })
        .filter_map(
            |section: object::Section<'_, '_>| -> Option<CodeWindow<'_>> {
                let bytes: &[u8] = section.data().ok()?;
                (!bytes.is_empty()).then_some(CodeWindow {
                    address: section.address(),
                    bytes,
                })
            },
        )
        .collect();
    code.sort_by_key(|window: &CodeWindow<'_>| window.address);
    let input: DiscoveryInput<'_> = DiscoveryInput {
        bitness: Bitness::Bits64,
        code,
        rodata: Vec::new(),
        seeds: Vec::new(),
        noreturn: BTreeSet::new(),
    };
    let evidence: BTreeMap<u64, DirectCallTargetEvidence> = direct_call_target_evidence(&input);
    let decoded: BTreeSet<u64> = evidence.keys().copied().collect();
    let multiple_independent_calls: BTreeSet<u64> = evidence
        .iter()
        .filter_map(
            |(target, target_evidence): (&u64, &DirectCallTargetEvidence)| {
                (target_evidence.independent > 1).then_some(*target)
            },
        )
        .collect();
    let linearly_validated: BTreeSet<u64> = evidence
        .iter()
        .filter_map(
            |(target, target_evidence): (&u64, &DirectCallTargetEvidence)| {
                target_evidence.accepted().then_some(*target)
            },
        )
        .collect();
    let decoded_false: BTreeSet<u64> = decoded.difference(&truth).copied().collect();
    let multiple_independent_call_false: BTreeSet<u64> = multiple_independent_calls
        .difference(&truth)
        .copied()
        .collect();
    let linearly_validated_false: BTreeSet<u64> =
        linearly_validated.difference(&truth).copied().collect();
    if !decoded_false.is_empty() {
        let false_evidence: BTreeMap<u64, DirectCallTargetEvidence> = evidence
            .iter()
            .filter_map(
                |(target, target_evidence): (&u64, &DirectCallTargetEvidence)| {
                    decoded_false
                        .contains(target)
                        .then_some((*target, *target_evidence))
                },
            )
            .collect();
        println!(
            "candidate function starts not present in symbols: decoded {decoded_false:x?}, multiple independent calls {multiple_independent_call_false:x?}, linearly validated {linearly_validated_false:x?}, evidence {false_evidence:x?}"
        );
    }
    CallEvidenceGrade {
        decoded_candidates: decoded.len(),
        decoded_false_starts: decoded_false.len(),
        multiple_independent_call_candidates: multiple_independent_calls.len(),
        multiple_independent_call_false_starts: multiple_independent_call_false.len(),
        linearly_validated_candidates: linearly_validated.len(),
        linearly_validated_false_starts: linearly_validated_false.len(),
    }
}

#[test]
fn real_stripped_x86_64_images_measure_function_start_discovery() {
    let Some(toolchain): Option<Toolchain> = Toolchain::discover() else {
        eprintln!("skipping: the corpus fixture directory is absent");
        return;
    };
    if !toolchain.has_clang() || !toolchain.can_strip() {
        eprintln!("skipping: clang and a native object stripper are required");
        return;
    }
    let programs: Vec<String> = toolchain.programs();
    let levels: [&str; 3] = ["O0", "O2", "Os"];
    let hosted_available: bool = programs.first().is_some_and(|program: &String| {
        let key: BuildKey = BuildKey {
            program: program.to_owned(),
            compiler: Compiler::Clang,
            flavor: Flavor::Hosted,
            level: "O0",
        };
        toolchain.build(&key).is_some()
    });
    if !hosted_available {
        eprintln!("skipping hosted PE64 measurement: the MinGW target is unavailable");
    }
    let flavors: Vec<Flavor> = if hosted_available {
        vec![Flavor::FreestandingElf64, Flavor::Hosted]
    } else {
        vec![Flavor::FreestandingElf64]
    };
    let mut eligible_call_evidence_false_starts: usize = 0;
    for program in &programs {
        for flavor in &flavors {
            for level in levels {
                let key: BuildKey = BuildKey {
                    program: program.to_owned(),
                    compiler: Compiler::Clang,
                    flavor: *flavor,
                    level,
                };
                let built: Option<Artifact> = toolchain.build(&key);
                let artifact: Artifact = if matches!(flavor, Flavor::Hosted) {
                    let Some(artifact): Option<Artifact> = built else {
                        eprintln!("skipping hosted PE64 measurement for {}", key.describe());
                        continue;
                    };
                    artifact
                } else {
                    built.expect("compile real stripped image")
                };
                let grade: DiscoveryGrade = grade_discovery(&artifact);
                let call_evidence: CallEvidenceGrade = grade_call_evidence(&artifact);
                if matches!(flavor, Flavor::FreestandingElf64) {
                    assert_eq!(
                        grade.false_starts,
                        0,
                        "function discovery introduced false starts for {}",
                        key.describe()
                    );
                    assert_eq!(
                        call_evidence.linearly_validated_false_starts,
                        0,
                        "direct-call evidence introduced false starts for {}",
                        key.describe()
                    );
                    eligible_call_evidence_false_starts +=
                        call_evidence.linearly_validated_false_starts;
                }
                println!(
                    "discovery {program} clang {} -{level} stripped x86-64: true starts {}, discovered {}, false starts {}, missed {}",
                    flavor.label(),
                    grade.true_starts,
                    grade.discovered,
                    grade.false_starts,
                    grade.missed
                );
                println!(
                    "call sweep {program} {} -{level}: decoded candidates {}, false starts {}; multiple-independent-call candidates {}, false starts {}; linearly-validated candidates {}, false starts {}",
                    flavor.label(),
                    call_evidence.decoded_candidates,
                    call_evidence.decoded_false_starts,
                    call_evidence.multiple_independent_call_candidates,
                    call_evidence.multiple_independent_call_false_starts,
                    call_evidence.linearly_validated_candidates,
                    call_evidence.linearly_validated_false_starts
                );
            }
        }
    }
    assert_eq!(
        eligible_call_evidence_false_starts, 0,
        "direct-call evidence introduced false starts"
    );
}
