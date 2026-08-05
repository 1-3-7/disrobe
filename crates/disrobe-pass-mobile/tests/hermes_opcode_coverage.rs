#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::uninlined_format_args
)]

#[path = "support/hermes_production_bundle.rs"]
#[allow(clippy::redundant_pub_crate, dead_code, clippy::panic)]
mod hermes_production_bundle;

use std::path::{Path, PathBuf};

use disrobe_pass_mobile::{
    DeclineCount, DecompileReport, DecompiledFunction, HermesModule, OpcodeCount,
    decompile_hermes_module, parse_hermes_module,
};
use hermes_production_bundle::{PUBLISHED_FUNCTION_COUNT, load_bundle};

const TRACKED_V96_SAMPLE_COUNT: usize = 5;

const TRACKED_V96_SAMPLES: [[&str; 2]; TRACKED_V96_SAMPLE_COUNT] = [
    ["sample", "sample.hbc.v96"],
    ["regex", "regexes.hbc.v96"],
    ["regex", "edge.hbc.v96"],
    ["regex", "nest.hbc.v96"],
    ["hello", "index.android.bundle"],
];

const BUNDLE_OPCODES_DECODED: usize = 5_765_066;
const BUNDLE_DISTINCT_OPCODES: usize = 167;
const BUNDLE_STRUCTURED_FLOOR: usize = 112_823;
const BUNDLE_TAIL_REPORT_WIDTH: usize = 12;

fn corpus(parts: &[&str]) -> PathBuf {
    let mut path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("corpus")
        .join("mobile")
        .join("hermes");
    for part in parts {
        path = path.join(part);
    }
    path
}

fn report_for(parts: &[&str]) -> DecompileReport {
    let path: PathBuf = corpus(parts);
    let bytes: Vec<u8> = std::fs::read(&path).unwrap_or_else(|error: std::io::Error| {
        panic!(
            "{} is committed to this repository, so a run that cannot read it must fail rather \
             than report a green that graded nothing: {error}",
            path.display()
        )
    });
    let module: HermesModule = parse_hermes_module(&bytes).unwrap_or_else(|error| {
        panic!("{} must parse as a Hermes module: {error}", path.display())
    });
    decompile_hermes_module(&module)
}

fn decoded_instructions(report: &DecompileReport) -> usize {
    report
        .functions
        .iter()
        .map(|f: &DecompiledFunction| f.instruction_count)
        .sum()
}

fn column_total(counts: &[OpcodeCount]) -> usize {
    counts
        .iter()
        .map(|count: &OpcodeCount| count.occurrences)
        .sum()
}

fn assert_columns_partition_the_stream(report: &DecompileReport, label: &str) {
    let decoded: usize = decoded_instructions(report);
    assert_eq!(
        report.total_reconstructed_ops + report.total_fallback_ops + report.total_unaccounted_ops,
        decoded,
        "{label}: every decoded instruction must land in exactly one of reconstructed, declined or \
         unaccounted. A lifting rule that emits a statement without counting itself would leave an \
         instruction out of the denominator and raise the coverage ratio for free"
    );
    assert_eq!(
        column_total(&report.reconstructed_opcodes),
        report.total_reconstructed_ops,
        "{label}: the per-opcode histogram must sum to the reconstructed total, otherwise the long \
         tail is read off a different population than the published ratio"
    );
    assert_eq!(
        column_total(&report.declined_opcodes),
        report.total_fallback_ops,
        "{label}: every declined instruction must be enumerated under the opcode that declined it"
    );
    assert_eq!(
        column_total(&report.unaccounted_opcodes),
        report.total_unaccounted_ops,
        "{label}: an unaccounted instruction must still name its opcode"
    );
}

fn describe_tail(counts: &[OpcodeCount], width: usize) -> String {
    let start: usize = counts.len().saturating_sub(width);
    counts[start..]
        .iter()
        .map(|count: &OpcodeCount| format!("{}x{}", count.opcode, count.occurrences))
        .collect::<Vec<String>>()
        .join(" ")
}

#[test]
fn every_decoded_opcode_in_the_tracked_corpus_lands_in_exactly_one_column() {
    assert_eq!(
        TRACKED_V96_SAMPLES.len(),
        TRACKED_V96_SAMPLE_COUNT,
        "the graded corpus is pinned by equality, so deleting a sample fails here rather than \
         quietly narrowing what this gate reads"
    );
    for parts in TRACKED_V96_SAMPLES {
        let label: String = parts.join("/");
        let report: DecompileReport = report_for(&parts);
        assert!(report.lift_supported, "{label}");
        assert_columns_partition_the_stream(&report, &label);
        assert!(
            decoded_instructions(&report) > 0,
            "{label}: a sample that decodes nothing grades nothing"
        );
        eprintln!(
            "{label}: {} decoded, {} reconstructed, {} declined, {} unaccounted, {} distinct opcodes",
            decoded_instructions(&report),
            report.total_reconstructed_ops,
            report.total_fallback_ops,
            report.total_unaccounted_ops,
            report.reconstructed_opcodes.len()
        );
    }
}

#[test]
fn the_tracked_corpus_declines_no_opcode_and_names_any_that_it_would() {
    for parts in TRACKED_V96_SAMPLES {
        let label: String = parts.join("/");
        let report: DecompileReport = report_for(&parts);
        assert!(
            report.declined_opcodes.is_empty(),
            "{label}: every opcode in this sample has a lifting rule; declined {:?}",
            report.declined_opcodes
        );
        assert!(
            report.unaccounted_opcodes.is_empty(),
            "{label}: unaccounted {:?}",
            report.unaccounted_opcodes
        );
    }
}

#[test]
fn the_histogram_is_ordered_so_the_long_tail_reads_from_the_end() {
    let report: DecompileReport = report_for(&["sample", "sample.hbc.v96"]);
    let counts: &[OpcodeCount] = &report.reconstructed_opcodes;
    assert!(counts.len() > 1, "the sample must exercise several opcodes");
    for pair in counts.windows(2) {
        let [left, right]: &[OpcodeCount; 2] = pair.try_into().expect("windows(2) yields pairs");
        let ordered: bool = left.occurrences > right.occurrences
            || (left.occurrences == right.occurrences && left.opcode < right.opcode);
        assert!(
            ordered,
            "the histogram must be ordered by descending occurrences then opcode name, so the tail \
             is deterministic across runs; {left:?} preceded {right:?}"
        );
    }
    eprintln!(
        "sample.hbc.v96 tail: {}",
        describe_tail(counts, BUNDLE_TAIL_REPORT_WIDTH)
    );
}

#[test]
fn the_production_bundle_opcode_long_tail_is_enumerated_and_declines_nothing() {
    let Some(bytes): Option<Vec<u8>> = load_bundle("the production-bundle opcode long tail") else {
        return;
    };
    let module: HermesModule = parse_hermes_module(&bytes).expect("full Hermes module parse");
    let report: DecompileReport = decompile_hermes_module(&module);

    assert_eq!(
        report.function_count, PUBLISHED_FUNCTION_COUNT,
        "the graded population is the whole bundle, pinned by equality so a run that lifts fewer \
         functions scores worse instead of shrinking what it is measured against"
    );
    assert_eq!(
        report.functions_with_body, PUBLISHED_FUNCTION_COUNT,
        "every function header in this bundle owns bytecode, so every one of them must decode"
    );
    assert_columns_partition_the_stream(&report, "discord/index.android.bundle");
    assert_eq!(
        decoded_instructions(&report),
        BUNDLE_OPCODES_DECODED,
        "the opcode denominator is pinned by equality; a change that decodes fewer instructions \
         must move this figure deliberately rather than raise the coverage ratio by dropping them"
    );

    eprintln!(
        "discord/index.android.bundle: {} functions, {} opcodes decoded across {} distinct opcodes, \
         {} reconstructed, {} declined, {} unaccounted",
        report.function_count,
        decoded_instructions(&report),
        report.reconstructed_opcodes.len(),
        report.total_reconstructed_ops,
        report.total_fallback_ops,
        report.total_unaccounted_ops
    );
    eprintln!(
        "long tail (rarest {BUNDLE_TAIL_REPORT_WIDTH} opcodes): {}",
        describe_tail(&report.reconstructed_opcodes, BUNDLE_TAIL_REPORT_WIDTH)
    );

    assert!(
        report.declined_opcodes.is_empty(),
        "every opcode this production bundle uses must have a lifting rule; declined {:?}",
        report.declined_opcodes
    );
    assert!(
        report.unaccounted_opcodes.is_empty(),
        "unaccounted {:?}",
        report.unaccounted_opcodes
    );
    assert!(
        report.reconstructed_opcodes.len() >= BUNDLE_DISTINCT_OPCODES,
        "this bundle exercises {BUNDLE_DISTINCT_OPCODES} distinct opcodes, which is the real long \
         tail the eight-opcode committed sample cannot reach; got {}",
        report.reconstructed_opcodes.len()
    );
}

#[test]
fn the_production_bundle_structures_the_bulk_of_its_functions_and_names_every_refusal() {
    let Some(bytes): Option<Vec<u8>> = load_bundle("the production-bundle structuring rate") else {
        return;
    };
    let module: HermesModule = parse_hermes_module(&bytes).expect("full Hermes module parse");
    let report: DecompileReport = decompile_hermes_module(&module);

    let declined: usize = report
        .structure_declines
        .iter()
        .map(|count: &DeclineCount| count.functions)
        .sum();
    assert_eq!(
        report.structured_functions + declined,
        report.functions_with_body,
        "structured plus declined must account for every bodied function, so a body can never fall \
         out of both columns; declines {:?}",
        report.structure_declines
    );
    let counted_per_function: usize = report
        .functions
        .iter()
        .filter(|f: &&DecompiledFunction| f.structure_decline.is_some())
        .count();
    assert_eq!(
        counted_per_function, declined,
        "every per-function refusal must appear under a named reason in the module totals"
    );

    eprintln!(
        "discord/index.android.bundle: {} of {} functions structured, declines {:?}",
        report.structured_functions, report.functions_with_body, report.structure_declines
    );

    assert!(
        report.structured_functions >= BUNDLE_STRUCTURED_FLOOR,
        "structuring over this bundle has reached {BUNDLE_STRUCTURED_FLOOR} of \
         {PUBLISHED_FUNCTION_COUNT} functions; got {}. This floor is the rate measured with object \
         identity threaded through a variable. Re-materialising an allocation at each use site \
         structures a few dozen more functions, and every one of them returns a fresh empty object \
         instead of the mutated one, so the lower rate is the correct one",
        report.structured_functions
    );

    for recovered in &report.functions {
        if recovered.structure_decline.is_some() {
            assert!(
                recovered.source.contains("unstructured ("),
                "{}: declined without saying so in the body a reader sees",
                recovered.name
            );
        }
    }
}
