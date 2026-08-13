#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::uninlined_format_args
)]

use std::path::{Path, PathBuf};

use disrobe_pass_mobile::{
    DecompileReport, DecompiledFunction, HERMES_LIFT_VERSION, HERMES_LIFTED_VERSIONS,
    HERMES_MAX_VERSION, HERMES_MIN_VERSION, HermesModule, decompile_hermes_module,
    parse_hermes_module,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Measured {
    sample: &'static str,
    upstream_tag: &'static str,
    functions: usize,
    bodies: usize,
    decoded_ops: usize,
    reconstructed_ops: usize,
    declined_ops: usize,
    unaccounted_ops: usize,
    structured: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Coverage {
    BodiesGraded(Measured),
    NoSample(&'static str),
}

const NO_RELEASE_SAMPLE: &str = "no bundle at this bytecode version is in the corpus, because \
     producing one needs the matching Hermes compiler release and none is redistributable here; \
     the reader is exercised at this version by the layout probe in hermes_reader_versions.rs and \
     bodies are refused by number";

const LAYOUT_BOUNDARY_87: &str = "the header gains the two big-int fields at this version and no \
     release bundle for it is in the corpus, so the field layout is exercised by the layout probe \
     in hermes_reader_versions.rs and bodies are refused by number";

const NO_RELEASE_TAG_89: &str = "facebook/hermes tag v0.12.0 declares this bytecode version and \
     its opcode order is knowable, but no bundle compiled by that release is in the corpus, so \
     nothing would grade a lifted body here and bodies are refused by number";

const NO_RELEASE_TAG_83: &str = "facebook/hermes tag v0.8.0 declares this bytecode version and its \
     opcode order matches the v84 table, but no bundle compiled by that release is in the corpus, \
     so nothing would grade a lifted body here and bodies are refused by number";

const NO_RELEASE_TAG_74: &str = "facebook/hermes tags v0.4.0 through v0.6.0 declare this bytecode \
     version and its opcode order matches the v76 table, but no bundle compiled by those releases \
     is in the corpus, so nothing would grade a lifted body here and bodies are refused by number";

const NO_RELEASE_TAG_71: &str = "facebook/hermes tag v0.3.0 declares this bytecode version and its \
     opcode order is knowable, but no bundle compiled by that release is in the corpus, so nothing \
     would grade a lifted body here and bodies are refused by number";

const NO_RELEASE_TAG_62: &str = "facebook/hermes tag v0.2.1 declares this bytecode version and its \
     opcode order is knowable, but no bundle compiled by that release is in the corpus, so nothing \
     would grade a lifted body here and bodies are refused by number";

const V76: Measured = Measured {
    sample: "sample/sample.hbc.v76",
    upstream_tag: "v0.7.2",
    functions: 8,
    bodies: 8,
    decoded_ops: 98,
    reconstructed_ops: 98,
    declined_ops: 0,
    unaccounted_ops: 0,
    structured: 8,
};

const V84: Measured = Measured {
    sample: "sample/sample.hbc.v84",
    upstream_tag: "v0.11.0",
    functions: 8,
    bodies: 8,
    decoded_ops: 98,
    reconstructed_ops: 98,
    declined_ops: 0,
    unaccounted_ops: 0,
    structured: 8,
};

const V96: Measured = Measured {
    sample: "sample/sample.hbc.v96",
    upstream_tag: "v0.13.0",
    functions: 8,
    bodies: 8,
    decoded_ops: 99,
    reconstructed_ops: 99,
    declined_ops: 0,
    unaccounted_ops: 0,
    structured: 8,
};

const BAND: [(u32, Coverage); 37] = [
    (60, Coverage::NoSample(NO_RELEASE_SAMPLE)),
    (61, Coverage::NoSample(NO_RELEASE_SAMPLE)),
    (62, Coverage::NoSample(NO_RELEASE_TAG_62)),
    (63, Coverage::NoSample(NO_RELEASE_SAMPLE)),
    (64, Coverage::NoSample(NO_RELEASE_SAMPLE)),
    (65, Coverage::NoSample(NO_RELEASE_SAMPLE)),
    (66, Coverage::NoSample(NO_RELEASE_SAMPLE)),
    (67, Coverage::NoSample(NO_RELEASE_SAMPLE)),
    (68, Coverage::NoSample(NO_RELEASE_SAMPLE)),
    (69, Coverage::NoSample(NO_RELEASE_SAMPLE)),
    (70, Coverage::NoSample(NO_RELEASE_SAMPLE)),
    (71, Coverage::NoSample(NO_RELEASE_TAG_71)),
    (72, Coverage::NoSample(NO_RELEASE_SAMPLE)),
    (73, Coverage::NoSample(NO_RELEASE_SAMPLE)),
    (74, Coverage::NoSample(NO_RELEASE_TAG_74)),
    (75, Coverage::NoSample(NO_RELEASE_SAMPLE)),
    (76, Coverage::BodiesGraded(V76)),
    (77, Coverage::NoSample(NO_RELEASE_SAMPLE)),
    (78, Coverage::NoSample(NO_RELEASE_SAMPLE)),
    (79, Coverage::NoSample(NO_RELEASE_SAMPLE)),
    (80, Coverage::NoSample(NO_RELEASE_SAMPLE)),
    (81, Coverage::NoSample(NO_RELEASE_SAMPLE)),
    (82, Coverage::NoSample(NO_RELEASE_SAMPLE)),
    (83, Coverage::NoSample(NO_RELEASE_TAG_83)),
    (84, Coverage::BodiesGraded(V84)),
    (85, Coverage::NoSample(NO_RELEASE_SAMPLE)),
    (86, Coverage::NoSample(NO_RELEASE_SAMPLE)),
    (87, Coverage::NoSample(LAYOUT_BOUNDARY_87)),
    (88, Coverage::NoSample(NO_RELEASE_SAMPLE)),
    (89, Coverage::NoSample(NO_RELEASE_TAG_89)),
    (90, Coverage::NoSample(NO_RELEASE_SAMPLE)),
    (91, Coverage::NoSample(NO_RELEASE_SAMPLE)),
    (92, Coverage::NoSample(NO_RELEASE_SAMPLE)),
    (93, Coverage::NoSample(NO_RELEASE_SAMPLE)),
    (94, Coverage::NoSample(NO_RELEASE_SAMPLE)),
    (95, Coverage::NoSample(NO_RELEASE_SAMPLE)),
    (96, Coverage::BodiesGraded(V96)),
];

const SAMPLE_NAMES: [&str; 7] = [
    "add",
    "sumRange",
    "greet",
    "Counter",
    "main",
    "increment",
    "label",
];

const PINNED_GRADED_VERSIONS: usize = 3;
const PINNED_GRADED_FUNCTIONS: usize = 24;
const PINNED_GRADED_DECODED_OPS: usize = 295;
const PINNED_GRADED_RECONSTRUCTED_OPS: usize = 295;
const PINNED_GRADED_STRUCTURED: usize = 24;

fn corpus(relative: &str) -> PathBuf {
    let mut path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("corpus")
        .join("mobile")
        .join("hermes");
    for part in relative.split('/') {
        path = path.join(part);
    }
    path
}

fn report_for(relative: &str) -> DecompileReport {
    let path: PathBuf = corpus(relative);
    let bytes: Vec<u8> = std::fs::read(&path).unwrap_or_else(|error: std::io::Error| {
        panic!(
            "the version-band table names {relative} as the sample it grades, so a run that cannot \
             read it must fail rather than report a green that graded no version: {error} at {}",
            path.display()
        )
    });
    let module: HermesModule = parse_hermes_module(&bytes)
        .unwrap_or_else(|error| panic!("{relative} must parse as a Hermes module: {error}"));
    decompile_hermes_module(&module)
}

const fn decoded_ops(report: &DecompileReport) -> usize {
    report.total_reconstructed_ops + report.total_fallback_ops + report.total_unaccounted_ops
}

#[test]
fn the_table_lists_every_version_the_reader_accepts_and_nothing_outside_it() {
    let mut expected: u32 = HERMES_MIN_VERSION;
    for (version, _) in BAND {
        assert_eq!(
            version, expected,
            "the version-band table must run from {HERMES_MIN_VERSION} to {HERMES_MAX_VERSION} \
             with no gap and no repeat, because a version the reader accepts and this table skips \
             is a version nothing grades"
        );
        expected = expected.saturating_add(1);
    }
    assert_eq!(
        expected,
        HERMES_MAX_VERSION.saturating_add(1),
        "the table ends at {} while the reader accepts up to {HERMES_MAX_VERSION}; widening the \
         accepted band must add a row here and state what grades it",
        expected.saturating_sub(1)
    );
    assert_eq!(BAND.len(), 37);
}

#[test]
fn the_versions_that_claim_graded_bodies_are_exactly_the_versions_the_crate_lifts() {
    let mut bodies_graded: Vec<u32> = Vec::new();
    for (version, coverage) in BAND {
        match coverage {
            Coverage::BodiesGraded(measured) => {
                bodies_graded.push(version);
                assert!(
                    measured.sample.ends_with(&format!("v{version}")),
                    "v{version} is graded by {}, which is not a sample at that version",
                    measured.sample
                );
                assert!(
                    measured.functions > 0 && measured.decoded_ops > 0,
                    "v{version} claims graded bodies over an empty population, so every equality \
                     below would hold over nothing"
                );
            }
            Coverage::NoSample(reason) => {
                assert!(
                    reason.len() > 40,
                    "version {version} carries no sample, so the table must say why in words a \
                     reader can act on rather than leave it blank"
                );
                assert!(
                    !reason.contains("graded by"),
                    "version {version} has no sample, so its row must not read as if something \
                     grades it"
                );
            }
        }
    }
    assert_eq!(
        bodies_graded,
        HERMES_LIFTED_VERSIONS.to_vec(),
        "a version claims graded bodies here exactly when the crate lifts it. A lifted version \
         missing from this table would emit JavaScript no row measures, and a row claiming a \
         version the crate refuses would publish a recovery that never runs"
    );
    assert_eq!(bodies_graded.len(), PINNED_GRADED_VERSIONS);
    assert!(
        bodies_graded.contains(&HERMES_LIFT_VERSION),
        "v{HERMES_LIFT_VERSION} is the reference version the published Hermes figures are measured \
         at, so it must stay graded"
    );
}

#[test]
fn each_graded_version_meets_its_pinned_recovery_counts_and_the_rest_refuse_by_number() {
    let mut graded_versions: usize = 0;
    let mut refused_versions: usize = 0;
    let mut total_functions: usize = 0;
    let mut total_decoded: usize = 0;
    let mut total_reconstructed: usize = 0;
    let mut total_declined: usize = 0;
    let mut total_structured: usize = 0;

    for (version, coverage) in BAND {
        match coverage {
            Coverage::BodiesGraded(measured) => {
                let report: DecompileReport = report_for(measured.sample);
                let label: &str = measured.sample;
                assert_eq!(report.hermes_version, version, "{label}");
                assert!(
                    report.lift_supported,
                    "{label}: this row claims graded bodies at v{version}, decoded through the \
                     opcode table transcribed from facebook/hermes tag {}, so a refusal here is a \
                     failure and never a skip",
                    measured.upstream_tag
                );
                assert_eq!(
                    report.function_count, measured.functions,
                    "{label}: the function denominator is pinned by equality, so a change that \
                     raises a rate by parsing fewer functions fails here instead"
                );
                assert_eq!(report.functions_with_body, measured.bodies, "{label}");
                assert_eq!(
                    decoded_ops(&report),
                    measured.decoded_ops,
                    "{label}: the opcode denominator is pinned by equality; decoding fewer \
                     instructions must move this figure deliberately rather than raise the \
                     coverage ratio by dropping them"
                );
                assert_eq!(
                    report.total_reconstructed_ops, measured.reconstructed_ops,
                    "{label}: opcode coverage at this version is \
                     {}/{} and is pinned by equality",
                    measured.reconstructed_ops, measured.decoded_ops
                );
                assert_eq!(
                    report.total_fallback_ops, measured.declined_ops,
                    "{label}: declined {:?}",
                    report.declined_opcodes
                );
                assert_eq!(
                    report.total_unaccounted_ops, measured.unaccounted_ops,
                    "{label}: unaccounted {:?}",
                    report.unaccounted_opcodes
                );
                assert_eq!(
                    report.structured_functions, measured.structured,
                    "{label}: declines {:?}",
                    report.structure_declines
                );
                assert_eq!(
                    report.declined_opcodes.len(),
                    0,
                    "{label}: a declined opcode is allowed but must be named here rather than \
                     absent from the report; declined {:?}",
                    report.declined_opcodes
                );
                for name in SAMPLE_NAMES {
                    assert!(
                        report
                            .functions
                            .iter()
                            .any(|f: &DecompiledFunction| f.name == name),
                        "{label}: name recovery holds at every graded version, so a lifted body \
                         must still name its function"
                    );
                }
                graded_versions += 1;
                total_functions += report.function_count;
                total_decoded += decoded_ops(&report);
                total_reconstructed += report.total_reconstructed_ops;
                total_declined += report.total_fallback_ops;
                total_structured += report.structured_functions;
            }
            Coverage::NoSample(_) => {
                assert!(
                    !HERMES_LIFTED_VERSIONS.contains(&version),
                    "v{version} carries no sample here yet the crate lifts it, so its bodies would \
                     be emitted with nothing measuring them"
                );
                refused_versions += 1;
            }
        }
    }

    assert_eq!(
        graded_versions, PINNED_GRADED_VERSIONS,
        "three versions in the accepted band have a committed sample; a run that grades fewer of \
         them is reading the wrong corpus path rather than meeting a legitimate absence"
    );
    assert_eq!(
        graded_versions + refused_versions,
        BAND.len(),
        "every version lands in exactly one column"
    );
    assert_eq!(total_functions, PINNED_GRADED_FUNCTIONS);
    assert_eq!(total_decoded, PINNED_GRADED_DECODED_OPS);
    assert_eq!(total_reconstructed, PINNED_GRADED_RECONSTRUCTED_OPS);
    assert_eq!(total_declined, 0);
    assert_eq!(total_structured, PINNED_GRADED_STRUCTURED);

    eprintln!(
        "hermes version band {HERMES_MIN_VERSION} to {HERMES_MAX_VERSION}: {} versions listed, \
         {graded_versions} with graded bodies, {refused_versions} refused by number with a stated \
         reason",
        BAND.len()
    );
    for (version, coverage) in BAND {
        if let Coverage::BodiesGraded(measured) = coverage {
            eprintln!(
                "  hbc v{version} ({}) {}: opcodes {}/{} reconstructed, {} declined, functions \
                 {}/{} structured",
                measured.upstream_tag,
                measured.sample,
                measured.reconstructed_ops,
                measured.decoded_ops,
                measured.declined_ops,
                measured.structured,
                measured.bodies
            );
        }
    }
}
