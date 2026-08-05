#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::uninlined_format_args
)]

use std::path::{Path, PathBuf};

use disrobe_pass_mobile::{
    DeclineCount, DecompileReport, DecompiledFunction, HERMES_LIFT_VERSION, HERMES_MAX_VERSION,
    HERMES_MIN_VERSION, HermesModule, StructureDecline, decompile_hermes_module,
    parse_hermes_module,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Coverage {
    BodiesGraded(&'static str),
    ContainerGraded(&'static str),
    NoSample(&'static str),
}

const NO_RELEASE_SAMPLE: &str = "no bundle at this bytecode version is in the corpus, because \
     producing one needs the matching Hermes compiler release and none is redistributable here; \
     the reader is exercised at this version by the layout probe in hermes_reader_versions.rs and \
     bodies are refused by number";

const LAYOUT_BOUNDARY_87: &str = "the header gains the two big-int fields at this version and no \
     release bundle for it is in the corpus, so the field layout is exercised by the layout probe \
     in hermes_reader_versions.rs and bodies are refused by number";

const BAND: [(u32, Coverage); 37] = [
    (60, Coverage::NoSample(NO_RELEASE_SAMPLE)),
    (61, Coverage::NoSample(NO_RELEASE_SAMPLE)),
    (62, Coverage::NoSample(NO_RELEASE_SAMPLE)),
    (63, Coverage::NoSample(NO_RELEASE_SAMPLE)),
    (64, Coverage::NoSample(NO_RELEASE_SAMPLE)),
    (65, Coverage::NoSample(NO_RELEASE_SAMPLE)),
    (66, Coverage::NoSample(NO_RELEASE_SAMPLE)),
    (67, Coverage::NoSample(NO_RELEASE_SAMPLE)),
    (68, Coverage::NoSample(NO_RELEASE_SAMPLE)),
    (69, Coverage::NoSample(NO_RELEASE_SAMPLE)),
    (70, Coverage::NoSample(NO_RELEASE_SAMPLE)),
    (71, Coverage::NoSample(NO_RELEASE_SAMPLE)),
    (72, Coverage::NoSample(NO_RELEASE_SAMPLE)),
    (73, Coverage::NoSample(NO_RELEASE_SAMPLE)),
    (74, Coverage::NoSample(NO_RELEASE_SAMPLE)),
    (75, Coverage::NoSample(NO_RELEASE_SAMPLE)),
    (76, Coverage::ContainerGraded("sample/sample.hbc.v76")),
    (77, Coverage::NoSample(NO_RELEASE_SAMPLE)),
    (78, Coverage::NoSample(NO_RELEASE_SAMPLE)),
    (79, Coverage::NoSample(NO_RELEASE_SAMPLE)),
    (80, Coverage::NoSample(NO_RELEASE_SAMPLE)),
    (81, Coverage::NoSample(NO_RELEASE_SAMPLE)),
    (82, Coverage::NoSample(NO_RELEASE_SAMPLE)),
    (83, Coverage::NoSample(NO_RELEASE_SAMPLE)),
    (84, Coverage::ContainerGraded("sample/sample.hbc.v84")),
    (85, Coverage::NoSample(NO_RELEASE_SAMPLE)),
    (86, Coverage::NoSample(NO_RELEASE_SAMPLE)),
    (87, Coverage::NoSample(LAYOUT_BOUNDARY_87)),
    (88, Coverage::NoSample(NO_RELEASE_SAMPLE)),
    (89, Coverage::NoSample(NO_RELEASE_SAMPLE)),
    (90, Coverage::NoSample(NO_RELEASE_SAMPLE)),
    (91, Coverage::NoSample(NO_RELEASE_SAMPLE)),
    (92, Coverage::NoSample(NO_RELEASE_SAMPLE)),
    (93, Coverage::NoSample(NO_RELEASE_SAMPLE)),
    (94, Coverage::NoSample(NO_RELEASE_SAMPLE)),
    (95, Coverage::NoSample(NO_RELEASE_SAMPLE)),
    (96, Coverage::BodiesGraded("sample/sample.hbc.v96")),
];

const SAMPLE_FUNCTIONS: usize = 8;
const SAMPLE_NAMES: [&str; 5] = ["add", "sumRange", "greet", "Counter", "main"];

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
fn only_the_lifted_version_claims_graded_bodies_and_every_other_row_states_its_reason() {
    let mut bodies_graded: Vec<u32> = Vec::new();
    for (version, coverage) in BAND {
        match coverage {
            Coverage::BodiesGraded(sample) => {
                bodies_graded.push(version);
                assert!(!sample.is_empty());
            }
            Coverage::ContainerGraded(sample) => {
                assert!(!sample.is_empty());
                assert_ne!(
                    version, HERMES_LIFT_VERSION,
                    "the lifted version must claim graded bodies, not container-only grading"
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
        vec![HERMES_LIFT_VERSION],
        "exactly one version has an opcode table here, so exactly one version may claim graded \
         bodies"
    );
}

#[test]
fn the_lifted_version_grades_bodies_and_the_container_versions_refuse_them_by_number() {
    let mut graded: usize = 0;
    for (version, coverage) in BAND {
        match coverage {
            Coverage::BodiesGraded(sample) => {
                let report: DecompileReport = report_for(sample);
                assert_eq!(report.hermes_version, version, "{sample}");
                assert!(report.lift_supported, "{sample}");
                assert_eq!(report.function_count, SAMPLE_FUNCTIONS, "{sample}");
                assert_eq!(report.functions_with_body, SAMPLE_FUNCTIONS, "{sample}");
                assert!(report.total_reconstructed_ops > 0, "{sample}");
                graded += 1;
            }
            Coverage::ContainerGraded(sample) => {
                let report: DecompileReport = report_for(sample);
                assert_eq!(report.hermes_version, version, "{sample}");
                assert!(
                    !report.lift_supported,
                    "{sample}: only v{HERMES_LIFT_VERSION} has an opcode table, so no other \
                     version may report lifted bodies"
                );
                assert_eq!(report.functions_with_body, 0, "{sample}");
                assert_eq!(report.total_reconstructed_ops, 0, "{sample}");
                assert_eq!(report.total_fallback_ops, 0, "{sample}");
                assert_eq!(report.total_unaccounted_ops, 0, "{sample}");
                let [refusal]: &[DeclineCount; 1] = report
                    .structure_declines
                    .as_slice()
                    .try_into()
                    .unwrap_or_else(|_| {
                        panic!(
                            "{sample}: the refusal is counted under one reason; got {:?}",
                            report.structure_declines
                        )
                    });
                assert_eq!(
                    refusal.reason,
                    StructureDecline::UnsupportedBytecodeVersion,
                    "{sample}"
                );
                assert_eq!(refusal.functions, SAMPLE_FUNCTIONS, "{sample}");
                for name in SAMPLE_NAMES {
                    assert!(
                        report
                            .functions
                            .iter()
                            .any(|f: &DecompiledFunction| f.name == name),
                        "{sample}: container-level name recovery holds at every accepted version, \
                         so a refused body must still name its function"
                    );
                }
                graded += 1;
            }
            Coverage::NoSample(_) => {}
        }
    }
    assert_eq!(
        graded, 3,
        "three versions in the accepted band have a committed sample; a run that grades fewer of \
         them is reading the wrong corpus path rather than meeting a legitimate absence"
    );
    eprintln!(
        "hermes version band {HERMES_MIN_VERSION} to {HERMES_MAX_VERSION}: {} versions listed, \
         {graded} with a committed sample, 1 with graded bodies, {} with no sample and a stated \
         reason",
        BAND.len(),
        BAND.len() - graded
    );
}
