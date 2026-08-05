#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr
)]

use std::path::{Path, PathBuf};

use disrobe_pass_mobile::{
    DeclineCount, DecompileReport, DecompiledFunction, HERMES_LIFT_VERSION, HermesModule,
    StructureDecline, decompile_hermes_module, parse_hermes_module,
};
use oxc_allocator::Allocator;
use oxc_parser::Parser;
use oxc_span::SourceType;

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

fn parses_as_javascript(source: &str) -> bool {
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path("recovered.js").unwrap_or_default();
    let parsed: oxc_parser::ParserReturn<'_> = Parser::new(&allocator, source, source_type).parse();
    parsed.errors.is_empty() && !parsed.panicked
}

fn function<'report>(report: &'report DecompileReport, name: &str) -> &'report DecompiledFunction {
    report
        .functions
        .iter()
        .find(|f: &&DecompiledFunction| f.name == name)
        .unwrap_or_else(|| panic!("function {name} not recovered"))
}

const SAMPLE_FUNCTIONS: usize = 8;

#[test]
fn every_function_in_the_v96_sample_reaches_structured_control_flow() {
    let report: DecompileReport = report_for(&["sample", "sample.hbc.v96"]);
    assert!(report.lift_supported);
    assert_eq!(
        report.function_count, SAMPLE_FUNCTIONS,
        "the graded population is pinned by equality, so a change that structures more of a \
         smaller module fails instead of scoring better"
    );
    assert_eq!(report.functions_with_body, SAMPLE_FUNCTIONS);
    assert_eq!(
        report.structured_functions, SAMPLE_FUNCTIONS,
        "declines: {:?}",
        report.structure_declines
    );
    assert!(
        report.structure_declines.is_empty(),
        "declines: {:?}",
        report.structure_declines
    );

    for recovered in &report.functions {
        assert!(recovered.structured, "{} declined", recovered.name);
        assert_eq!(recovered.structure_decline, None);
        assert!(
            !recovered.source.contains("goto "),
            "{}: a structured body carries no goto edges; src:\n{}",
            recovered.name,
            recovered.source
        );
        assert!(
            !recovered.source.contains("unstructured ("),
            "{}: src:\n{}",
            recovered.name,
            recovered.source
        );
        assert!(
            parses_as_javascript(&recovered.source),
            "{}: src:\n{}",
            recovered.name,
            recovered.source
        );
    }
}

#[test]
fn the_counted_loop_recovers_as_a_loop_and_not_as_a_jump_ladder() {
    let report: DecompileReport = report_for(&["sample", "sample.hbc.v96"]);
    let sum_range: &str = &function(&report, "sumRange").source;
    assert!(
        sum_range.contains("do {") && sum_range.contains("} while ("),
        "hermes lowers this counted for-loop to a guarded do-while, so that is the form recovery \
         must produce; src:\n{sum_range}"
    );
    assert!(
        !sum_range.contains("for (;;)"),
        "an unlabelled infinite loop with an inner break is the unsugared form, not the recovered \
         one; src:\n{sum_range}"
    );

    let global: &str = &function(&report, "global").source;
    assert!(
        global.contains("do {") && global.contains("} while ("),
        "the inlined closure body carries the same loop form; src:\n{global}"
    );
}

#[test]
fn a_bytecode_version_the_opcode_table_does_not_cover_is_refused_by_number() {
    for (file, version) in [("sample.hbc.v84", 84u32), ("sample.hbc.v76", 76)] {
        let report: DecompileReport = report_for(&["sample", file]);
        assert_eq!(report.hermes_version, version);
        assert!(
            !report.lift_supported,
            "{file}: only v{HERMES_LIFT_VERSION} has an opcode table here, so no other version may \
             report lifted bodies"
        );
        assert_eq!(
            report.function_count, SAMPLE_FUNCTIONS,
            "{file}: the container still parses"
        );
        assert_eq!(report.functions_with_body, 0, "{file}");
        assert_eq!(report.total_reconstructed_ops, 0, "{file}");
        assert_eq!(report.total_fallback_ops, 0, "{file}");
        assert_eq!(report.structured_functions, 0, "{file}");
        let [counted]: &[DeclineCount; 1] = report
            .structure_declines
            .as_slice()
            .try_into()
            .unwrap_or_else(|_| {
                panic!(
                    "{file}: the refusal is counted under one reason; got {:?}",
                    report.structure_declines
                )
            });
        assert_eq!(
            counted.reason,
            StructureDecline::UnsupportedBytecodeVersion,
            "{file}"
        );
        assert_eq!(counted.functions, SAMPLE_FUNCTIONS, "{file}");
        for recovered in &report.functions {
            assert_eq!(
                recovered.structure_decline,
                Some(StructureDecline::UnsupportedBytecodeVersion),
                "{file}: {}",
                recovered.name
            );
            assert!(
                recovered.source.contains(&format!("hbc v{version}")),
                "{file}: the refusal names the version; src: {}",
                recovered.source
            );
            assert!(
                !recovered.source.contains("function "),
                "{file}: a refused version must not emit anything a reader takes for a recovered \
                 body; src: {}",
                recovered.source
            );
        }
        for name in ["add", "sumRange", "greet", "Counter", "main"] {
            assert!(
                report
                    .functions
                    .iter()
                    .any(|f: &DecompiledFunction| f.name == name),
                "{file}: container-level name recovery still holds across versions"
            );
        }
    }
}

#[test]
fn every_declined_function_in_the_regex_bundles_names_its_reason() {
    for file in ["regexes.hbc.v96", "edge.hbc.v96", "nest.hbc.v96"] {
        let report: DecompileReport = report_for(&["regex", file]);
        assert!(report.lift_supported, "{file}");
        let declined: usize = report
            .functions
            .iter()
            .filter(|f: &&DecompiledFunction| f.structure_decline.is_some())
            .count();
        let counted: usize = report
            .structure_declines
            .iter()
            .map(|count: &DeclineCount| count.functions)
            .sum();
        assert_eq!(
            declined, counted,
            "{file}: every decline is counted under a named reason, so none can go missing from \
             the report"
        );
        eprintln!(
            "{file}: {} of {} functions structured, declines {:?}",
            report.structured_functions, report.functions_with_body, report.structure_declines
        );
        for recovered in &report.functions {
            if recovered.structure_decline.is_some() {
                assert!(
                    recovered.source.contains("unstructured ("),
                    "{file}: {} declined without saying so; src:\n{}",
                    recovered.name,
                    recovered.source
                );
            } else {
                assert!(
                    !recovered.source.contains("goto "),
                    "{file}: {} claims structure while carrying goto edges; src:\n{}",
                    recovered.name,
                    recovered.source
                );
            }
        }
    }
}

#[test]
fn a_bundle_from_an_android_asset_structures_the_same_way() {
    let report: DecompileReport = report_for(&["hello", "index.android.bundle"]);
    assert_eq!(report.hermes_version, HERMES_LIFT_VERSION);
    assert!(report.lift_supported);
    assert!(report.functions_with_body > 0);
    let counted: usize = report
        .structure_declines
        .iter()
        .map(|count: &DeclineCount| count.functions)
        .sum();
    assert_eq!(
        report.structured_functions + counted,
        report.functions_with_body,
        "structured plus declined accounts for every bodied function, so a body can never fall \
         out of both columns; declines {:?}",
        report.structure_declines
    );
    eprintln!(
        "hello bundle: {} of {} functions structured, declines {:?}",
        report.structured_functions, report.functions_with_body, report.structure_declines
    );
}
