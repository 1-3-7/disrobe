#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::uninlined_format_args
)]

use std::path::{Path, PathBuf};

use boa_engine::{Context, Source};
use disrobe_pass_mobile::{
    DecompileReport, DecompiledFunction, HermesModule, decompile_hermes_module, parse_hermes_module,
};
use oxc_allocator::Allocator;
use oxc_parser::Parser;
use oxc_span::SourceType;

fn sample(file: &str) -> PathBuf {
    let manifest_dir: &str = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest_dir)
        .join("..")
        .join("..")
        .join("corpus")
        .join("mobile")
        .join("hermes")
        .join("sample")
        .join(file)
}

fn load_report() -> DecompileReport {
    let path: PathBuf = sample("sample.hbc.v96");
    let bytes: Vec<u8> = std::fs::read(&path).unwrap_or_else(|error: std::io::Error| {
        panic!(
            "the graded bytecode is committed to this repository, so a run that cannot read {} \
             must fail rather than report a green over nothing: {error}",
            path.display()
        )
    });
    assert!(
        bytes.len() >= 12 && bytes[8..12] == 96u32.to_le_bytes(),
        "{} must still declare bytecode version 96; every figure below is measured at that \
         version and a swapped file must fail rather than skip",
        path.display()
    );
    let module: HermesModule = parse_hermes_module(&bytes)
        .unwrap_or_else(|error: disrobe_pass_mobile::Error| panic!("{}: {error}", path.display()));
    decompile_hermes_module(&module)
}

fn function<'a>(report: &'a DecompileReport, name: &str) -> &'a DecompiledFunction {
    report
        .functions
        .iter()
        .find(|f: &&DecompiledFunction| f.name == name)
        .unwrap_or_else(|| panic!("function {name} not recovered"))
}

fn parses_as_javascript(src: &str) -> bool {
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path("recovered.js").unwrap_or_default();
    let parsed: oxc_parser::ParserReturn<'_> = Parser::new(&allocator, src, source_type).parse();
    parsed.errors.is_empty() && !parsed.panicked
}

fn eval_capture(program: &str) -> Option<String> {
    let mut context: Context = Context::default();
    {
        let runtime: &mut boa_engine::vm::RuntimeLimits = context.runtime_limits_mut();
        runtime.set_loop_iteration_limit(2_000_000);
        runtime.set_recursion_limit(1_500);
        runtime.set_stack_size_limit(50_000);
    }
    let harness: String = format!(
        "var __out = []; var print = function(v){{ __out.push(String(v)); }};\n{program}\n__out.join('\\u0001');"
    );
    let value: boa_engine::JsValue = context.eval(Source::from_bytes(harness.as_bytes())).ok()?;
    value
        .as_string()
        .map(boa_engine::JsString::to_std_string_escaped)
}

fn unalias(recovered: &str) -> String {
    recovered
        .replace("new globalThis.", "new ")
        .replace("globalThis.globalThis.", "globalThis.")
        .replace("globalThis.greet(", "greet(")
        .replace("globalThis.Counter(", "Counter(")
        .replace("globalThis.add(", "add(")
        .replace("globalThis.sumRange(", "sumRange(")
        .replace("globalThis.main(", "main(")
        .replace("globalThis.print(", "print(")
}

fn unalias_self_contained(recovered: &str) -> String {
    recovered.replace("globalThis.globalThis.", "globalThis.")
}

struct BehaviorSpec {
    name: &'static str,
    original_unit: &'static str,
    recovered_driver: fn(&DecompileReport) -> String,
    inputs_note: &'static str,
}

fn drive_add(report: &DecompileReport) -> String {
    format!(
        "{}\nprint(add(2, 3)); print(add(-7, 40)); print(add(0, 0));",
        unalias(&function(report, "add").source)
    )
}

fn drive_greet(report: &DecompileReport) -> String {
    format!(
        "{}\nprint(greet('alice')); print(greet(''));",
        unalias(&function(report, "greet").source)
    )
}

fn drive_counter(report: &DecompileReport) -> String {
    format!(
        "{}\nvar a = new Counter(99); var b = new Counter(-3);\nprint(a.value); print(b.value);",
        unalias(&function(report, "Counter").source)
    )
}

fn drive_increment(report: &DecompileReport) -> String {
    format!(
        "{}\nvar o = new Counter(41);\no.increment = {};\nprint(o.increment()); print(o.increment()); print(o.value);",
        unalias(&function(report, "Counter").source),
        unalias(&function(report, "increment").source)
    )
}

fn drive_label(report: &DecompileReport) -> String {
    format!(
        "{}\n{}\nvar o = new Counter(7);\no.label = {};\nprint(o.label());",
        unalias(&function(report, "greet").source),
        unalias(&function(report, "Counter").source),
        unalias(&function(report, "label").source)
    )
}

fn drive_sum_range(report: &DecompileReport) -> String {
    format!(
        "{}\nprint(sumRange(10)); print(sumRange(0)); print(sumRange(1)); print(sumRange(100));",
        unalias(&function(report, "sumRange").source)
    )
}

fn drive_main(report: &DecompileReport) -> String {
    format!(
        "{add}\n{counter}\n{greet}\n{sum_range}\nCounter.prototype.increment = {increment};\nCounter.prototype.label = {label};\n{main}\nprint(main());",
        add = unalias(&function(report, "add").source),
        counter = unalias(&function(report, "Counter").source),
        greet = unalias(&function(report, "greet").source),
        sum_range = unalias(&function(report, "sumRange").source),
        increment = unalias(&function(report, "increment").source),
        label = unalias(&function(report, "label").source),
        main = unalias(&function(report, "main").source)
    )
}

fn drive_global(report: &DecompileReport) -> String {
    format!(
        "globalThis.print = print;\n{}\nglobal();",
        unalias_self_contained(&function(report, "global").source)
    )
}

const SPECS: &[BehaviorSpec] = &[
    BehaviorSpec {
        name: "add",
        original_unit: "function add(a, b) { return a + b; }\nprint(add(2, 3)); print(add(-7, 40)); print(add(0, 0));",
        recovered_driver: drive_add,
        inputs_note: "pure arithmetic on three operand pairs",
    },
    BehaviorSpec {
        name: "greet",
        original_unit: "function greet(name) { var prefix = 'disrobe-hermes-'; return prefix + name + '!'; }\nprint(greet('alice')); print(greet(''));",
        recovered_driver: drive_greet,
        inputs_note: "string concatenation chain on two inputs",
    },
    BehaviorSpec {
        name: "Counter",
        original_unit: "function Counter(start) { this.value = start; }\nvar a = new Counter(99); var b = new Counter(-3);\nprint(a.value); print(b.value);",
        recovered_driver: drive_counter,
        inputs_note: "constructor field assignment via new on two inputs",
    },
    BehaviorSpec {
        name: "increment",
        original_unit: "function Counter(start) { this.value = start; }\nvar o = new Counter(41);\no.increment = function() { this.value = this.value + 1; return this.value; };\nprint(o.increment()); print(o.increment()); print(o.value);",
        recovered_driver: drive_increment,
        inputs_note: "prototype-method this-field update invoked twice",
    },
    BehaviorSpec {
        name: "label",
        original_unit: "function greet(name) { var prefix = 'disrobe-hermes-'; return prefix + name + '!'; }\nfunction Counter(start) { this.value = start; }\nvar o = new Counter(7);\no.label = function() { return greet('counter-' + this.value); };\nprint(o.label());",
        recovered_driver: drive_label,
        inputs_note: "cross-function call composing greet over this.value",
    },
    BehaviorSpec {
        name: "sumRange",
        original_unit: "function sumRange(n) { var total = 0; for (var i = 1; i <= n; i = i + 1) { total = total + i; } return total; }\nprint(sumRange(10)); print(sumRange(0)); print(sumRange(1)); print(sumRange(100));",
        recovered_driver: drive_sum_range,
        inputs_note: "counted accumulation loop with loop-carried induction and accumulator",
    },
    BehaviorSpec {
        name: "main",
        original_unit: "function add(a, b) { return a + b; }\nfunction Counter(start) { this.value = start; }\nfunction greet(name) { var prefix = 'disrobe-hermes-'; return prefix + name + '!'; }\nfunction sumRange(n) { var total = 0; for (var i = 1; i <= n; i = i + 1) { total = total + i; } return total; }\nCounter.prototype.increment = function() { this.value = this.value + 1; return this.value; };\nCounter.prototype.label = function() { return greet('counter-' + this.value); };\nfunction main() { var c = new Counter(add(2, 3)); c.increment(); print(c.label()); print(sumRange(10)); return c.value; }\nprint(main());",
        recovered_driver: drive_main,
        inputs_note: "call-frame argument modeling, method dispatch, and cross-function composition",
    },
    BehaviorSpec {
        name: "global",
        original_unit: "function add(a, b) { return a + b; }\nfunction sumRange(n) { var total = 0; for (var i = 1; i <= n; i = i + 1) { total = total + i; } return total; }\nfunction greet(name) { var prefix = 'disrobe-hermes-'; return prefix + name + '!'; }\nfunction Counter(start) { this.value = start; }\nCounter.prototype.increment = function() { this.value = this.value + 1; return this.value; };\nCounter.prototype.label = function() { return greet('counter-' + this.value); };\nfunction main() { var c = new Counter(add(2, 3)); c.increment(); print(c.label()); print(sumRange(10)); return c.value; }\nmain();",
        recovered_driver: drive_global,
        inputs_note: "top-level module: recursively inlined closure bodies, prototype wiring, and the entrypoint call",
    },
];

const PINNED_FUNCTIONS: usize = 8;
const PINNED_BEHAVIORALLY_CORRECT: usize = 8;
const CORRECTNESS_FLOOR_PERCENT: usize = 100;

const PINNED_EXECUTION_ELIGIBLE: usize = 8;
const PINNED_STRUCTURE_GRADED_ONLY: usize = 0;

#[test]
fn the_two_grading_populations_partition_the_pinned_function_count() {
    let report: DecompileReport = load_report();

    let mut execution_eligible: Vec<&str> = Vec::new();
    let mut structure_graded_only: Vec<&str> = Vec::new();
    for recovered in &report.functions {
        if SPECS
            .iter()
            .any(|spec: &BehaviorSpec| spec.name == recovered.name)
        {
            execution_eligible.push(&recovered.name);
        } else {
            structure_graded_only.push(&recovered.name);
        }
    }

    assert_eq!(
        execution_eligible.len() + structure_graded_only.len(),
        report.function_count,
        "every function lands in exactly one grading population, so none can be dropped from both"
    );
    assert_eq!(
        report.function_count, PINNED_FUNCTIONS,
        "the denominator is pinned by equality, so a change that raises a rate by grading fewer \
         functions fails instead"
    );
    assert_eq!(
        execution_eligible.len(),
        PINNED_EXECUTION_ELIGIBLE,
        "execution-graded population: {execution_eligible:?}"
    );
    assert_eq!(
        structure_graded_only.len(),
        PINNED_STRUCTURE_GRADED_ONLY,
        "structure-graded population: {structure_graded_only:?}"
    );

    let mut structure_graded_correct: usize = 0;
    for name in &structure_graded_only {
        let recovered: &DecompiledFunction = function(&report, name);
        assert!(
            recovered.structured && recovered.structure_decline.is_none(),
            "{name}: a function with no behavior spec is graded on structure, so a decline here is \
             a failure and not a skip; src:\n{}",
            recovered.source
        );
        assert!(
            parses_as_javascript(&recovered.source),
            "{name}: src:\n{}",
            recovered.source
        );
        structure_graded_correct += 1;
    }

    eprintln!(
        "hermes v96 sample grading populations: execution-equivalent {}/{} functions, \
         structure-graded {}/{} functions; the two denominators sum to the pinned {} and are \
         never added together into one rate",
        PINNED_BEHAVIORALLY_CORRECT,
        execution_eligible.len(),
        structure_graded_correct,
        structure_graded_only.len(),
        PINNED_FUNCTIONS
    );
}

#[test]
fn hbc_v96_sample_decompile_is_behaviorally_correct_against_real_js_engine() {
    let report: DecompileReport = load_report();

    let total_functions: usize = report.function_count;
    assert_eq!(
        total_functions, PINNED_FUNCTIONS,
        "global plus seven authored functions"
    );
    assert_eq!(
        SPECS.len(),
        PINNED_FUNCTIONS,
        "every function in the sample carries a behavior spec, so the graded population cannot \
         shrink onto whichever functions happen to reproduce"
    );

    let mut behaviorally_correct: usize = 0;
    for spec in SPECS {
        let recovered_src: String = function(&report, spec.name).source.clone();
        assert!(
            parses_as_javascript(&recovered_src),
            "{}: recovered body must parse as valid JavaScript before it can be graded correct; src:\n{}",
            spec.name,
            recovered_src
        );

        let driver: String = (spec.recovered_driver)(&report);
        let want: String = eval_capture(spec.original_unit)
            .unwrap_or_else(|| panic!("{}: original source unit must evaluate", spec.name));
        let got: String = eval_capture(&driver).unwrap_or_else(|| {
            panic!(
                "{}: recovered driver must evaluate in a real JS engine; driver:\n{}",
                spec.name, driver
            )
        });
        let matched: bool = want == got;
        eprintln!(
            "correctness[{}] ({}): match={} want={:?} got={:?}",
            spec.name, spec.inputs_note, matched, want, got
        );
        assert!(
            matched,
            "{}: recovered behavior diverged from the original through boa\n--want--\n{}\n--got--\n{}\n--driver--\n{}",
            spec.name, want, got, driver
        );
        behaviorally_correct += 1;
    }

    let correctness: f64 = behaviorally_correct as f64 / total_functions as f64;
    let op_coverage: f64 = {
        let total_ops: usize = report.total_reconstructed_ops + report.total_fallback_ops;
        report.total_reconstructed_ops as f64 / total_ops as f64
    };
    eprintln!(
        "hermes v96 sample: op-coverage={:.1}% ({}/{} ops) decompile-correctness={:.1}% ({}/{} functions behaviorally verified vs original through boa)",
        op_coverage * 100.0,
        report.total_reconstructed_ops,
        report.total_reconstructed_ops + report.total_fallback_ops,
        correctness * 100.0,
        behaviorally_correct,
        total_functions
    );

    assert!(
        (op_coverage - 1.0).abs() < f64::EPSILON,
        "op-coverage is a separate, already-ratcheted number and must stay 100%; got {:.1}%",
        op_coverage * 100.0
    );

    assert_eq!(
        behaviorally_correct, PINNED_BEHAVIORALLY_CORRECT,
        "all eight functions (global, add, greet, Counter, increment, label, sumRange, main) reproduce original behavior through a real JS engine"
    );
    assert!(
        correctness * 100.0 >= CORRECTNESS_FLOOR_PERCENT as f64,
        "decompile-correctness floor: at least {CORRECTNESS_FLOOR_PERCENT}% of functions must behaviorally match (distinct from op-coverage); got {:.1}%",
        correctness * 100.0
    );
}

fn has_bare_register_token(src: &str) -> bool {
    src.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .any(|tok: &str| {
            tok.len() >= 2
                && tok.starts_with('r')
                && tok[1..].chars().all(|c: char| c.is_ascii_digit())
        })
}

#[test]
fn hbc_v96_loop_and_call_frame_recovery_is_locked() {
    let report: DecompileReport = load_report();

    let sum_range: String = function(&report, "sumRange").source.clone();
    assert!(
        !sum_range.contains("goto ") && parses_as_javascript(&sum_range),
        "sumRange must lower its counted loop to structured control flow with threaded loop-carried variables, not goto edges.\nsrc:\n{}",
        sum_range
    );
    assert!(
        !has_bare_register_token(&sum_range),
        "sumRange must not leak un-threaded machine registers.\nsrc:\n{}",
        sum_range
    );

    let main_src: String = function(&report, "main").source.clone();
    assert!(
        !main_src.contains("<arg?>") && parses_as_javascript(&main_src),
        "main must model the call-frame argument window instead of emitting placeholder arguments.\nsrc:\n{}",
        main_src
    );
    assert!(
        !has_bare_register_token(&main_src),
        "main must thread its call results through materialized variables, not leak bare registers.\nsrc:\n{}",
        main_src
    );
}

#[test]
fn correctness_oracle_rejects_a_deliberately_wrong_body() {
    let original_add: &str =
        "function add(a, b) { return a + b; }\nprint(add(2, 3)); print(add(-7, 40));";
    let wrong_add: &str =
        "function add(arg0, arg1) { return (arg0 - arg1); }\nprint(add(2, 3)); print(add(-7, 40));";
    let want: String = eval_capture(original_add).expect("original add evaluates");
    let got: String = eval_capture(wrong_add).expect("wrong add evaluates");
    assert_ne!(
        want, got,
        "a body that subtracts instead of adds must NOT pass the differential, proving the oracle measures behavior not op-coverage"
    );

    assert!(
        parses_as_javascript(wrong_add),
        "the wrong body still parses, proving parse-validity alone is insufficient and the behavioral differential is load-bearing"
    );
}

const NON_DETERMINISTIC_SOURCES: &[&str] = &["Date", "Math.random", "performance", " in "];

#[test]
fn neither_side_of_the_differential_reads_a_value_that_can_change_between_runs() {
    let report: DecompileReport = load_report();
    for spec in SPECS {
        let recovered: String = (spec.recovered_driver)(&report);
        for token in NON_DETERMINISTIC_SOURCES {
            assert!(
                !spec.original_unit.contains(token),
                "{}: the reference unit reads {token}, so a match between the two sides could \
                 come from both reading the same changing value rather than from equal behavior",
                spec.name
            );
            assert!(
                !recovered.contains(token),
                "{}: the recovered driver reads {token}, so its output is not repeatable and the \
                 differential cannot grade it",
                spec.name
            );
        }
    }

    for spec in SPECS {
        let driver: String = (spec.recovered_driver)(&report);
        let first: String = eval_capture(&driver)
            .unwrap_or_else(|| panic!("{}: recovered driver must evaluate", spec.name));
        let second: String = eval_capture(&driver)
            .unwrap_or_else(|| panic!("{}: recovered driver must evaluate twice", spec.name));
        assert_eq!(
            first, second,
            "{}: two runs of the same recovered driver must produce the same output, or the \
             single run the correctness figure rests on proves nothing",
            spec.name
        );
    }
}
