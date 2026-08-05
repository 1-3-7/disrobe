#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::uninlined_format_args
)]

use std::path::{Path, PathBuf};

use boa_engine::{Context, JsError, JsString, JsValue, Source};
use disrobe_pass_mobile::{
    DecompileReport, DecompiledFunction, HermesModule, decompile_hermes_module, parse_hermes_module,
};
use oxc_allocator::Allocator;
use oxc_parser::Parser;
use oxc_span::SourceType;

const REGEX_SWEEP: &str = concat!(
    "var __probe = ['', 'abc', 'foobar', 'xyz', 'a.c', 'colour', 'color', 'aaaa', 'word here', ",
    "'XXX', 'hello world', '.', '9', 'e\\u00ea', 'ab', 'cd', 'abbbc', 'a1_b', 'foo', 'bar'];\n",
    "for (var i = 0; i < __values.length; i++) {\n",
    "  for (var j = 0; j < __probe.length; j++) {\n",
    "    __values[i].lastIndex = 0;\n",
    "    print(i + ':' + j + ':' + String(__values[i].test(__probe[j])));\n",
    "  }\n",
    "}\n"
);

struct ModuleCase {
    directory: &'static str,
    bytecode: &'static str,
    original: &'static str,
    observation: &'static str,
    shapes: &'static str,
}

const CASES: &[ModuleCase] = &[
    ModuleCase {
        directory: "sample",
        bytecode: "sample.hbc.v96",
        original: "sample.js",
        observation: "",
        shapes: "top-level module, constructor, prototype method, getter-style method, counted \
                 loop, cross-function call",
    },
    ModuleCase {
        directory: "hello",
        bytecode: "index.android.bundle",
        original: "hello.bundle.js",
        observation: "",
        shapes: "top-level module inside an Android asset container, single nested closure",
    },
    ModuleCase {
        directory: "regex",
        bytecode: "regexes.hbc.v96",
        original: "regexes.js",
        observation: "var __values = useThem();\n",
        shapes: "twenty-three regular-expression literals with flags, returned through an array",
    },
    ModuleCase {
        directory: "regex",
        bytecode: "edge.hbc.v96",
        original: "edge.js",
        observation: "var __values = u();\n",
        shapes: "lookbehind, negated lookbehind, non-word boundary, unicode class range, unicode \
                 flag",
    },
    ModuleCase {
        directory: "regex",
        bytecode: "nest.hbc.v96",
        original: "nest.js",
        observation: "var __values = u();\n",
        shapes: "nested and repeated capture groups, anchored quantified groups",
    },
];

const PINNED_MODULES: usize = 5;
const PINNED_FUNCTIONS_PARSED: usize = 16;
const PINNED_FUNCTIONS_WITH_BODY: usize = 16;
const PINNED_FUNCTIONS_CARRIED: usize = 16;
const PINNED_FUNCTIONS_PARSE_VALID: usize = 16;
const PINNED_FUNCTIONS_DECLINED: usize = 0;

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

fn eval_capture(program: &str) -> Result<String, String> {
    let mut context: Context = Context::default();
    {
        let runtime: &mut boa_engine::vm::RuntimeLimits = context.runtime_limits_mut();
        runtime.set_loop_iteration_limit(2_000_000);
        runtime.set_recursion_limit(1_500);
        runtime.set_stack_size_limit(50_000);
    }
    let harness: String = format!(
        "var __out = []; var print = function(v){{ __out.push(String(v)); }}; globalThis.print = print;\n{program}\n__out.join('\\u0001');"
    );
    let value: JsValue = context
        .eval(Source::from_bytes(harness.as_bytes()))
        .map_err(|error: JsError| error.to_string())?;
    value
        .as_string()
        .map(JsString::to_std_string_escaped)
        .ok_or_else(|| "the harness must yield the joined observation string".to_owned())
}

fn parses_as_javascript(source: &str) -> bool {
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path("recovered.js").unwrap_or_default();
    let parsed: oxc_parser::ParserReturn<'_> = Parser::new(&allocator, source, source_type).parse();
    parsed.errors.is_empty() && !parsed.panicked
}

fn unalias(recovered: &str) -> String {
    recovered.replace("globalThis.globalThis.", "globalThis.")
}

fn recovered_driver(global: &str, observation: &str) -> String {
    format!(
        "{}\nglobal();\n{observation}{}",
        unalias(global),
        sweep(observation)
    )
}

fn original_driver(original: &str, observation: &str) -> String {
    format!("{original}\n{observation}{}", sweep(observation))
}

const fn sweep(observation: &str) -> &'static str {
    if observation.is_empty() {
        ""
    } else {
        REGEX_SWEEP
    }
}

#[derive(Debug, Default)]
struct Population {
    modules: usize,
    modules_equivalent: usize,
    functions_parsed: usize,
    functions_with_body: usize,
    functions_declined: usize,
    functions_parse_valid: usize,
    functions_carried_by_execution: usize,
}

fn grade(case: &ModuleCase, population: &mut Population) {
    let label: String = format!("{}/{}", case.directory, case.bytecode);
    let bytes: Vec<u8> = std::fs::read(corpus(&[case.directory, case.bytecode])).unwrap_or_else(
        |error: std::io::Error| {
            panic!(
                "{label} is committed, so a run that cannot read it must fail rather than report a \
                 green that graded nothing: {error}"
            )
        },
    );
    let original: String = std::fs::read_to_string(corpus(&[case.directory, case.original]))
        .unwrap_or_else(|error: std::io::Error| {
            panic!(
                "{}/{} is the source this differential grades against, so an unreadable original \
                 is a failure and never a skip: {error}",
                case.directory, case.original
            )
        });

    let module: HermesModule = parse_hermes_module(&bytes).expect("hermes module parse");
    let report: DecompileReport = decompile_hermes_module(&module);
    assert!(report.lift_supported, "{label}");

    let global: &DecompiledFunction = report
        .functions
        .iter()
        .find(|f: &&DecompiledFunction| f.name == "global")
        .unwrap_or_else(|| panic!("{label}: every Hermes module carries a global function"));

    population.modules += 1;
    population.functions_parsed += report.function_count;
    population.functions_with_body += report.functions_with_body;

    for recovered in &report.functions {
        if recovered.structure_decline.is_some() {
            population.functions_declined += 1;
        }
        if parses_as_javascript(&recovered.source) {
            population.functions_parse_valid += 1;
        }
        let carried: bool =
            recovered.name == "global" || global.source.contains(recovered.source.trim());
        if carried {
            population.functions_carried_by_execution += 1;
        } else {
            eprintln!(
                "{label}: {} is decompiled but its body is not carried by the executed program, so \
                 it is execution-ineligible here and is not counted correct",
                recovered.name
            );
        }
    }

    let want: String = eval_capture(&original_driver(&original, case.observation)).unwrap_or_else(
        |error: String| panic!("{label}: the original source must evaluate: {error}"),
    );
    let got: String = eval_capture(&recovered_driver(&global.source, case.observation))
        .unwrap_or_else(|error: String| {
            panic!(
                "{label}: the recovered module must evaluate in a real engine, and a body that \
                 throws on entry is a failure rather than a skip: {error}\n--driver--\n{}",
                recovered_driver(&global.source, case.observation)
            )
        });
    assert!(
        !want.is_empty(),
        "{label}: the original produced no observation, so the comparison below would compare two \
         empty strings and could not fail"
    );
    assert_eq!(
        want,
        got,
        "{label} ({}): recovered behavior diverged from the original\n--want--\n{want}\n--got--\n\
         {got}\n--driver--\n{}",
        case.shapes,
        recovered_driver(&global.source, case.observation)
    );
    population.modules_equivalent += 1;
    eprintln!(
        "{label} ({}): {} functions, {} observations matched",
        case.shapes,
        report.function_count,
        want.split('\u{1}').count()
    );
}

#[test]
fn every_tracked_v96_module_reproduces_its_original_behavior_in_a_real_engine() {
    let mut population: Population = Population::default();
    for case in CASES {
        grade(case, &mut population);
    }

    eprintln!(
        "hermes tracked v96 population: modules {} of {}, functions parsed {}, decompiled {}, \
         carried by the executed program {}, parse-valid {}, declined {}",
        population.modules_equivalent,
        population.modules,
        population.functions_parsed,
        population.functions_with_body,
        population.functions_carried_by_execution,
        population.functions_parse_valid,
        population.functions_declined
    );

    assert_eq!(
        population.modules, PINNED_MODULES,
        "the graded module population is pinned by equality, so a change that grades fewer modules \
         fails instead of scoring better on what is left"
    );
    assert_eq!(
        population.functions_parsed, PINNED_FUNCTIONS_PARSED,
        "the function denominator is pinned by equality for the same reason"
    );
    assert_eq!(population.functions_with_body, PINNED_FUNCTIONS_WITH_BODY);
    assert_eq!(
        population.functions_carried_by_execution, PINNED_FUNCTIONS_CARRIED,
        "execution equivalence is claimed only for functions whose recovered body the executed \
         program actually carries; a function outside that set is execution-ineligible and must \
         never be counted correct"
    );
    assert_eq!(
        population.functions_parse_valid,
        PINNED_FUNCTIONS_PARSE_VALID
    );
    assert_eq!(population.functions_declined, PINNED_FUNCTIONS_DECLINED);
    assert_eq!(
        population.modules_equivalent, PINNED_MODULES,
        "every graded module must reproduce its original behavior"
    );
}

#[test]
fn the_differential_rejects_a_body_that_parses_but_behaves_differently() {
    let case: &ModuleCase = CASES
        .iter()
        .find(|case: &&ModuleCase| case.bytecode == "nest.hbc.v96")
        .expect("the nested-regex case is declared above");
    let bytes: Vec<u8> =
        std::fs::read(corpus(&[case.directory, case.bytecode])).expect("hermes bytecode");
    let original: String =
        std::fs::read_to_string(corpus(&[case.directory, case.original])).expect("original source");
    let module: HermesModule = parse_hermes_module(&bytes).expect("hermes module parse");
    let report: DecompileReport = decompile_hermes_module(&module);
    let global: &DecompiledFunction = report
        .functions
        .iter()
        .find(|f: &&DecompiledFunction| f.name == "global")
        .expect("global");

    let seeded: String = global.source.replace("/(ab)+/", "/(ab)*/");
    assert_ne!(
        seeded, global.source,
        "the seeded edit must actually change the recovered body, otherwise the check below proves \
         nothing"
    );
    assert!(
        parses_as_javascript(&seeded),
        "the seeded body still parses, which is the point: parse validity alone cannot separate a \
         correct recovery from a wrong one"
    );

    let want: String =
        eval_capture(&original_driver(&original, case.observation)).expect("original evaluates");
    let got: String =
        eval_capture(&recovered_driver(&seeded, case.observation)).expect("seeded body evaluates");
    assert_ne!(
        want, got,
        "a quantifier changed from one-or-more to zero-or-more must fail the differential, which \
         is what proves this gate measures behavior rather than shape"
    );
}
