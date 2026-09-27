#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use disrobe_core::scratch::{ScratchDir, ScratchFile};
use disrobe_core::subprocess::{CapturedOutput, run_captured_with_env};
use disrobe_pass_js_deob::{AstUnminifyStats, unminify, unminify_ast};
use oxc_allocator::Allocator;
use oxc_ast::ast::{
    ArrowFunctionExpression, AwaitExpression, CallExpression, Expression, Function,
    IdentifierReference, YieldExpression,
};
use oxc_ast::{Visit, visit::walk};
use oxc_parser::Parser;
use oxc_semantic::ScopeFlags;
use oxc_span::SourceType;
use sha2::{Digest, Sha256};

const NODE_TIMEOUT: Duration = Duration::from_secs(30);
const NODE_CAPTURE: usize = 1 << 20;
const PROFILES: [&str; 2] = ["es5", "es2015"];
const MINIFIED_PROFILES: [&str; 4] = [
    "es5-terser",
    "es5-terser-mangle",
    "es2015-terser",
    "es2015-terser-mangle",
];
const MINIFIED_FLOORS: [(&str, usize); 4] = [
    ("es5-terser", 3),
    ("es5-terser-mangle", 3),
    ("es2015-terser", 41),
    ("es2015-terser-mangle", 41),
];
const PROGRAMS: [&str; 9] = [
    "arguments_defaults",
    "early_return",
    "interleave",
    "loops",
    "methods",
    "nested",
    "sequential",
    "switch_labels",
    "try_finally",
];

fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("ts_helpers")
}

fn build_records() -> BTreeMap<String, String> {
    let text: String = std::fs::read_to_string(fixture_root().join("records.toml"))
        .expect("tests/fixtures/ts_helpers/records.toml is required");
    let parsed: toml::Table = toml::from_str(&text).expect("records.toml parses");
    let artifacts: &Vec<toml::Value> = parsed
        .get("artifact")
        .and_then(toml::Value::as_array)
        .expect("records.toml lists artifacts");
    artifacts
        .iter()
        .map(|artifact: &toml::Value| {
            let path: &str = artifact
                .get("path")
                .and_then(toml::Value::as_str)
                .expect("artifact path");
            let sha256: &str = artifact
                .get("sha256")
                .and_then(toml::Value::as_str)
                .expect("artifact sha256");
            (path.to_owned(), sha256.to_owned())
        })
        .collect()
}

fn read_recorded(relative: &str) -> String {
    let records: BTreeMap<String, String> = build_records();
    let pinned: &String = records
        .get(relative)
        .unwrap_or_else(|| panic!("{relative} has no build record in records.toml"));
    let text: String = std::fs::read_to_string(fixture_root().join(relative))
        .unwrap_or_else(|error| panic!("read {relative}: {error}"))
        .replace("\r\n", "\n");
    assert_eq!(
        format!("{:x}", Sha256::digest(text.as_bytes())),
        *pinned,
        "{relative} differs from the output its build record describes"
    );
    text
}

fn node_output_at(path: &Path, source: &str) -> String {
    let args: [&OsStr; 1] = [path.as_os_str()];
    let captured: CapturedOutput = run_captured_with_env(
        Path::new("node"),
        &args,
        [("FORCE_COLOR", "0"), ("NO_COLOR", "1")],
        NODE_TIMEOUT,
        NODE_CAPTURE,
    )
    .expect("node is required for the TypeScript helper execution grade")
    .expect("node must finish within the timeout");
    assert_eq!(
        captured.exit_code,
        Some(0),
        "node failed:\n{}\n--- program ---\n{source}",
        String::from_utf8_lossy(&captured.stderr)
    );
    String::from_utf8(captured.stdout).expect("node output is utf-8")
}

fn node_output(source: &str) -> String {
    let (scratch, mut file): (ScratchFile, std::fs::File) =
        ScratchFile::create("disrobe_ts_helpers", "cjs").expect("scratch file");
    file.write_all(source.as_bytes()).expect("write program");
    drop(file);
    node_output_at(scratch.path(), source)
}

fn node_output_in(directory: &Path, source: &str) -> String {
    let path: PathBuf = directory.join("program.cjs");
    std::fs::write(&path, source).expect("write program");
    node_output_at(&path, source)
}

#[derive(Debug, Default)]
struct Shape {
    async_functions: usize,
    awaits: usize,
    yields: usize,
    generators: usize,
    helper_names: usize,
    state_machine_calls: usize,
}

struct ShapeProbe {
    shape: Shape,
}

impl<'a> Visit<'a> for ShapeProbe {
    fn visit_function(&mut self, function: &Function<'a>, flags: ScopeFlags) {
        if function.r#async {
            self.shape.async_functions += 1;
        }
        if function.generator {
            self.shape.generators += 1;
        }
        walk::walk_function(self, function, flags);
    }

    fn visit_arrow_function_expression(&mut self, arrow: &ArrowFunctionExpression<'a>) {
        if arrow.r#async {
            self.shape.async_functions += 1;
        }
        walk::walk_arrow_function_expression(self, arrow);
    }

    fn visit_await_expression(&mut self, expression: &AwaitExpression<'a>) {
        self.shape.awaits += 1;
        walk::walk_await_expression(self, expression);
    }

    fn visit_yield_expression(&mut self, expression: &YieldExpression<'a>) {
        self.shape.yields += 1;
        walk::walk_yield_expression(self, expression);
    }

    fn visit_identifier_reference(&mut self, reference: &IdentifierReference<'a>) {
        if matches!(reference.name.as_str(), "__awaiter" | "__generator") {
            self.shape.helper_names += 1;
        }
    }

    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        if let Expression::StaticMemberExpression(member) = &call.callee
            && member.property.name == "sent"
        {
            self.shape.state_machine_calls += 1;
        }
        walk::walk_call_expression(self, call);
    }
}

fn shape(source: &str, path: &str) -> Shape {
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path(path).expect("source type");
    let parsed: oxc_parser::ParserReturn<'_> = Parser::new(&allocator, source, source_type).parse();
    assert!(
        parsed.errors.is_empty() && !parsed.panicked,
        "{path} must parse: {:?}\n{source}",
        parsed.errors
    );
    let mut probe: ShapeProbe = ShapeProbe {
        shape: Shape::default(),
    };
    probe.visit_program(&parsed.program);
    probe.shape
}

struct Graded {
    source_async: usize,
    recovered_async: usize,
    execution_equal: bool,
}

fn grade(label: &str, original: &str, source_async: usize, recovered: &str) -> Graded {
    let expected: String = node_output(original);
    assert!(
        !expected.trim().is_empty(),
        "{label}: original prints output"
    );
    let actual: String = node_output(recovered);
    assert_eq!(
        expected, actual,
        "{label}: recovered module changed behaviour\n--- recovered ---\n{recovered}"
    );
    let recovered_shape: Shape = shape(recovered, "recovered.js");
    assert_eq!(
        recovered_shape.helper_names, 0,
        "{label}: helper references remain\n{recovered}"
    );
    assert_eq!(
        recovered_shape.state_machine_calls, 0,
        "{label}: state machine remains\n{recovered}"
    );
    assert_eq!(
        recovered_shape.yields, 0,
        "{label}: yield remains\n{recovered}"
    );
    assert_eq!(
        recovered_shape.generators, 0,
        "{label}: generator function remains\n{recovered}"
    );
    assert!(recovered_shape.awaits > 0, "{label}: no await recovered");
    Graded {
        source_async,
        recovered_async: recovered_shape.async_functions,
        execution_equal: true,
    }
}

fn source_async_functions(program: &str) -> usize {
    let source: String = read_recorded(&format!("src/{program}.ts"));
    shape(&source, "program.ts").async_functions
}

#[test]
fn committed_outputs_match_their_build_records() {
    let records: BTreeMap<String, String> = build_records();
    for profile in PROFILES.into_iter().chain(MINIFIED_PROFILES) {
        for program in PROGRAMS {
            let relative: String = format!("{profile}/{program}.js");
            assert!(records.contains_key(&relative), "{relative} lacks a record");
            read_recorded(&relative);
        }
    }
    read_recorded("tsconfig.es5.json");
    read_recorded("tsconfig.es2015.json");
}

#[test]
fn typescript_helper_recovery_matrix() {
    for profile in PROFILES {
        let mut source_total: usize = 0;
        let mut recovered_total: usize = 0;
        let mut execution_equal: usize = 0;
        for program in PROGRAMS {
            let original: String = read_recorded(&format!("{profile}/{program}.js"));
            let source_async: usize = source_async_functions(program);
            let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(&original);
            let label: String = format!("{profile}/{program}");
            let graded: Graded = grade(&label, &original, source_async, &recovered);
            assert_eq!(
                stats.ts_async_functions_restored, source_async,
                "{label}: every async function of the source must be recovered\n{recovered}"
            );
            assert_eq!(
                graded.recovered_async, graded.source_async,
                "{label}: async function count differs from the source\n{recovered}"
            );
            let (peeled, _): (String, _) = unminify(&original);
            let (chained, _): (String, AstUnminifyStats) = unminify_ast(&peeled);
            grade(
                &format!("{label} (peephole chain)"),
                &original,
                source_async,
                &chained,
            );
            source_total += graded.source_async;
            recovered_total += graded.recovered_async;
            execution_equal += usize::from(graded.execution_equal);
        }
        println!(
            "ts-helpers {profile}: {recovered_total}/{source_total} async functions recovered; \
             {execution_equal}/{} programs execution-equal",
            PROGRAMS.len()
        );
        assert_eq!(recovered_total, source_total);
    }
}

#[test]
fn minified_helper_recovery_is_measured_against_its_floor() {
    for (profile, floor) in MINIFIED_FLOORS {
        let mut source_total: usize = 0;
        let mut recovered_total: usize = 0;
        for program in PROGRAMS {
            let original: String = read_recorded(&format!("{profile}/{program}.js"));
            let source_async: usize = source_async_functions(program);
            let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(&original);
            let label: String = format!("{profile}/{program}");
            assert_eq!(
                node_output(&original),
                node_output(&recovered),
                "{label}: recovered module changed behaviour\n{recovered}"
            );
            let recovered_async: usize = shape(&recovered, "recovered.js").async_functions;
            assert_eq!(
                recovered_async, stats.ts_async_functions_restored,
                "{label}: every restored function is async in the output\n{recovered}"
            );
            source_total += source_async;
            recovered_total += recovered_async;
        }
        println!(
            "ts-helpers {profile}: {recovered_total}/{source_total} async functions recovered; \
             {}/{} programs execution-equal",
            PROGRAMS.len(),
            PROGRAMS.len()
        );
        assert!(
            recovered_total >= floor,
            "{profile}: recovered {recovered_total} is below the floor {floor}"
        );
    }
}

fn mangle_helpers(source: &str) -> String {
    source
        .replace("__awaiter", "n")
        .replace("__generator", "r")
        .replace("this && this.n", "this && this.__awaiter")
        .replace("this && this.r", "this && this.__generator")
}

#[test]
fn mangled_helper_aliases_are_identified_by_shape() {
    for profile in PROFILES {
        let mut recovered_total: usize = 0;
        let mut source_total: usize = 0;
        for program in PROGRAMS {
            let original: String =
                mangle_helpers(&read_recorded(&format!("{profile}/{program}.js")));
            assert!(
                !original.contains("__awaiter("),
                "mangling must rename call sites"
            );
            let source_async: usize = source_async_functions(program);
            let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(&original);
            let graded: Graded = grade(
                &format!("{profile}/{program} (mangled)"),
                &original,
                source_async,
                &recovered,
            );
            assert_eq!(stats.ts_async_functions_restored, source_async);
            source_total += source_async;
            recovered_total += graded.recovered_async;
        }
        println!(
            "ts-helpers {profile} mangled aliases: {recovered_total}/{source_total} async functions recovered"
        );
    }
}

fn tslib_namespace(source: &str) -> (String, String) {
    let helpers_end: usize = source
        .find("Object.defineProperty(exports, \"__esModule\"")
        .expect("CommonJS marker follows the inline helpers");
    let helpers: &str = &source["\"use strict\";\n".len()..helpers_end];
    let exports: &str = if helpers.contains("var __generator") {
        "module.exports = { __awaiter: __awaiter, __generator: __generator };\n"
    } else {
        "module.exports = { __awaiter: __awaiter };\n"
    };
    let module: String = format!("\"use strict\";\n{helpers}{exports}");
    let body: String = source[helpers_end..]
        .replace("__awaiter(", "tslib_1.__awaiter(")
        .replace("__generator(", "tslib_1.__generator(");
    let program: String = format!(
        "\"use strict\";\n{}var tslib_1 = require(\"tslib\");\n{}",
        "Object.defineProperty(exports, \"__esModule\", { value: true });\n",
        body.trim_start_matches(
            "Object.defineProperty(exports, \"__esModule\", { value: true });\n"
        )
    );
    (program, module)
}

#[test]
fn tslib_namespace_calls_are_recovered() {
    let scratch: ScratchDir = ScratchDir::create("disrobe_ts_helpers_tslib").expect("scratch dir");
    let package: PathBuf = scratch.path().join("node_modules").join("tslib");
    std::fs::create_dir_all(&package).expect("create tslib stand-in");
    for profile in PROFILES {
        let mut recovered_total: usize = 0;
        let mut source_total: usize = 0;
        for program in PROGRAMS {
            let compiled: String = read_recorded(&format!("{profile}/{program}.js"));
            let (original, module): (String, String) = tslib_namespace(&compiled);
            std::fs::write(package.join("index.js"), &module).expect("write tslib stand-in");
            let source_async: usize = source_async_functions(program);
            let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(&original);
            let label: String = format!("{profile}/{program} (tslib namespace)");
            let expected: String = node_output_in(scratch.path(), &original);
            let actual: String = node_output_in(scratch.path(), &recovered);
            assert_eq!(expected, actual, "{label}: behaviour changed\n{recovered}");
            assert!(
                !recovered.contains("tslib_1.__awaiter("),
                "{label}\n{recovered}"
            );
            assert!(
                !recovered.contains("tslib_1.__generator("),
                "{label}\n{recovered}"
            );
            assert_eq!(
                stats.ts_async_functions_restored, source_async,
                "{label}\n{recovered}"
            );
            source_total += source_async;
            recovered_total += shape(&recovered, "recovered.js").async_functions;
        }
        println!(
            "ts-helpers {profile} tslib namespace: {recovered_total}/{source_total} async functions recovered"
        );
        assert_eq!(recovered_total, source_total);
    }
}

#[test]
fn a_misdecoded_generator_opcode_turns_the_execution_grade_red() {
    let original: String = read_recorded("es5/loops.js");
    let site: &str = "if (!(_i < items_1.length)) return [3 /*break*/, 4];";
    assert!(
        original.contains(site),
        "loops.js keeps the for-of exit instruction"
    );
    let misdecoded: String = original.replacen(
        site,
        "if (!(_i < items_1.length)) return [2 /*return*/, 4];",
        1,
    );
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(&misdecoded);
    assert!(
        stats.ts_async_functions_restored > 0,
        "the mutated machine must still be recovered so the grade can see it"
    );
    let expected: String = node_output(&original);
    let actual: String = node_output(&recovered);
    assert_ne!(
        expected, actual,
        "decoding one break as a return must change the recovered behaviour"
    );
}

const COUNTERFEIT_AWAITER: &str = r#""use strict";
var __awaiter = function (thisArg, _arguments, P, generator) {
    var iterator = generator.apply(thisArg, _arguments || []);
    var step = iterator.next();
    while (!step.done) { step = iterator.next("counterfeit:" + step.value); }
    return step.value;
};
function main() {
    return __awaiter(this, void 0, void 0, function* () {
        const value = yield 41;
        console.log(value);
        return value;
    });
}
console.log(String(main()));
"#;

#[test]
fn a_user_function_named_awaiter_with_another_body_is_left_untouched() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(COUNTERFEIT_AWAITER);
    assert_eq!(stats.ts_async_functions_restored, 0);
    let recovered_shape: Shape = shape(&recovered, "recovered.js");
    assert_eq!(recovered_shape.async_functions, 0, "{recovered}");
    assert_eq!(recovered_shape.generators, 1, "{recovered}");
    assert_eq!(recovered_shape.helper_names, 1, "{recovered}");
    assert_eq!(node_output(COUNTERFEIT_AWAITER), node_output(&recovered));
    assert_eq!(node_output(&recovered), "counterfeit:41\ncounterfeit:41\n");
}

#[test]
fn a_counterfeit_generator_body_is_left_untouched() {
    let original: String = read_recorded("es5/sequential.js");
    let counterfeit: String = original.replacen("case 4: _.label++;", "case 4: _.label += 2;", 1);
    assert_ne!(
        original, counterfeit,
        "the counterfeit must alter the helper body"
    );
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(&counterfeit);
    assert_eq!(stats.ts_async_state_machines_restored, 0, "{recovered}");
    let recovered_shape: Shape = shape(&recovered, "recovered.js");
    assert!(recovered_shape.state_machine_calls > 0, "{recovered}");
}

#[test]
fn a_rebound_global_promise_blocks_recovery() {
    let original: String = read_recorded("es2015/sequential.js");
    let rebound: String = original.replacen(
        "Object.defineProperty(exports, \"__esModule\", { value: true });",
        "Object.defineProperty(exports, \"__esModule\", { value: true });\nclass TaggedPromise extends Promise {}\nglobalThis.Promise = TaggedPromise;\nconsole.log(String(main() instanceof TaggedPromise));",
        1,
    );
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(&rebound);
    assert_eq!(stats.ts_async_functions_restored, 0, "{recovered}");
    assert_eq!(node_output(&rebound), node_output(&recovered));
}

fn es5_helpers() -> String {
    let compiled: String = read_recorded("es5/sequential.js");
    let end: usize = compiled
        .find("Object.defineProperty(exports")
        .expect("inline helpers precede the CommonJS marker");
    compiled[..end].to_owned()
}

fn assert_refused(label: &str, body: &str, expected_output: &str) {
    let program: String = format!("{}{body}", es5_helpers());
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(&program);
    assert_eq!(
        stats.ts_async_functions_restored, 0,
        "{label}: an unprovable shape must stay untouched
{recovered}"
    );
    assert!(
        recovered.contains("__generator(this, function (_a)"),
        "{label}: the state machine must remain
{recovered}"
    );
    let original_output: String = node_output(&program);
    assert_eq!(original_output, expected_output, "{label}: fixture output");
    assert_eq!(
        original_output,
        node_output(&recovered),
        "{label}: behaviour changed"
    );
}

#[test]
fn an_effect_before_the_resumed_value_is_refused() {
    assert_refused(
        "sent prefix effect",
        r#"var order = [];
function note(value) { order.push(value); return value; }
function run() {
    return __awaiter(this, void 0, void 0, function () {
        var total;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0: return [4 /*yield*/, Promise.resolve(note("operand"))];
                case 1:
                    total = note("before") + _a.sent();
                    return [2 /*return*/, total];
            }
        });
    });
}
run().then(function (value) { console.log(value, order.join(",")); });
"#,
        "beforeoperand operand,before
",
    );
}

#[test]
fn a_jump_into_a_catch_part_is_refused() {
    assert_refused(
        "jump into catch",
        r#"function run(flag) {
    return __awaiter(this, void 0, void 0, function () {
        var error_1;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    if (flag) return [3 /*break*/, 2];
                    _a.label = 1;
                case 1:
                    _a.trys.push([1, 2, , 3]);
                    return [3 /*break*/, 3];
                case 2:
                    error_1 = _a.sent();
                    console.log("caught", String(error_1));
                    return [3 /*break*/, 3];
                case 3: return [2 /*return*/, "done"];
            }
        });
    });
}
run(true).then(function (value) { console.log(value); });
"#,
        "caught undefined
done
",
    );
}

#[test]
fn an_irreducible_state_machine_is_refused() {
    assert_refused(
        "irreducible flow",
        r#"function run(start) {
    return __awaiter(this, void 0, void 0, function () {
        var steps;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    steps = [];
                    if (start) return [3 /*break*/, 2];
                    _a.label = 1;
                case 1:
                    steps.push("a");
                    if (steps.length > 3) return [3 /*break*/, 3];
                    return [3 /*break*/, 2];
                case 2:
                    steps.push("b");
                    return [3 /*break*/, 1];
                case 3: return [2 /*return*/, steps.join("")];
            }
        });
    });
}
run(true).then(function (value) { console.log(value); });
"#,
        "baba
",
    );
}

#[test]
fn a_generator_reading_its_own_arguments_is_refused() {
    let program: String = format!(
        "{}{}",
        read_recorded("es2015/sequential.js")
            .split("Object.defineProperty(exports")
            .next()
            .expect("helper prefix"),
        r"function count(first) {
    return __awaiter(this, void 0, void 0, function* () {
        return (yield Promise.resolve(arguments.length)) + first;
    });
}
count(5).then((value) => console.log(value));
"
    );
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(&program);
    assert_eq!(stats.ts_async_functions_restored, 0, "{recovered}");
    assert_eq!(
        node_output(&program),
        "5
"
    );
    assert_eq!(node_output(&program), node_output(&recovered));
}

#[test]
fn direct_eval_inside_the_function_is_refused() {
    assert_refused(
        "direct eval",
        r#"function run() {
    return __awaiter(this, void 0, void 0, function () {
        var total;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0: return [4 /*yield*/, Promise.resolve(2)];
                case 1:
                    total = _a.sent();
                    return [2 /*return*/, eval("total * 21")];
            }
        });
    });
}
run().then(function (value) { console.log(value); });
"#,
        "42
",
    );
}
