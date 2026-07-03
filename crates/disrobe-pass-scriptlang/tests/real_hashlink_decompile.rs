#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use std::collections::BTreeSet;

use disrobe_pass_scriptlang::lang::hashlink::{HlCode, read_code};

const CALC_HL: &[u8] = include_bytes!("fixtures/haxe_calc.hl");
const CALC_HX: &str = include_str!("fixtures/HaxeCalc.hx");
const MAIN_HL: &[u8] = include_bytes!("fixtures/haxe_main.hl");
const MAIN_HX: &str = include_str!("fixtures/Main.hx");

fn source_classes(src: &str) -> BTreeSet<String> {
    src.lines()
        .filter_map(|line: &str| {
            let rest: &str = line.trim().strip_prefix("class ")?;
            let name: String = rest
                .chars()
                .take_while(|c: &char| c.is_alphanumeric() || *c == '_')
                .collect();
            (!name.is_empty()).then_some(name)
        })
        .collect()
}

fn source_functions(src: &str) -> BTreeSet<String> {
    src.lines()
        .filter_map(|line: &str| {
            let at: usize = line.find("function ")?;
            let after: &str = &line[at + "function ".len()..];
            let name: String = after
                .chars()
                .take_while(|c: &char| c.is_alphanumeric() || *c == '_')
                .collect();
            (!name.is_empty()).then_some(name)
        })
        .collect()
}

fn assert_full_structural_parse(code: &HlCode) {
    assert_eq!(
        code.version, 4,
        "committed HL fixtures are bytecode version 4"
    );
    assert!(code.has_debug, "fixtures were compiled with -debug");
    assert!(
        code.fully_parsed(),
        "the reader must consume the whole HLB image ({} of {} bytes); any wrong opcode arg-count \
         or section order desyncs the stream",
        code.bytes_consumed,
        code.total_len
    );
    for (fi, function) in code.functions.iter().enumerate() {
        assert!(
            code.types.get(function.type_index).is_some(),
            "function {fi} has an unresolved type index"
        );
        for &reg in &function.regs {
            assert!(
                reg < code.types.len(),
                "function {fi} has an out-of-range register type"
            );
        }
        for op in &function.ops {
            let mnemonic: &str = op.mnemonic();
            assert!(
                mnemonic != "Unknown" && mnemonic != "Last",
                "every decoded opcode must map to a known HL mnemonic, got {mnemonic}"
            );
        }
    }
    for global in &code.globals {
        assert!(
            *global < code.types.len(),
            "global has an out-of-range type index"
        );
    }
    for native in &code.natives {
        assert!(
            !native.name.is_empty(),
            "native names must be resolved from the string pool"
        );
        assert!(
            native.type_index < code.types.len(),
            "native type must resolve"
        );
    }
}

#[test]
fn calc_hl_parses_every_section_byte_exact() {
    let code: HlCode = read_code(CALC_HL).expect("HaxeCalc HL image must fully parse");
    assert_eq!(code.types.len(), 421);
    assert_eq!(code.functions.len(), 336);
    assert_eq!(code.natives.len(), 52);
    assert_eq!(code.globals.len(), 95);
    assert_eq!(code.constants.len(), 51);
    assert_full_structural_parse(&code);
    let total_ops: usize = code.functions.iter().map(|f| f.ops.len()).sum();
    assert!(
        total_ops > 400,
        "decoded opcode stream is substantial: {total_ops}"
    );
}

#[test]
fn main_hl_parses_every_section_byte_exact() {
    let code: HlCode = read_code(MAIN_HL).expect("Main HL image must fully parse");
    assert!(code.functions.len() > 300);
    assert_full_structural_parse(&code);
}

#[test]
fn calc_hl_recovers_source_classes_and_methods() {
    let code: HlCode = read_code(CALC_HL).expect("parse");
    let classes: Vec<String> = code.object_type_names();
    let methods: Vec<String> = code.method_names();

    let src_classes: BTreeSet<String> = source_classes(CALC_HX);
    let src_functions: BTreeSet<String> = source_functions(CALC_HX);
    assert_eq!(
        src_classes,
        BTreeSet::from(["Calculator".to_owned(), "Main".to_owned()]),
        "source parser sanity"
    );

    for class in &src_classes {
        assert!(
            classes.iter().any(|n: &String| n == class),
            "recovered object types must include source class {class}: {classes:?}"
        );
    }

    let nameable: BTreeSet<&String> = src_functions
        .iter()
        .filter(|f: &&String| f.as_str() != "new")
        .collect();
    for method in &nameable {
        assert!(
            methods.iter().any(|n: &String| &n == method),
            "recovered methods must include every non-constructor source method {method} \
             (instance protos + function-typed static fields); the constructor `new` is stored \
             positionally in HL with no name string and is the single expected miss"
        );
    }

    let hit_methods: usize = src_functions
        .iter()
        .filter(|f: &&String| methods.iter().any(|n: &String| n == *f))
        .count();
    let method_coverage: f64 = hit_methods as f64 / src_functions.len() as f64;
    let hit_classes: usize = src_classes
        .iter()
        .filter(|c: &&String| classes.iter().any(|n: &String| n == *c))
        .count();
    let class_coverage: f64 = hit_classes as f64 / src_classes.len() as f64;

    assert!(
        (class_coverage - 1.0).abs() < f64::EPSILON,
        "class name coverage must be 100% ({hit_classes}/{})",
        src_classes.len()
    );
    assert!(
        method_coverage >= 0.75,
        "measured method name coverage {method_coverage:.3} below floor 0.75 ({hit_methods}/{}); \
         3 of 4 declared methods (add, describe, main) are name-recoverable, the constructor is not",
        src_functions.len()
    );
}

#[test]
fn main_hl_recovers_source_classes_and_methods() {
    let code: HlCode = read_code(MAIN_HL).expect("parse");
    let classes: Vec<String> = code.object_type_names();
    let methods: Vec<String> = code.method_names();
    assert!(classes.iter().any(|n: &String| n == "Main"));
    for method in ["greet", "add", "main"] {
        assert!(
            methods.iter().any(|n: &String| n == method),
            "Main.hx static methods must be recovered as function-typed fields: {method}"
        );
    }
    assert!(
        source_functions(MAIN_HX).contains("greet"),
        "source parser sanity"
    );
}

#[test]
fn calc_hl_disassembly_reconstructs_typed_function_bodies() {
    let code: HlCode = read_code(CALC_HL).expect("parse");
    let names = code.function_name_map();

    let add: &_ = code
        .function_by_findex(28)
        .expect("Calculator.add is findex 28");
    let add_text: String = code.disassemble_function(add, &names);
    assert!(
        add_text.contains("fn Calculator.add(r0: Calculator, r1: i32, r2: i32) -> i32"),
        "typed signature reconstruction: {add_text}"
    );
    assert!(
        add_text.contains("Add") && add_text.contains("Ret"),
        "body opcodes: {add_text}"
    );

    let describe: &_ = code
        .function_by_findex(29)
        .expect("Calculator.describe is findex 29");
    let describe_text: String = code.disassemble_function(describe, &names);
    assert!(
        describe_text.contains("-> String"),
        "describe returns String: {describe_text}"
    );

    assert!(
        code.strings
            .iter()
            .any(|s: &String| s.contains("disrobe-demo")),
        "the literal from `new Calculator(\"disrobe-demo\")` must survive in the string pool \
         (HL stores it as a global constant loaded via OGetGlobal, not an inline OString)"
    );
    let full: String = code.disassemble();
    assert!(
        full.contains("str@"),
        "OString operands must render with their resolved string-pool text"
    );
    assert!(
        full.contains("Calculator.add"),
        "resolved call targets appear in the listing"
    );
    assert!(
        full.contains("fn Calculator.describe(r0: Calculator) -> String"),
        "every function gets a reconstructed typed signature"
    );
}

#[test]
fn hashlink_summary_reports_full_recovery() {
    let code: HlCode = read_code(CALC_HL).expect("parse");
    let summary = code.summary();
    assert!(summary.fully_parsed);
    assert_eq!(summary.version, 4);
    assert_eq!(summary.num_functions, 336);
    assert!(summary.num_opcodes > 400);
    assert!(
        summary
            .object_types
            .iter()
            .any(|n: &String| n == "Calculator")
    );
    assert!(
        summary
            .method_names
            .iter()
            .any(|n: &String| n == "describe")
    );
    assert!(summary.source_files.iter().any(|n: &String| n == "Main.hx"));
    assert!(
        !summary.native_names.is_empty(),
        "natives are named library entry points resolved from the string pool, not fabricated"
    );
    assert_eq!(summary.num_types, code.types.len());
    assert!(code.types.len() > 400, "type table is fully populated");
}
