#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::uninlined_format_args
)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use disrobe_pass_mobile::flutter::disasm::disassemble_range;
use disrobe_pass_mobile::{
    AotLiftReport, Arm64FlowKind, DartCallKind, DartKernel, DartLiftedFunction, DartPoolLiteral,
    KernelClass, dart_isolate_instruction_bytes, lift_libapp_aot, parse_dart_kernel,
    parse_libapp_so,
};

fn sample_dir() -> PathBuf {
    let manifest_dir: &str = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest_dir)
        .join("..")
        .join("..")
        .join("corpus")
        .join("mobile")
        .join("flutter")
        .join("disrobe_sample")
}

fn read_sample(name: &str) -> Vec<u8> {
    let path: PathBuf = sample_dir().join(name);
    std::fs::read(&path)
        .unwrap_or_else(|e| panic!("sample {} must be committed: {e}", path.display()))
}

fn dill_ground_truth() -> DartKernel {
    parse_dart_kernel(&read_sample("disrobe_aot_sample.app.dill")).expect("parse .dill oracle")
}

fn aot_report() -> AotLiftReport {
    lift_libapp_aot(&read_sample("libapp_arm64.so")).expect("lift ARM64 AOT")
}

fn qualified_procedure_names(kernel: &DartKernel) -> BTreeSet<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    for library in &kernel.libraries {
        for procedure in &library.procedures {
            out.insert(procedure.name.clone());
        }
        for class in &library.classes {
            for procedure in &class.procedures {
                out.insert(format!("{}.{}", class.name, procedure.name));
            }
        }
    }
    out
}

fn bare_procedure_names(kernel: &DartKernel) -> BTreeSet<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    for library in &kernel.libraries {
        for procedure in &library.procedures {
            out.insert(procedure.name.clone());
        }
        for class in &library.classes {
            for procedure in &class.procedures {
                out.insert(procedure.name.clone());
            }
        }
    }
    out
}

fn lifted_names(report: &AotLiftReport) -> BTreeSet<String> {
    report
        .functions
        .iter()
        .filter_map(|f: &DartLiftedFunction| f.name.clone())
        .collect::<BTreeSet<String>>()
}

fn find_lifted<'a>(report: &'a AotLiftReport, name: &str) -> Option<&'a DartLiftedFunction> {
    report
        .functions
        .iter()
        .find(|f: &&DartLiftedFunction| f.name.as_deref() == Some(name))
}

#[test]
fn fibonacci_step_recovers_nested_pseudocode() {
    let report: AotLiftReport = aot_report();
    let fib: &DartLiftedFunction =
        find_lifted(&report, "fibonacciStep").expect("fibonacciStep must lift");

    assert!(
        fib.is_structured(),
        "the shared structurer must recover fibonacciStep to nested pseudocode; it fell back to the flat call-list"
    );
    let dart: String = fib.best_pseudo_dart();
    eprintln!("--- fibonacciStep structured pseudo-Dart ---\n{}", dart);

    assert!(
        dart.contains("if (") && dart.contains("} else {"),
        "the source `if (depth < 2) ... else ...` must recover as a nested if/else, got:\n{dart}"
    );
    assert!(
        dart.matches("fibonacciStep(").count() >= 3,
        "the signature plus the two recursive self-calls must render as fibonacciStep(...), got:\n{dart}"
    );
    assert!(
        dart.contains("return;"),
        "both arms return; the structured body must render return statements, got:\n{dart}"
    );
}

#[test]
fn conditional_select_recovers_the_real_backorder_predicate() {
    let source: String = String::from_utf8(read_sample("disrobe_aot_sample.dart"))
        .expect("committed Dart source is UTF-8");
    assert!(
        source.contains("quantityOnHand <= 0"),
        "the source oracle must contain the predicate compiled into the committed AOT image"
    );

    let report: AotLiftReport = aot_report();
    let predicate: &DartLiftedFunction = find_lifted(
        &report,
        "WarehouseLedger.countBackordered.<anonymous closure>",
    )
    .expect("the committed AOT symbol table names the backorder predicate closure");
    let compiler_sequence: Vec<&str> = predicate
        .unlifted_arm64
        .iter()
        .map(|instruction| instruction.text.as_str())
        .collect::<Vec<&str>>();
    assert!(
        compiler_sequence.windows(4).any(|window: &[&str]| {
            window
                == [
                    "cmp x2, #0x0",
                    "add x16, x22, #0x20",
                    "add x17, x22, #0x30",
                    "csel x0, x16, x17, le",
                ]
        }),
        "the committed Flutter compiler artifact must carry the exact comparison and conditional-select evidence"
    );

    let dart: String = predicate.best_pseudo_dart();
    assert!(
        predicate.is_structured(),
        "the conditional-select predicate must lift instead of staying a flat ARM64 listing:\n{dart}"
    );
    assert!(
        dart.starts_with("WarehouseLedger.countBackordered.<anonymous closure>(arg0) {"),
        "the lifted signature must retain only the parameter consumed by the predicate:\n{dart}"
    );
    assert_eq!(
        predicate.arg_registers, 1,
        "the structured body and machine-readable argument count must agree"
    );
    assert!(
        dart.contains("return arg0.field@0xb <= 0;"),
        "the compiled field comparison must recover as a boolean return:\n{dart}"
    );
}

#[test]
fn structuring_reports_structured_and_fallback_counts() {
    let report: AotLiftReport = aot_report();
    eprintln!(
        "structuring: structured={} flat_fallback={} of function_count={}",
        report.structured_function_count, report.flat_fallback_count, report.function_count,
    );
    assert_eq!(
        report.structured_function_count + report.flat_fallback_count,
        report.function_count,
        "every function is either structured or falls back to the flat list"
    );
    assert!(
        report.structured_function_count >= 1,
        "at least fibonacciStep structures on the real sample, got {}",
        report.structured_function_count
    );
    assert!(
        report.flat_fallback_count >= 1,
        "functions with unrecovered control flow must honestly fall back to the flat list, got {}",
        report.flat_fallback_count
    );

    for func in &report.functions {
        if !func.is_structured() {
            assert_eq!(
                func.best_pseudo_dart(),
                func.to_pseudo_dart(),
                "a fallback function's best rendering must equal its unchanged flat call-list"
            );
        }
    }
}

#[test]
fn real_aot_bodies_retain_exact_unlifted_arm64_residue() {
    let bytes: Vec<u8> = read_sample("libapp_arm64.so");
    let layout = parse_libapp_so(&bytes).expect("parse real libapp layout");
    let instructions: Vec<u8> =
        dart_isolate_instruction_bytes(&bytes).expect("read real isolate instructions");
    let symbol = layout
        .function_symbols
        .iter()
        .find(|symbol| symbol.name == "fibonacciStep")
        .expect("real symbol table carries fibonacciStep");
    let first_word: u32 = u32::from_le_bytes(
        instructions[symbol.offset..symbol.offset + 4]
            .try_into()
            .expect("fibonacciStep starts on one complete ARM64 word"),
    );
    assert_eq!(first_word, 0xa9bf_79fd, "committed artifact changed");

    let report: AotLiftReport = lift_libapp_aot(&bytes).expect("lift real ARM64 AOT");
    let fib: &DartLiftedFunction =
        find_lifted(&report, "fibonacciStep").expect("fibonacciStep must lift");
    let structured: String = fib.best_pseudo_dart();
    assert!(
        structured.contains(
            "unliftedArm64(address: 0x000a8500, bytes: 0xa9bf79fd, text: \"stp x29, x30, [x15, #-0x10]!\")"
        ),
        "the structured body must retain the artifact's exact first unlifted instruction, got:\n{structured}"
    );
    assert!(
        fib.unlifted_arm64
            .windows(2)
            .all(|pair| pair[0].address < pair[1].address),
        "unlifted residue must preserve strict instruction order"
    );
    let next_offset: usize = layout
        .function_symbols
        .iter()
        .filter_map(|candidate| (candidate.offset > symbol.offset).then_some(candidate.offset))
        .min()
        .unwrap_or(instructions.len());
    let limit: usize = symbol
        .offset
        .saturating_add(symbol.size as usize)
        .min(next_offset)
        .min(instructions.len());
    let disassembly = disassemble_range(
        &instructions,
        0,
        symbol.offset,
        limit,
        Some(symbol.name.clone()),
    );
    let expected_residue = disassembly
        .instructions
        .iter()
        .filter(|instruction| {
            matches!(
                instruction.flow,
                Arm64FlowKind::Sequential
                    | Arm64FlowKind::IndirectBranch
                    | Arm64FlowKind::DecodeError
            ) && instruction.bytes & 0xffe0_001f != 0xd420_0000
        })
        .collect::<Vec<_>>();
    assert_eq!(
        fib.unlifted_arm64.len(),
        expected_residue.len(),
        "every non-semantic instruction must remain as residue"
    );
    for (residue, instruction) in fib.unlifted_arm64.iter().zip(expected_residue) {
        assert_eq!(residue.address, instruction.address);
        assert_eq!(residue.bytes, instruction.bytes);
        assert_eq!(residue.text, instruction.text);
        assert!(
            structured.contains(&residue.to_pseudo_dart()),
            "structured output omitted residue at {:#x}",
            residue.address
        );
    }

    let fallback: &DartLiftedFunction = report
        .functions
        .iter()
        .find(|function: &&DartLiftedFunction| !function.is_structured())
        .expect("the real image must retain at least one flat fallback");
    assert!(
        fallback.best_pseudo_dart().contains("unliftedArm64("),
        "flat fallback output must expose its unlifted ARM64 residue"
    );
}

#[cfg(feature = "chain")]
#[test]
fn mobile_chain_pass_exposes_unlifted_arm64_residue() {
    use disrobe_core::chain::Pass as _;
    use disrobe_core::{Artifact, Rung};
    use disrobe_pass_mobile::chain_detector::MOBILE_PASS;

    let input: Artifact = Artifact::new(Rung::Raw, read_sample("libapp_arm64.so"), [0_u8; 32]);
    let output: Artifact = MOBILE_PASS
        .run(&input)
        .expect("mobile pass runs on real Flutter AOT");
    let json: serde_json::Value =
        serde_json::from_slice(&output.envelope).expect("mobile pass emits JSON");
    let functions = json
        .pointer("/flutter_aot_lift/functions")
        .and_then(serde_json::Value::as_array)
        .expect("mobile output carries Flutter AOT functions");
    let fibonacci = functions
        .iter()
        .find(|function: &&serde_json::Value| {
            function.get("name").and_then(serde_json::Value::as_str) == Some("fibonacciStep")
        })
        .expect("mobile output carries fibonacciStep");
    let residue = fibonacci
        .get("unlifted_arm64")
        .and_then(serde_json::Value::as_array)
        .expect("mobile output carries unlifted ARM64 residue");
    assert!(
        residue.iter().any(|instruction: &serde_json::Value| {
            instruction
                .get("address")
                .and_then(serde_json::Value::as_u64)
                == Some(0x000a_8500)
                && instruction.get("bytes").and_then(serde_json::Value::as_u64) == Some(0xa9bf_79fd)
        }),
        "the registered mobile pass must expose the real artifact's first unlifted instruction"
    );
}

#[test]
fn abi_is_version_pinned_and_functions_lift() {
    let report: AotLiftReport = aot_report();
    assert!(
        report.abi_resolved,
        "the pinned Dart 3.12.2 snapshot must resolve the ARM64 ABI profile"
    );
    assert!(
        report.function_count > 100,
        "the real AOT image lifts thousands of code objects, got {}",
        report.function_count
    );
    assert_eq!(
        report.named_function_count, report.function_count,
        "symtab-driven lift names every function it lifts"
    );
    assert!(
        report
            .notes
            .iter()
            .any(|n: &String| n.contains("Precompiler::DropFields")),
        "the field-name wall must be stated honestly in the report notes"
    );
    assert!(
        report
            .notes
            .iter()
            .any(|n: &String| n.contains("ObjectPool cluster")),
        "the pool-content wall must be stated honestly"
    );
}

#[test]
fn function_boundary_recall_graded_against_dill() {
    let kernel: DartKernel = dill_ground_truth();
    let report: AotLiftReport = aot_report();
    let ground_truth: BTreeSet<String> = qualified_procedure_names(&kernel);
    let lifted: BTreeSet<String> = lifted_names(&report);

    let recovered: Vec<&String> = ground_truth
        .iter()
        .filter(|name: &&String| lifted.contains(*name))
        .collect::<Vec<&String>>();
    let walled: Vec<&String> = ground_truth
        .iter()
        .filter(|name: &&String| !lifted.contains(*name))
        .collect::<Vec<&String>>();

    let denominator: usize = ground_truth.len();
    let numerator: usize = recovered.len();

    eprintln!(
        "AOT-lift boundary recall vs .dill: {}/{} declared procedures lifted with a name",
        numerator, denominator
    );
    eprintln!("  recovered: {:?}", recovered);
    eprintln!(
        "  walled (inlined/tree-shaken by the AOT compiler, honestly absent): {:?}",
        walled
    );

    assert!(
        denominator >= 8,
        "the .dill must declare the sample procedures"
    );
    assert!(
        numerator >= 4,
        "at least the non-inlined procedures (fibonacciStep, main, WarehouseLedger methods) must lift, got {numerator}"
    );
    for surviving in ["fibonacciStep", "main"] {
        assert!(
            lifted.contains(surviving),
            "{surviving} survives the AOT compile and must lift by name"
        );
    }
}

#[test]
fn fibonacci_step_is_self_recursive_static_edge() {
    let report: AotLiftReport = aot_report();
    let fib: &DartLiftedFunction =
        find_lifted(&report, "fibonacciStep").expect("fibonacciStep must lift");

    let self_edges: usize = fib
        .calls
        .iter()
        .filter(|c: &&_| c.kind == DartCallKind::Static && c.is_self_recursive)
        .count();
    eprintln!(
        "fibonacciStep: instructions={} calls={} static_self_edges={} conditional_raw={} source_conditional_estimate={} elided={:?}",
        fib.instruction_count,
        fib.calls.len(),
        self_edges,
        fib.conditional_branch_count,
        fib.source_conditional_estimate,
        fib.elided_checks,
    );
    eprintln!(
        "--- fibonacciStep pseudo-Dart ---\n{}",
        fib.to_pseudo_dart()
    );

    assert!(
        self_edges >= 1,
        "the source recurses (fibonacciStep(depth-1)+fibonacciStep(depth-2)); the lift must recover a self-recursive static call, calls={:?}",
        fib.calls
    );
    assert!(
        self_edges <= 2,
        "at most the two textual recursive calls; register-allocation may share a call site"
    );
    assert!(
        fib.source_conditional_estimate <= fib.conditional_branch_count,
        "elision never increases the branch count"
    );
    assert!(
        fib.source_conditional_estimate <= 3,
        "after eliding the prologue stack-overflow guard, fibonacciStep is near its single source `if`, got {}",
        fib.source_conditional_estimate
    );
}

#[test]
fn call_graph_edges_carry_dill_names() {
    let kernel: DartKernel = dill_ground_truth();
    let report: AotLiftReport = aot_report();
    let ground_truth: BTreeSet<String> = qualified_procedure_names(&kernel);

    let mut named_edges: BTreeSet<String> = BTreeSet::new();
    for func in &report.functions {
        for call in &func.calls {
            if call.kind == DartCallKind::Static
                && let Some(name) = &call.target_name
            {
                named_edges.insert(name.clone());
            }
        }
    }
    let edges_into_app: Vec<&String> = named_edges
        .iter()
        .filter(|n: &&String| ground_truth.contains(*n))
        .collect::<Vec<&String>>();

    eprintln!(
        "call-graph: static_edges={} named_static_edges={} instance={} table={} runtime_stub={} self_recursive_fns={}",
        report.static_call_edges,
        report.named_static_call_edges,
        report.instance_call_sites,
        report.table_dispatch_sites,
        report.runtime_stub_calls,
        report.self_recursive_functions,
    );
    eprintln!(
        "  named static edges landing on .dill-declared app procedures: {:?}",
        edges_into_app
    );

    assert!(
        report.named_static_call_edges > 0,
        "the static call graph must resolve callee names via code-object attribution"
    );
    assert!(
        report.self_recursive_functions >= 1,
        "fibonacciStep is a self-recursive function; the call graph must show it"
    );
    assert!(
        !edges_into_app.is_empty(),
        "at least one recovered static edge must land on a .dill-declared app procedure (two independent extraction paths agree)"
    );
}

#[test]
fn check_branch_elision_reduces_control_flow() {
    let report: AotLiftReport = aot_report();
    let total_elided: usize = report.elided_null_checks
        + report.elided_bounds_checks
        + report.elided_stack_overflow_checks
        + report.elided_write_barriers;
    let raw_conditionals: usize = report
        .functions
        .iter()
        .map(|f: &DartLiftedFunction| f.conditional_branch_count)
        .sum::<usize>();
    let source_estimate: usize = report
        .functions
        .iter()
        .map(|f: &DartLiftedFunction| f.source_conditional_estimate)
        .sum::<usize>();

    eprintln!(
        "check-branch elision: raw_conditionals={} source_conditional_estimate={} elided[null={} bounds={} stack_overflow={} write_barrier={}]",
        raw_conditionals,
        source_estimate,
        report.elided_null_checks,
        report.elided_bounds_checks,
        report.elided_stack_overflow_checks,
        report.elided_write_barriers,
    );

    assert!(
        total_elided > 0,
        "a real AOT image is dense with compiler-inserted null/bounds/stack guards; elision must find them"
    );
    assert!(
        report.elided_stack_overflow_checks > 0,
        "functions with frames carry a prologue stack-overflow guard that must be elided"
    );
    assert!(
        source_estimate <= raw_conditionals,
        "elision brings the branch count down toward source, never up"
    );
}

fn dill_source_text(kernel: &DartKernel) -> String {
    let mut text: String = String::new();
    for source in &kernel.sources {
        text.push_str(&source.text);
        text.push('\n');
    }
    for library in &kernel.libraries {
        for procedure in &library.procedures {
            if let Some(body) = &procedure.recovered_source {
                text.push_str(body);
                text.push('\n');
            }
        }
        for class in &library.classes {
            if let Some(body) = &class.recovered_source {
                text.push_str(body);
                text.push('\n');
            }
        }
    }
    text
}

fn pool_strings(report: &AotLiftReport) -> BTreeSet<String> {
    report
        .pool_literals
        .iter()
        .filter_map(|l: &DartPoolLiteral| l.as_str().map(str::to_owned))
        .collect::<BTreeSet<String>>()
}

fn pool_doubles(report: &AotLiftReport) -> Vec<f64> {
    report
        .pool_literals
        .iter()
        .filter_map(DartPoolLiteral::as_double)
        .collect::<Vec<f64>>()
}

fn inline_doubles(report: &AotLiftReport) -> Vec<f64> {
    report
        .inline_double_literals
        .iter()
        .filter_map(DartPoolLiteral::as_double)
        .collect::<Vec<f64>>()
}

#[test]
fn pool_resolution_covers_wide_offset_load_forms() {
    let report: AotLiftReport = aot_report();
    eprintln!(
        "object-pool resolution: refs_total={} wide_offset(add/reg)={} content_resolved={} literals={}",
        report.pool_refs_total,
        report.pool_refs_wide_offset,
        report.pool_content_resolved,
        report.pool_literals.len(),
    );

    assert!(
        report.pool_refs_total > 100,
        "the app references the object pool from many sites, got {}",
        report.pool_refs_total
    );
    assert!(
        report.pool_refs_wide_offset > 0,
        "a 1.8MB app has an object pool larger than the 4096-slot direct ldr range, forcing add/movk wide-offset load forms; the resolver must decode them, got {}",
        report.pool_refs_wide_offset
    );
    assert!(
        report.pool_content_resolved > 0,
        "ObjectPool string and kImmediate double literal content now resolves, got {}",
        report.pool_content_resolved
    );
    assert_eq!(
        report.pool_content_resolved,
        report.pool_literals.len(),
        "the resolved count must equal the recovered typed literal inventory"
    );
}

#[test]
fn pool_literals_match_dill_declared_constants() {
    let kernel: DartKernel = dill_ground_truth();
    let report: AotLiftReport = aot_report();
    let source: String = dill_source_text(&kernel);
    let strings: BTreeSet<String> = pool_strings(&report);
    let doubles: Vec<f64> = pool_doubles(&report);

    eprintln!(
        "resolved pool literals: {} strings, {} doubles",
        strings.len(),
        doubles.len()
    );

    let named_strings: [&str; 7] = [
        "widget-alpha",
        "gadget-bravo",
        "sprocket-charlie",
        "flange-delta",
        "enterprise-tier",
        "mid-market-tier",
        "starter-tier",
    ];
    for literal in named_strings {
        assert!(
            source.contains(literal),
            "the .dill must declare the source string literal {literal}"
        );
        assert!(
            strings.contains(literal),
            "the ObjectPool must resolve the byte-exact string literal {literal} (recovered {} strings)",
            strings.len()
        );
    }

    let named_doubles: [(&str, f64); 5] = [
        ("19.95", 19.95),
        ("149.50", 149.5),
        ("2400.00", 2400.0),
        ("10000.0", 10000.0),
        ("1000.0", 1000.0),
    ];
    for (token, value) in named_doubles {
        assert!(
            source.contains(token),
            "the .dill must declare the source double literal {token}"
        );
        assert!(
            doubles.iter().any(|d: &f64| d.to_bits() == value.to_bits()),
            "the ObjectPool kImmediate double {value} must resolve byte-exact, got {doubles:?}"
        );
    }

    assert!(
        source.contains("4.25"),
        "the .dill declares the 4.25 literal"
    );
    assert!(
        !doubles
            .iter()
            .any(|d: &f64| d.to_bits() == 4.25f64.to_bits()),
        "4.25 is an fmov-encodable inline immediate, not an ObjectPool entry; it never enters the pool literal set"
    );
    eprintln!(
        "pool residual: 4.25 is not an ObjectPool entry (it is recovered from the inline fmov path); Smi integer immediates and per-slot attribution stay behind the version-keyed ObjectPool cluster"
    );
}

#[test]
fn inline_fmov_doubles_recover_the_pool_double_residual() {
    let kernel: DartKernel = dill_ground_truth();
    let report: AotLiftReport = aot_report();
    let source: String = dill_source_text(&kernel);
    let inline: Vec<f64> = inline_doubles(&report);

    eprintln!(
        "inline fmov double literals: count={} values={:?}",
        report.inline_double_count, inline,
    );

    assert_eq!(
        report.inline_double_count,
        report.inline_double_literals.len(),
        "the inline count must equal the recovered inline literal inventory"
    );
    assert!(
        source.contains("4.25"),
        "the .dill declares the 4.25 source literal"
    );
    assert!(
        inline
            .iter()
            .any(|d: &f64| d.to_bits() == 4.25f64.to_bits()),
        "4.25 is materialized as an inline fmov #imm and must decode byte-exact from the instruction stream, got {inline:?}"
    );
    assert!(
        !pool_doubles(&report)
            .iter()
            .any(|d: &f64| d.to_bits() == 4.25f64.to_bits()),
        "the inline path is distinct from the ObjectPool: 4.25 must not appear in pool_literals"
    );
    for (token, value) in [("19.95", 19.95f64), ("149.50", 149.5), ("2400.00", 2400.0)] {
        assert!(source.contains(token), "sanity: {token} is declared");
        assert!(
            !inline.iter().any(|d: &f64| d.to_bits() == value.to_bits()),
            "{value} is stored in the ObjectPool, not as an fmov immediate; the two paths must not overlap"
        );
    }
}

#[test]
fn field_names_and_inlined_leaves_stay_walled() {
    let kernel: DartKernel = dill_ground_truth();
    let report: AotLiftReport = aot_report();
    let lifted: BTreeSet<String> = lifted_names(&report);

    let inventory: &KernelClass = kernel
        .libraries
        .iter()
        .flat_map(|l| l.classes.iter())
        .find(|c: &&KernelClass| c.name == "InventoryItem")
        .expect("InventoryItem in .dill");
    assert!(
        inventory.fields.contains(&"skuLabel".to_owned()),
        "the .dill proves the field skuLabel exists in source"
    );

    let bare: BTreeSet<String> = bare_procedure_names(&kernel);
    assert!(
        bare.contains("extendedValue") && bare.contains("classifyMagnitude"),
        "the .dill declares the leaf methods that the AOT compiler inlines"
    );
    for inlined in ["InventoryItem.extendedValue", "classifyMagnitude"] {
        assert!(
            !lifted.contains(inlined),
            "{inlined} is inlined/tree-shaken by the AOT compiler; its boundary is genuinely absent and must not be fabricated"
        );
    }

    eprintln!(
        "honest walls confirmed: field names dropped by product precompiler (0 in .so), inlined leaves absent from AOT boundaries, pool content unresolved without the cluster"
    );
}
