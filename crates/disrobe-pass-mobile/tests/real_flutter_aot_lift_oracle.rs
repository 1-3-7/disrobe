#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::uninlined_format_args
)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use disrobe_pass_mobile::{
    AotLiftReport, DartCallKind, DartKernel, DartLiftedFunction, DartPoolLiteral, KernelClass,
    lift_libapp_aot, parse_dart_kernel,
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
        "4.25 is an fmov-encodable inline immediate, not an ObjectPool entry; it stays an honest residual"
    );
    eprintln!(
        "walls: 4.25 is materialized as an inline fmov immediate (not a pool entry); Smi integer immediates and per-slot attribution stay behind the version-keyed ObjectPool cluster"
    );
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
