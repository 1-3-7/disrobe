#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::uninlined_format_args
)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use disrobe_pass_mobile::{
    AotLiftReport, DART_POOL_ELEMENT_BASE_BYTES, DartGraphLimits, DartKernel, DartLiftedFunction,
    DartPoolLiteralKind, DartPoolTable, DartPoolTableStats, dart_isolate_data_bytes,
    dart_vm_data_bytes, lift_libapp_aot, parse_dart_kernel,
};

const RECORDED_OPAQUE_BASELINE: usize = 25_833;

const COMMITTED_SAMPLES: [&str; 4] = [
    "disrobe_sample/libapp_arm64.so",
    "pinned_graph_fixture/receipt_validator_arm64.so",
    "pinned_graph_fixture/receipt_validator_obfuscated_arm64.so",
    "pinned_graph_fixture/voucher_validator_arm64.so",
];

fn corpus() -> PathBuf {
    let manifest_dir: &str = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest_dir)
        .join("..")
        .join("..")
        .join("corpus")
        .join("mobile")
        .join("flutter")
}

fn read_sample(relative: &str) -> Vec<u8> {
    let mut path: PathBuf = corpus();
    for part in relative.split('/') {
        path = path.join(part);
    }
    std::fs::read(&path)
        .unwrap_or_else(|e| panic!("sample {} must be committed: {e}", path.display()))
}

fn primary_report() -> AotLiftReport {
    lift_libapp_aot(&read_sample("disrobe_sample/libapp_arm64.so")).expect("lift ARM64 AOT")
}

fn primary_pool() -> DartPoolTable {
    let bytes: Vec<u8> = read_sample("disrobe_sample/libapp_arm64.so");
    let vm: Vec<u8> = dart_vm_data_bytes(&bytes).expect("vm snapshot data");
    let isolate: Vec<u8> = dart_isolate_data_bytes(&bytes).expect("isolate snapshot data");
    DartPoolTable::build(&vm, &isolate, DartGraphLimits::default())
        .expect("the pinned object pool must deserialize")
        .expect("the pinned Dart 3.12.2 layout must match this sample")
}

fn body(report: &AotLiftReport, name: &str) -> String {
    report
        .functions
        .iter()
        .find(|f: &&DartLiftedFunction| f.name.as_deref() == Some(name) && f.is_structured())
        .unwrap_or_else(|| panic!("{name} must lift to structured pseudocode"))
        .best_pseudo_dart()
}

fn dill_source() -> String {
    let kernel: DartKernel =
        parse_dart_kernel(&read_sample("disrobe_sample/disrobe_aot_sample.app.dill"))
            .expect("parse the .dill reference");
    let mut text: String = String::new();
    for source in &kernel.sources {
        text.push_str(&source.text);
        text.push('\n');
    }
    text
}

#[test]
fn pool_slots_resolve_to_the_source_declared_constructor_literals() {
    let table: DartPoolTable = primary_pool();
    let source: String = dill_source();

    let expected: [(u64, bool, &str, &str); 12] = [
        (0x5728, false, "\"widget-alpha\"", "widget-alpha"),
        (0x5730, true, "19.95", "19.95"),
        (0x5738, false, "\"gadget-bravo\"", "gadget-bravo"),
        (0x5740, true, "149.5", "149.50"),
        (0x5748, false, "\"sprocket-charlie\"", "sprocket-charlie"),
        (0x5750, true, "2400.0", "2400.00"),
        (0x5758, false, "\"flange-delta\"", "flange-delta"),
        (0x5798, true, "10000.0", "10000.0"),
        (0x57a0, false, "\"enterprise-tier\"", "enterprise-tier"),
        (0x57a8, true, "1000.0", "1000.0"),
        (0x57b0, false, "\"mid-market-tier\"", "mid-market-tier"),
        (0x57b8, false, "\"starter-tier\"", "starter-tier"),
    ];

    for (byte_offset, float, rendered, declared) in expected {
        assert!(
            source.contains(declared),
            "the .dill source must declare {declared}, which is what makes this pool expectation independent of the pool decoder"
        );
        assert_eq!(
            table.render_at_offset(byte_offset, float).as_deref(),
            Some(rendered),
            "pool byte offset {byte_offset:#x} must decode to the value the source declares"
        );
    }

    assert_eq!(
        table.render_at_offset(0x5878, false).as_deref(),
        Some("<anonymous closure>"),
        "the pool slot the where() closure allocation loads must name the closure the source declares"
    );
    assert!(
        source.contains("(InventoryItem e) => e.isBackordered"),
        "the .dill source must declare the anonymous closure that slot names"
    );

    assert_eq!(
        DART_POOL_ELEMENT_BASE_BYTES, 16,
        "the pool element base is derived from these thirteen source-anchored pairs"
    );
}

#[test]
fn pool_literal_kinds_are_typed_from_the_deserialized_cluster() {
    let table: DartPoolTable = primary_pool();
    let mut tally: BTreeMap<String, usize> = BTreeMap::new();
    for slot in 0..table.slot_count() {
        let offset: u64 = DART_POOL_ELEMENT_BASE_BYTES + (slot as u64) * 8;
        *tally
            .entry(format!("{:?}", table.kind_at_offset(offset, false)))
            .or_default() += 1;
    }
    eprintln!("pinned object-pool slot kinds: {tally:?}");

    for observed in ["Str", "Double", "Integer", "List", "Named", "RawImmediate"] {
        assert!(
            tally.get(observed).copied().unwrap_or(0) > 0,
            "the pinned pool must carry at least one {observed} slot, got {tally:?}"
        );
    }
    eprintln!(
        "pool literal kinds NOT observed in this corpus and therefore not claimed: null, true, false and Smi never reach a pool slot in this build (null and the booleans arrive through the null register and its +0x20/+0x30 offsets, Smis are inline immediates); Symbol, Type and TypeArguments slots deserialize but keep no readable value and stay Unresolved"
    );

    let unresolved: usize = tally.get("Unresolved").copied().unwrap_or(0);
    assert!(
        unresolved < table.slot_count(),
        "an all-unresolved pool would mean the cluster walk failed"
    );
}

#[test]
fn out_of_range_and_misaligned_pool_offsets_do_not_resolve() {
    let table: DartPoolTable = primary_pool();
    let past_end: u64 = DART_POOL_ELEMENT_BASE_BYTES + (table.slot_count() as u64) * 8;
    assert_eq!(table.slot_index(past_end), None);
    assert_eq!(table.render_at_offset(past_end, false), None);
    assert_eq!(table.render_at_offset(u64::MAX, false), None);
    assert_eq!(table.render_at_offset(0, false), None);
    assert_eq!(
        table.render_at_offset(DART_POOL_ELEMENT_BASE_BYTES + 4, false),
        None,
        "a misaligned pool offset is not a slot"
    );
    assert_eq!(
        table.kind_at_offset(past_end, false),
        DartPoolLiteralKind::Unresolved
    );
}

#[test]
fn recursive_call_carries_its_recovered_argument_expression() {
    let report: AotLiftReport = primary_report();
    let dart: String = body(&report, "fibonacciStep");
    eprintln!("--- fibonacciStep ---\n{dart}");
    assert!(
        dart.contains("fibonacciStep(arg0 - 1);"),
        "the source calls fibonacciStep(depth - 1); the argument register must reconstruct that expression, got:\n{dart}"
    );
    assert!(
        !dart.contains("fibonacciStep(...)"),
        "no recursive call site may stay opaque, got:\n{dart}"
    );
}

#[test]
fn structured_signature_uses_pinned_snapshot_parameter_metadata() {
    let report: AotLiftReport = primary_report();
    let function: &DartLiftedFunction = report
        .functions
        .iter()
        .find(|function: &&DartLiftedFunction| {
            function.name.as_deref() == Some("fibonacciStep") && function.is_structured()
        })
        .expect("fibonacciStep must lift to structured pseudocode");
    let dart: String = function.best_pseudo_dart();

    assert!(
        dill_source().contains("int fibonacciStep(int depth)"),
        "the committed source must independently establish one declared parameter"
    );
    assert_eq!(
        function.arg_registers, 1,
        "the report must not turn scratch-register reads into source parameters"
    );
    assert!(
        dart.starts_with("fibonacciStep(arg0) {"),
        "the rendered signature must agree with the report and the committed source, got:\n{dart}"
    );

    let repeated: AotLiftReport = primary_report();
    let repeated_function: &DartLiftedFunction = repeated
        .functions
        .iter()
        .find(|candidate: &&DartLiftedFunction| {
            candidate.name.as_deref() == Some("fibonacciStep") && candidate.is_structured()
        })
        .expect("fibonacciStep must lift identically on a repeated run");
    assert_eq!(repeated_function.arg_registers, function.arg_registers);
    assert_eq!(repeated_function.best_pseudo_dart(), dart);
}

#[test]
fn pool_name_and_null_register_inline_at_a_real_call_site() {
    let report: AotLiftReport = primary_report();
    let dart: String = body(&report, "WarehouseLedger.countBackordered");
    eprintln!("--- WarehouseLedger.countBackordered ---\n{dart}");
    assert!(
        dart.contains("(<anonymous closure>, null);"),
        "the closure allocation reads its function from the object pool and null from the null register, got:\n{dart}"
    );
    assert!(
        dart.contains("Iterable.where(?, v0)"),
        "the where() call must thread the previous call result and keep the unrecoverable receiver as the placeholder, got:\n{dart}"
    );
    assert!(
        dart.contains("Iterable.length(v1)"),
        "the length() call passes its receiver on the Dart stack, got:\n{dart}"
    );
}

#[test]
fn main_recovers_integer_call_and_result_arguments() {
    let report: AotLiftReport = primary_report();
    let mains: Vec<String> = report
        .functions
        .iter()
        .filter(|f: &&DartLiftedFunction| f.name.as_deref() == Some("main") && f.is_structured())
        .map(DartLiftedFunction::best_pseudo_dart)
        .collect::<Vec<String>>();
    let dart: &String = mains
        .iter()
        .find(|body: &&String| body.contains("fibonacciStep"))
        .expect("the application main must lift");
    eprintln!("--- main ---\n{dart}");

    for expected in [
        "_Random.nextInt(v0, 3)",
        "fibonacciStep(v2 + 12)",
        "double.toStringAsFixed(?, 2)",
    ] {
        assert!(
            dart.contains(expected),
            "main must render {expected}, got:\n{dart}"
        );
    }
    let source: String = dill_source();
    assert!(
        source.contains("nextInt(3)") && source.contains("12 +"),
        "the .dill source must declare the nextInt(3) and 12 + ... expressions these arguments reconstruct"
    );
}

#[test]
fn argument_locations_exercised_by_the_committed_corpus() {
    let report: AotLiftReport = primary_report();
    let mut arities: BTreeSet<usize> = BTreeSet::new();
    let mut stack_slot_sites: usize = 0;
    let mut tail_call_sites: usize = 0;
    let mut null_arguments: usize = 0;
    let mut boolean_arguments: usize = 0;
    let mut pool_arguments: usize = 0;
    let mut immediate_arguments: usize = 0;
    let mut field_arguments: usize = 0;
    let mut result_arguments: usize = 0;
    let mut placeholder_arguments: usize = 0;

    for function in &report.functions {
        if !function.is_structured() {
            continue;
        }
        let dart: String = function.best_pseudo_dart();
        for line in dart.lines() {
            let Some(open): Option<usize> = line.find('(') else {
                continue;
            };
            if !line.ends_with(");") || line.contains("unliftedArm64(") {
                continue;
            }
            let inner: &str = &line[open + 1..line.len() - 2];
            if inner == "..." {
                continue;
            }
            let parts: Vec<&str> = if inner.is_empty() {
                Vec::new()
            } else {
                inner.split(", ").collect::<Vec<&str>>()
            };
            if parts.len() > 6 {
                stack_slot_sites += 1;
            }
            if line.trim_start().starts_with("return ") {
                tail_call_sites += 1;
            }
            arities.insert(parts.len());
            for part in &parts {
                match *part {
                    "null" => null_arguments += 1,
                    "true" | "false" => boolean_arguments += 1,
                    "?" => placeholder_arguments += 1,
                    text if text.starts_with('"') || text.starts_with("pool[") => {
                        pool_arguments += 1;
                    }
                    text if text.starts_with('v') && text[1..].chars().all(char::is_numeric) => {
                        result_arguments += 1;
                    }
                    text if text.contains(".field@") => field_arguments += 1,
                    text if text.parse::<i64>().is_ok() => immediate_arguments += 1,
                    _ => {}
                }
            }
        }
    }

    eprintln!(
        "argument locations on the real sample: rendered arities={:?} calls_beyond_the_register_file={} tail_calls={} null={} bool={} pool={} immediate={} field={} call_result={} placeholder={}",
        arities,
        stack_slot_sites,
        tail_call_sites,
        null_arguments,
        boolean_arguments,
        pool_arguments,
        immediate_arguments,
        field_arguments,
        result_arguments,
        placeholder_arguments
    );
    eprintln!(
        "argument locations NOT observed in this corpus and therefore not claimed: no call site passes an unboxed floating-point argument, so the floating-point argument registers are modelled only as the result register V0 and never as an argument position; the Dart arguments-descriptor register R4 never carries an argument at any observed call site and is excluded from the argument sequence"
    );

    for arity in 1..=6_usize {
        assert!(
            arities.contains(&arity),
            "every Dart integer argument register position must be exercised, got arities {arities:?}"
        );
    }
    assert!(
        stack_slot_sites > 0,
        "a call with more arguments than the register file must place the rest in Dart stack slots"
    );
    assert!(
        tail_call_sites > 0,
        "a tail call must render its recovered arguments rather than disappearing"
    );
    assert!(null_arguments > 0, "null arguments must be recovered");
    assert!(boolean_arguments > 0, "boolean arguments must be recovered");
    assert!(
        pool_arguments > 0,
        "pool literals must inline at call sites"
    );
    assert!(
        immediate_arguments > 0,
        "immediate arguments must be recovered"
    );
    assert!(
        field_arguments > 0,
        "field loads must be recovered as argument expressions"
    );
    assert!(
        result_arguments > 0,
        "values produced by an earlier call must be recovered as argument expressions"
    );
    assert!(
        placeholder_arguments > 0,
        "unrecoverable arguments must keep the placeholder rather than a guess"
    );
}

#[test]
fn opaque_invocation_count_drops_from_the_recorded_baseline() {
    let mut total: usize = 0;
    let mut per_sample: Vec<(String, usize)> = Vec::new();
    for sample in COMMITTED_SAMPLES {
        let report: AotLiftReport =
            lift_libapp_aot(&read_sample(sample)).expect("lift committed Dart sample");
        let opaque: usize = report
            .functions
            .iter()
            .filter(|f: &&DartLiftedFunction| f.is_structured())
            .map(|f: &DartLiftedFunction| f.best_pseudo_dart().matches("(...)").count())
            .sum::<usize>();
        assert_eq!(
            opaque, report.call_sites_opaque,
            "the reported opaque count must equal the count in the rendered bodies for {sample}"
        );
        assert!(
            report.call_sites_with_arguments > 0,
            "{sample} must recover arguments at real call sites"
        );
        total += opaque;
        per_sample.push((sample.to_owned(), opaque));
    }
    eprintln!(
        "opaque invocation renderings across the committed real Dart samples: baseline {RECORDED_OPAQUE_BASELINE} -> {total} {per_sample:?}"
    );
    assert!(
        total < RECORDED_OPAQUE_BASELINE,
        "call-argument reconstruction must reduce opaque invoke renderings below the recorded baseline of {RECORDED_OPAQUE_BASELINE}, got {total}"
    );
    assert!(
        total * 4 < RECORDED_OPAQUE_BASELINE,
        "the drop must be substantial, not incidental: got {total} against a baseline of {RECORDED_OPAQUE_BASELINE}"
    );
}

#[test]
fn pool_statistics_are_reported_with_the_lift() {
    let report: AotLiftReport = primary_report();
    let stats: DartPoolTableStats = report
        .pool_slots
        .expect("the pinned sample must carry object-pool slot statistics");
    eprintln!("pool slots: {stats:?}");
    assert!(stats.slots > 1000);
    assert!(stats.literals > 0);
    assert!(stats.literals <= stats.slots);
    assert!(stats.tagged_objects + stats.raw_immediates <= stats.slots);
}

#[cfg(feature = "chain")]
#[test]
fn mobile_pass_renders_the_same_pseudocode_as_the_library() {
    use disrobe_core::chain::Pass as _;
    use disrobe_core::{Artifact, Rung};
    use disrobe_pass_mobile::chain_detector::MOBILE_PASS;

    let bytes: Vec<u8> = read_sample("disrobe_sample/libapp_arm64.so");
    let report: AotLiftReport = lift_libapp_aot(&bytes).expect("library lift");
    let expected: String = body(&report, "fibonacciStep");

    let input: Artifact = Artifact::new(Rung::Raw, bytes, [0_u8; 32]);
    let output: Artifact = MOBILE_PASS.run(&input).expect("mobile pass runs");
    let json: serde_json::Value =
        serde_json::from_slice(&output.envelope).expect("mobile pass emits JSON");
    let functions = json
        .pointer("/flutter_aot_lift/functions")
        .and_then(serde_json::Value::as_array)
        .expect("envelope carries Flutter AOT functions");
    let structured: &str = functions
        .iter()
        .find(|function: &&serde_json::Value| {
            function.get("name").and_then(serde_json::Value::as_str) == Some("fibonacciStep")
        })
        .and_then(|function: &serde_json::Value| function.get("structured_body"))
        .and_then(serde_json::Value::as_str)
        .expect("envelope carries the structured body");
    assert_eq!(
        structured, expected,
        "the registered mobile pass must expose byte-identical pseudocode to the library API"
    );
    assert!(structured.contains("fibonacciStep(arg0 - 1);"));
}
