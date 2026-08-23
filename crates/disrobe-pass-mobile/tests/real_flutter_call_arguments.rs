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
    DartPoolLiteralKind, DartPoolTable, DartPoolTableStats, DartPoolUnresolvedReason,
    DartPoolUnresolvedSlots, dart_isolate_data_bytes, dart_vm_data_bytes, lift_libapp_aot,
    parse_dart_kernel,
};
use sha2::{Digest as _, Sha256};

const RECORDED_OPAQUE_BASELINE: usize = 25_833;

const RECORDED_RESOLVED_POOL_SLOTS: usize = 2_501;

const EXPECTED_UNRESOLVED_REASONS: [&str; 4] = [
    "ClusterBodyUnmodelled",
    "DepthExceeded",
    "TypeArgumentsMalformed",
    "TypeParameter",
];

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

#[test]
fn disrobe_sample_checksum_manifest_matches_every_tracked_fixture() {
    let root: PathBuf = corpus().join("disrobe_sample");
    let manifest: String = std::fs::read_to_string(root.join("SHA256SUMS"))
        .expect("Flutter checksum manifest must be committed");
    let mut names: BTreeSet<String> = BTreeSet::new();
    let mut checked: usize = 0;
    for line in manifest.lines() {
        let (expected, name): (&str, &str) = line
            .split_once(" *")
            .expect("each checksum line must use sha256sum binary syntax");
        assert_eq!(expected.len(), 64, "{name} must have one SHA-256 digest");
        assert!(
            names.insert(name.to_owned()),
            "{name} must appear exactly once"
        );
        let bytes: Vec<u8> = std::fs::read(root.join(name))
            .unwrap_or_else(|error| panic!("{name} must be committed: {error}"));
        assert_eq!(format!("{:x}", Sha256::digest(bytes)), expected, "{name}");
        checked += 1;
    }
    assert_eq!(checked, 4, "the checksum manifest must cover every fixture");
    let files: BTreeSet<String> = std::fs::read_dir(&root)
        .expect("Flutter fixture directory must be committed")
        .map(|entry: std::io::Result<std::fs::DirEntry>| {
            entry
                .expect("Flutter fixture directory entry must be readable")
                .file_name()
                .into_string()
                .expect("Flutter fixture names must be Unicode")
        })
        .filter(|name: &String| name != "SHA256SUMS")
        .collect();
    assert_eq!(
        names, files,
        "the checksum manifest must cover every fixture"
    );
}

fn primary_report() -> AotLiftReport {
    lift_libapp_aot(&read_sample("disrobe_sample/libapp_arm64.so")).expect("lift ARM64 AOT")
}

fn pool(relative: &str) -> DartPoolTable {
    let bytes: Vec<u8> = read_sample(relative);
    let vm: Vec<u8> = dart_vm_data_bytes(&bytes).expect("vm snapshot data");
    let isolate: Vec<u8> = dart_isolate_data_bytes(&bytes).expect("isolate snapshot data");
    DartPoolTable::build(&vm, &isolate, DartGraphLimits::default())
        .expect("the pinned object pool must deserialize")
        .expect("the pinned Dart 3.12.2 layout must match this sample")
}

fn primary_pool() -> DartPoolTable {
    pool("disrobe_sample/libapp_arm64.so")
}

fn body(report: &AotLiftReport, name: &str) -> String {
    report
        .functions
        .iter()
        .find(|f: &&DartLiftedFunction| f.name.as_deref() == Some(name) && f.is_structured())
        .unwrap_or_else(|| panic!("{name} must lift to structured pseudocode"))
        .best_pseudo_dart()
}

#[cfg(feature = "chain")]
fn mobile_pass_body(bytes: Vec<u8>, name: &str) -> String {
    use disrobe_core::chain::Pass as _;
    use disrobe_core::{Artifact, Rung};
    use disrobe_pass_mobile::chain_detector::MOBILE_PASS;

    let input: Artifact = Artifact::new(Rung::Raw, bytes, [0_u8; 32]);
    let output: Artifact = MOBILE_PASS.run(&input).expect("mobile pass runs");
    let json: serde_json::Value =
        serde_json::from_slice(&output.envelope).expect("mobile pass emits JSON");
    json.pointer("/flutter_aot_lift/functions")
        .and_then(serde_json::Value::as_array)
        .expect("envelope carries Flutter AOT functions")
        .iter()
        .find(|function: &&serde_json::Value| {
            function.get("name").and_then(serde_json::Value::as_str) == Some(name)
        })
        .and_then(|function: &serde_json::Value| function.get("structured_body"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or_else(|| panic!("envelope carries the structured {name} body"))
        .to_owned()
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

    for observed in [
        "Str",
        "Double",
        "Integer",
        "List",
        "Named",
        "Type",
        "TypeArguments",
        "RawImmediate",
        "NativeFunction",
        "StubEntry",
    ] {
        assert!(
            tally.get(observed).copied().unwrap_or(0) > 0,
            "the pinned pool must carry at least one {observed} slot, got {tally:?}"
        );
    }
    eprintln!(
        "pool literal kinds NOT observed in this sample and therefore not claimed here: null, true, false and Smi never reach a pool slot in this build (null and the booleans arrive through the null register and its +0x20/+0x30 offsets, Smis are inline immediates); this sample declares no Symbol, which is graded instead on the fixture that carries one"
    );

    let unresolved: usize = tally.get("Unresolved").copied().unwrap_or(0);
    assert!(
        unresolved < table.slot_count(),
        "an all-unresolved pool would mean the cluster walk failed"
    );
}

#[test]
fn type_pool_entries_follow_the_pinned_dart_object_layout() {
    let first: DartPoolTable = pool("pinned_graph_fixture/receipt_validator_arm64.so");
    let second: DartPoolTable = pool("pinned_graph_fixture/receipt_validator_arm64.so");
    let cases: [(u64, DartPoolLiteralKind, &str); 2] = [
        (0x1630, DartPoolLiteralKind::Type, "InstructionsTable"),
        (0x13a8, DartPoolLiteralKind::TypeArguments, "<Error>"),
    ];
    for (offset, kind, expected) in cases {
        assert_eq!(first.kind_at_offset(offset, false), kind);
        assert_eq!(
            first.render_at_offset(offset, false).as_deref(),
            Some(expected)
        );
        assert_eq!(
            second.render_at_offset(offset, false),
            first.render_at_offset(offset, false),
            "the same pinned snapshot must render type metadata identically"
        );
    }
    let report: AotLiftReport = lift_libapp_aot(&read_sample(
        "pinned_graph_fixture/receipt_validator_arm64.so",
    ))
    .expect("lift pinned receipt validator");
    let rendered: Vec<String> = report
        .functions
        .iter()
        .map(DartLiftedFunction::best_pseudo_dart)
        .filter(|body: &String| body.contains("sub_0x1737c0(<Error>, ?);"))
        .collect();
    assert!(
        !rendered.is_empty(),
        "the real public lift must inline the recovered type arguments at their call site"
    );
    assert!(
        rendered
            .iter()
            .all(|body: &String| !body.contains("pool[627]")),
        "a resolved TypeArguments slot must not remain an opaque pool reference"
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
        dart.contains("Iterable.where(arg0.field@0x7, v0)"),
        "the where() call must retain the field receiver across compressed-pointer decompression and thread the previous call result, got:\n{dart}"
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

    for expected in ["_Random.nextInt(v0, 3)", "double.toStringAsFixed(?, 2)"] {
        assert!(
            dart.contains(expected),
            "main must render {expected}, got:\n{dart}"
        );
    }
    let seed: &str = dart
        .lines()
        .map(str::trim)
        .find_map(|line: &str| {
            line.strip_prefix("var ")?
                .strip_suffix(" = _Random.nextInt(v0, 3);")
        })
        .unwrap_or_else(|| panic!("the nextInt result must bind, got:\n{dart}"));
    assert!(
        dart.contains(&format!("fibonacciStep({seed} + 12)")),
        "main must add 12 to the bound nextInt result at the fibonacciStep call, got:\n{dart}"
    );
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
    let bytes: Vec<u8> = read_sample("disrobe_sample/libapp_arm64.so");
    let report: AotLiftReport = lift_libapp_aot(&bytes).expect("library lift");
    let expected: String = body(&report, "fibonacciStep");
    let structured: String = mobile_pass_body(bytes, "fibonacciStep");
    assert_eq!(
        structured, expected,
        "the registered mobile pass must expose byte-identical pseudocode to the library API"
    );
    assert!(structured.contains("fibonacciStep(arg0 - 1);"));
}

#[cfg(feature = "chain")]
#[test]
fn compressed_pointer_receiver_survives_the_registered_mobile_pass() {
    let bytes: Vec<u8> = read_sample("disrobe_sample/libapp_arm64.so");
    let source: String = dill_source();
    assert!(source.contains("trackedItems.where("));

    let structured: String = mobile_pass_body(bytes.clone(), "WarehouseLedger.countBackordered");
    assert!(
        structured.contains("Iterable.where(arg0.field@0x7, v0)"),
        "the compiler's X28 heap-base decompression must preserve the tracked receiver, got:\n{structured}"
    );

    let encoded: Vec<u8> = [
        0xb840_7020_u32,
        0x8b1c_8000,
        0xf81f_83a0,
        0xf96c_3f61,
        0xaa16_03e2,
    ]
    .into_iter()
    .flat_map(u32::to_le_bytes)
    .collect::<Vec<u8>>();
    let positions: Vec<usize> = bytes
        .windows(encoded.len())
        .enumerate()
        .filter_map(|(offset, window): (usize, &[u8])| {
            (window == encoded.as_slice()).then_some(offset)
        })
        .collect::<Vec<usize>>();
    assert_eq!(positions.len(), 1);
    let mut mutated: Vec<u8> = bytes;
    let replacement: [u8; 4] = 0x8b1b_8000_u32.to_le_bytes();
    let add_offset: usize = positions[0] + 4;
    mutated[add_offset..add_offset + replacement.len()].copy_from_slice(&replacement);

    let rejected: String = mobile_pass_body(mutated, "WarehouseLedger.countBackordered");
    assert!(rejected.contains("Iterable.where(?, v0)"));
    assert!(!rejected.contains("Iterable.where(arg0.field@0x7, v0)"));
}

const fn slot_offset(slot: usize) -> u64 {
    DART_POOL_ELEMENT_BASE_BYTES + (slot as u64) * 8
}

#[test]
fn load_reset_pool_slots_render_the_value_the_snapshot_deserializer_assigns_them() {
    let table: DartPoolTable = primary_pool();
    let mut stub_slots: BTreeMap<String, usize> = BTreeMap::new();
    let mut stub_kind_slots: usize = 0;
    let mut native_function_slots: usize = 0;
    let mut stub_rendered_outside_a_reset_slot: Vec<usize> = Vec::new();

    for slot in 0..table.slot_count() {
        let kind: DartPoolLiteralKind = table.kind_at_offset(slot_offset(slot), false);
        let rendered: Option<String> = table.render_slot(slot, false);
        let is_stub_token: bool = rendered
            .as_deref()
            .is_some_and(|text: &str| text.starts_with("stub@"));
        match kind {
            DartPoolLiteralKind::StubEntry => {
                stub_kind_slots += 1;
                let text: String = rendered
                    .clone()
                    .expect("a stub-entry slot must render the stub the deserializer installs");
                *stub_slots.entry(text).or_default() += 1;
            }
            DartPoolLiteralKind::NativeFunction => {
                native_function_slots += 1;
                assert_eq!(
                    rendered.as_deref(),
                    Some("stub@linkNativeCall"),
                    "ObjectPoolDeserializationCluster::ReadFill initializes a kNativeFunction entry with NativeEntry::LinkNativeCallEntry()"
                );
            }
            _ => {
                if is_stub_token {
                    stub_rendered_outside_a_reset_slot.push(slot);
                }
            }
        }
    }

    eprintln!(
        "load-reset pool slots on the real sample: stub_entry_slots={stub_kind_slots} native_function_slots={native_function_slots} rendered={stub_slots:?}"
    );
    assert!(
        stub_rendered_outside_a_reset_slot.is_empty(),
        "a stub token may only come from a slot the snapshot marks reset-at-load, got slots {stub_rendered_outside_a_reset_slot:?}"
    );
    assert!(
        stub_kind_slots > 0,
        "the real sample must carry at least one reset-at-load stub slot"
    );
    for token in stub_slots.keys() {
        assert!(
            token == "stub@callBootstrapNative" || token == "stub@switchableCallMiss",
            "SnapshotBehavior carries exactly two reset-to-stub values, got {token}"
        );
    }
}

#[test]
fn set_to_zero_pool_slots_carry_the_zero_the_deserializer_writes() {
    let mut per_sample: Vec<(String, usize)> = Vec::new();
    for sample in COMMITTED_SAMPLES {
        let table: DartPoolTable = pool(sample);
        let mut reset_zero_slots: usize = 0;
        for slot in 0..table.slot_count() {
            if table.kind_at_offset(slot_offset(slot), false) != DartPoolLiteralKind::LoadResetZero
            {
                continue;
            }
            reset_zero_slots += 1;
            assert_eq!(
                table.render_slot(slot, false).as_deref(),
                Some("0"),
                "ReadFill writes raw_value_ = 0 for a kSetToZero entry and PostLoad leaves it alone"
            );
            assert_eq!(
                table.render_slot(slot, true).as_deref(),
                Some("0.0"),
                "the same raw zero read through a floating-point load form is the double zero"
            );
        }
        per_sample.push((sample.to_owned(), reset_zero_slots));
    }
    eprintln!("kSetToZero pool slots per committed real Dart sample: {per_sample:?}");
    assert!(
        per_sample
            .iter()
            .any(|(_, slots): &(String, usize)| *slots > 0),
        "at least one committed sample must carry a kSetToZero entry for this rendering to be claimed against real Dart bytes, got {per_sample:?}"
    );
}

#[test]
fn every_pool_slot_either_renders_or_names_why_it_did_not() {
    let mut totals: BTreeMap<String, usize> = BTreeMap::new();
    let mut unresolved_total: usize = 0;
    let mut resolved_total: usize = 0;

    for sample in COMMITTED_SAMPLES {
        let report: AotLiftReport =
            lift_libapp_aot(&read_sample(sample)).expect("lift committed Dart sample");
        let stats: DartPoolTableStats = report
            .pool_slots
            .expect("every committed sample must carry object-pool slot statistics");
        let unresolved: usize = report
            .pool_unresolved
            .iter()
            .map(|entry: &DartPoolUnresolvedSlots| entry.slots)
            .sum::<usize>();
        eprintln!(
            "{sample}: slots={} resolved={} unresolved={unresolved} by reason={:?}",
            stats.slots, stats.literals, report.pool_unresolved
        );
        assert_eq!(
            stats.literals + unresolved,
            stats.slots,
            "{sample}: a slot must either render a value or name one reason it did not, never neither and never both"
        );
        for entry in &report.pool_unresolved {
            assert!(
                entry.slots > 0,
                "{sample}: a named reason with no slots behind it must not be reported"
            );
            *totals.entry(format!("{:?}", entry.reason)).or_default() += entry.slots;
        }
        unresolved_total += unresolved;
        resolved_total += stats.literals;
    }

    eprintln!(
        "unresolved object-pool slots across the committed real Dart samples: {unresolved_total} unresolved against {resolved_total} resolved, by reason {totals:?}"
    );
    assert_eq!(
        totals.keys().cloned().collect::<BTreeSet<String>>(),
        EXPECTED_UNRESOLVED_REASONS
            .into_iter()
            .map(str::to_owned)
            .collect::<BTreeSet<String>>(),
        "the reasons a real Dart pool slot stays unresolved are pinned by name, so a new reason or a vanished one is attributable rather than a shift in one total"
    );
}

#[test]
fn resolved_pool_slots_rise_above_the_recorded_baseline() {
    let report: AotLiftReport = primary_report();
    let stats: DartPoolTableStats = report
        .pool_slots
        .expect("the pinned sample must carry object-pool slot statistics");
    eprintln!(
        "resolved object-pool slots on the primary sample: baseline {RECORDED_RESOLVED_POOL_SLOTS} -> {} of {}",
        stats.literals, stats.slots
    );
    assert!(
        stats.literals > RECORDED_RESOLVED_POOL_SLOTS,
        "reading the snapshot behavior of every pool entry must resolve more slots than the recorded baseline of {RECORDED_RESOLVED_POOL_SLOTS}, got {}",
        stats.literals
    );
}

#[test]
fn a_call_site_load_disrobe_cannot_tie_to_a_pool_value_names_its_reason() {
    let report: AotLiftReport = primary_report();
    let table: DartPoolTable = primary_pool();
    let mut unresolved_loads: usize = 0;
    let mut resolved_loads: usize = 0;
    let mut named_reasons: BTreeMap<String, usize> = BTreeMap::new();

    for function in &report.functions {
        if !function.is_structured() {
            continue;
        }
        let dart: String = function
            .best_pseudo_dart()
            .replace("selector@pool[", "selector@dispatch[");
        for reference in &function.pool_refs {
            let Ok(slot): Result<usize, _> = usize::try_from(reference.slot_index) else {
                continue;
            };
            let reason: Option<DartPoolUnresolvedReason> =
                table.unresolved_reason_at_offset(slot_offset(slot), false);
            match (&reference.resolved_content, reason) {
                (Some(_), Some(named)) => panic!(
                    "slot {slot} reports the value {:?} and the refusal {named:?} at the same time",
                    reference.resolved_content
                ),
                (None, None) => panic!(
                    "slot {slot} resolves to no value and names no reason, which is the silent case this gate exists to forbid"
                ),
                (Some(_), None) => {
                    resolved_loads += 1;
                    assert!(
                        !dart.contains(&format!("pool[{slot}]")),
                        "slot {slot} resolves, so no body may still render it as the unresolved placeholder"
                    );
                }
                (None, Some(named)) => {
                    unresolved_loads += 1;
                    *named_reasons.entry(format!("{named:?}")).or_default() += 1;
                    assert_eq!(
                        table.render_slot(slot, false),
                        None,
                        "slot {slot} names the reason {named:?} and must therefore render no value at all"
                    );
                }
            }
        }
    }

    eprintln!(
        "call-site pool loads on the real sample: {resolved_loads} carry a value, {unresolved_loads} name a reason instead, reasons {named_reasons:?}"
    );
    assert!(
        resolved_loads > 0,
        "the real sample must resolve at least one call-site pool load"
    );
    assert!(
        unresolved_loads > 0,
        "the real sample must exercise at least one call-site pool load that stays unresolved"
    );
}
