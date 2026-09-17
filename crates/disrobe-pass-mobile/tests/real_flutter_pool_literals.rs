#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::uninlined_format_args
)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use disrobe_pass_mobile::flutter::pool_table::pool_offset_of_slot;
use disrobe_pass_mobile::{
    AotLiftReport, DartGraphLimits, DartLiftedFunction, DartPoolLiteralKind, DartPoolRef,
    DartPoolTable, DartPoolUnresolvedReason, dart_isolate_data_bytes, dart_vm_data_bytes,
    lift_libapp_aot,
};

const COMMITTED_SAMPLES: [&str; 4] = [
    "disrobe_sample/libapp_arm64.so",
    "pinned_graph_fixture/receipt_validator_arm64.so",
    "pinned_graph_fixture/receipt_validator_obfuscated_arm64.so",
    "pinned_graph_fixture/voucher_validator_arm64.so",
];

const TRUNCATED_STRING: &str = "truncatedString(";

fn corpus() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
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

fn dart_source() -> String {
    String::from_utf8(read_sample("disrobe_sample/disrobe_aot_sample.dart"))
        .expect("the committed Dart source is UTF-8")
}

fn sample_report() -> AotLiftReport {
    lift_libapp_aot(&read_sample("disrobe_sample/libapp_arm64.so")).expect("lift the sample")
}

fn resolved_contents(report: &AotLiftReport) -> BTreeSet<String> {
    let mut found: BTreeSet<String> = BTreeSet::new();
    for function in &report.functions {
        for pool_ref in &function.pool_refs {
            if let Some(text) = pool_ref.resolved_content.as_deref() {
                found.insert(text.to_owned());
            }
        }
    }
    found
}

#[test]
fn source_declared_string_literals_resolve_from_the_object_pool() {
    let source: String = dart_source();
    let declared: [&str; 5] = [
        "widget-alpha",
        "gadget-bravo",
        "sprocket-charlie",
        "mid-market-tier",
        "starter-tier",
    ];
    for literal in &declared {
        assert!(
            source.contains(&format!("'{literal}'")),
            "the committed Dart source must declare '{literal}'; it is the reference this grade reads"
        );
    }
    for excluded in ["dart:io", "dart:math"] {
        assert!(
            source.contains(&format!("'{excluded}'")),
            "the excluded import URI '{excluded}' must still be declared by the source"
        );
    }

    let report: AotLiftReport = sample_report();
    let contents: BTreeSet<String> = resolved_contents(&report);
    let mut recovered: usize = 0;
    for literal in &declared {
        let quoted: String = format!("\"{literal}\"");
        if contents.contains(&quoted) {
            recovered += 1;
        } else {
            eprintln!("unrecovered source literal: {literal}");
        }
    }
    eprintln!(
        "source-declared runtime string literals recovered from the object pool: {recovered}/{}",
        declared.len()
    );
    assert_eq!(
        recovered,
        declared.len(),
        "every runtime string literal the Dart source declares must resolve from a pool reference"
    );
}

#[test]
fn an_import_uri_is_named_as_unrecoverable_rather_than_guessed() {
    let report: AotLiftReport = sample_report();
    let contents: BTreeSet<String> = resolved_contents(&report);
    for excluded in ["dart:io", "dart:math"] {
        assert!(
            !contents.contains(&format!("\"{excluded}\"")),
            "'{excluded}' is an import URI that the precompiler drops rather than materializing as a \
             runtime constant; if it now resolves, move it into the graded list instead of leaving it \
             recorded as unrecoverable"
        );
    }
}

#[test]
fn source_declared_double_literals_resolve_from_the_lift() {
    let source: String = dart_source();
    let declared: [(&str, &str); 4] = [
        ("19.95", "19.95"),
        ("149.50", "149.5"),
        ("2400.00", "2400.0"),
        ("4.25", "4.25"),
    ];
    for (written, _) in &declared {
        assert!(
            source.contains(written),
            "the committed Dart source must declare the double {written}"
        );
    }
    let report: AotLiftReport = sample_report();
    let bodies: String = report
        .functions
        .iter()
        .filter_map(|f: &DartLiftedFunction| f.structured_body.clone())
        .collect::<Vec<String>>()
        .join("\n");
    let mut recovered: usize = 0;
    for (written, rendered) in &declared {
        if bodies.contains(rendered) {
            recovered += 1;
        } else {
            eprintln!("unrecovered source double: {written}");
        }
    }
    eprintln!(
        "source-declared double literals recovered: {recovered}/{}",
        declared.len()
    );
    assert_eq!(
        recovered,
        declared.len(),
        "every double the Dart source declares must reach a recovered body"
    );
}

const TYPE_PARAMETER_PREFIX: &str = "typeParam@";

const RECORDED_RENDERED_VECTOR_FLOOR: usize = 180;

const RECORDED_NAMED_VECTOR_FLOOR: usize = 100;

fn pool_table_for(sample: &str) -> DartPoolTable {
    let bytes: Vec<u8> = read_sample(sample);
    let vm: Vec<u8> = dart_vm_data_bytes(&bytes).expect("vm snapshot data");
    let isolate: Vec<u8> = dart_isolate_data_bytes(&bytes).expect("isolate snapshot data");
    DartPoolTable::build(&vm, &isolate, DartGraphLimits::default())
        .expect("the pinned layout parses")
        .expect("the committed sample carries a pinned pool table")
}

fn top_level_elements(rendered: &str) -> Vec<String> {
    let inner: &str = rendered
        .strip_prefix('<')
        .and_then(|rest: &str| rest.strip_suffix('>'))
        .unwrap_or(rendered);
    let mut elements: Vec<String> = Vec::new();
    let mut depth: usize = 0;
    let mut current: String = String::new();
    for character in inner.chars() {
        match character {
            '<' => {
                depth += 1;
                current.push(character);
            }
            '>' => {
                depth = depth.saturating_sub(1);
                current.push(character);
            }
            ',' if depth == 0 => {
                elements.push(current.trim().to_owned());
                current.clear();
            }
            _ => current.push(character),
        }
    }
    if !current.trim().is_empty() {
        elements.push(current.trim().to_owned());
    }
    elements
}

#[test]
fn a_type_parameter_argument_renders_its_position_and_never_a_source_name() {
    let mut rendered_vectors: usize = 0;
    let mut naming_a_real_element: usize = 0;
    let mut positional: usize = 0;
    for sample in COMMITTED_SAMPLES {
        let table: DartPoolTable = pool_table_for(sample);
        for index in 0..table.slot_count() {
            let offset: u64 = pool_offset_of_slot(index as u64);
            if table.kind_at_offset(offset, false) != DartPoolLiteralKind::TypeArguments {
                continue;
            }
            let Some(text): Option<String> = table.render_slot(index, false) else {
                continue;
            };
            rendered_vectors += 1;
            let elements: Vec<String> = top_level_elements(&text);
            if elements
                .iter()
                .any(|element: &String| !element.starts_with(TYPE_PARAMETER_PREFIX))
            {
                naming_a_real_element += 1;
            }
            for (position, element) in elements.iter().enumerate() {
                let Some(declared): Option<&str> = element.strip_prefix(TYPE_PARAMETER_PREFIX)
                else {
                    continue;
                };
                positional += 1;
                assert_eq!(
                    declared.parse::<usize>().ok(),
                    Some(position),
                    "{sample} rendered {element} at vector position {position}; a type parameter \
                     surfaces by position because the product precompiler drops its name, so the \
                     two must agree in {text}"
                );
            }
        }
    }
    eprintln!(
        "type-argument vectors rendered across the committed corpus: {rendered_vectors}, of which \
         {naming_a_real_element} name a real element; {positional} type parameters rendered by position"
    );
    assert!(
        rendered_vectors >= RECORDED_RENDERED_VECTOR_FLOOR,
        "only {rendered_vectors} type-argument vectors render, below the recorded floor of \
         {RECORDED_RENDERED_VECTOR_FLOOR}"
    );
    assert!(
        naming_a_real_element >= RECORDED_NAMED_VECTOR_FLOOR,
        "only {naming_a_real_element} vectors name a real element, below the recorded floor of \
         {RECORDED_NAMED_VECTOR_FLOOR}; rendering every element as a positional placeholder would \
         satisfy the arity check while recovering no type"
    );
    assert!(
        positional > 0,
        "the corpus must contain uninstantiated type parameters for the positional rendering to be \
         exercised"
    );
}

const RECORDED_REFUSED_VECTOR_BASELINE: usize = 148;
const RECORDED_REFUSED_VECTOR_CEILING: usize = 13;
const RECORDED_NULLABLE_FUNCTION_TYPE_COUNT: usize = 128;

#[test]
fn committed_snapshot_function_type_renders_from_its_pinned_pool_metadata() {
    let table: DartPoolTable = pool_table_for("disrobe_sample/libapp_arm64.so");
    let slot: usize = 905;
    let offset: u64 = pool_offset_of_slot(slot as u64);

    assert_eq!(
        table.kind_at_offset(offset, false),
        DartPoolLiteralKind::TypeArguments
    );
    assert_eq!(
        table.render_slot(slot, false).as_deref(),
        Some("<void Function(IsolateSpawnException)>")
    );
}

#[test]
fn serialized_function_type_nullability_is_recovered_without_spreading_to_other_types() {
    let mut unexpected: Vec<String> = Vec::new();
    let mut carrying: usize = 0;
    let mut rendered: usize = 0;
    let mut refused: usize = 0;
    for sample in COMMITTED_SAMPLES {
        let table: DartPoolTable = pool_table_for(sample);
        for index in 0..table.slot_count() {
            let offset: u64 = pool_offset_of_slot(index as u64);
            let kind: DartPoolLiteralKind = table.kind_at_offset(offset, false);
            if !matches!(
                kind,
                DartPoolLiteralKind::Type | DartPoolLiteralKind::TypeArguments
            ) {
                continue;
            }
            let Some(text): Option<String> = table.render_slot(index, false) else {
                refused += 1;
                continue;
            };
            rendered += 1;
            let carries: bool = text.ends_with('?')
                || text.ends_with('*')
                || text.contains("?>")
                || text.contains("*>")
                || text.contains("?,")
                || text.contains("*,");
            if carries {
                carrying += 1;
                if !text.contains("Function(") && unexpected.len() < 8 {
                    unexpected.push(format!("{sample}: {text}"));
                }
            }
        }
    }
    eprintln!(
        "recovered type renderings: {rendered}, refused: {refused}, nullable function types: {carrying}"
    );
    assert!(
        unexpected.is_empty(),
        "a nullability suffix escaped the FunctionType decoder: {unexpected:?}"
    );
    assert_eq!(
        carrying, RECORDED_NULLABLE_FUNCTION_TYPE_COUNT,
        "the committed Dart 3.12.2 snapshots contain \
         {RECORDED_NULLABLE_FUNCTION_TYPE_COUNT} nullable FunctionType renderings"
    );
    assert!(
        rendered > 0,
        "the corpus must recover types for this check to mean anything"
    );
}

#[test]
fn an_unreadable_type_flag_word_no_longer_discards_a_resolved_class_name() {
    let mut refused: usize = 0;
    let mut vectors: usize = 0;
    let mut reasons: BTreeMap<DartPoolUnresolvedReason, usize> = BTreeMap::new();
    for sample in COMMITTED_SAMPLES {
        let table: DartPoolTable = pool_table_for(sample);
        let mut sample_refused: usize = 0;
        for index in 0..table.slot_count() {
            let offset: u64 = pool_offset_of_slot(index as u64);
            if table.kind_at_offset(offset, false) != DartPoolLiteralKind::TypeArguments {
                continue;
            }
            vectors += 1;
            if table.render_slot(index, false).is_none() {
                sample_refused += 1;
                let reason: DartPoolUnresolvedReason = table
                    .unresolved_reason_at_offset(offset, false)
                    .expect("a refused type-argument slot must carry its reason");
                *reasons.entry(reason).or_insert(0) += 1;
            }
        }
        eprintln!("{sample}: {sample_refused} type-argument vectors still refuse");
        refused += sample_refused;
    }
    eprintln!(
        "type-argument vectors across the committed corpus: {vectors}, baseline refusing: \
         {RECORDED_REFUSED_VECTOR_BASELINE}, refusing now: {refused}, by reason: {reasons:?}"
    );
    assert!(
        refused < RECORDED_REFUSED_VECTOR_BASELINE,
        "{refused} type-argument vectors refuse, so the recorded baseline of \
         {RECORDED_REFUSED_VECTOR_BASELINE} did not improve"
    );
    assert!(
        refused <= RECORDED_REFUSED_VECTOR_CEILING,
        "{refused} type-argument vectors refuse, above the recorded ceiling of \
         {RECORDED_REFUSED_VECTOR_CEILING}; an unreadable flag word must not discard a class name \
         the walk already resolved"
    );
    assert!(
        refused > 0,
        "some vectors must still refuse, or the soundness refusals have been removed rather than \
         the flag refusal"
    );
}

const UNNAMED_CLASS_PREFIX: &str = "cid@";

#[test]
fn a_class_whose_metadata_the_precompiler_dropped_surfaces_by_class_id() {
    let mut unnamed: usize = 0;
    let mut examples: Vec<String> = Vec::new();
    for sample in COMMITTED_SAMPLES {
        let table: DartPoolTable = pool_table_for(sample);
        for index in 0..table.slot_count() {
            let offset: u64 = pool_offset_of_slot(index as u64);
            if !matches!(
                table.kind_at_offset(offset, false),
                DartPoolLiteralKind::Type | DartPoolLiteralKind::TypeArguments
            ) {
                continue;
            }
            let Some(text): Option<String> = table.render_slot(index, false) else {
                continue;
            };
            for at in text.match_indices(UNNAMED_CLASS_PREFIX).map(|(at, _)| at) {
                let digits: String = text[at + UNNAMED_CLASS_PREFIX.len()..]
                    .chars()
                    .take_while(char::is_ascii_digit)
                    .collect::<String>();
                assert!(
                    !digits.is_empty(),
                    "{sample} rendered an unnamed class without its class id in {text}"
                );
                unnamed += 1;
                if examples.len() < 4 {
                    examples.push(format!("{sample}: {text}"));
                }
            }
        }
    }
    eprintln!("classes surfacing by class id because their metadata was dropped: {unnamed}");
    eprintln!("examples: {examples:?}");
    assert!(
        unnamed > 0,
        "the committed corpus carries types whose class metadata the precompiler dropped; if none \
         surfaces by class id the recovery has either started inventing names or gone back to \
         refusing the type"
    );
}

#[test]
fn the_soundness_refusals_still_fire_on_the_committed_corpus() {
    let mut refused: usize = 0;
    for sample in COMMITTED_SAMPLES {
        let table: DartPoolTable = pool_table_for(sample);
        let mut sample_refused: usize = 0;
        for index in 0..table.slot_count() {
            let offset: u64 = pool_offset_of_slot(index as u64);
            if table.kind_at_offset(offset, false) != DartPoolLiteralKind::TypeArguments {
                continue;
            }
            if table.render_slot(index, false).is_none() {
                sample_refused += 1;
            }
        }
        eprintln!("{sample}: {sample_refused} type-argument vectors still refuse");
        assert!(
            sample_refused > 0,
            "{sample} refuses no type-argument vector at all; a vector whose element is not a type, \
             and a cycle or budget exhaustion, must still refuse rather than render"
        );
        refused += sample_refused;
    }
    eprintln!("type-argument vectors still refusing across the committed corpus: {refused}");
    assert!(
        refused <= RECORDED_REFUSED_VECTOR_CEILING,
        "{refused} type-argument vectors refuse, above the recorded ceiling of \
         {RECORDED_REFUSED_VECTOR_CEILING}"
    );
}

#[test]
fn a_pool_slot_resolves_to_one_value_or_to_none_but_never_to_two() {
    for sample in COMMITTED_SAMPLES {
        let report: AotLiftReport =
            lift_libapp_aot(&read_sample(sample)).expect("lift committed Dart sample");
        let mut by_slot: BTreeMap<u64, BTreeSet<String>> = BTreeMap::new();
        for function in &report.functions {
            for pool_ref in &function.pool_refs {
                if let Some(text) = pool_ref.resolved_content.as_deref() {
                    by_slot
                        .entry(pool_ref.slot_index)
                        .or_default()
                        .insert(text.to_owned());
                }
            }
        }
        for (slot, values) in &by_slot {
            assert_eq!(
                values.len(),
                1,
                "{sample} resolved pool slot {slot} to more than one value, so at least one is \
                 reconstructed rather than read: {values:?}"
            );
        }
        eprintln!("{sample}: {} pool slots resolve to content", by_slot.len());
    }
}

#[test]
fn a_slot_rendered_as_a_placeholder_is_never_resolved_elsewhere() {
    for sample in COMMITTED_SAMPLES {
        let report: AotLiftReport =
            lift_libapp_aot(&read_sample(sample)).expect("lift committed Dart sample");
        let mut resolved_slots: BTreeSet<u64> = BTreeSet::new();
        for function in &report.functions {
            for pool_ref in &function.pool_refs {
                if pool_ref.resolved_content.is_some() {
                    resolved_slots.insert(pool_ref.slot_index);
                }
            }
        }
        let mut placeholder_slots: BTreeSet<u64> = BTreeSet::new();
        for function in &report.functions {
            let Some(body): Option<&str> = function.structured_body.as_deref() else {
                continue;
            };
            for at in body.match_indices("pool[").map(|(at, _)| at) {
                let digits: String = body[at + 5..]
                    .chars()
                    .take_while(char::is_ascii_digit)
                    .collect::<String>();
                if let Ok(slot) = digits.parse::<u64>() {
                    placeholder_slots.insert(slot);
                }
            }
        }
        let both: Vec<u64> = placeholder_slots
            .intersection(&resolved_slots)
            .copied()
            .collect::<Vec<u64>>();
        assert!(
            both.is_empty(),
            "{sample} rendered slots {both:?} as an unresolved pool placeholder in one place while \
             claiming resolved content for the same slot elsewhere; a slot must be readable or \
             refused, never both"
        );
        eprintln!(
            "{sample}: {} slots refused as placeholders, {} resolved, 0 overlapping",
            placeholder_slots.len(),
            resolved_slots.len()
        );
    }
}

#[test]
fn a_truncated_pool_string_is_never_rendered_as_a_complete_literal() {
    let mut truncated: usize = 0;
    for sample in COMMITTED_SAMPLES {
        let report: AotLiftReport =
            lift_libapp_aot(&read_sample(sample)).expect("lift committed Dart sample");
        for text in resolved_contents(&report) {
            if !text.starts_with(TRUNCATED_STRING) {
                continue;
            }
            truncated += 1;
            let count: &str = text
                .rsplit(',')
                .next()
                .unwrap_or("")
                .trim_end_matches(')')
                .trim();
            let declared: u64 = count.parse::<u64>().unwrap_or_else(|_| {
                panic!("a truncated pool string must carry its character count, got {text}")
            });
            assert!(
                declared > 0,
                "a truncated pool string must declare the length it was cut from, got {text}"
            );
        }
        let refs: usize = report
            .functions
            .iter()
            .map(|f: &DartLiftedFunction| f.pool_refs.len())
            .sum::<usize>();
        let resolved: usize = report
            .functions
            .iter()
            .flat_map(|f: &DartLiftedFunction| f.pool_refs.iter())
            .filter(|r: &&DartPoolRef| r.resolved_content.is_some())
            .count();
        eprintln!("{sample}: pool references resolved {resolved}/{refs}");
        assert!(
            resolved > 0,
            "{sample} must expose resolved pool content on the artifact envelope, not only inside \
             the rendered pseudocode"
        );
    }
    eprintln!("truncated pool strings across the committed corpus: {truncated}");
}
