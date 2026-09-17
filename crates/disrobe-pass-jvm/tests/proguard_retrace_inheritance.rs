#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::case_sensitive_file_extension_comparisons
)]

use disrobe_pass_jvm::{
    AppliedNames, ClassFile, ClassHierarchy, InheritedField, InheritedMethod, JarExtract,
    ProguardMapping, RetracedFrame, apply_proguard_mapping_with_hierarchy, extract_jar,
    parse_classfile, parse_proguard_mapping,
};

const EDGECASES_PG_JAR: &[u8] = include_bytes!("../../../corpus/jvm/proguard/EdgeCases-pg.jar");
const EDGECASES_PG_MAPPING: &str =
    include_str!("../../../corpus/jvm/proguard/EdgeCases-mapping.txt");
const HELLO_R8_MAPPING: &str = include_str!("../../../corpus/jvm/r8/mapping.txt");

fn edgecases_mapping() -> ProguardMapping {
    parse_proguard_mapping(EDGECASES_PG_MAPPING).expect("parse edgecases mapping")
}

#[test]
fn retrace_maps_obfuscated_line_to_original_source_line_on_real_r8_output() {
    let mapping: ProguardMapping = parse_proguard_mapping(HELLO_R8_MAPPING).expect("r8 mapping");
    let frames: Vec<RetracedFrame> = mapping.retrace("Hello", "main", 1);
    assert_eq!(frames.len(), 1, "obf line 1 is a single non-inlined frame");
    let frame: &RetracedFrame = &frames[0];
    assert_eq!(frame.class_name, "Hello");
    assert_eq!(frame.method_name, "main");
    assert_eq!(
        frame.original_line,
        Some(24),
        "obf line 1 of main maps to original source line 24"
    );
}

#[test]
fn retrace_recovers_inlined_callee_chain_on_real_r8_output() {
    let mapping: ProguardMapping = parse_proguard_mapping(HELLO_R8_MAPPING).expect("r8 mapping");
    let frames: Vec<RetracedFrame> = mapping.retrace("Hello", "main", 2);
    assert_eq!(
        frames.len(),
        2,
        "obf line 2 of main holds an inlined bumpCounter frame plus the outer main, got {frames:?}"
    );
    assert_eq!(frames[0].method_name, "bumpCounter");
    assert_eq!(frames[0].class_name, "Hello");
    assert_eq!(frames[0].original_line, Some(12));
    assert_eq!(frames[1].method_name, "main");
    assert_eq!(frames[1].original_line, Some(25));
}

#[test]
fn retrace_recovers_cross_class_inline_from_real_proguard_inline_frames() {
    let mapping: ProguardMapping = edgecases_mapping();
    let frames: Vec<RetracedFrame> = mapping.retrace("EdgeCases", "a", 3783);
    assert_eq!(
        frames.len(),
        2,
        "obf line 3783 of a is an inlined Pair.first call inside unpackPair, got {frames:?}"
    );
    assert_eq!(frames[0].class_name, "EdgeCases$Pair");
    assert_eq!(frames[0].method_name, "first");
    assert_eq!(frames[0].original_line, Some(783));
    assert_eq!(frames[1].class_name, "EdgeCases");
    assert_eq!(frames[1].method_name, "unpackPair");
    assert_eq!(frames[1].original_line, Some(783));
}

#[test]
fn retrace_recovers_circle_radius_inlined_into_main() {
    let mapping: ProguardMapping = edgecases_mapping();
    let frames: Vec<RetracedFrame> = mapping.retrace("EdgeCases", "main", 9099);
    assert_eq!(frames.len(), 2, "got {frames:?}");
    assert_eq!(frames[0].class_name, "EdgeCases$Circle");
    assert_eq!(frames[0].method_name, "radius");
    assert_eq!(frames[0].original_line, Some(99));
    assert_eq!(frames[1].class_name, "EdgeCases");
    assert_eq!(frames[1].method_name, "main");
    assert_eq!(frames[1].original_line, Some(99));
}

#[test]
fn retrace_of_unknown_line_returns_empty() {
    let mapping: ProguardMapping = edgecases_mapping();
    assert!(mapping.retrace("EdgeCases", "a", 999_999).is_empty());
    assert!(mapping.retrace("NoSuchClass", "a", 1).is_empty());
    assert!(mapping.retrace("EdgeCases", "noSuchMethod", 1).is_empty());
}

#[test]
fn inline_frames_never_pollute_the_overload_table() {
    let mapping: ProguardMapping = edgecases_mapping();
    let edge: &disrobe_pass_jvm::ClassMapping = mapping
        .lookup_obfuscated_class("EdgeCases")
        .expect("EdgeCases");
    let a_overloads: &Vec<disrobe_pass_jvm::MethodMapping> =
        edge.methods.get("a").expect("obf method a");
    for m in a_overloads {
        assert!(
            !m.original_name.contains('.'),
            "qualified inline frame {} leaked into the overload table",
            m.original_name
        );
    }
    let names: std::collections::BTreeSet<&str> = a_overloads
        .iter()
        .map(|m| m.original_name.as_str())
        .collect();
    assert!(
        !names.contains("first") && !names.contains("second"),
        "Pair accessors inlined into unpackPair must not appear as overloads of obf a: {names:?}"
    );
    assert!(
        names.contains("unpackPair"),
        "the physical unpackPair method must remain in the overload table"
    );
}

fn build_hierarchy(jar: &[u8]) -> (ClassHierarchy, JarExtract) {
    let jx: JarExtract = extract_jar(jar).expect("extract jar");
    let mut hierarchy: ClassHierarchy = ClassHierarchy::new();
    for (name, bytes) in &jx.classes {
        if !name.ends_with(".class") {
            continue;
        }
        if let Ok(cf) = parse_classfile(bytes) {
            hierarchy.record_classfile(&cf);
        }
    }
    (hierarchy, jx)
}

#[test]
fn class_hierarchy_records_real_subclass_super_edge() {
    let (hierarchy, _jx): (ClassHierarchy, JarExtract) = build_hierarchy(EDGECASES_PG_JAR);
    assert_eq!(
        hierarchy.super_of("EdgeCases$d"),
        Some("EdgeCases$a"),
        "CounterWorker (d) must record AbstractWorker (a) as its super"
    );
}

#[test]
fn inherited_method_resolves_up_the_real_class_hierarchy() {
    let mapping: ProguardMapping = edgecases_mapping();
    let (hierarchy, _jx): (ClassHierarchy, JarExtract) = build_hierarchy(EDGECASES_PG_JAR);

    let resolved: InheritedMethod = mapping
        .resolve_method_with_inheritance(&hierarchy, "EdgeCases$d", "run", Some("()V"))
        .expect("run() must resolve through CounterWorker -> AbstractWorker");
    assert_eq!(
        resolved.original_name, "run",
        "the inherited run is named run in the original source"
    );
    assert_eq!(
        resolved.declaring_class, "EdgeCases$AbstractWorker",
        "run is physically declared on AbstractWorker, not CounterWorker"
    );
    assert!(
        resolved.inherited,
        "run is inherited by CounterWorker, not declared locally"
    );
}

#[test]
fn locally_declared_method_is_not_marked_inherited() {
    let mapping: ProguardMapping = edgecases_mapping();
    let (hierarchy, _jx): (ClassHierarchy, JarExtract) = build_hierarchy(EDGECASES_PG_JAR);
    let resolved: InheritedMethod = mapping
        .resolve_method_with_inheritance(
            &hierarchy,
            "EdgeCases$d",
            "a",
            Some("()Ljava/lang/Integer;"),
        )
        .expect("CounterWorker.call (obf a) resolves locally");
    assert_eq!(resolved.original_name, "call");
    assert_eq!(resolved.declaring_class, "EdgeCases$CounterWorker");
    assert!(
        !resolved.inherited,
        "call is declared on CounterWorker itself"
    );
}

#[test]
fn inherited_field_resolves_up_the_real_class_hierarchy() {
    let mapping: ProguardMapping = edgecases_mapping();
    let (hierarchy, _jx): (ClassHierarchy, JarExtract) = build_hierarchy(EDGECASES_PG_JAR);
    let resolved: InheritedField = mapping
        .resolve_field_with_inheritance(&hierarchy, "EdgeCases$d", "a", Some("Ljava/lang/String;"))
        .expect("the String field a inherited from AbstractWorker resolves");
    assert_eq!(resolved.original_name, "name");
    assert_eq!(resolved.declaring_class, "EdgeCases$AbstractWorker");
    assert!(resolved.inherited);
}

#[test]
fn apply_with_hierarchy_restores_more_than_without_on_real_jar() {
    let mapping: ProguardMapping = edgecases_mapping();
    let (hierarchy, jx): (ClassHierarchy, JarExtract) = build_hierarchy(EDGECASES_PG_JAR);
    let worker: &Vec<u8> = jx
        .classes
        .get("EdgeCases$d.class")
        .expect("CounterWorker class present");
    let cf: ClassFile = parse_classfile(worker).expect("parse CounterWorker");

    let empty: ClassHierarchy = ClassHierarchy::new();
    let without: AppliedNames = apply_proguard_mapping_with_hierarchy(&mapping, &cf, &empty);
    let with: AppliedNames = apply_proguard_mapping_with_hierarchy(&mapping, &cf, &hierarchy);

    assert_eq!(with.class_name.as_deref(), Some("EdgeCases$CounterWorker"));
    assert!(
        with.restored_count >= without.restored_count,
        "hierarchy-aware apply must restore at least as many names ({} vs {})",
        with.restored_count,
        without.restored_count
    );
}

#[test]
fn hand_authored_spec_mapping_retraces_inline_and_inheritance() {
    let src: &str = concat!(
        "com.acme.Base -> a.A:\n",
        "    java.lang.String log -> f\n",
        "    1:5:void emit(java.lang.String):40:44 -> g\n",
        "com.acme.Child -> a.B:\n",
        "    1:3:int compute(int):10:12 -> h\n",
        "    2:2:int helper(int):60:60 -> h\n",
        "    2:2:int compute(int):11 -> h\n",
    );
    let mapping: ProguardMapping = parse_proguard_mapping(src).expect("parse hand-authored");

    let frames: Vec<RetracedFrame> = mapping.retrace("a.B", "h", 2);
    assert_eq!(frames.len(), 2, "got {frames:?}");
    assert_eq!(frames[0].method_name, "helper");
    assert_eq!(frames[0].original_line, Some(60));
    assert_eq!(frames[1].method_name, "compute");
    assert_eq!(frames[1].original_line, Some(11));

    let mut hierarchy: ClassHierarchy = ClassHierarchy::new();
    hierarchy.record("a/B", "a/A");
    let inherited: InheritedMethod = mapping
        .resolve_method_with_inheritance(&hierarchy, "a.B", "g", Some("(Ljava/lang/String;)V"))
        .expect("emit resolves up to Base");
    assert_eq!(inherited.original_name, "emit");
    assert_eq!(inherited.declaring_class, "com.acme.Base");
    assert!(inherited.inherited);

    let interp: Vec<RetracedFrame> = mapping.retrace("a.A", "g", 3);
    assert_eq!(
        interp.first().and_then(|f: &RetracedFrame| f.original_line),
        Some(42),
        "obf line 3 within range 1:5 -> 40:44 interpolates to original line 42"
    );
}
