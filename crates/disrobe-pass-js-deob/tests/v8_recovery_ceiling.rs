#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use std::path::{Path, PathBuf};

use disrobe_pass_js_deob::v8::{
    BytenodeCacheBody, CodeSerializerGraph, Disassembly, LiftedFunction, NodeVersion, OpcodeTable,
    RecoveredBytecodeArray, StructuralRecovery, disassemble, disassemble_with_table,
    encode_instruction, lift_disassembly, parse_bytenode_full, parse_code_serializer_graph,
    recover_structure,
};

const FIXTURE: &str = "corpus/v8/node-24-multi/multi-24.jsc";

const CLASSIFY_MNEMONICS: &[&str] = &[
    "LdaZero",
    "TestLessThan",
    "JumpIfFalse",
    "LdaConstant",
    "Return",
    "LdaZero",
    "TestEqualStrict",
    "JumpIfFalse",
    "LdaConstant",
    "Return",
    "LdaConstant",
    "Return",
];

const ACCUMULATE_MNEMONICS: &[&str] = &[
    "LdaZero",
    "Star0",
    "LdaZero",
    "Star1",
    "GetNamedProperty",
    "TestLessThan",
    "JumpIfFalse",
    "Ldar",
    "GetKeyedProperty",
    "Add",
    "Star0",
    "Ldar",
    "Inc",
    "Star1",
    "JumpLoop",
    "Ldar",
    "Return",
];

const GREET_MNEMONICS: &[&str] = &[
    "LdaConstant",
    "Star0",
    "Ldar",
    "Add",
    "Star0",
    "LdaConstant",
    "Add",
    "Return",
];

fn workspace_root() -> PathBuf {
    let manifest: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .ancestors()
        .nth(2)
        .map(|p: &Path| p.to_path_buf())
        .unwrap_or(manifest)
}

fn load_graph() -> Option<(BytenodeCacheBody, CodeSerializerGraph)> {
    let path: PathBuf = workspace_root().join(FIXTURE);
    let bytes: Vec<u8> = std::fs::read(&path).ok()?;
    let body: BytenodeCacheBody =
        parse_bytenode_full(&bytes).expect("multi-24 .jsc header must parse");
    assert_eq!(body.header.version_hash.node, NodeVersion::Node24);
    let graph: CodeSerializerGraph =
        parse_code_serializer_graph(&body).expect("multi-24 .jsc graph must parse");
    Some((body, graph))
}

fn mnemonics_of(arr: &RecoveredBytecodeArray) -> Vec<&'static str> {
    let disasm: Disassembly = disassemble(&arr.bytecode, NodeVersion::Node24);
    assert_eq!(
        disasm.trailing_garbage,
        0,
        "recovered array (len {}) must disassemble with no trailing garbage",
        arr.bytecode.len()
    );
    assert!(
        disasm.unknown_opcode_counts.is_empty(),
        "recovered array (len {}) must have no unknown opcodes: {:?}",
        arr.bytecode.len(),
        disasm.unknown_opcode_counts
    );
    disasm.instructions.iter().map(|i| i.mnemonic).collect()
}

fn find_by_mnemonics<'a>(
    graph: &'a CodeSerializerGraph,
    expected: &[&str],
) -> &'a RecoveredBytecodeArray {
    graph
        .bytecode_arrays
        .iter()
        .find(|a: &&RecoveredBytecodeArray| mnemonics_of(a) == expected)
        .unwrap_or_else(|| {
            panic!(
                "no recovered BytecodeArray matched the V8 --print-bytecode mnemonic sequence {expected:?}; \
                 recovered array lengths: {:?}",
                graph
                    .bytecode_arrays
                    .iter()
                    .map(|a: &RecoveredBytecodeArray| a.bytecode.len())
                    .collect::<Vec<usize>>()
            )
        })
}

#[test]
fn recovers_all_four_eagerly_compiled_user_functions() {
    let Some((_body, graph)): Option<(BytenodeCacheBody, CodeSerializerGraph)> = load_graph()
    else {
        eprintln!("FIXTURE PENDING: {FIXTURE} absent; regenerate via node vm produceCachedData");
        return;
    };
    assert_eq!(
        graph.bytecode_arrays.len(),
        4,
        "the IIFE sample eagerly compiles top-level + classify + accumulate + greet => 4 BytecodeArrays; \
         recovering fewer means a lazy-compilation boundary, recovering more means a graph-walk over-read"
    );
}

#[test]
fn each_user_function_disassembles_byte_exact_to_v8_print_bytecode() {
    let Some((_body, graph)): Option<(BytenodeCacheBody, CodeSerializerGraph)> = load_graph()
    else {
        eprintln!("FIXTURE PENDING: {FIXTURE} absent");
        return;
    };
    let classify: &RecoveredBytecodeArray = find_by_mnemonics(&graph, CLASSIFY_MNEMONICS);
    assert_eq!(classify.bytecode.len(), 21, "classify body length per V8");
    let accumulate: &RecoveredBytecodeArray = find_by_mnemonics(&graph, ACCUMULATE_MNEMONICS);
    assert_eq!(
        accumulate.bytecode.len(),
        34,
        "accumulate body length per V8"
    );
    let greet: &RecoveredBytecodeArray = find_by_mnemonics(&graph, GREET_MNEMONICS);
    assert_eq!(greet.bytecode.len(), 15, "greet body length per V8");
}

#[test]
fn aggregate_disassembly_is_fully_clean_and_lift_meets_floor() {
    let Some((_body, graph)): Option<(BytenodeCacheBody, CodeSerializerGraph)> = load_graph()
    else {
        eprintln!("FIXTURE PENDING: {FIXTURE} absent");
        return;
    };
    let mut total_ins: usize = 0;
    let mut total_unknown: usize = 0;
    let mut total_trailing: usize = 0;
    let mut total_rev: usize = 0;
    for arr in &graph.bytecode_arrays {
        let disasm: Disassembly = disassemble(&arr.bytecode, NodeVersion::Node24);
        let lifted: LiftedFunction = lift_disassembly(&disasm);
        total_ins += lifted.lines.len();
        total_unknown += disasm
            .unknown_opcode_counts
            .values()
            .copied()
            .sum::<usize>();
        total_trailing += disasm.trailing_garbage;
        total_rev += lifted.reversible_count;
    }
    assert_eq!(
        total_unknown, 0,
        "every byte V8 serialized must decode to a known opcode (clean disasm == 100%)"
    );
    assert_eq!(
        total_trailing, 0,
        "no trailing garbage across any recovered array"
    );
    assert!(
        total_ins >= 50,
        "expected >= 50 decoded instructions, got {total_ins}"
    );
    let rev_pct: f64 = 100.0 * (total_rev as f64) / (total_ins as f64);
    assert!(
        rev_pct >= 80.0,
        "aggregate reversible-lift fidelity floor is 80% on real eager user code; got {rev_pct:.2}% ({total_rev}/{total_ins})"
    );
}

#[test]
fn structural_recovery_surfaces_names_and_documents_the_real_residue() {
    let Some((body, _graph)): Option<(BytenodeCacheBody, CodeSerializerGraph)> = load_graph()
    else {
        eprintln!("FIXTURE PENDING: {FIXTURE} absent");
        return;
    };
    let recovery: StructuralRecovery =
        recover_structure(&body.payload, body.header.version_hash.node);
    let names: Vec<&str> = recovery.function_name_candidates();
    assert!(
        names.contains(&"classify") && names.contains(&"greet"),
        "expected eager function names recovered from inline string records, got {names:?}"
    );
    let internalized_note: &String = recovery
        .lossy_notes
        .iter()
        .find(|n: &&String| n.contains("identifiers"))
        .expect("the corrected constant-pool note must be present");
    assert!(
        internalized_note.contains("inline") && internalized_note.contains("recovered"),
        "the note must state user identifiers are serialized inline and recovered, not walled: {internalized_note}"
    );
    assert!(
        internalized_note.contains("root") && internalized_note.contains("pinned"),
        "the note must scope the residue to pinned-table root strings only: {internalized_note}"
    );
    assert!(
        recovery
            .lossy_notes
            .iter()
            .any(|n: &String| n.contains("lazily-compiled")),
        "the lazy-compilation wall (inner functions have no BytecodeArray until first runtime call) must be documented"
    );
}

fn lift_invoke_intrinsic_then_return(
    id: i64,
    first_reg: i64,
    count: i64,
) -> (LiftedFunction, String) {
    let table: OpcodeTable = OpcodeTable::for_node(NodeVersion::Node24);
    let mut bytes: Vec<u8> = encode_instruction(&table, "InvokeIntrinsic", &[id, first_reg, count])
        .expect("InvokeIntrinsic must encode in the node-24 table");
    bytes.extend(encode_instruction(&table, "Return", &[]).expect("Return must encode"));
    let disasm: Disassembly = disassemble_with_table(&bytes, &table);
    assert_eq!(
        disasm.trailing_garbage, 0,
        "encoded InvokeIntrinsic + Return must round-trip with no trailing garbage"
    );
    assert_eq!(disasm.instructions[0].mnemonic, "InvokeIntrinsic");
    let lifted: LiftedFunction = lift_disassembly(&disasm);
    let js: String = lifted.render_js("f");
    (lifted, js)
}

#[test]
fn disasm_labels_invoke_intrinsic_exactly_like_node_print_bytecode() {
    let table: OpcodeTable = OpcodeTable::for_node(NodeVersion::Node24);
    let bytes: Vec<u8> = encode_instruction(&table, "InvokeIntrinsic", &[12, 12, 2])
        .expect("InvokeIntrinsic must encode");
    let disasm: Disassembly = disassemble_with_table(&bytes, &table);
    let rendered: String = disasm.instructions[0].render();
    assert!(
        rendered.starts_with("InvokeIntrinsic [_CopyDataProperties]"),
        "disasm must label intrinsic id 12 exactly as node-24 prints \
         `InvokeIntrinsic [_CopyDataProperties]`, got `{rendered}`"
    );
}

#[test]
fn invoke_intrinsic_table_matches_real_v8_13_6_intrinsics_list() {
    let (copy, copy_js): (LiftedFunction, String) = lift_invoke_intrinsic_then_return(12, 4, 1);
    assert!(
        copy_js.contains("...") && copy_js.contains('{'),
        "id 12 is CopyDataProperties (node-24 prints `InvokeIntrinsic [_CopyDataProperties]`); \
         surface must be an object spread, got `{copy_js}`"
    );
    assert!(
        !copy_js.contains("Array.isArray")
            && !copy_js.contains("Number.isInteger")
            && !copy_js.contains(" in ("),
        "the fabricated id->predicate mappings (HasProperty/IsArray/IsSmi) must be gone, got `{copy_js}`"
    );
    let intrinsic_line: &str = copy
        .lines
        .iter()
        .find(|l: &&disrobe_pass_js_deob::v8::LiftedLine| l.mnemonic == "InvokeIntrinsic")
        .map_or("", |l: &disrobe_pass_js_deob::v8::LiftedLine| {
            l.ir_comment.as_deref().unwrap_or("")
        });
    assert!(
        intrinsic_line.contains("CopyDataProperties"),
        "the ir comment must name the real intrinsic CopyDataProperties, got `{intrinsic_line}`"
    );

    let (_iter, iter_js): (LiftedFunction, String) = lift_invoke_intrinsic_then_return(14, 4, 2);
    assert!(
        iter_js.contains("value:") && iter_js.contains("done:"),
        "id 14 is CreateIterResultObject; surface must be {{value, done}}, got `{iter_js}`"
    );

    let (_meta, meta_js): (LiftedFunction, String) = lift_invoke_intrinsic_then_return(11, 4, 0);
    assert!(
        meta_js.contains("import.meta"),
        "id 11 is GetImportMetaObject; surface must be import.meta, got `{meta_js}`"
    );

    for async_id in [0_i64, 1, 4, 8, 10, 15] {
        let (opaque, opaque_js): (LiftedFunction, String) =
            lift_invoke_intrinsic_then_return(async_id, 4, 1);
        assert!(
            opaque_js.contains('%'),
            "async/generator intrinsic id {async_id} has no plain-JS surface and must render as \
             a named %Intrinsic placeholder, got `{opaque_js}`"
        );
        let invoke: &disrobe_pass_js_deob::v8::LiftedLine = opaque
            .lines
            .iter()
            .find(|l: &&disrobe_pass_js_deob::v8::LiftedLine| l.mnemonic == "InvokeIntrinsic")
            .expect("InvokeIntrinsic line present");
        assert_eq!(
            invoke.fidelity,
            disrobe_pass_js_deob::v8::LiftFidelity::OpaqueRuntime,
            "id {async_id} must be marked OpaqueRuntime, not silently lifted to a wrong surface"
        );
    }
}
