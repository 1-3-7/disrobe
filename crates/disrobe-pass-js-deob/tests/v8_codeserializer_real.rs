#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use std::path::{Path, PathBuf};

use disrobe_pass_js_deob::v8::{
    BytenodeCacheBody, CodeSerializerGraph, ConstantPoolEntry, Disassembly, LiftedFunction,
    NodeVersion, RecoveredBytecodeArray, disassemble, lift_disassembly, lift_disassembly_with_pool,
    parse_bytenode_full, parse_code_serializer_graph,
};

struct VersionFixture {
    node: NodeVersion,
    dir: &'static str,
    file: &'static str,
    greet_hex: &'static str,
    top_level_hex: &'static str,
    top_level_len: usize,
    top_level_mnemonics: &'static [&'static str],
    length_root_index: u32,
}

const GREET_MNEMONICS: [&str; 14] = [
    "LdaConstant",
    "Star1",
    "Ldar",
    "Add",
    "Star0",
    "LdaGlobal",
    "Star2",
    "GetNamedProperty",
    "Star2",
    "GetNamedProperty",
    "Star1",
    "CallProperty1",
    "GetNamedProperty",
    "Return",
];

const TOP_LEVEL_MNEMONICS_PRE_SCRIPT_CONTEXT: [&str; 38] = [
    "LdaConstant",
    "Star2",
    "Mov",
    "CallRuntime",
    "LdaGlobal",
    "Star3",
    "GetNamedProperty",
    "Star3",
    "GetNamedProperty",
    "Star2",
    "LdaConstant",
    "Star4",
    "CallProperty1",
    "LdaConstant",
    "StaCurrentContextSlot",
    "LdaZero",
    "StaCurrentContextSlot",
    "LdaZero",
    "Star1",
    "LdaSmi",
    "TestLessThan",
    "JumpIfFalse",
    "LdaCurrentContextSlot",
    "Star2",
    "Ldar",
    "Add",
    "StaCurrentContextSlot",
    "Ldar",
    "Inc",
    "Star1",
    "JumpLoop",
    "LdaGlobal",
    "Star2",
    "LdaConstant",
    "Star3",
    "CallUndefinedReceiver1",
    "Star0",
    "Return",
];

const TOP_LEVEL_MNEMONICS_MIXED_CONTEXT: [&str; 38] = [
    "LdaConstant",
    "Star2",
    "Mov",
    "CallRuntime",
    "LdaGlobal",
    "Star3",
    "GetNamedProperty",
    "Star3",
    "GetNamedProperty",
    "Star2",
    "LdaConstant",
    "Star4",
    "CallProperty1",
    "LdaConstant",
    "StaCurrentContextSlot",
    "LdaZero",
    "StaCurrentScriptContextSlot",
    "LdaZero",
    "Star1",
    "LdaSmi",
    "TestLessThan",
    "JumpIfFalse",
    "LdaCurrentContextSlot",
    "Star2",
    "Ldar",
    "Add",
    "StaCurrentScriptContextSlot",
    "Ldar",
    "Inc",
    "Star1",
    "JumpLoop",
    "LdaGlobal",
    "Star2",
    "LdaConstant",
    "Star3",
    "CallUndefinedReceiver1",
    "Star0",
    "Return",
];

const TOP_LEVEL_MNEMONICS_SCRIPT_CONTEXT: [&str; 38] = [
    "LdaConstant",
    "Star2",
    "Mov",
    "CallRuntime",
    "LdaGlobal",
    "Star3",
    "GetNamedProperty",
    "Star3",
    "GetNamedProperty",
    "Star2",
    "LdaConstant",
    "Star4",
    "CallProperty1",
    "LdaConstant",
    "StaCurrentScriptContextSlot",
    "LdaZero",
    "StaCurrentScriptContextSlot",
    "LdaZero",
    "Star1",
    "LdaSmi",
    "TestLessThan",
    "JumpIfFalse",
    "LdaCurrentScriptContextSlot",
    "Star2",
    "Ldar",
    "Add",
    "StaCurrentScriptContextSlot",
    "Ldar",
    "Inc",
    "Star1",
    "JumpLoop",
    "LdaGlobal",
    "Star2",
    "LdaConstant",
    "Star3",
    "CallUndefinedReceiver1",
    "Star0",
    "Return",
];

const FIXTURES: [VersionFixture; 4] = [
    VersionFixture {
        node: NodeVersion::Node18,
        dir: "node-18",
        file: "hello-18.jsc",
        greet_hex: "1300c30b0339f900c4210101c22df80203c22df80305c35ef9f8fa072dfa0409a9",
        top_level_hex: "1300c219fef7655701f802210100c12df70202c12df70304c21304c05ef8f7f606130525020c25030c\
             c30d0a6df90899141603c20bf939f80925030bf9510ac389160021060bc21307c162f8f70dc4a9",
        top_level_len: 80usize,
        top_level_mnemonics: &TOP_LEVEL_MNEMONICS_PRE_SCRIPT_CONTEXT,
        length_root_index: 424u32,
    },
    VersionFixture {
        node: NodeVersion::Node20,
        dir: "node-20",
        file: "hello-20.jsc",
        greet_hex: "1300c30b0338f900c4210101c22df80203c22df80305c35ef9f8fa072dfa0409a9",
        top_level_hex: "1300c219fef7656401f802210100c12df70202c12df70304c21304c05ef8f7f606130525020c25030c\
             c30d0a6df90899151603c20bf938f80925030bf9500ac38916000b21060cc21307c162f8f70ec4a9",
        top_level_len: 81usize,
        top_level_mnemonics: &TOP_LEVEL_MNEMONICS_PRE_SCRIPT_CONTEXT,
        length_root_index: 155u32,
    },
    VersionFixture {
        node: NodeVersion::Node22,
        dir: "node-22",
        file: "hello-22.jsc",
        greet_hex: "1300c80b033bf800c9210101c72ff70203c72ff70305c861f8f7f9072ff90409ae",
        top_level_hex: "1300c719fef6686901f702210100c62ff60202c62ff60304c71304c561f7f6f506130525030c27040c\
             c80d0a71f8089e151604c70bf83bf70927040bf8530ac88e16000b21060cc71307c665f7f60ec9ae",
        top_level_len: 81usize,
        top_level_mnemonics: &TOP_LEVEL_MNEMONICS_MIXED_CONTEXT,
        length_root_index: 164u32,
    },
    VersionFixture {
        node: NodeVersion::Node24,
        dir: "node-24",
        file: "hello-24.jsc",
        greet_hex: "1300cd0b033ff800ce230101cc33f70203cc33f70305cd65f8f7f90733f90409b3",
        top_level_hex: "1300cc1bfef66c6a01f702230100cb33f60202cb33f60304cc1304ca65f7f6f506130529030c29040c\
             cd0d0a75f808a3151804cc0bf83ff70929040bf8570acd9216000b23060ccc1307cb69f7f60eceb3",
        top_level_len: 81usize,
        top_level_mnemonics: &TOP_LEVEL_MNEMONICS_SCRIPT_CONTEXT,
        length_root_index: 1007u32,
    },
];

fn jsc_path(dir: &str, file: &str) -> PathBuf {
    let manifest: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .ancestors()
        .nth(2)
        .map(|p: &Path| p.to_path_buf())
        .unwrap_or(manifest)
        .join("corpus/v8")
        .join(dir)
        .join(file)
}

fn hex_to_bytes(s: &str) -> Vec<u8> {
    let cleaned: String = s.chars().filter(|c: &char| !c.is_whitespace()).collect();
    assert_eq!(cleaned.len() % 2, 0usize, "odd hex length");
    (0..cleaned.len())
        .step_by(2usize)
        .map(|i: usize| u8::from_str_radix(&cleaned[i..i + 2usize], 16u32).expect("valid hex byte"))
        .collect()
}

fn load_graph(fx: &VersionFixture) -> Option<(BytenodeCacheBody, CodeSerializerGraph)> {
    let path: PathBuf = jsc_path(fx.dir, fx.file);
    let bytes: Vec<u8> = std::fs::read(&path).ok()?;
    let body: BytenodeCacheBody = parse_bytenode_full(&bytes)
        .unwrap_or_else(|e| panic!("{} .jsc header must parse: {e}", fx.dir));
    assert_eq!(body.header.version_hash.node, fx.node);
    let graph: CodeSerializerGraph = parse_code_serializer_graph(&body)
        .unwrap_or_else(|e| panic!("{} .jsc code-serializer graph must parse: {e}", fx.dir));
    Some((body, graph))
}

fn find_array<'a>(graph: &'a CodeSerializerGraph, hex: &str) -> &'a RecoveredBytecodeArray {
    let expected: Vec<u8> = hex_to_bytes(hex);
    graph
        .bytecode_arrays
        .iter()
        .find(|a: &&RecoveredBytecodeArray| a.bytecode == expected)
        .unwrap_or_else(|| {
            panic!(
                "BytecodeArray not recovered byte-exact; recovered lengths: {:?}",
                graph
                    .bytecode_arrays
                    .iter()
                    .map(|a: &RecoveredBytecodeArray| a.bytecode.len())
                    .collect::<Vec<usize>>()
            )
        })
}

#[test]
fn every_version_graph_walks_to_completion() {
    let mut exercised: usize = 0usize;
    for fx in &FIXTURES {
        let Some((body, graph)): Option<(BytenodeCacheBody, CodeSerializerGraph)> = load_graph(fx)
        else {
            eprintln!("FIXTURE PENDING: corpus/v8/{}/{} absent", fx.dir, fx.file);
            continue;
        };
        assert_eq!(graph.node_version, fx.node);
        assert!(
            graph.object_count > 10usize,
            "{} graph should contain many serialized objects, got {}",
            fx.dir,
            graph.object_count
        );
        let tail: usize = body.payload.len().saturating_sub(graph.bytes_consumed);
        assert!(
            tail <= 16usize,
            "{} graph parse should consume up to the deferred-section sync, left {tail} bytes",
            fx.dir
        );
        exercised += 1usize;
    }
    assert!(
        exercised > 0usize,
        "no corpus/v8 .jsc fixtures present; this differential must exercise at least one"
    );
}

#[test]
fn every_version_recovers_exactly_two_user_bytecode_arrays() {
    let mut exercised: usize = 0usize;
    for fx in &FIXTURES {
        let Some((_body, graph)): Option<(BytenodeCacheBody, CodeSerializerGraph)> = load_graph(fx)
        else {
            eprintln!("FIXTURE PENDING: corpus/v8/{}/{} absent", fx.dir, fx.file);
            continue;
        };
        assert_eq!(
            graph.bytecode_arrays.len(),
            2usize,
            "{} holds exactly two eagerly-compiled BytecodeArrays (top-level + greet); recovered {}",
            fx.dir,
            graph.bytecode_arrays.len()
        );
        exercised += 1usize;
    }
    assert!(
        exercised > 0usize,
        "no corpus/v8 .jsc fixtures present; this differential must exercise at least one"
    );
}

#[test]
fn every_version_greet_bytecode_is_byte_exact_against_v8_print_bytecode() {
    let mut exercised: usize = 0usize;
    for fx in &FIXTURES {
        let Some((_body, graph)): Option<(BytenodeCacheBody, CodeSerializerGraph)> = load_graph(fx)
        else {
            eprintln!("FIXTURE PENDING: corpus/v8/{}/{} absent", fx.dir, fx.file);
            continue;
        };
        let greet: &RecoveredBytecodeArray = find_array(&graph, fx.greet_hex);
        assert_eq!(greet.frame_size, 24i32, "{} greet frame size", fx.dir);
        assert_eq!(
            greet.parameter_count, 2u16,
            "{} greet parameter count",
            fx.dir
        );
        assert_eq!(greet.bytecode.len(), 33usize, "{} greet length", fx.dir);
        exercised += 1usize;
    }
    assert!(
        exercised > 0usize,
        "no corpus/v8 .jsc fixtures present; this differential must exercise at least one"
    );
}

#[test]
fn every_version_top_level_bytecode_is_byte_exact_against_v8_print_bytecode() {
    let mut exercised: usize = 0usize;
    for fx in &FIXTURES {
        let Some((_body, graph)): Option<(BytenodeCacheBody, CodeSerializerGraph)> = load_graph(fx)
        else {
            eprintln!("FIXTURE PENDING: corpus/v8/{}/{} absent", fx.dir, fx.file);
            continue;
        };
        let top: &RecoveredBytecodeArray = find_array(&graph, fx.top_level_hex);
        assert_eq!(top.frame_size, 40i32, "{} top-level frame size", fx.dir);
        assert_eq!(
            top.parameter_count, 1u16,
            "{} top-level param count",
            fx.dir
        );
        assert_eq!(
            top.bytecode.len(),
            fx.top_level_len,
            "{} top-level length",
            fx.dir
        );
        exercised += 1usize;
    }
    assert!(
        exercised > 0usize,
        "no corpus/v8 .jsc fixtures present; this differential must exercise at least one"
    );
}

#[test]
fn every_version_greet_disassembles_to_v8_mnemonic_sequence() {
    let mut exercised: usize = 0usize;
    for fx in &FIXTURES {
        let Some((_body, graph)): Option<(BytenodeCacheBody, CodeSerializerGraph)> = load_graph(fx)
        else {
            eprintln!("FIXTURE PENDING: corpus/v8/{}/{} absent", fx.dir, fx.file);
            continue;
        };
        let greet: &RecoveredBytecodeArray = find_array(&graph, fx.greet_hex);
        let disasm: Disassembly = disassemble(&greet.bytecode, fx.node);
        assert_eq!(
            disasm.trailing_garbage, 0usize,
            "{} greet must disassemble with no trailing garbage",
            fx.dir
        );
        assert!(
            disasm.unknown_opcode_counts.is_empty(),
            "{} greet must have no unknown opcodes: {:?}",
            fx.dir,
            disasm.unknown_opcode_counts
        );
        let mnemonics: Vec<&str> = disasm.instructions.iter().map(|i| i.mnemonic).collect();
        assert_eq!(
            mnemonics, GREET_MNEMONICS,
            "{} disassembly of recovered greet must match V8 --print-bytecode mnemonics",
            fx.dir
        );
        exercised += 1usize;
    }
    assert!(
        exercised > 0usize,
        "no corpus/v8 .jsc fixtures present; this differential must exercise at least one"
    );
}

#[test]
fn every_version_top_level_disassembles_to_v8_mnemonic_sequence() {
    let mut exercised: usize = 0usize;
    for fx in &FIXTURES {
        let Some((_body, graph)): Option<(BytenodeCacheBody, CodeSerializerGraph)> = load_graph(fx)
        else {
            eprintln!("FIXTURE PENDING: corpus/v8/{}/{} absent", fx.dir, fx.file);
            continue;
        };
        let top: &RecoveredBytecodeArray = find_array(&graph, fx.top_level_hex);
        let disasm: Disassembly = disassemble(&top.bytecode, fx.node);
        assert_eq!(
            disasm.trailing_garbage, 0usize,
            "{} top-level trailing garbage",
            fx.dir
        );
        assert!(
            disasm.unknown_opcode_counts.is_empty(),
            "{} top-level unknown opcodes: {:?}",
            fx.dir,
            disasm.unknown_opcode_counts
        );
        let mnemonics: Vec<&str> = disasm.instructions.iter().map(|i| i.mnemonic).collect();
        assert_eq!(
            mnemonics, fx.top_level_mnemonics,
            "{} disassembly of recovered top-level must match V8 --print-bytecode mnemonics",
            fx.dir
        );
        exercised += 1usize;
    }
    assert!(
        exercised > 0usize,
        "no corpus/v8 .jsc fixtures present; this differential must exercise at least one"
    );
}

#[test]
fn node24_recovered_greet_lifts_to_readable_surface() {
    let fx: &VersionFixture = &FIXTURES[3];
    let Some((_body, graph)): Option<(BytenodeCacheBody, CodeSerializerGraph)> = load_graph(fx)
    else {
        eprintln!("FIXTURE PENDING: corpus/v8/{}/{} absent", fx.dir, fx.file);
        return;
    };
    let greet: &RecoveredBytecodeArray = find_array(&graph, fx.greet_hex);
    let disasm: Disassembly = disassemble(&greet.bytecode, fx.node);
    let lifted: LiftedFunction = lift_disassembly(&disasm);
    let js: String = lifted.render_js("greet");
    assert!(js.contains("function greet"), "{js}");
    assert!(
        js.contains("return") || js.contains("__c"),
        "lifted greet should expose its body shape: {js}"
    );
}

#[test]
fn opcode_table_byte_assignments_match_v8_print_bytecode_per_version() {
    use disrobe_pass_js_deob::v8::OpcodeTable;
    let node18_22_anchors: [(&str, u8); 6] = [
        ("LdaConstant", 0x13),
        ("Ldar", 0x0b),
        ("LdaGlobal", 0x21),
        ("GetNamedProperty", 0x2d),
        ("CallProperty1", 0x5e),
        ("Return", 0xa9),
    ];
    let n18: OpcodeTable = OpcodeTable::for_node(NodeVersion::Node18);
    for (mnemonic, byte) in node18_22_anchors {
        assert_eq!(
            n18.lookup_mnemonic(mnemonic),
            Some(byte),
            "node-18 (v8 10.2) `{mnemonic}` byte"
        );
    }
    let n20: OpcodeTable = OpcodeTable::for_node(NodeVersion::Node20);
    assert_eq!(n20.lookup_mnemonic("Return"), Some(0xa9u8));
    assert_eq!(n20.lookup_mnemonic("Add"), Some(0x38u8));
    let n18_add: OpcodeTable = OpcodeTable::for_node(NodeVersion::Node18);
    assert_eq!(
        n18_add.lookup_mnemonic("Add"),
        Some(0x39u8),
        "v8 10.2 Add precedes v8 11.3 Add by one slot (extra opcode removed in 11.3)"
    );
    let n22: OpcodeTable = OpcodeTable::for_node(NodeVersion::Node22);
    let n22_anchors: [(&str, u8); 5] = [
        ("LdaGlobal", 0x21),
        ("GetNamedProperty", 0x2f),
        ("CallProperty1", 0x61),
        ("Star0", 0xc9),
        ("Return", 0xae),
    ];
    for (mnemonic, byte) in n22_anchors {
        assert_eq!(
            n22.lookup_mnemonic(mnemonic),
            Some(byte),
            "node-22 (v8 12.4) `{mnemonic}` byte"
        );
    }
    let n24: OpcodeTable = OpcodeTable::for_node(NodeVersion::Node24);
    assert_eq!(n24.lookup_mnemonic("Return"), Some(0xb3u8));
    assert_eq!(n24.lookup_mnemonic("Star0"), Some(0xceu8));
    assert_eq!(n24.lookup_mnemonic("GetNamedProperty"), Some(0x33u8));
}

fn pool_names(arr: &RecoveredBytecodeArray) -> Vec<String> {
    arr.constant_pool
        .iter()
        .map(|e: &ConstantPoolEntry| match e {
            ConstantPoolEntry::InlineString { value } => format!("string:{value}"),
            ConstantPoolEntry::BuiltinName { name, .. } => format!("builtin:{name}"),
            ConstantPoolEntry::InnerFunction { .. } => "inner-fn".to_owned(),
            ConstantPoolEntry::NestedArray { .. } => "array".to_owned(),
            ConstantPoolEntry::RootIndex { root_index } => format!("root:{root_index}"),
            ConstantPoolEntry::ReadOnlyHeap { offset, .. } => format!("ro-heap:{offset}"),
            ConstantPoolEntry::Other { .. } => "other".to_owned(),
        })
        .collect()
}

#[test]
fn node24_greet_constant_pool_links_user_identifiers_against_print_bytecode() {
    let fx: &VersionFixture = &FIXTURES[3];
    let Some((_body, graph)): Option<(BytenodeCacheBody, CodeSerializerGraph)> = load_graph(fx)
    else {
        eprintln!("FIXTURE PENDING: corpus/v8/{}/{} absent", fx.dir, fx.file);
        return;
    };
    let greet: &RecoveredBytecodeArray = find_array(&graph, fx.greet_hex);
    assert_eq!(
        pool_names(greet),
        vec![
            "string:hello ".to_owned(),
            "string:process".to_owned(),
            "string:stdout".to_owned(),
            "string:write".to_owned(),
            "builtin:length".to_owned(),
        ],
        "greet constant pool must match node --print-bytecode slot order: \
         [0]\"hello \" [1]process [2]stdout [3]write [4]length(root)"
    );
}

#[test]
fn node24_greet_lift_replaces_placeholders_with_real_names() {
    let fx: &VersionFixture = &FIXTURES[3];
    let Some((_body, graph)): Option<(BytenodeCacheBody, CodeSerializerGraph)> = load_graph(fx)
    else {
        eprintln!("FIXTURE PENDING: corpus/v8/{}/{} absent", fx.dir, fx.file);
        return;
    };
    let greet: &RecoveredBytecodeArray = find_array(&graph, fx.greet_hex);
    let disasm: Disassembly = disassemble(&greet.bytecode, fx.node);
    let linked: String =
        lift_disassembly_with_pool(&disasm, &greet.constant_pool).render_js("greet");
    for needle in ["\"hello \"", ".stdout", ".write", ".length", "process"] {
        assert!(
            linked.contains(needle),
            "linked greet must contain {needle}: {linked}"
        );
    }
    assert!(
        !linked.contains("__c"),
        "every greet constant-pool reference must be resolved (no __c placeholder): {linked}"
    );
    let unlinked: String = lift_disassembly(&disasm).render_js("greet");
    assert!(
        unlinked.contains("__c"),
        "without the linked pool the lift still emits __c placeholders (control): {unlinked}"
    );
}

#[test]
fn every_version_builtin_root_strings_resolve_through_pinned_table() {
    let mut exercised: usize = 0usize;
    for fx in &FIXTURES {
        let Some((_body, graph)): Option<(BytenodeCacheBody, CodeSerializerGraph)> = load_graph(fx)
        else {
            eprintln!("FIXTURE PENDING: corpus/v8/{}/{} absent", fx.dir, fx.file);
            continue;
        };
        let greet: &RecoveredBytecodeArray = find_array(&graph, fx.greet_hex);
        let length_entry: &ConstantPoolEntry = greet
            .constant_pool
            .last()
            .expect("greet pool has a trailing length slot");
        match length_entry {
            ConstantPoolEntry::BuiltinName { name, root_index } => {
                assert_eq!(name, "length", "{} root slot must resolve by name", fx.dir);
                assert_eq!(
                    *root_index,
                    Some(fx.length_root_index),
                    "{} length root index",
                    fx.dir
                );
            }
            other => panic!(
                "{} greet pool slot 4 must resolve to builtin `length`, got {other:?}",
                fx.dir
            ),
        }
        exercised += 1usize;
    }
    assert!(
        exercised > 0usize,
        "no corpus/v8 .jsc fixtures present; this differential must exercise at least one"
    );
}

#[test]
fn node24_multi_inner_functions_recover_literals_and_inner_fn_refs() {
    let path: PathBuf = workspace_root_multi();
    let Some(bytes): Option<Vec<u8>> = std::fs::read(&path).ok() else {
        eprintln!("FIXTURE PENDING: {} absent", path.display());
        return;
    };
    let body: BytenodeCacheBody = parse_bytenode_full(&bytes).expect("multi-24 header parses");
    let graph: CodeSerializerGraph =
        parse_code_serializer_graph(&body).expect("multi-24 graph parses");

    let classify: &RecoveredBytecodeArray = find_by_pool_strings(&graph, &["neg", "zero", "pos"]);
    assert_eq!(
        pool_names(classify),
        vec![
            "string:neg".to_owned(),
            "string:zero".to_owned(),
            "string:pos".to_owned(),
        ],
        "classify pool is three inline string literals per node --print-bytecode"
    );

    let top: &RecoveredBytecodeArray = graph
        .bytecode_arrays
        .iter()
        .find(|a: &&RecoveredBytecodeArray| {
            a.constant_pool
                .iter()
                .filter(|e: &&ConstantPoolEntry| {
                    matches!(e, ConstantPoolEntry::InnerFunction { .. })
                })
                .count()
                >= 2
        })
        .expect("the multi top-level pool references the inner function SharedFunctionInfos");
    let names: Vec<String> = pool_names(top);
    assert!(
        names
            .iter()
            .filter(|n: &&String| n.as_str() == "inner-fn")
            .count()
            >= 2,
        "multi top-level pool must link inner-function refs (CreateClosure targets): {names:?}"
    );
    assert!(
        names.contains(&"string:world".to_owned()),
        "multi top-level pool must include the inline literal \"world\": {names:?}"
    );
}

fn workspace_root_multi() -> PathBuf {
    let manifest: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .ancestors()
        .nth(2)
        .map(|p: &Path| p.to_path_buf())
        .unwrap_or(manifest)
        .join("corpus/v8/node-24-multi/multi-24.jsc")
}

fn find_by_pool_strings<'a>(
    graph: &'a CodeSerializerGraph,
    expected: &[&str],
) -> &'a RecoveredBytecodeArray {
    graph
        .bytecode_arrays
        .iter()
        .find(|a: &&RecoveredBytecodeArray| {
            let got: Vec<&str> = a
                .constant_pool
                .iter()
                .filter_map(ConstantPoolEntry::as_inline_string)
                .collect();
            got == expected
        })
        .unwrap_or_else(|| panic!("no recovered function had inline pool {expected:?}"))
}
