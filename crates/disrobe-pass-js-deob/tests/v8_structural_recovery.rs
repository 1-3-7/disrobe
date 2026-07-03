#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use std::path::{Path, PathBuf};

use disrobe_pass_js_deob::v8::{
    BytenodeCacheBody, CodeSerializerGraph, ConstantPoolEntry, NodeVersion, RecoveredBytecodeArray,
    StringClass, StructuralRecovery, extract_framed_strings, parse_bytenode_full,
    parse_code_serializer_graph, recover_structure,
};

fn corpus_dir() -> PathBuf {
    let manifest: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .ancestors()
        .nth(2)
        .map(|p: &Path| p.to_path_buf())
        .unwrap_or(manifest)
        .join("corpus/v8/node-24")
}

fn load_real_jsc() -> Option<BytenodeCacheBody> {
    let path: PathBuf = corpus_dir().join("hello-24.jsc");
    let bytes: Vec<u8> = std::fs::read(&path).ok()?;
    parse_bytenode_full(&bytes).ok()
}

#[test]
fn real_node_24_jsc_recovers_eager_function_names_and_literals() {
    let Some(body): Option<BytenodeCacheBody> = load_real_jsc() else {
        eprintln!("FIXTURE PENDING: corpus/v8/node-24/hello-24.jsc absent; regenerate via node vm");
        return;
    };
    assert_eq!(body.header.version_hash.node, NodeVersion::Node24);
    let recovery: StructuralRecovery =
        recover_structure(&body.payload, body.header.version_hash.node);

    let names: Vec<&str> = recovery.function_name_candidates();
    assert!(
        names.contains(&"greet"),
        "expected lazily-named function `greet` recovered from inline string record, got {names:?}"
    );

    let literals: Vec<&str> = recovery.string_literal_candidates();
    assert!(
        literals
            .iter()
            .any(|s: &&str| s.contains("evalmachine.<anonymous>")),
        "expected script name literal recovered, got {literals:?}"
    );

    let all: Vec<&str> = recovery
        .framed_strings
        .iter()
        .map(|s| s.value.as_str())
        .collect();
    assert!(
        all.contains(&"world"),
        "expected argument literal `world` recovered, got {all:?}"
    );

    assert!(
        recovery.shared_function_info_markers >= 2usize,
        "expected at least 2 SFI markers (eval wrapper + bodies), got {}",
        recovery.shared_function_info_markers
    );
}

#[test]
fn recovered_strings_are_bounded_not_naive_runs() {
    let Some(body): Option<BytenodeCacheBody> = load_real_jsc() else {
        return;
    };
    let strings: Vec<_> = extract_framed_strings(&body.payload);
    for s in &strings {
        assert!(s.byte_length as usize == s.value.len());
        assert!(
            s.value.chars().all(|c: char| !c.is_control() || c == '\t'),
            "framed string {:?} contains unexpected control bytes",
            s.value
        );
    }
}

#[test]
fn root_strings_are_not_inline_but_resolve_through_the_graph_linker() {
    let Some(body): Option<BytenodeCacheBody> = load_real_jsc() else {
        return;
    };
    let recovery: StructuralRecovery =
        recover_structure(&body.payload, body.header.version_hash.node);
    let scraped: Vec<&str> = recovery
        .framed_strings
        .iter()
        .map(|s| s.value.as_str())
        .collect();
    assert!(
        !scraped.contains(&"length"),
        "the version-agnostic string scrape does not surface root strings like `length` inline; \
         got {scraped:?}"
    );
    let note: &String = recovery
        .lossy_notes
        .iter()
        .find(|n: &&String| n.contains("identifiers"))
        .expect("the corrected constant-pool note must be present");
    assert!(
        note.contains("recovered") && note.contains("inline"),
        "the note must say user identifiers ARE recovered from the inline pool, not walled: {note}"
    );

    let graph: CodeSerializerGraph =
        parse_code_serializer_graph(&body).expect("node-24 graph parses");
    let greet: &RecoveredBytecodeArray = graph
        .bytecode_arrays
        .iter()
        .find(|a: &&RecoveredBytecodeArray| {
            a.constant_pool
                .iter()
                .any(|e: &ConstantPoolEntry| e.as_inline_string() == Some("process"))
        })
        .expect("greet links `process` from its inline pool");
    assert!(
        greet
            .constant_pool
            .iter()
            .any(|e: &ConstantPoolEntry| matches!(
                e,
                ConstantPoolEntry::BuiltinName { name, .. } if name == "length"
            )),
        "the `length` root string resolves to a name via the pinned per-release root table, \
         not left as a bare index: {:?}",
        greet.constant_pool
    );
}

#[test]
fn classes_partition_cleanly() {
    let Some(body): Option<BytenodeCacheBody> = load_real_jsc() else {
        return;
    };
    let strings: Vec<_> = extract_framed_strings(&body.payload);
    let seq: usize = strings
        .iter()
        .filter(|s| s.class == StringClass::SeqOneByte)
        .count();
    assert!(
        seq > 0usize,
        "expected at least one seq-one-byte identifier"
    );
}
