#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use disrobe_pass_jvm::dex_builder::{
    ClassDef, DexBuilder, EncodedMethod, MethodRef, ProtoRef, insn,
};
use disrobe_pass_jvm::{decode_method, decompile_dex, parse_dex};
use disrobe_tool_process::{CaptureOutcome, CommandSpec, Completion, Execution};
use sha2::{Digest as _, Sha256};

const CLASS: &str = "Lfixture/SuspendProbe;";
const CONTINUATION: &str = "Lkotlin/coroutines/Continuation;";
const EDGECASES_KT_DEX: &[u8] = include_bytes!("../../../corpus/jvm/dex/EdgeCasesKt.dex");
const GENERATED_KOTLIN_DEX: &[u8] =
    include_bytes!("fixtures/kotlin_suspend_abi/KotlinSuspendAbi.dex");
const METADATA_STRIPPED_KOTLIN_DEX: &[u8] =
    include_bytes!("fixtures/kotlin_suspend_abi/KotlinSuspendAbi.metadata-stripped.dex");
const KOTLIN_SOURCE: &[u8] = include_bytes!("fixtures/kotlin_suspend_abi/KotlinSuspendAbi.kt");
const KOTLIN_SCRIPT: &[u8] = include_bytes!("fixtures/kotlin_suspend_abi/KotlinSuspendScript.kts");
const PROVENANCE: &str = include_str!("fixtures/kotlin_suspend_abi/provenance.toml");

fn sha256(bytes: &[u8]) -> String {
    let mut hex: String = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        write!(hex, "{byte:02x}").expect("writing to a string is infallible");
    }
    hex
}

fn method(name: &str, insns: Vec<u16>) -> EncodedMethod {
    EncodedMethod {
        tries: Vec::new(),
        method: MethodRef {
            class: CLASS.to_owned(),
            proto: ProtoRef {
                return_type: "Ljava/lang/Object;".to_owned(),
                params: vec![CONTINUATION.to_owned()],
            },
            name: name.to_owned(),
        },
        access_flags: 0x0009,
        is_direct: false,
        registers_size: 2,
        ins_size: 1,
        outs_size: 0,
        insns,
        relocations: Vec::new(),
    }
}

fn source_file_index(bytes: &[u8], source_file: &str) -> u32 {
    let dex = parse_dex(bytes).expect("format-valid dex fixture parses");
    dex.strings
        .iter()
        .position(|value: &String| value == source_file)
        .and_then(|index: usize| u32::try_from(index).ok())
        .expect("source-file string is interned")
}

fn with_source_file(mut bytes: Vec<u8>, source_file: &str) -> Vec<u8> {
    let dex = parse_dex(&bytes).expect("format-valid dex fixture parses before source file patch");
    let source_idx: u32 = source_file_index(&bytes, source_file);
    let class_def: usize = dex.header.class_defs_off as usize;
    bytes[class_def + 16..class_def + 20].copy_from_slice(&source_idx.to_le_bytes());
    bytes
}

fn fixture(source_file: &str, name: &str, insns: Vec<u16>) -> Vec<u8> {
    fixture_with_super(source_file, name, insns, "Ljava/lang/Object;")
}

fn fixture_with_super(
    source_file: &str,
    name: &str,
    insns: Vec<u16>,
    super_class: &str,
) -> Vec<u8> {
    let mut builder: DexBuilder = DexBuilder::new();
    builder.intern_string(source_file);
    builder.add_class(ClassDef {
        class: CLASS.to_owned(),
        super_class: super_class.to_owned(),
        access_flags: 0x0001,
        static_fields: Vec::new(),
        static_values: Vec::new(),
        direct_methods: Vec::new(),
        virtual_methods: vec![method(name, insns)],
    });
    with_source_file(builder.build(), source_file)
}

fn rendered_signature(bytes: &[u8], name: &str) -> String {
    let dex = parse_dex(bytes).expect("format-valid dex fixture parses");
    let source = decompile_dex(&dex, bytes).source;
    let prefix = format!("Object {name}(");
    let start = source.find(&prefix).expect("method is rendered");
    source[start..]
        .lines()
        .next()
        .expect("method signature has a line")
        .to_owned()
}

fn class_def_offset(bytes: &[u8], class: &str) -> usize {
    let dex = parse_dex(bytes).expect("DEX fixture parses");
    let index: usize = dex
        .class_descriptors
        .iter()
        .position(|descriptor: &String| descriptor == class)
        .expect("class is present");
    dex.header.class_defs_off as usize + index * 32
}

fn annotation_directory_offset(bytes: &[u8], class: &str) -> usize {
    let offset: usize = class_def_offset(bytes, class) + 20;
    u32::from_le_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("annotation-directory offset bytes"),
    ) as usize
}

fn metadata_annotation_offset(bytes: &[u8], class: &str) -> usize {
    let dex = parse_dex(bytes).expect("DEX fixture parses");
    let directory: usize = annotation_directory_offset(bytes, class);
    let set: usize = u32::from_le_bytes(
        bytes[directory..directory + 4]
            .try_into()
            .expect("class-annotation set offset bytes"),
    ) as usize;
    let count: usize = u32::from_le_bytes(
        bytes[set..set + 4]
            .try_into()
            .expect("class-annotation count bytes"),
    ) as usize;
    for index in 0..count {
        let entry: usize = set + 4 + index * 4;
        let annotation: usize = u32::from_le_bytes(
            bytes[entry..entry + 4]
                .try_into()
                .expect("class-annotation offset bytes"),
        ) as usize;
        let mut value: usize = 0;
        for byte_index in 0..5 {
            let byte: u8 = bytes[annotation + 1 + byte_index];
            value |= usize::from(byte & 0x7f) << (byte_index * 7);
            if byte & 0x80 == 0 {
                break;
            }
        }
        if dex.type_names.get(value).map(String::as_str) == Some("Lkotlin/Metadata;") {
            return annotation;
        }
    }
    panic!("class has no Kotlin metadata annotation")
}

fn required_tool(name: &str) -> PathBuf {
    let path: std::ffi::OsString = std::env::var_os("PATH")
        .unwrap_or_else(|| panic!("the recovered-source behavior gate requires PATH"));
    let extensions: &[&str] = if cfg!(windows) { &[".exe", ""] } else { &[""] };
    for directory in std::env::split_paths(&path) {
        for extension in extensions {
            let candidate: PathBuf = directory.join(format!("{name}{extension}"));
            if candidate.is_file() {
                return candidate;
            }
        }
    }
    panic!("the recovered-source behavior gate requires `{name}` on PATH")
}

fn captured_text(outcome: &CaptureOutcome) -> String {
    let captured = outcome
        .captured()
        .expect("trusted-tool output capture completes");
    assert!(
        !captured.truncated,
        "trusted-tool output exceeded its bound"
    );
    String::from_utf8_lossy(&captured.bytes).into_owned()
}

fn run_tool(program: &Path, args: &[&Path]) -> (bool, String, String) {
    let mut spec: CommandSpec =
        CommandSpec::new(program, Duration::from_secs(30)).capture_limits(64 * 1024, 64 * 1024);
    for argument in args {
        spec = spec.arg(argument.as_os_str());
    }
    let execution: Execution = spec.run().expect("bounded trusted tool executes");
    let success: bool =
        matches!(execution.completion, Completion::Exited(status) if status.success());
    (
        success,
        captured_text(&execution.stdout),
        captured_text(&execution.stderr),
    )
}

fn recovered_method(source: &str, declaration: &str) -> String {
    let start: usize = source
        .find(declaration)
        .unwrap_or_else(|| panic!("recovered declaration missing: {declaration}"));
    let body_start: usize = source[start..]
        .find('{')
        .map(|offset: usize| start + offset)
        .expect("recovered method has a body");
    let mut depth: usize = 0;
    for (offset, byte) in source.as_bytes()[body_start..].iter().enumerate() {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth = depth.checked_sub(1).expect("balanced recovered method");
                if depth == 0 {
                    return source[start..=body_start + offset].to_owned();
                }
            }
            _ => {}
        }
    }
    panic!("recovered method body is unterminated: {declaration}")
}

#[test]
fn metadata_stripped_kotlin_suspend_abi_hides_only_an_unused_final_continuation() {
    let bytes: Vec<u8> = fixture(
        "SuspendProbe.kt",
        "unused",
        [insn::fmt11n(0x12, 0, 0), insn::fmt11x(0x11, 0)].concat(),
    );
    let dex = parse_dex(&bytes).expect("format-valid metadata-absent dex fixture parses");
    let source_offset: usize = dex.header.class_defs_off as usize + 16;
    let source_index: usize = u32::from_le_bytes(
        bytes[source_offset..source_offset + 4]
            .try_into()
            .expect("source index bytes"),
    ) as usize;
    assert_eq!(
        dex.strings.get(source_index).map(String::as_str),
        Some("SuspendProbe.kt"),
        "the fixture carries Kotlin SourceFile evidence"
    );
    assert!(
        decode_method(&[insn::fmt11n(0x12, 0, 0), insn::fmt11x(0x11, 0)].concat())
            .iter()
            .all(|insn| !insn.regs.contains(&1)),
        "the fixture leaves the continuation register unread"
    );
    let descriptor = disrobe_pass_jvm::descriptor::parse_method(
        "(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
    )
    .expect("suspend abi descriptor parses");
    assert!(
        disrobe_pass_jvm::kotlin::is_metadata_absent_suspend_signature(
            true,
            Some("SuspendProbe.kt"),
            "unused",
            &descriptor,
            true,
            false,
        ),
        "the fixture's source-file and ABI satisfy the bounded rule: {descriptor:?}"
    );
    let out = decompile_dex(&dex, &bytes);

    assert!(
        out.source.contains("Object unused()"),
        "the unused continuation is an ABI marker and must not be exposed: {}",
        out.source
    );
    assert!(
        !out.source.contains("Continuation arg0"),
        "the unused continuation must be absent from the recovered signature: {}",
        out.source
    );
}

#[test]
fn kotlin_suspend_abi_retains_used_java_and_bridge_continuations() {
    let cases: [(&str, &str, Vec<u16>, bool); 4] = [
        (
            "SuspendProbe.kts",
            "scriptUnused",
            [insn::fmt11n(0x12, 0, 0), insn::fmt11x(0x11, 0)].concat(),
            false,
        ),
        ("SuspendProbe.kt", "returned", insn::fmt11x(0x11, 1), true),
        (
            "SuspendProbe.java",
            "javaLike",
            [insn::fmt11n(0x12, 0, 0), insn::fmt11x(0x11, 0)].concat(),
            true,
        ),
        (
            "SuspendProbe.kt",
            "invokeSuspend",
            [insn::fmt11n(0x12, 0, 0), insn::fmt11x(0x11, 0)].concat(),
            true,
        ),
    ];

    for (source_file, name, insns, retains_continuation) in cases {
        let bytes: Vec<u8> = fixture(source_file, name, insns);
        let dex = parse_dex(&bytes).expect("format-valid dex fixture parses");
        let out = decompile_dex(&dex, &bytes);
        let signature = format!("Object {name}(");
        let method_start: usize = out.source.find(&signature).expect("method is rendered");
        let method: &str = &out.source[method_start..];
        assert_eq!(
            method.starts_with(&format!("{signature}kotlin.coroutines.Continuation arg0)")),
            retains_continuation,
            "{name} continuation visibility must match the bounded suspend ABI rule: {}",
            out.source
        );
    }
}

#[test]
fn overwritten_continuation_register_does_not_make_the_incoming_value_used() {
    let bytes: Vec<u8> = fixture(
        "SuspendProbe.kt",
        "overwritten",
        [insn::fmt11n(0x12, 1, 0), insn::fmt11x(0x11, 1)].concat(),
    );

    assert_eq!(
        rendered_signature(&bytes, "overwritten"),
        "Object overwritten() {"
    );
}

#[test]
fn a_branch_that_bypasses_the_overwrite_retains_the_incoming_continuation() {
    let bytes: Vec<u8> = fixture(
        "SuspendProbe.kt",
        "branchUse",
        [
            insn::fmt11n(0x12, 0, 0),
            vec![0x38, 3],
            insn::fmt11n(0x12, 1, 0),
            insn::fmt11x(0x11, 1),
        ]
        .concat(),
    );

    assert_eq!(
        rendered_signature(&bytes, "branchUse"),
        "Object branchUse(kotlin.coroutines.Continuation arg0) {"
    );
}

#[test]
fn check_cast_reads_the_incoming_continuation_before_redefining_its_register() {
    let seed: Vec<u8> = fixture(
        "SuspendProbe.kt",
        "seed",
        [insn::fmt11n(0x12, 0, 0), insn::fmt11x(0x11, 0)].concat(),
    );
    let seed_dex = parse_dex(&seed).expect("seed dex parses");
    let continuation_index: u16 = seed_dex
        .type_names
        .iter()
        .position(|name: &String| name == CONTINUATION)
        .and_then(|index: usize| u16::try_from(index).ok())
        .expect("continuation type index fits the DEX instruction");
    let bytes: Vec<u8> = fixture(
        "SuspendProbe.kt",
        "checked",
        [
            insn::fmt21c(0x1f, 1, continuation_index),
            insn::fmt11n(0x12, 0, 0),
            insn::fmt11x(0x11, 0),
        ]
        .concat(),
    );

    assert_eq!(
        rendered_signature(&bytes, "checked"),
        "Object checked(kotlin.coroutines.Continuation arg0) {"
    );
}

#[test]
fn continuation_impl_subclasses_retain_the_compiler_bridge_parameter() {
    let bytes: Vec<u8> = fixture_with_super(
        "SuspendProbe.kt",
        "resumeWith",
        [insn::fmt11n(0x12, 0, 0), insn::fmt11x(0x11, 0)].concat(),
        "Lkotlin/coroutines/jvm/internal/ContinuationImpl;",
    );

    assert_eq!(
        rendered_signature(&bytes, "resumeWith"),
        "Object resumeWith(kotlin.coroutines.Continuation arg0) {"
    );
}

#[test]
fn metadata_present_compiled_kotlin_retains_the_continuation_abi() {
    let dex = parse_dex(EDGECASES_KT_DEX).expect("tracked Kotlin 2.1.20 D8 artifact parses");
    let out = decompile_dex(&dex, EDGECASES_KT_DEX);
    assert!(
        out.source
            .contains("asyncDouble(int arg0, kotlin.coroutines.Continuation arg1)"),
        "metadata-present Kotlin must retain its JVM continuation ABI: {}",
        out.source
    );
}

#[test]
fn generated_kotlin_d8_artifact_covers_the_suspend_abi_matrix() {
    let dex = parse_dex(GENERATED_KOTLIN_DEX).expect("Kotlin 2.1.20 D8 9.1.31 fixture parses");
    let out = decompile_dex(&dex, GENERATED_KOTLIN_DEX);
    assert!(
        out.source
            .contains("unusedContinuation(kotlin.coroutines.Continuation $completion)"),
        "metadata-present Kotlin retains its continuation ABI: {}",
        out.source
    );
    let stripped_dex =
        parse_dex(METADATA_STRIPPED_KOTLIN_DEX).expect("metadata-stripped DEX parses");
    let stripped_out = decompile_dex(&stripped_dex, METADATA_STRIPPED_KOTLIN_DEX);
    assert!(
        stripped_out.source.contains("unusedContinuation()"),
        "metadata-stripped unused ABI marker must be hidden: {}",
        stripped_out.source
    );
    for name in [
        "readContinuation",
        "returnContinuation",
        "forwardContinuation",
    ] {
        assert!(
            stripped_out
                .source
                .contains(&format!("Object {name}(kotlin.coroutines.Continuation")),
            "{name} must retain its used continuation: {}",
            stripped_out.source
        );
    }
    assert!(
        stripped_out
            .source
            .contains("Object storeContinuation(kotlin.coroutines.Continuation"),
        "a stored continuation remains explicit: {}",
        stripped_out.source
    );
    assert!(
        stripped_out
            .source
            .contains("Object callContinuation(kotlin.coroutines.Continuation"),
        "callContinuation must retain its used continuation: {}",
        stripped_out.source
    );
    assert!(
        stripped_out.source.contains("Object scriptUnused()"),
        "the compiler-produced .kts method recovers under the same bounded rule: {}",
        stripped_out.source
    );
    assert!(
        stripped_out
            .source
            .contains("actualStateMachine(kotlin.coroutines.Continuation"),
        "the compiled state-machine entry uses and therefore retains its continuation: {}",
        stripped_out.source
    );
    let continuation_impl: (&String, &String) = stripped_dex
        .class_super_descriptors
        .iter()
        .find(|(_, parent): &(&String, &String)| {
            parent.as_str() == "Lkotlin/coroutines/jvm/internal/ContinuationImpl;"
        })
        .expect("the compiler emitted an actual ContinuationImpl subclass");
    assert!(
        stripped_out
            .source
            .contains("actualStateMachine$_1(kotlin.coroutines.Continuation arg0)"),
        "the actual ContinuationImpl constructor remains explicit for {}: {}",
        continuation_impl.0,
        stripped_out.source
    );
}

#[test]
fn recovered_suspend_methods_recompile_and_match_authored_jvm_behavior() {
    let dex = parse_dex(METADATA_STRIPPED_KOTLIN_DEX).expect("metadata-stripped DEX parses");
    let recovered = decompile_dex(&dex, METADATA_STRIPPED_KOTLIN_DEX);
    let unused: String = recovered_method(
        &recovered.source,
        "public static Object unusedContinuation()",
    );
    let script: String = recovered_method(&recovered.source, "public Object scriptUnused()");
    let source: String = format!(
        "public final class RecoveredSuspend {{\n{unused}\n{script}\n    public static void main(String[] args) {{\n        System.out.println(unusedContinuation());\n        System.out.println(new RecoveredSuspend().scriptUnused());\n    }}\n}}\n"
    );
    let boxing: &str = "package kotlin.coroutines.jvm.internal;\npublic final class Boxing {\n    private Boxing() {}\n    public static Integer boxInt(int value) { return value; }\n}\n";
    let purpose: String = format!("disrobe-kotlin-suspend-{}", std::process::id());
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch directory");
    let root: &Path = scratch.path();
    let classes: PathBuf = root.join("classes");
    let boxing_dir: PathBuf = root.join("kotlin/coroutines/jvm/internal");
    std::fs::create_dir_all(&classes).expect("create class output directory");
    std::fs::create_dir_all(&boxing_dir).expect("create Boxing source directory");
    let recovered_path: PathBuf = root.join("RecoveredSuspend.java");
    let boxing_path: PathBuf = boxing_dir.join("Boxing.java");
    std::fs::write(&recovered_path, source).expect("write recovered source projection");
    std::fs::write(&boxing_path, boxing).expect("write typed Kotlin Boxing stub");
    let javac: PathBuf = required_tool("javac");
    let javac_args: [&Path; 6] = [
        Path::new("-proc:none"),
        Path::new("-d"),
        &classes,
        &recovered_path,
        &boxing_path,
        Path::new("-Xlint:all"),
    ];
    let (compiled, _, compile_errors): (bool, String, String) = run_tool(&javac, &javac_args);
    assert!(
        compiled,
        "exact recovered method blocks did not compile under javac: {compile_errors}"
    );
    let java: PathBuf = required_tool("java");
    let java_args: [&Path; 3] = [Path::new("-cp"), &classes, Path::new("RecoveredSuspend")];
    let (ran, output, run_errors): (bool, String, String) = run_tool(&java, &java_args);
    assert!(
        ran,
        "recompiled recovered methods failed JVM verification: {run_errors}"
    );
    assert_eq!(output.replace("\r\n", "\n"), "7\n11\n");
}

#[test]
fn metadata_only_derivative_preserves_method_annotations_and_repairs_dex_integrity() {
    let original = parse_dex(GENERATED_KOTLIN_DEX).expect("original DEX parses");
    let stripped = parse_dex(METADATA_STRIPPED_KOTLIN_DEX).expect("stripped DEX parses");
    assert_eq!(original.class_descriptors, stripped.class_descriptors);
    assert_eq!(original.method_ids, stripped.method_ids);
    assert_eq!(
        &METADATA_STRIPPED_KOTLIN_DEX[8..12],
        &0x0cc7_94f5u32.to_le_bytes()
    );
    assert_eq!(
        &METADATA_STRIPPED_KOTLIN_DEX[12..32],
        &[
            0x4c, 0x53, 0xcc, 0xa2, 0x88, 0x09, 0x85, 0x86, 0xb9, 0x9f, 0xb0, 0x85, 0xcc, 0xe8,
            0x9b, 0xa3, 0xeb, 0x58, 0xa6, 0x8d,
        ]
    );
    let directories: Vec<usize> = original
        .class_descriptors
        .iter()
        .map(|class: &String| annotation_directory_offset(GENERATED_KOTLIN_DEX, class))
        .collect();
    assert_eq!(directories, vec![5832, 5864, 5888]);
    let method_counts: Vec<u32> = directories
        .iter()
        .map(|directory: &usize| {
            u32::from_le_bytes(
                METADATA_STRIPPED_KOTLIN_DEX[*directory + 8..*directory + 12]
                    .try_into()
                    .expect("annotated-method count bytes"),
            )
        })
        .collect();
    assert_eq!(method_counts, vec![2, 1, 13]);
    assert!(directories.iter().all(|directory: &usize| {
        METADATA_STRIPPED_KOTLIN_DEX[*directory..*directory + 4] == [0, 0, 0, 0]
    }));
    let changed: Vec<usize> = GENERATED_KOTLIN_DEX
        .iter()
        .zip(METADATA_STRIPPED_KOTLIN_DEX)
        .enumerate()
        .filter_map(|(index, (before, after))| (before != after).then_some(index))
        .collect();
    assert!(
        changed.iter().all(|index: &usize| (8..32).contains(index)
            || directories
                .iter()
                .any(|directory: &usize| (*directory..*directory + 4).contains(index))),
        "the derivative may change only integrity fields and class-annotation references: {changed:?}"
    );
}

#[test]
fn malformed_annotation_evidence_fails_closed() {
    let facade: &str = "Lfixture/KotlinSuspendAbiKt;";
    let class_def: usize = class_def_offset(GENERATED_KOTLIN_DEX, facade);
    let annotation: usize = metadata_annotation_offset(GENERATED_KOTLIN_DEX, facade);
    let mut cases: Vec<Vec<u8>> = Vec::new();
    for malformed in [u32::MAX, 1u32] {
        let mut bytes: Vec<u8> = GENERATED_KOTLIN_DEX.to_vec();
        bytes[class_def + 20..class_def + 24].copy_from_slice(&malformed.to_le_bytes());
        cases.push(bytes);
    }
    let mut visibility: Vec<u8> = GENERATED_KOTLIN_DEX.to_vec();
    visibility[annotation] = 3;
    cases.push(visibility);
    let mut truncated_uleb: Vec<u8> = GENERATED_KOTLIN_DEX.to_vec();
    truncated_uleb[annotation + 1..annotation + 6].fill(0x80);
    cases.push(truncated_uleb);
    let mut overflowing_uleb: Vec<u8> = GENERATED_KOTLIN_DEX.to_vec();
    overflowing_uleb[annotation + 1..annotation + 5].fill(0x80);
    overflowing_uleb[annotation + 5] = 0x10;
    cases.push(overflowing_uleb);
    let mut invalid_type: Vec<u8> = GENERATED_KOTLIN_DEX.to_vec();
    invalid_type[annotation + 1] = 0x7f;
    cases.push(invalid_type);

    for bytes in cases {
        let dex = parse_dex(&bytes).expect("annotation mutation preserves the DEX tables");
        let out = decompile_dex(&dex, &bytes);
        assert!(
            out.source
                .contains("unusedContinuation(kotlin.coroutines.Continuation $completion)"),
            "malformed metadata evidence must retain the ABI parameter: {}",
            out.source
        );
    }
}

#[test]
fn fixture_provenance_binds_exact_sources_and_reproducible_outputs() {
    let expected: [(&str, String); 4] = [
        ("source_sha256", sha256(KOTLIN_SOURCE)),
        ("script_sha256", sha256(KOTLIN_SCRIPT)),
        ("dex_sha256", sha256(GENERATED_KOTLIN_DEX)),
        (
            "metadata_stripped_dex_sha256",
            sha256(METADATA_STRIPPED_KOTLIN_DEX),
        ),
    ];
    for (key, digest) in expected {
        assert!(
            PROVENANCE.contains(&format!("{key} = \"{digest}\"")),
            "provenance must bind {key} to {digest}"
        );
    }
    for command in [
        "kotlinc KotlinSuspendAbi.kt -jvm-target 17 -d KotlinSuspendAbi.jar",
        "kotlinc -language-version 1.9 -Xallow-any-scripts-in-source-roots KotlinSuspendScript.kts -jvm-target 17 -d KotlinSuspendScript.jar",
        "com.android.tools.r8.D8 --min-api 26 --output dex KotlinSuspendAbi.jar KotlinSuspendScript.jar",
    ] {
        assert!(
            PROVENANCE.contains(command),
            "missing exact command: {command}"
        );
    }
}
