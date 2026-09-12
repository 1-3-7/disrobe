#![allow(clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use disrobe_core::scratch::ScratchDir;
use disrobe_pass_jvm::{DecompiledDex, DexFile, decompile_dex, parse_dex};

const LOW_MINIMUM: &[u8] =
    include_bytes!("../../../corpus/jvm/desugar-core/CoreLibraryProbe-min21.dex");
const DEBUG_MINIMUM: &[u8] =
    include_bytes!("../../../corpus/jvm/desugar-core/CoreLibraryProbe-min21-debug.dex");
const HIGH_MINIMUM: &[u8] =
    include_bytes!("../../../corpus/jvm/desugar-core/CoreLibraryProbe-min34.dex");
const IDENTIFIER: &str = "com.tools.android:desugar_jdk_libs_configuration:2.1.5";
const AUTHORED: &str = include_str!("../../../corpus/jvm/desugar-core/CoreLibraryProbe.java");
const EXPECTED_RECOVERED: &str =
    include_str!("../../../corpus/jvm/desugar-core/CoreLibraryProbe.recovered.java.txt");
const HARNESS: &str = r#"package fixtures.desugar;

import java.nio.file.LinkOption;
import java.nio.file.Paths;
import java.util.Arrays;

public final class CoreLibraryHarness {
    public static void main(String[] args) {
        System.out.println(CoreLibraryProbe.duration(2).toMinutes());
        System.out.println(CoreLibraryProbe.seconds(2));
        System.out.println(CoreLibraryProbe.range(1, 4).sum());
        System.out.println(CoreLibraryProbe.identity().apply("identity"));
        System.out.println(CoreLibraryProbe.optional("optional").orElse("missing"));
        System.out.println(CoreLibraryProbe.collection(Arrays.asList("a", "b")).count());
        System.out.println(CoreLibraryProbe.exists(Paths.get(args[0]), new LinkOption[0]));
    }
}
"#;

fn source(bytes: &[u8]) -> String {
    let dex: DexFile = parse_dex(bytes).expect("parse D8 compiler artifact");
    decompile_dex(&dex, bytes).source
}

fn source_from(dex: &DexFile, bytes: &[u8]) -> String {
    let recovered: DecompiledDex = decompile_dex(dex, bytes);
    recovered
        .sources
        .get("fixtures/desugar/CoreLibraryProbe.java")
        .expect("recover authored compilation unit")
        .clone()
}

fn compile_and_run(label: &str, sources: &[(String, String)]) -> Output {
    let scratch: ScratchDir = ScratchDir::create(label).expect("create Java scratch directory");
    let source_root: PathBuf = scratch.path().join("src");
    let classes: PathBuf = scratch.path().join("classes");
    std::fs::create_dir_all(&classes).expect("create Java class output");
    let mut paths: Vec<PathBuf> = Vec::with_capacity(sources.len());
    for (relative, source) in sources {
        let path: PathBuf = source_root.join(relative);
        let parent: &Path = path.parent().expect("source path parent");
        std::fs::create_dir_all(parent).expect("create Java source parent");
        std::fs::write(&path, source).expect("write Java source");
        paths.push(path);
    }
    let harness_path: PathBuf = source_root.join("fixtures/desugar/CoreLibraryHarness.java");
    std::fs::write(&harness_path, HARNESS).expect("write Java behavior harness");
    paths.push(harness_path);
    let compile: Output = Command::new("javac")
        .arg("--release")
        .arg("11")
        .arg("-d")
        .arg(&classes)
        .args(&paths)
        .output()
        .expect("run javac");
    assert!(
        compile.status.success(),
        "javac rejected {label}: {}",
        String::from_utf8_lossy(&compile.stderr)
    );
    Command::new("java")
        .arg("-cp")
        .arg(classes)
        .arg("fixtures.desugar.CoreLibraryHarness")
        .arg(scratch.path().join("missing"))
        .output()
        .expect("run Java")
}

#[test]
fn broad_relocation_requires_the_supported_marker_and_no_program_owned_j_prefix() {
    let parsed: DexFile = parse_dex(LOW_MINIMUM).expect("parse low-minimum D8 artifact");
    let mut missing_marker: DexFile = parsed.clone();
    missing_marker
        .strings
        .retain(|value: &String| !value.starts_with("~~D8"));
    let missing_source: String = source_from(&missing_marker, LOW_MINIMUM);
    assert!(
        missing_source.contains("$-EL") || missing_source.contains("j$__0"),
        "missing marker must preserve generated identities:\n{missing_source}"
    );
    assert!(
        missing_source.contains("DR-JVM-CORE-0001"),
        "{missing_source}"
    );
    assert!(
        missing_source.contains("java.util.concurrent.TimeUnit.SECONDS.convert"),
        "{missing_source}"
    );
    assert!(
        !missing_source.contains("DesugarTimeUnit"),
        "{missing_source}"
    );

    let mut unknown_identifier: DexFile = parsed.clone();
    for value in &mut unknown_identifier.strings {
        if value.starts_with("~~D8") {
            *value = value.replace(IDENTIFIER, "unknown:configuration:9.9.9");
        }
    }
    let unknown_source: String = source_from(&unknown_identifier, LOW_MINIMUM);
    assert!(
        unknown_source.contains("$-EL") || unknown_source.contains("j$__0"),
        "unknown configuration must preserve generated identities:\n{unknown_source}"
    );
    assert!(
        unknown_source.contains("DR-JVM-CORE-0002"),
        "{unknown_source}"
    );

    let mut conflicting_identifiers: DexFile = parsed.clone();
    conflicting_identifiers.strings.push(
        r#"~~D8{"desugared-library-identifiers":["unknown:configuration:9.9.9"]}"#.to_string(),
    );
    let conflicting_source: String = source_from(&conflicting_identifiers, LOW_MINIMUM);
    assert!(
        conflicting_source.contains("$-EL") || conflicting_source.contains("j$__0"),
        "conflicting configuration markers must preserve generated identities:\n{conflicting_source}"
    );
    assert!(
        conflicting_source.contains("DR-JVM-CORE-0002"),
        "{conflicting_source}"
    );

    let mut malformed_marker: DexFile = parsed.clone();
    malformed_marker.strings.push("~~R8{".to_string());
    let malformed_source: String = source_from(&malformed_marker, LOW_MINIMUM);
    assert!(
        malformed_source.contains("$-EL") || malformed_source.contains("j$__0"),
        "malformed configuration marker must preserve generated identities:\n{malformed_source}"
    );
    assert!(
        malformed_source.contains("DR-JVM-CORE-0002"),
        "{malformed_source}"
    );

    let mut owned_prefix: DexFile = parsed;
    owned_prefix
        .class_descriptors
        .push("Lj$/application/Owned;".to_string());
    let collision_source: String = source_from(&owned_prefix, LOW_MINIMUM);
    assert!(
        collision_source.contains("$-EL") || collision_source.contains("j$__0"),
        "program-owned j$ prefix must prevent broad relocation:\n{collision_source}"
    );
    assert!(
        collision_source.contains("DR-JVM-CORE-0003"),
        "{collision_source}"
    );

    let mut owned_helper: DexFile = missing_marker;
    owned_helper
        .class_descriptors
        .push("Lj$/util/concurrent/DesugarTimeUnit;".to_string());
    let helper_source: String = source_from(&owned_helper, LOW_MINIMUM);
    assert!(
        helper_source.contains("DesugarTimeUnit"),
        "program-owned exact helper must remain unchanged:\n{helper_source}"
    );

    let mut wrong_helper_descriptor: DexFile = parse_dex(LOW_MINIMUM).expect("parse helper source");
    let time_unit: &mut disrobe_pass_jvm::dex::MethodId = wrong_helper_descriptor
        .method_ids
        .iter_mut()
        .find(|method: &&mut disrobe_pass_jvm::dex::MethodId| {
            method.class == "Lj$/util/concurrent/DesugarTimeUnit;" && method.name == "convert"
        })
        .expect("find exact retarget helper");
    time_unit.proto.return_type = "I".to_string();
    let wrong_helper_source: String = source_from(&wrong_helper_descriptor, LOW_MINIMUM);
    assert!(
        wrong_helper_source.contains("DesugarTimeUnit"),
        "wrong helper descriptor must remain unchanged:\n{wrong_helper_source}"
    );
    assert!(
        wrong_helper_source.contains("DR-JVM-CORE-0004"),
        "{wrong_helper_source}"
    );

    for (owner, witness) in [
        ("Lj$/util/Optional$Wrapper;", "Wrapper"),
        ("Lj$/nio/file/PathApiFlips;", "ApiFlips"),
    ] {
        let mut unsupported_adapter: DexFile =
            parse_dex(LOW_MINIMUM).expect("parse adapter source");
        let adapter: &mut disrobe_pass_jvm::dex::MethodId = unsupported_adapter
            .method_ids
            .iter_mut()
            .find(|method: &&mut disrobe_pass_jvm::dex::MethodId| {
                method.class == "Lj$/util/concurrent/DesugarTimeUnit;"
            })
            .expect("find helper to mutate into adapter");
        adapter.class = owner.to_string();
        let adapter_source: String = source_from(&unsupported_adapter, LOW_MINIMUM);
        assert!(adapter_source.contains(witness), "{adapter_source}");
        assert!(
            adapter_source.contains("DR-JVM-CORE-0004"),
            "{adapter_source}"
        );
    }

    let mut wrong_receiver: DexFile = parse_dex(LOW_MINIMUM).expect("parse mutation source");
    let collection: &mut disrobe_pass_jvm::dex::MethodId = wrong_receiver
        .method_ids
        .iter_mut()
        .find(|method: &&mut disrobe_pass_jvm::dex::MethodId| {
            method.class == "Lj$/util/Collection$-EL;" && method.name == "stream"
        })
        .expect("find receiver-first helper");
    collection.proto.parameters = vec!["Ljava/lang/Object;".to_string()];
    let wrong_receiver_source: String = source_from(&wrong_receiver, LOW_MINIMUM);
    assert!(
        wrong_receiver_source.contains("$-EL") || wrong_receiver_source.contains("j$__0"),
        "wrong receiver descriptor must abstain:\n{wrong_receiver_source}"
    );
    assert!(
        wrong_receiver_source.contains("DR-JVM-CORE-0004"),
        "{wrong_receiver_source}"
    );

    let mut wrong_arity: DexFile = parse_dex(LOW_MINIMUM).expect("parse arity mutation source");
    let arity_target: &mut disrobe_pass_jvm::dex::MethodId = wrong_arity
        .method_ids
        .iter_mut()
        .find(|method: &&mut disrobe_pass_jvm::dex::MethodId| {
            method.class == "Lj$/util/Collection$-EL;" && method.name == "stream"
        })
        .expect("find receiver-first arity target");
    arity_target.proto.parameters.push("I".to_string());
    let wrong_arity_source: String = source_from(&wrong_arity, LOW_MINIMUM);
    assert!(
        wrong_arity_source.contains("$-EL") || wrong_arity_source.contains("j$__0"),
        "wrong invocation arity must abstain:\n{wrong_arity_source}"
    );
}

#[test]
fn real_d8_core_library_calls_return_to_the_high_minimum_source_shape() {
    let low: DexFile = parse_dex(LOW_MINIMUM).expect("parse low-minimum D8 artifact");
    assert!(low.strings.iter().any(|value: &String| {
        value.starts_with("~~D8")
            && value.contains(IDENTIFIER)
            && value.contains(r#""compilation-mode":"release""#)
    }));
    let debug: DexFile = parse_dex(DEBUG_MINIMUM).expect("parse debug D8 artifact");
    assert!(debug.strings.iter().any(|value: &String| {
        value.starts_with("~~D8")
            && value.contains(IDENTIFIER)
            && value.contains(r#""compilation-mode":"debug""#)
    }));
    for witness in [
        "Lj$/time/Duration;",
        "Lj$/util/Optional;",
        "Lj$/util/concurrent/DesugarTimeUnit;",
        "Lj$/util/function/Function$-CC;",
        "Lj$/util/stream/IntStream$-CC;",
        "Lj$/util/Collection$-EL;",
    ] {
        assert!(
            low.type_names.iter().any(|value: &String| value == witness),
            "the real D8 artifact must retain {witness}"
        );
    }

    let low_source: String = source(LOW_MINIMUM);
    let debug_source: String = source(DEBUG_MINIMUM);
    let high_source: String = source(HIGH_MINIMUM);
    assert_eq!(low_source, EXPECTED_RECOVERED);
    assert_eq!(debug_source, EXPECTED_RECOVERED);
    assert!(!low_source.contains("DR-JVM-CORE-"), "{low_source}");
    for generated in ["j$.", "$-EL", "$-CC", "DesugarTimeUnit"] {
        assert!(
            !low_source.contains(generated),
            "recovered source retained {generated}:\n{low_source}"
        );
    }
    for original in [
        "java.time.Duration.ofMinutes",
        "java.util.concurrent.TimeUnit.SECONDS.convert",
        "java.util.stream.IntStream.range",
        "java.util.function.Function.identity",
        "java.util.Optional.of",
        "java.nio.file.Files.exists",
    ] {
        assert!(
            low_source.contains(original),
            "missing {original}:\n{low_source}"
        );
        assert!(
            high_source.contains(original),
            "high-minimum reference lost {original}"
        );
    }

    let recovered: DecompiledDex = decompile_dex(&low, LOW_MINIMUM);
    let recovered_sources: Vec<(String, String)> = recovered.sources.into_iter().collect();
    let authored_output: Output = compile_and_run(
        "d8-core-library-authored",
        &[(
            "fixtures/desugar/CoreLibraryProbe.java".to_string(),
            AUTHORED.to_string(),
        )],
    );
    let recovered_output: Output = compile_and_run("d8-core-library-recovered", &recovered_sources);
    assert!(authored_output.status.success());
    assert!(recovered_output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&authored_output.stdout)
            .lines()
            .collect::<Vec<&str>>(),
        ["2", "120", "6", "identity", "optional", "2", "false"]
    );
    assert_eq!(recovered_output.stdout, authored_output.stdout);
}
