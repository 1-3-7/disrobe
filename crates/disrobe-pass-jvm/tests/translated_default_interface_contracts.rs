#![allow(clippy::expect_used)]

use std::path::PathBuf;
use std::process::{Command, Output};

use disrobe_core::scratch::ScratchDir;
use disrobe_pass_jvm::{BackendPreference, android_decompile_dex};

const EDGECASES_DEX: &[u8] = include_bytes!("../../../corpus/jvm/dex/EdgeCases.dex");
const ATTRIBUTION_PROBE_FILE: &str = "TypeCheckReached.java";
const ATTRIBUTION_PROBE_SOURCE: &str = "final class TypeCheckReached {\n    static final Object VALUE = typeCheckReachedSymbolThatCannotResolve;\n}\n";

fn javac() -> PathBuf {
    std::env::split_paths(&std::env::var_os("PATH").expect("PATH for javac"))
        .map(|directory: PathBuf| directory.join(if cfg!(windows) { "javac.exe" } else { "javac" }))
        .find(|candidate: &PathBuf| candidate.is_file())
        .expect("javac on PATH")
}

fn compile_sources(sources: &std::collections::BTreeMap<String, String>) -> Output {
    let scratch: ScratchDir = ScratchDir::create("translated-interface-contracts")
        .expect("create javac scratch directory");
    let mut paths: Vec<PathBuf> = Vec::with_capacity(sources.len());
    for (relative, source) in sources {
        let path: PathBuf = scratch.path().join(relative);
        std::fs::create_dir_all(path.parent().expect("source parent"))
            .expect("create source parent");
        std::fs::write(&path, source).expect("write recovered source");
        paths.push(path);
    }
    let mut command: Command = Command::new(javac());
    command
        .current_dir(scratch.path())
        .arg("-XDrawDiagnostics")
        .arg("-Xmaxerrs")
        .arg("1000")
        .arg("-d")
        .arg(scratch.path().join("classes"));
    command
        .args(paths)
        .output()
        .expect("compile recovered sources")
}

#[test]
fn translated_d8_sources_have_no_public_path_or_default_contract_defects() {
    let recovered = android_decompile_dex(EDGECASES_DEX, BackendPreference::PreferInHouse)
        .expect("recover EdgeCases.dex through the translated-class route");
    let edgecases: &String = recovered
        .sources
        .get("EdgeCases.java")
        .expect("recover EdgeCases.java");

    assert!(
        recovered.sources.contains_key("EdgeCases_u002D_IA.java"),
        "the source path must use the escaped public declaration identifier"
    );
    assert!(!recovered.sources.contains_key("EdgeCases-IA.java"));
    assert!(
        edgecases.contains("public default String label()"),
        "{edgecases}"
    );
    assert!(
        edgecases.contains("new StringBuilder(\"shape:\")"),
        "{edgecases}"
    );
    assert!(
        !edgecases.contains("public abstract String label();"),
        "{edgecases}"
    );
    assert_eq!(
        edgecases.matches(" String label(").count(),
        1,
        "{edgecases}"
    );

    let mut probed_sources: std::collections::BTreeMap<String, String> = recovered.sources.clone();
    assert!(
        probed_sources
            .insert(
                ATTRIBUTION_PROBE_FILE.to_owned(),
                ATTRIBUTION_PROBE_SOURCE.to_owned()
            )
            .is_none(),
        "the attribution probe must not replace a recovered source"
    );
    let compiled: Output = compile_sources(&probed_sources);
    let diagnostics: String = String::from_utf8_lossy(&compiled.stderr).into_owned();
    assert!(
        diagnostics.lines().any(|line: &str| {
            line.contains(ATTRIBUTION_PROBE_FILE) && line.contains("compiler.err.cant.resolve")
        }),
        "javac did not reach attribution, so zero attribution diagnostics prove nothing:\n{diagnostics}"
    );
    assert_eq!(
        diagnostics
            .matches("compiler.err.class.public.should.be.in.file")
            .count(),
        0,
        "{diagnostics}"
    );
    assert_eq!(
        diagnostics
            .matches("compiler.err.does.not.override.abstract")
            .count(),
        0,
        "{diagnostics}"
    );
}

#[test]
fn translated_public_identifier_source_compiles_in_isolation() {
    let recovered = android_decompile_dex(EDGECASES_DEX, BackendPreference::PreferInHouse)
        .expect("recover EdgeCases.dex through the translated-class route");
    let source: String = recovered
        .sources
        .get("EdgeCases_u002D_IA.java")
        .expect("recover escaped public source path")
        .clone();
    let sources =
        std::collections::BTreeMap::from([("EdgeCases_u002D_IA.java".to_owned(), source)]);
    let compiled: Output = compile_sources(&sources);
    assert!(
        compiled.status.success(),
        "isolated escaped public source did not compile:\n{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
}
