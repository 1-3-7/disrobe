#![allow(clippy::expect_used, clippy::panic)]

use disrobe_pass_jvm::{DecompiledDex, DexFile, decompile_dex, parse_dex};

const EDGECASES_DEX: &[u8] = include_bytes!("../../../corpus/jvm/dex/EdgeCases.dex");
const WIDGET_CLEAN_DEX: &[u8] =
    include_bytes!("../../../corpus/jvm/dex/obfuscators/r8/Widget-clean.dex");

fn recovered(dex_bytes: &[u8]) -> DecompiledDex {
    let dex: DexFile = parse_dex(dex_bytes).expect("parse the dex");
    decompile_dex(&dex, dex_bytes)
}

fn package_declarations(source: &str) -> Vec<&str> {
    source
        .lines()
        .map(str::trim_start)
        .filter(|line: &&str| line.starts_with("package ") && line.ends_with(';'))
        .collect()
}

#[test]
fn every_emitted_source_is_one_compilation_unit() {
    for dex_bytes in [EDGECASES_DEX, WIDGET_CLEAN_DEX] {
        let out: DecompiledDex = recovered(dex_bytes);
        assert!(
            !out.sources.is_empty(),
            "the recovery has to emit at least one source file"
        );
        for (path, source) in &out.sources {
            let declarations: Vec<&str> = package_declarations(source);
            assert!(
                declarations.len() <= 1,
                "`{path}` carries {} package declarations. A java file may declare a package once \
                 and only as its first statement, so a file that repeats it cannot be compiled at \
                 all, whatever its method bodies look like: {declarations:?}",
                declarations.len()
            );
            if let Some(first) = declarations.first() {
                let leading: Option<&str> = source
                    .lines()
                    .map(str::trim_start)
                    .find(|line: &&str| !line.is_empty());
                assert_eq!(
                    leading,
                    Some(*first),
                    "`{path}` declares its package after other content, which java rejects"
                );
            }
        }
    }
}

#[test]
fn a_public_class_is_emitted_into_the_file_java_requires() {
    let out: DecompiledDex = recovered(WIDGET_CLEAN_DEX);
    for (path, source) in &out.sources {
        let leaf: &str = path.rsplit('/').next().unwrap_or(path);
        let stem: &str = leaf.trim_end_matches(".java");
        let declares_public: bool = source
            .lines()
            .any(|line: &str| line.starts_with(&format!("public class {stem} ")));
        assert!(
            declares_public,
            "`{path}` has to hold the public class named after it, because javac refuses a public \
             class declared in any other file"
        );
    }
}

#[test]
fn the_split_sources_cover_the_same_classes_as_the_concatenation() {
    let out: DecompiledDex = recovered(EDGECASES_DEX);
    let concatenated_classes: usize = out
        .source
        .lines()
        .filter(|line: &&str| {
            line.starts_with("public class ") || line.starts_with("public abstract class ")
        })
        .count();
    let split_classes: usize = out
        .sources
        .values()
        .flat_map(|source: &String| source.lines())
        .filter(|line: &&str| {
            line.starts_with("public class ") || line.starts_with("public abstract class ")
        })
        .count();
    assert_eq!(
        concatenated_classes, split_classes,
        "splitting the output into files must not lose or duplicate a class"
    );
}
