#![allow(clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use disrobe_core::scratch::ScratchDir;
use disrobe_pass_jvm::dex2jar::{Dex2JarResult, translate_dex_bytes};
use disrobe_pass_jvm::{
    ClassFile, DecompiledClass, DecompiledDex, DexFile, decompile_class, decompile_dex,
    parse_classfile, parse_dex,
};

const EDGECASES_DEX: &[u8] = include_bytes!("../../../corpus/jvm/dex/EdgeCases.dex");
const HELLO_DEX: &[u8] = include_bytes!("../../../corpus/jvm/dex/Hello.dex");

const PROBE_FILE: &str = "TypeCheckReached.java";
const PROBE_SOURCE: &str = "final class TypeCheckReached {\n    static final Object VALUE = \
                            typeCheckReachedSymbolThatCannotResolve;\n}\n";

fn is_identifier_start(c: char) -> bool {
    c.is_alphabetic() || c == '$' || c == '_'
}

fn is_identifier_part(c: char) -> bool {
    c.is_alphanumeric() || c == '$' || c == '_'
}

fn unwritable_identifiers(source: &str) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    for line in source.lines() {
        let code: &str = line.split('"').next().unwrap_or(line);
        let mut current: String = String::new();
        for c in code.chars() {
            if is_identifier_part(c) || c == '-' {
                current.push(c);
                continue;
            }
            if !current.is_empty() {
                found.extend(unwritable_token(&current));
                current.clear();
            }
        }
        found.extend(unwritable_token(&current));
    }
    found.sort_unstable();
    found.dedup();
    found
}

fn unwritable_token(token: &str) -> Option<String> {
    if token.is_empty() || token.chars().all(|c: char| c == '-') {
        return None;
    }
    let numeric_literal: bool = token
        .trim_start_matches('-')
        .chars()
        .next()
        .is_some_and(|c: char| c.is_ascii_digit());
    if numeric_literal {
        return None;
    }
    let mut chars: core::str::Chars<'_> = token.chars();
    let start_ok: bool = chars.next().is_some_and(is_identifier_start);
    if start_ok && chars.all(is_identifier_part) {
        return None;
    }
    Some(token.to_owned())
}

#[test]
fn every_identifier_the_dalvik_recovery_emits_can_be_written_in_java() {
    let dex: DexFile = parse_dex(EDGECASES_DEX).expect("parse EdgeCases.dex");
    let recovered: DecompiledDex = decompile_dex(&dex, EDGECASES_DEX);
    let offenders: Vec<String> = unwritable_identifiers(&recovered.source);
    assert!(
        offenders.is_empty(),
        "the recovered source carries {} identifier(s) that no Java compiler can parse, so the \
         whole file stops at the parser and no method in it can be graded: {offenders:?}. D8 and \
         R8 emit nest-access bridges and interface companions whose names contain characters that \
         are legal in a dex and illegal in Java source; every one of them has to be rewritten at \
         the declaration and at every reference alike",
        offenders.len()
    );
}

#[test]
fn distinct_unwritable_names_never_collapse_onto_one_legal_name() {
    let originals: [&str; 8] = [
        "-$$Nest$sfgetCTR",
        "+$$Nest$sfgetCTR",
        "-$$Nest$sfgetOTHER",
        "a-b",
        "a+b",
        "a b",
        "0leading",
        "class",
    ];
    let mut seen: std::collections::BTreeMap<String, &str> = std::collections::BTreeMap::new();
    for original in originals {
        let rewritten: String = disrobe_pass_jvm::java_writable_identifier(original);
        assert!(
            unwritable_token(&rewritten).is_none(),
            "`{original}` rewrote to `{rewritten}`, which java still cannot parse"
        );
        if let Some(previous) = seen.insert(rewritten.clone(), original) {
            panic!(
                "`{previous}` and `{original}` both rewrote to `{rewritten}`. Two distinct names \
                 in a dex collapsing onto one java name silently merges two members, which is a \
                 worse defect than the syntax error the rewrite exists to remove"
            );
        }
    }
}

fn classfile_route_sources(dex_bytes: &[u8]) -> BTreeMap<String, String> {
    let translated: Dex2JarResult = translate_dex_bytes(dex_bytes).expect("translate the dex");
    let mut sources: BTreeMap<String, String> = BTreeMap::new();
    for (entry, bytes) in &translated.jar_entries {
        let Some(stem): Option<&str> = entry.strip_suffix(".class") else {
            continue;
        };
        let class: ClassFile = parse_classfile(bytes).expect("parse the translated class");
        let recovered: DecompiledClass = decompile_class(&class);
        sources.insert(format!("{stem}.java"), recovered.source);
    }
    assert!(
        !sources.is_empty(),
        "the classfile route has to emit at least one source file"
    );
    sources
}

fn jvm_name_call_sites(sources: &BTreeMap<String, String>) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    for (path, source) in sources {
        for (index, line) in source.lines().enumerate() {
            if line.contains(".<init>(") || line.contains(".<clinit>(") {
                found.push(format!("{path}:{}: {}", index + 1, line.trim()));
            }
        }
    }
    found
}

fn find_on_path(name: &str) -> Option<PathBuf> {
    let path_var: std::ffi::OsString = std::env::var_os("PATH")?;
    let exts: &[&str] = if cfg!(windows) { &["", ".exe"] } else { &[""] };
    for dir in std::env::split_paths(&path_var) {
        for ext in exts {
            let candidate: PathBuf = dir.join(format!("{name}{ext}"));
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

fn javac_reached_type_checking(sources: &BTreeMap<String, String>) -> bool {
    let javac: PathBuf = find_on_path("javac")
        .expect("javac (JDK) has to be on PATH; a compiler this gate cannot run grades nothing");
    let scratch: ScratchDir = ScratchDir::create("disrobe_writable_java").expect("scratch dir");
    let dir: &Path = scratch.path();
    let mut written: Vec<PathBuf> = Vec::with_capacity(sources.len() + 1);
    for (relative, text) in sources {
        let path: PathBuf = dir.join(relative);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("source directory");
        }
        std::fs::write(&path, text).expect("write the recovered source");
        written.push(path);
    }
    let probe: PathBuf = dir.join(PROBE_FILE);
    std::fs::write(&probe, PROBE_SOURCE).expect("write the type-check probe");
    written.push(probe);

    let stub: PathBuf = dir.join("cp");
    std::fs::create_dir(&stub).expect("stub classpath");
    let out_dir: PathBuf = dir.join("out");
    std::fs::create_dir(&out_dir).expect("javac output directory");
    let mut command: Command = Command::new(&javac);
    command
        .arg("-nowarn")
        .arg("-proc:none")
        .arg("-Xmaxerrs")
        .arg("100000")
        .arg("-cp")
        .arg(&stub)
        .arg("-d")
        .arg(&out_dir);
    for source in &written {
        command.arg(source);
    }
    let output: Output = command.output().expect("run javac");
    assert!(
        !output.status.success(),
        "the type-check probe compiled without reporting its unresolvable symbol, so it can no \
         longer tell a parsed file from an unparsed one"
    );
    let diagnostics: String = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );
    diagnostics.contains(PROBE_FILE)
}

#[test]
fn a_deferred_constructor_call_is_emitted_as_one_allocation() {
    let sources: BTreeMap<String, String> = classfile_route_sources(HELLO_DEX);
    let main: &String = sources
        .get("Hello.java")
        .expect("the classfile route emits Hello.java");
    assert!(
        main.contains("= new Hello(arg0)"),
        "the allocation and the constructor call it belongs to have to arrive as one assignment, \
         with the arguments the constructor was actually passed:\n{main}"
    );
    assert!(
        !main.contains("new Hello()"),
        "emitting a no-argument allocation beside the merged one calls a constructor that may not \
         exist, which reads as correct source and is not:\n{main}"
    );
}

#[test]
fn no_recovered_source_calls_a_method_by_its_jvm_internal_name() {
    for dex_bytes in [HELLO_DEX, EDGECASES_DEX] {
        let sources: BTreeMap<String, String> = classfile_route_sources(dex_bytes);
        let offenders: Vec<String> = jvm_name_call_sites(&sources);
        assert!(
            offenders.is_empty(),
            "`<init>` and `<clinit>` are legal in a class file and illegal in java source, so a \
             call written under either name stops the compiler at the parser and certifies no \
             method in that file: {offenders:?}"
        );
    }
}

#[test]
fn javac_parses_the_unit_the_classfile_route_recovers_from_hello_dex() {
    let sources: BTreeMap<String, String> = classfile_route_sources(HELLO_DEX);
    assert!(
        javac_reached_type_checking(&sources),
        "real javac never reached type checking over the recovered unit, which means it stopped at \
         a parse defect and no method in the file can be graded"
    );
}

#[test]
fn a_rewritten_name_is_stable_between_its_declaration_and_its_uses() {
    let dex: DexFile = parse_dex(EDGECASES_DEX).expect("parse EdgeCases.dex");
    let recovered: DecompiledDex = decompile_dex(&dex, EDGECASES_DEX);
    let joined: String = recovered.source;
    let expected: String = disrobe_pass_jvm::java_writable_identifier("-$$Nest$sfgetCTR");
    assert_ne!(
        expected, "-$$Nest$sfgetCTR",
        "the name under test has to be one the rewrite actually changes"
    );
    assert!(
        joined.contains(&format!("{expected}(")),
        "the nest-access bridge has to survive the rewrite under the one name the rewriter chose, \
         `{expected}`, not disappear and not appear under a second spelling"
    );
    assert!(
        !joined.contains("-$$Nest"),
        "no reference may keep the original unwritable spelling once the declaration was rewritten"
    );
}
