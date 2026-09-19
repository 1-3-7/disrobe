#![allow(clippy::expect_used, clippy::panic)]

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use disrobe_core::scratch::ScratchDir;
use disrobe_pass_jvm::classfile::MethodInfo;
use disrobe_pass_jvm::descriptor::{JavaType, parse_method};
use disrobe_pass_jvm::{
    AndroidDecompileOutput, BackendPreference, ClassFile, DecompiledClass, Dex2JarResult,
    android_decompile_dex, decompile_class_with_inners, parse_classfile, translate_dex_bytes,
};

pub mod common;

const PROBE_SOURCE: &str = r#"public class AnonymousTypeProbe {
    interface Job { int run(); }
    static class Base { int run() { return 0; } }

    static Job interfaceBody() {
        Job value = new Job() {
            public int run() { return 1; }
        };
        return value;
    }

    static Base superclassBody() {
        Base value = new Base() {
            int run() { return 2; }
        };
        return value;
    }

    static Object mixedReuse(boolean selectAnonymous) {
        if (selectAnonymous) {
            Job value = new Job() {
                public int run() { return 3; }
            };
            if (value.run() == 3) return value;
        }
        String value = new String("plain");
        return value;
    }
}
"#;

const EDGECASES_DEX: &[u8] = include_bytes!("../../../corpus/jvm/dex/EdgeCases.dex");
const EDGECASES_METHOD_TOTAL: usize = 215;
const ANONYMOUS_METHOD_TOTAL: usize = 20;
const ANONYMOUS_DECLARATION_TOTAL: usize = 21;
const AFFECTED_METHODS: [&str; ANONYMOUS_METHOD_TOTAL] = [
    "adderFn()",
    "closureCaptureLoop(int)",
    "constantInt(int)",
    "debugSink()",
    "executeWith(Executor, Supplier)",
    "formatter()",
    "synthLambda$chain$2(Integer)",
    "synthLambda$closureCaptureLoop$0(int)",
    "synthLambda$closureCaptureLoop$1(List)",
    "listSupplier()",
    "mapBuilder()",
    "memoize(Supplier)",
    "multiplier(int)",
    "nestedAnon(int)",
    "nonNull(Stream)",
    "reducerFn()",
    "repeat(Object, int)",
    "squares(int)",
    "totalArea(List)",
    "wordCount(String)",
];
const NEWLY_CLEAN: [&str; 15] = [
    "adderFn()",
    "closureCaptureLoop(int)",
    "constantInt(int)",
    "debugSink()",
    "formatter()",
    "synthLambda$closureCaptureLoop$0(int)",
    "synthLambda$closureCaptureLoop$1(List)",
    "listSupplier()",
    "mapBuilder()",
    "memoize(Supplier)",
    "multiplier(int)",
    "nestedAnon(int)",
    "nonNull(Stream)",
    "reducerFn()",
    "squares(int)",
];
const BASELINE_CLEAN: usize = 129;
const CANDIDATE_CLEAN: usize = 144;
const ATTRIBUTION_PROBE_FILE: &str = "TypeCheckReached.java";
const ATTRIBUTION_PROBE_SOURCE: &str = "final class TypeCheckReached {\n    static final Object VALUE = typeCheckReachedSymbolThatCannotResolve;\n}\n";
const JAVAC_TIMEOUT: Duration = Duration::from_secs(30);
const JAVAC_CAPTURE_LIMIT: usize = 16 * 1024 * 1024;

fn compiled_probe() -> (ScratchDir, BTreeMap<String, ClassFile>) {
    compiled_java(
        "anonymous_inner_declaration_type",
        "AnonymousTypeProbe",
        PROBE_SOURCE,
    )
}

fn compiled_java(
    scratch_name: &str,
    class_name: &str,
    source: &str,
) -> (ScratchDir, BTreeMap<String, ClassFile>) {
    let javac: PathBuf = common::find_on_path("javac").expect("javac is required for this test");
    let scratch: ScratchDir = ScratchDir::create(scratch_name).expect("create scratch directory");
    let source_path: PathBuf = scratch.path().join(format!("{class_name}.java"));
    std::fs::write(&source_path, source).expect("write probe source");
    let output: std::process::Output = Command::new(javac)
        .arg("-g:none")
        .arg("-d")
        .arg(scratch.path())
        .arg(&source_path)
        .output()
        .expect("run javac");
    assert!(
        output.status.success(),
        "probe compilation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let mut classes: BTreeMap<String, ClassFile> = BTreeMap::new();
    for entry in std::fs::read_dir(scratch.path()).expect("read probe output") {
        let path: PathBuf = entry.expect("read probe entry").path();
        if path.extension().and_then(std::ffi::OsStr::to_str) != Some("class") {
            continue;
        }
        let file_name: String = path
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .expect("class file name")
            .to_owned();
        let bytes: Vec<u8> = std::fs::read(&path).expect("read probe class");
        classes.insert(
            file_name,
            parse_classfile(&bytes).expect("parse probe class"),
        );
    }
    (scratch, classes)
}

fn decompile_probe(classes: &BTreeMap<String, ClassFile>) -> String {
    let main: &ClassFile = classes
        .get("AnonymousTypeProbe.class")
        .expect("main probe class");
    decompile_class_with_inners(main, classes).source
}

#[test]
fn successful_anonymous_inlines_use_the_interface_or_superclass_for_local_declarations() {
    let (_scratch, classes): (ScratchDir, BTreeMap<String, ClassFile>) = compiled_probe();
    let source: String = decompile_probe(&classes);

    assert!(source.contains("AnonymousTypeProbe.Job var0;"), "{source}");
    assert!(source.contains("AnonymousTypeProbe.Base var0;"), "{source}");
    assert!(
        source.contains("new AnonymousTypeProbe.Job() {"),
        "{source}"
    );
    assert!(
        source.contains("new AnonymousTypeProbe.Base() {"),
        "{source}"
    );
    assert!(!source.contains("AnonymousTypeProbe$_1 var0;"), "{source}");
    assert!(!source.contains("AnonymousTypeProbe$_2 var0;"), "{source}");
}

#[test]
fn a_concrete_allocation_keeps_its_concrete_local_type_when_inlining_is_unavailable() {
    let (_scratch, classes): (ScratchDir, BTreeMap<String, ClassFile>) = compiled_probe();
    let main: &ClassFile = classes
        .get("AnonymousTypeProbe.class")
        .expect("main probe class");
    let no_inners: BTreeMap<String, ClassFile> = BTreeMap::new();
    let decompiled: DecompiledClass = decompile_class_with_inners(main, &no_inners);

    assert!(
        decompiled.source.contains("AnonymousTypeProbe$_1 var0;"),
        "{}",
        decompiled.source
    );
    assert!(
        decompiled.source.contains("AnonymousTypeProbe$_2 var0;"),
        "{}",
        decompiled.source
    );
    assert!(
        decompiled.source.contains("new AnonymousTypeProbe$_1()"),
        "{}",
        decompiled.source
    );
    assert!(
        decompiled.source.contains("new AnonymousTypeProbe$_2()"),
        "{}",
        decompiled.source
    );
}

#[test]
fn a_later_concrete_allocation_prevents_anonymous_slot_normalization() {
    let (_scratch, classes): (ScratchDir, BTreeMap<String, ClassFile>) = compiled_probe();
    let source: String = decompile_probe(&classes);
    let method: &str = source
        .split("mixedReuse(boolean")
        .nth(1)
        .expect("mixed reuse method");

    assert!(!method.contains("AnonymousTypeProbe.Job var1;"), "{source}");
    assert!(method.contains("Object var1;"), "{source}");
    assert!(
        method.contains("new AnonymousTypeProbe.Job() {"),
        "{source}"
    );
    assert!(method.contains("new String("), "{source}");
}

const MEMBER_PROBE_SOURCE: &str = r#"public class AnonymousMemberProbe {
    interface Job { int run(); }

    static int objectExtra() {
        var value = new Object() { int extra() { return 4; } };
        return value.extra();
    }

    static int interfaceExtra() {
        var value = new Job() {
            public int run() { return 5; }
            int extra() { return 6; }
        };
        return value.extra();
    }

    static int fieldExtra() {
        var value = new Object() { int count = 7; };
        return value.count;
    }

    static String objectOverride() {
        var value = new Object() { public String toString() { return "eight"; } };
        return value.toString();
    }

    static int interfaceOverride() {
        var value = new Job() { public int run() { return 9; } };
        return value.run();
    }
}
"#;

fn member_probe_method<'a>(source: &'a str, signature: &str) -> &'a str {
    let start: usize = source
        .find(signature)
        .unwrap_or_else(|| panic!("{signature} in {source}"));
    let rest: &str = &source[start..];
    let end: usize = rest[1..]
        .find("\n    static ")
        .map_or(rest.len(), |offset: usize| offset + 1);
    &rest[..end]
}

#[test]
fn anonymous_locals_used_through_members_absent_from_the_supertype_are_not_recovered() {
    let (_scratch, classes): (ScratchDir, BTreeMap<String, ClassFile>) = compiled_java(
        "anonymous_member_probe",
        "AnonymousMemberProbe",
        MEMBER_PROBE_SOURCE,
    );
    let main: &ClassFile = classes
        .get("AnonymousMemberProbe.class")
        .expect("main member probe class");
    let source: String = decompile_class_with_inners(main, &classes).source;
    let refusal: &str = "not recovered: anonymous local is used through a member its source supertype does not declare";

    for signature in [
        "int objectExtra()",
        "int interfaceExtra()",
        "int fieldExtra()",
    ] {
        let method: &str = member_probe_method(&source, signature);
        assert!(method.contains(refusal), "{signature}: {source}");
        assert!(!method.contains(" var0;"), "{signature}: {source}");
    }
    let object_override: &str = member_probe_method(&source, "String objectOverride()");
    assert!(!object_override.contains(refusal), "{source}");
    assert!(object_override.contains("Object var0;"), "{source}");
    let interface_override: &str = member_probe_method(&source, "int interfaceOverride()");
    assert!(!interface_override.contains(refusal), "{source}");
    assert!(
        interface_override.contains("AnonymousMemberProbe.Job var0;"),
        "{source}"
    );
}

fn nested_anonymous_source(class_name: &str, depth: usize) -> String {
    let mut allocation: String = "null".to_owned();
    for _ in 0..depth {
        allocation = format!(
            "new Node() {{ public Node next() {{ Node value = {allocation}; return value; }} }}"
        );
    }
    format!(
        "public class {class_name} {{\n    interface Node {{ Node next(); }}\n    static Node root() {{ Node value = {allocation}; return value; }}\n}}\n"
    )
}

fn first_concrete_inner_allocation(
    source: &str,
    classes: &BTreeMap<String, ClassFile>,
    main_name: &str,
) -> Option<String> {
    classes.values().find_map(|class: &ClassFile| {
        let binary_name: &str = class.this_class_name().ok()?;
        (binary_name != main_name).then(|| {
            let source_name: String = disrobe_pass_jvm::descriptor::binary_to_source(binary_name);
            source
                .contains(&format!("new {source_name}("))
                .then_some(source_name)
        })?
    })
}

#[test]
fn recursive_anonymous_metadata_keeps_the_guarded_allocation_concrete() {
    let source_text: String = nested_anonymous_source("RecursiveProbe", 2);
    let (_scratch, mut classes): (ScratchDir, BTreeMap<String, ClassFile>) = compiled_java(
        "anonymous_inner_declaration_recursion",
        "RecursiveProbe",
        &source_text,
    );
    let first: ClassFile = classes
        .get("RecursiveProbe$1.class")
        .expect("first recursive probe anonymous class")
        .clone();
    classes.insert("RecursiveProbe$2.class".to_owned(), first);
    let main: &ClassFile = classes
        .get("RecursiveProbe.class")
        .expect("recursive probe main class");
    let source: String = decompile_class_with_inners(main, &classes).source;
    let concrete: String = first_concrete_inner_allocation(&source, &classes, "RecursiveProbe")
        .unwrap_or_else(|| panic!("recursive allocation did not fall back:\n{source}"));

    assert!(source.contains(&format!("{concrete} var")), "{source}");
    assert!(source.contains("new RecursiveProbe.Node() {"), "{source}");
}

#[test]
fn anonymous_depth_exhaustion_keeps_the_guarded_allocation_concrete() {
    let source_text: String = nested_anonymous_source("DepthProbe", 18);
    let (_scratch, classes): (ScratchDir, BTreeMap<String, ClassFile>) = compiled_java(
        "anonymous_inner_declaration_depth",
        "DepthProbe",
        &source_text,
    );
    let main: &ClassFile = classes
        .get("DepthProbe.class")
        .expect("depth probe main class");
    let source: String = decompile_class_with_inners(main, &classes).source;
    let concrete: String = first_concrete_inner_allocation(&source, &classes, "DepthProbe")
        .unwrap_or_else(|| panic!("depth-limited allocation did not fall back:\n{source}"));

    assert!(source.contains(&format!("{concrete} var")), "{source}");
    assert!(source.contains("new DepthProbe.Node() {"), "{source}");
}

fn translated_edgecases() -> (ClassFile, BTreeMap<String, ClassFile>) {
    let translated: Dex2JarResult =
        translate_dex_bytes(EDGECASES_DEX).expect("translate EdgeCases.dex");
    let mut classes: BTreeMap<String, ClassFile> = BTreeMap::new();
    for (name, bytes) in translated.jar_entries {
        classes.insert(
            name,
            parse_classfile(&bytes).expect("parse translated EdgeCases class"),
        );
    }
    let main: ClassFile = classes
        .get("EdgeCases.class")
        .expect("translated EdgeCases main class")
        .clone();
    (main, classes)
}

fn simple_type(ty: &JavaType) -> String {
    let rendered: String = ty.render();
    rendered
        .rsplit('.')
        .next()
        .map_or_else(|| rendered.clone(), str::to_owned)
}

fn method_identity(class: &ClassFile, method: &MethodInfo) -> String {
    let metadata_name: &str = class.utf8_at(method.name_index).expect("method name");
    let name: String = metadata_name.strip_prefix("lambda$").map_or_else(
        || metadata_name.to_owned(),
        |suffix: &str| format!("synthLambda${suffix}"),
    );
    let descriptor: &str = class
        .utf8_at(method.descriptor_index)
        .expect("method descriptor");
    let params: Vec<String> = parse_method(descriptor)
        .expect("parse method descriptor")
        .params
        .iter()
        .map(simple_type)
        .collect();
    format!("{name}({})", params.join(", "))
}

fn method_line_ranges(source: &str) -> Vec<(String, usize, usize)> {
    let lines: Vec<&str> = source.lines().collect();
    let mut ranges: Vec<(String, usize, usize)> = Vec::new();
    let mut index: usize = 0;
    let mut depth: i32 = 0;
    while index < lines.len() {
        let trimmed: &str = lines[index].trim();
        let type_declaration: bool = ["class ", "interface ", "enum ", "record ", "@interface "]
            .iter()
            .any(|keyword: &&str| trimmed.contains(keyword));
        let member: bool = depth >= 1
            && trimmed.contains('(')
            && (trimmed.contains(" static ")
                || trimmed.starts_with("public ")
                || trimmed.starts_with("private ")
                || trimmed.starts_with("protected ")
                || trimmed.starts_with("static"))
            && trimmed.contains('{')
            && !type_declaration;
        if member {
            let start: usize = index + 1;
            let mut member_depth: i32 =
                trimmed.matches('{').count() as i32 - trimmed.matches('}').count() as i32;
            let mut end: usize = index + 1;
            while end < lines.len() && member_depth > 0 {
                member_depth += lines[end].matches('{').count() as i32;
                member_depth -= lines[end].matches('}').count() as i32;
                end += 1;
            }
            ranges.push((trimmed.to_owned(), start, end + 1));
        }
        depth += lines[index].matches('{').count() as i32;
        depth -= lines[index].matches('}').count() as i32;
        index += 1;
    }
    ranges
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NormalizedDeclaration {
    identity: String,
    name: String,
    declaration_line: usize,
}

fn normalized_declarations(
    source: &str,
    ranges: &[(String, usize, usize)],
    method_identities: &BTreeMap<String, String>,
) -> Vec<NormalizedDeclaration> {
    let lines: Vec<&str> = source.lines().collect();
    let mut declarations: Vec<NormalizedDeclaration> = Vec::new();
    for (line_index, line) in lines.iter().enumerate() {
        let (name, allocation): (&str, &str) = match line.trim().split_once(" = new ") {
            Some(parts) if parts.1.ends_with('{') => parts,
            _ => continue,
        };
        let Some((allocation_type, _arguments)): Option<(&str, &str)> = allocation.split_once('(')
        else {
            continue;
        };
        let line_number: usize = line_index + 1;
        let (label, start, _end): &(String, usize, usize) = ranges
            .iter()
            .filter(|(_label, start, end): &&(String, usize, usize)| {
                line_number >= *start && line_number < *end
            })
            .max_by_key(|(_label, start, _end): &&(String, usize, usize)| *start)
            .unwrap_or_else(|| panic!("owning method for `{}`", line.trim()));
        let indentation: usize = line.len() - line.trim_start().len();
        let (declaration_line, declaration_type): (usize, &str) = lines
            [start.saturating_sub(1)..line_index]
            .iter()
            .enumerate()
            .rev()
            .find_map(|(relative, candidate): (usize, &&str)| {
                let candidate_indentation: usize = candidate.len() - candidate.trim_start().len();
                if candidate_indentation > indentation {
                    return None;
                }
                let declaration: &str = candidate.trim().strip_suffix(';')?;
                if declaration.contains('=') {
                    return None;
                }
                let (ty, declared_name): (&str, &str) = declaration.rsplit_once(' ')?;
                (declared_name == name)
                    .then_some((start.saturating_sub(1).saturating_add(relative), ty))
            })
            .unwrap_or_else(|| panic!("declaration for `{}`", line.trim()));
        if declaration_type != allocation_type {
            continue;
        }
        let method_name: &str = label
            .split_once('(')
            .and_then(|(prefix, _params): (&str, &str)| prefix.split_whitespace().last())
            .expect("rendered method name");
        let identity: String = method_identities
            .get(method_name)
            .unwrap_or_else(|| panic!("method identity for {label}"))
            .clone();
        declarations.push(NormalizedDeclaration {
            identity,
            name: name.to_owned(),
            declaration_line,
        });
    }
    declarations
}

fn declaration_types(
    source: &str,
    ranges: &[(String, usize, usize)],
    method_identities: &BTreeMap<String, String>,
) -> BTreeMap<(String, String), String> {
    let lines: Vec<&str> = source.lines().collect();
    let mut declarations: BTreeMap<(String, String), String> = BTreeMap::new();
    for (label, start, end) in ranges {
        let method_name: &str = label
            .split_once('(')
            .and_then(|(prefix, _params): (&str, &str)| prefix.split_whitespace().last())
            .expect("rendered method name");
        let Some(identity): Option<&String> = method_identities.get(method_name) else {
            continue;
        };
        for line in &lines[start.saturating_sub(1)..end.saturating_sub(1).min(lines.len())] {
            let Some(declaration): Option<&str> = line.trim().strip_suffix(';') else {
                continue;
            };
            if declaration.contains('=') {
                continue;
            }
            let Some((ty, name)): Option<(&str, &str)> = declaration.rsplit_once(' ') else {
                continue;
            };
            if name.starts_with("var") {
                declarations.insert((identity.clone(), name.to_owned()), ty.to_owned());
            }
        }
    }
    declarations
}

fn baseline_source(
    candidate: &str,
    sites: &[NormalizedDeclaration],
    fallback_types: &BTreeMap<(String, String), String>,
) -> String {
    let mut lines: Vec<String> = candidate.lines().map(str::to_owned).collect();
    for site in sites {
        let fallback_type: &str = fallback_types
            .get(&(site.identity.clone(), site.name.clone()))
            .unwrap_or_else(|| panic!("fallback declaration for {} {}", site.identity, site.name));
        let current: &str = lines
            .get(site.declaration_line)
            .unwrap_or_else(|| panic!("candidate declaration line for {}", site.identity));
        let indentation: &str = &current[..current.len() - current.trim_start().len()];
        lines[site.declaration_line] = format!("{indentation}{fallback_type} {};", site.name);
    }
    let mut source: String = lines.join("\n");
    if candidate.ends_with('\n') {
        source.push('\n');
    }
    source
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ScoredRegion {
    source: String,
    label: String,
    start: usize,
    end: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct JavacDiagnostic {
    source: String,
    line: usize,
    code: String,
}

#[derive(Debug)]
struct RegionScore {
    clean: usize,
    emitted: usize,
    clean_regions: BTreeSet<String>,
    regions: BTreeMap<String, ScoredRegion>,
}

fn scored_regions(sources: &BTreeMap<String, String>) -> Vec<ScoredRegion> {
    sources
        .iter()
        .flat_map(|(source_name, source): (&String, &String)| {
            method_line_ranges(source).into_iter().map(
                move |(label, start, end): (String, usize, usize)| ScoredRegion {
                    source: source_name.clone(),
                    label,
                    start,
                    end,
                },
            )
        })
        .collect()
}

fn source_name_matches(source: &str, diagnostic_source: &str) -> bool {
    let normalized_source: String = source.replace('\\', "/");
    let normalized_diagnostic: String = diagnostic_source.replace('\\', "/");
    normalized_source == normalized_diagnostic
        || normalized_diagnostic.ends_with(&format!("/{normalized_source}"))
        || normalized_source.ends_with(&format!("/{normalized_diagnostic}"))
}

fn parse_javac_diagnostics(output: &str) -> Vec<JavacDiagnostic> {
    let mut diagnostics: Vec<JavacDiagnostic> = Vec::new();
    for line in output.lines() {
        let Some((before, rest)): Option<(&str, &str)> = line.rsplit_once(".java:") else {
            continue;
        };
        let Some((line_number, after_line)): Option<(&str, &str)> = rest.split_once(':') else {
            continue;
        };
        let Ok(line_number): Result<usize, _> = line_number.trim().parse() else {
            continue;
        };
        let message: &str = after_line
            .split_once(':')
            .map_or(after_line, |(_column, message): (&str, &str)| message);
        let code: String = message
            .split_once(':')
            .map_or(message, |(code, _detail): (&str, &str)| code)
            .trim()
            .to_owned();
        diagnostics.push(JavacDiagnostic {
            source: format!("{}.java", before.trim()),
            line: line_number,
            code,
        });
    }
    diagnostics.sort();
    diagnostics.dedup();
    diagnostics
}

fn javac_output(
    javac: &Path,
    sources: &BTreeMap<String, String>,
    include_attribution_probe: bool,
    scratch_name: &str,
) -> disrobe_core::subprocess::CapturedOutput {
    let scratch: ScratchDir = ScratchDir::create(scratch_name).expect("create javac workspace");
    let mut source_paths: Vec<PathBuf> = Vec::new();
    for (relative, source) in sources {
        let path: PathBuf = scratch.path().join(relative.replace('\\', "/"));
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create javac source directory");
        }
        std::fs::write(&path, source).expect("write recovered Java source");
        source_paths.push(path);
    }
    if include_attribution_probe {
        let probe_path: PathBuf = scratch.path().join(ATTRIBUTION_PROBE_FILE);
        std::fs::write(&probe_path, ATTRIBUTION_PROBE_SOURCE).expect("write attribution probe");
        source_paths.push(probe_path);
    }
    let classpath: PathBuf = scratch.path().join("cp");
    let output_dir: PathBuf = scratch.path().join("out");
    std::fs::create_dir(&classpath).expect("create empty javac classpath");
    std::fs::create_dir(&output_dir).expect("create javac output directory");
    let mut args: Vec<OsString> = vec![
        "-nowarn".into(),
        "-proc:none".into(),
        "-XDrawDiagnostics".into(),
        "-Xmaxerrs".into(),
        "100000".into(),
        "-cp".into(),
        classpath.into_os_string(),
        "-d".into(),
        output_dir.into_os_string(),
    ];
    args.extend(
        source_paths
            .iter()
            .map(|path: &PathBuf| path.as_os_str().to_owned()),
    );
    disrobe_core::subprocess::run_captured(javac, &args, JAVAC_TIMEOUT, JAVAC_CAPTURE_LIMIT)
        .expect("start javac")
        .expect("javac completed within the scorer timeout")
}

fn score_recovered_sources(
    javac: &Path,
    sources: &BTreeMap<String, String>,
    scratch_name: &str,
) -> RegionScore {
    let regions: Vec<ScoredRegion> = scored_regions(sources);
    let output: disrobe_core::subprocess::CapturedOutput =
        javac_output(javac, sources, false, scratch_name);
    let combined: String = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );
    let diagnostics: Vec<JavacDiagnostic> = if output.exit_code == Some(0) {
        Vec::new()
    } else {
        parse_javac_diagnostics(&combined)
    };
    assert!(
        output.exit_code == Some(0) || !diagnostics.is_empty(),
        "javac emitted no parseable diagnostics:\n{combined}"
    );
    assert!(
        diagnostics.iter().all(|diagnostic: &JavacDiagnostic| {
            !["expected", "illegal.start", "premature.eof"]
                .iter()
                .any(|fragment: &&str| diagnostic.code.contains(fragment))
        }),
        "source-region isolation would be required: {diagnostics:#?}"
    );

    let probe: disrobe_core::subprocess::CapturedOutput =
        javac_output(javac, sources, true, &format!("{scratch_name}_probe"));
    let probe_combined: String = format!(
        "{}\n{}",
        String::from_utf8_lossy(&probe.stderr),
        String::from_utf8_lossy(&probe.stdout)
    );
    let probe_diagnostics: Vec<JavacDiagnostic> = parse_javac_diagnostics(&probe_combined);
    assert!(
        probe_diagnostics
            .iter()
            .any(|diagnostic: &JavacDiagnostic| {
                source_name_matches(ATTRIBUTION_PROBE_FILE, &diagnostic.source)
            }),
        "javac did not reach attribution:\n{probe_combined}"
    );

    let mut failed: BTreeSet<usize> = BTreeSet::new();
    for diagnostic in &diagnostics {
        if let Some((index, _region)) = regions
            .iter()
            .enumerate()
            .filter(|(_index, region): &(usize, &ScoredRegion)| {
                source_name_matches(&region.source, &diagnostic.source)
                    && diagnostic.line >= region.start
                    && diagnostic.line < region.end
            })
            .max_by_key(|(_index, region): &(usize, &ScoredRegion)| region.start)
        {
            failed.insert(index);
        }
    }
    let region_map: BTreeMap<String, ScoredRegion> = regions
        .iter()
        .enumerate()
        .map(|(index, region): (usize, &ScoredRegion)| (format!("{index}"), region.clone()))
        .collect();
    let clean_regions: BTreeSet<String> = regions
        .iter()
        .enumerate()
        .filter(|(index, _region): &(usize, &ScoredRegion)| !failed.contains(index))
        .map(|(index, _region): (usize, &ScoredRegion)| format!("{index}"))
        .collect();
    RegionScore {
        clean: clean_regions.len(),
        emitted: regions.len(),
        clean_regions,
        regions: region_map,
    }
}

fn identity_for_region(
    region: &ScoredRegion,
    method_identities: &BTreeMap<String, String>,
) -> Option<String> {
    let method_name: &str = region.label.split_once('(')?.0.split_whitespace().last()?;
    method_identities.get(method_name).cloned()
}

#[test]
fn edgecases_anonymous_declarations_produce_the_exact_javac_method_region_gain() {
    let (main, _classes): (ClassFile, BTreeMap<String, ClassFile>) = translated_edgecases();
    let recovered: AndroidDecompileOutput =
        android_decompile_dex(EDGECASES_DEX, BackendPreference::PreferInHouse)
            .expect("recover EdgeCases.dex through the production Android route");
    let candidate_key: String = recovered
        .sources
        .keys()
        .find(|name: &&String| name.replace('\\', "/").ends_with("EdgeCases.java"))
        .expect("recovered EdgeCases.java")
        .clone();
    let source: String = recovered
        .sources
        .get(&candidate_key)
        .expect("candidate EdgeCases source")
        .clone();
    let ranges: Vec<(String, usize, usize)> = method_line_ranges(&source);
    let emitted_methods: Vec<&MethodInfo> = main
        .methods
        .iter()
        .filter(|method: &&MethodInfo| {
            main.utf8_at(method.name_index)
                .is_ok_and(|name: &str| name != "<clinit>")
        })
        .collect();
    let method_identities: BTreeMap<String, String> = emitted_methods
        .iter()
        .filter_map(|method: &&MethodInfo| {
            let metadata_name: &str = main.utf8_at(method.name_index).ok()?;
            (!metadata_name.starts_with('<')).then(|| {
                let rendered_name: String = metadata_name.strip_prefix("lambda$").map_or_else(
                    || metadata_name.to_owned(),
                    |suffix: &str| format!("synthLambda${suffix}"),
                );
                (rendered_name, method_identity(&main, method))
            })
        })
        .collect();
    let sites: Vec<NormalizedDeclaration> =
        normalized_declarations(&source, &ranges, &method_identities);
    let affected: BTreeSet<String> = sites
        .iter()
        .map(|site: &NormalizedDeclaration| site.identity.clone())
        .collect();
    let expected_affected: BTreeSet<String> =
        AFFECTED_METHODS.into_iter().map(str::to_owned).collect();
    assert_eq!(affected, expected_affected);
    assert_eq!(sites.len(), ANONYMOUS_DECLARATION_TOTAL);

    let no_inners: BTreeMap<String, ClassFile> = BTreeMap::new();
    let fallback: String = decompile_class_with_inners(&main, &no_inners).source;
    let fallback_ranges: Vec<(String, usize, usize)> = method_line_ranges(&fallback);
    let fallback_types: BTreeMap<(String, String), String> =
        declaration_types(&fallback, &fallback_ranges, &method_identities);
    let baseline_main: String = baseline_source(&source, &sites, &fallback_types);
    let mut baseline_sources: BTreeMap<String, String> = recovered.sources.clone();
    baseline_sources.insert(candidate_key, baseline_main);

    let javac: PathBuf = common::find_on_path("javac").expect("javac is required for this test");
    let baseline_score: RegionScore = score_recovered_sources(
        &javac,
        &baseline_sources,
        "anonymous_inner_declaration_baseline_scorer",
    );
    let candidate_score: RegionScore = score_recovered_sources(
        &javac,
        &recovered.sources,
        "anonymous_inner_declaration_candidate_scorer",
    );
    assert_eq!(baseline_score.emitted, EDGECASES_METHOD_TOTAL);
    assert_eq!(candidate_score.emitted, EDGECASES_METHOD_TOTAL);
    assert_eq!(baseline_score.clean, BASELINE_CLEAN);
    assert_eq!(candidate_score.clean, CANDIDATE_CLEAN);
    assert!(
        baseline_score
            .clean_regions
            .is_subset(&candidate_score.clean_regions),
        "candidate introduced a newly defective method region"
    );
    let candidate_only_regions: BTreeSet<String> = candidate_score
        .clean_regions
        .difference(&baseline_score.clean_regions)
        .cloned()
        .collect();
    let candidate_only: BTreeSet<String> = candidate_only_regions
        .iter()
        .map(|key: &String| {
            let region: &ScoredRegion = candidate_score
                .regions
                .get(key)
                .expect("candidate-only method region");
            identity_for_region(region, &method_identities)
                .unwrap_or_else(|| panic!("method identity for {region:#?}"))
        })
        .collect();
    let expected_newly_clean: BTreeSet<String> =
        NEWLY_CLEAN.into_iter().map(str::to_owned).collect();
    assert_eq!(candidate_only_regions.len(), expected_newly_clean.len());
    assert_eq!(candidate_only, expected_newly_clean);
}
