#![allow(clippy::expect_used, clippy::panic)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use disrobe_core::scratch::ScratchDir;
use disrobe_pass_jvm::{DecompiledDex, DexFile, decompile_dex, parse_dex};

pub mod common;

const EDGECASES_DEX: &[u8] = include_bytes!("../../../corpus/jvm/dex/EdgeCases.dex");
const EDGECASES_SOURCE: &str = include_str!("../../../corpus/jvm/megafile/EdgeCases.java");

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum ReferenceForm {
    Static,
    UnboundInstance,
    BoundInstance,
    Constructor,
}

#[derive(Debug)]
struct ExpectedReference {
    method: &'static str,
    token: &'static str,
    form: ReferenceForm,
    probe: &'static str,
    needs_baseline: bool,
}

const EXPECTED: &[ExpectedReference] = &[
    ExpectedReference {
        method: "joinSquares",
        token: "Integer::toString",
        form: ReferenceForm::Static,
        probe: "java.util.function.IntFunction<String>",
        needs_baseline: true,
    },
    ExpectedReference {
        method: "groupByLength",
        token: "String::length",
        form: ReferenceForm::UnboundInstance,
        probe: "java.util.function.Function<String, Integer>",
        needs_baseline: true,
    },
    ExpectedReference {
        method: "virtualThreadFanout",
        token: "Integer::intValue",
        form: ReferenceForm::UnboundInstance,
        probe: "java.util.function.ToIntFunction<Integer>",
        needs_baseline: true,
    },
    ExpectedReference {
        method: "totalArea",
        token: "Shape::area",
        form: ReferenceForm::UnboundInstance,
        probe: "java.util.function.ToDoubleFunction<EdgeCases.Shape>",
        needs_baseline: true,
    },
    ExpectedReference {
        method: "listSupplier",
        token: "ArrayList::new",
        form: ReferenceForm::Constructor,
        probe: "java.util.function.Supplier<java.util.List<String>>",
        needs_baseline: true,
    },
    ExpectedReference {
        method: "wordCount",
        token: "TreeMap::new",
        form: ReferenceForm::Constructor,
        probe: "java.util.function.Supplier<java.util.TreeMap<String, Long>>",
        needs_baseline: true,
    },
    ExpectedReference {
        method: "main",
        token: "String::length",
        form: ReferenceForm::UnboundInstance,
        probe: "java.util.function.Function<String, Integer>",
        needs_baseline: true,
    },
    ExpectedReference {
        method: "main",
        token: "CTR::addAndGet",
        form: ReferenceForm::BoundInstance,
        probe: "java.util.function.Consumer<Integer>",
        needs_baseline: false,
    },
];

const ELIDED_SYNTHETICS: &[&str] = &[
    "EdgeCases$_28.java",
    "EdgeCases$_31.java",
    "EdgeCases$_33.java",
    "EdgeCases$_34.java",
    "EdgeCases$_40.java",
    "EdgeCases$_48.java",
    "EdgeCases$_57.java",
];

const RETAINED_CLASSES: &[&str] = &[
    "EdgeCases$_1.java",
    "EdgeCases$_2.java",
    "EdgeCases$_3.java",
    "EdgeCases$_4.java",
    "EdgeCases$_5.java",
    "EdgeCases$_27.java",
    "EdgeCases$_35.java",
    "EdgeCases$_52.java",
];

fn top_level_method_bodies(source: &str) -> BTreeMap<String, String> {
    let mut bodies: BTreeMap<String, String> = BTreeMap::new();
    let mut current: Option<(String, String)> = None;
    for line in source.lines() {
        if let Some((name, body)) = current.as_mut() {
            if line == "    }" {
                bodies
                    .entry(name.clone())
                    .or_default()
                    .push_str(body.as_str());
                current = None;
            } else {
                body.push_str(line);
                body.push('\n');
            }
            continue;
        }
        let Some(name): Option<String> = declared_method_name(line) else {
            continue;
        };
        current = Some((name, String::new()));
    }
    bodies
}

fn declared_method_name(line: &str) -> Option<String> {
    if !line.starts_with("    ") || line.starts_with("     ") || !line.ends_with('{') {
        return None;
    }
    let trimmed: &str = line.trim();
    if trimmed.starts_with("class ")
        || trimmed.contains(" class ")
        || trimmed.contains(" interface ")
        || trimmed.contains(" enum ")
        || trimmed.contains(" record ")
        || trimmed.starts_with("static {")
    {
        return None;
    }
    let open: usize = trimmed.find('(')?;
    let head: &str = trimmed.get(..open)?;
    let name: &str = head.rsplit([' ', '\t']).next()?;
    if name.is_empty()
        || !name
            .chars()
            .all(|c: char| c.is_ascii_alphanumeric() || c == '_' || c == '$')
    {
        return None;
    }
    Some(name.to_owned())
}

fn reference_tokens(body: &str) -> Vec<String> {
    let bytes: &[u8] = body.as_bytes();
    let mut out: Vec<String> = Vec::new();
    let mut index: usize = 0;
    while let Some(found) = body.get(index..).and_then(|rest: &str| rest.find("::")) {
        let at: usize = index + found;
        let mut start: usize = at;
        while start > 0 && is_qualifier_byte(bytes[start - 1]) {
            start -= 1;
        }
        let mut end: usize = at + 2;
        while end < bytes.len() && is_name_byte(bytes[end]) {
            end += 1;
        }
        index = at + 2;
        let (Some(qualifier), Some(name)): (Option<&str>, Option<&str>) =
            (body.get(start..at), body.get(at + 2..end))
        else {
            continue;
        };
        if qualifier.is_empty() || name.is_empty() {
            continue;
        }
        out.push(format!("{qualifier}::{name}"));
    }
    out
}

const fn is_qualifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'$' | b'.')
}

const fn is_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'$')
}

fn simple_token(token: &str) -> String {
    let Some((qualifier, name)): Option<(&str, &str)> = token.split_once("::") else {
        return token.to_owned();
    };
    let simple: &str = qualifier.rsplit('.').next().unwrap_or(qualifier);
    format!("{simple}::{name}")
}

fn pairs(bodies: &BTreeMap<String, String>) -> BTreeSet<(String, String)> {
    let mut out: BTreeSet<(String, String)> = BTreeSet::new();
    for (method, body) in bodies {
        for token in reference_tokens(body) {
            out.insert((method.clone(), simple_token(&token)));
        }
    }
    out
}

fn names_type(text: &str, stem: &str) -> bool {
    let bytes: &[u8] = text.as_bytes();
    let mut index: usize = 0;
    while let Some(found) = text.get(index..).and_then(|rest: &str| rest.find(stem)) {
        let at: usize = index + found;
        let after: usize = at + stem.len();
        let boundary: bool = bytes
            .get(after)
            .is_none_or(|byte: &u8| !is_name_byte(*byte));
        if boundary {
            return true;
        }
        index = after;
    }
    false
}

fn baseline_jar() -> PathBuf {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path.push("corpus");
    path.push("jvm");
    path.push("megafile");
    path.push("EdgeCases-baseline.jar");
    path
}

fn compile(javac: &Path, scratch: &Path, unit: &str, source: &str, classpath: Option<&Path>) {
    let file: PathBuf = scratch.join(format!("{unit}.java"));
    std::fs::write(&file, source).expect("write javac probe");
    let mut command: Command = Command::new(javac);
    command.arg("-d").arg(scratch);
    if let Some(jar) = classpath {
        command.arg("-cp").arg(jar);
    }
    let compiled: Output = command.arg(&file).output().expect("run javac");
    assert!(
        compiled.status.success(),
        "javac rejected the recovered method reference in {unit}:\n{}\n----\n{source}",
        String::from_utf8_lossy(&compiled.stderr)
    );
}

#[test]
fn real_d8_method_references_return_to_the_source_form() {
    let dex: DexFile = parse_dex(EDGECASES_DEX).expect("parse the real D8 artifact");
    let recovered: DecompiledDex = decompile_dex(&dex, EDGECASES_DEX);
    let recovered_source: &String = recovered
        .sources
        .get("EdgeCases.java")
        .expect("recover the EdgeCases compilation unit");

    let recovered_bodies: BTreeMap<String, String> = top_level_method_bodies(recovered_source);
    let original_bodies: BTreeMap<String, String> = top_level_method_bodies(EDGECASES_SOURCE);
    assert!(
        original_bodies.contains_key("main") && original_bodies.contains_key("totalArea"),
        "the original megafile must parse into named method bodies; the grader lost its reference"
    );

    let recovered_pairs: BTreeSet<(String, String)> = pairs(&recovered_bodies);
    let original_pairs: BTreeSet<(String, String)> = pairs(&original_bodies);
    assert!(
        !original_pairs.is_empty(),
        "corpus/jvm/megafile/EdgeCases.java must contain method references to grade against"
    );

    let unmatched: Vec<&(String, String)> = recovered_pairs
        .iter()
        .filter(|pair: &&(String, String)| !original_pairs.contains(*pair))
        .collect();
    assert!(
        unmatched.is_empty(),
        "every recovered method reference must sit in the same method the author wrote it in; \
         these are absent from the original source: {unmatched:?}"
    );

    let mut forms: BTreeSet<ReferenceForm> = BTreeSet::new();
    for expected in EXPECTED {
        let pair: (String, String) = (expected.method.to_owned(), expected.token.to_owned());
        assert!(
            original_pairs.contains(&pair),
            "the expectation {pair:?} is not in the original source, so it cannot grade anything"
        );
        assert!(
            recovered_pairs.contains(&pair),
            "D8 desugared {} in {} into a synthetic class and it did not come back",
            expected.token,
            expected.method
        );
        forms.insert(expected.form);
    }
    assert_eq!(
        forms.len(),
        4,
        "all four method-reference forms must be covered, saw {forms:?}"
    );

    for elided in ELIDED_SYNTHETICS {
        assert!(
            !recovered.sources.contains_key(*elided),
            "the D8 synthetic class {elided} was rewritten into a method reference and must not \
             be emitted as source"
        );
    }
    for retained in RETAINED_CLASSES {
        assert!(
            recovered.sources.contains_key(*retained),
            "{retained} is not a recovered method reference and must still be emitted"
        );
    }
    for elided in ELIDED_SYNTHETICS {
        let stem: &str = elided
            .strip_suffix(".java")
            .expect("an elided source path ends in .java");
        let mut sources: Vec<&String> = recovered.sources.values().collect();
        sources.push(&recovered.source);
        for text in sources {
            assert!(
                !names_type(text, stem),
                "{stem} was elided, so no recovered source may still name it"
            );
        }
    }

    let javac: PathBuf =
        common::find_on_path("javac").expect("the D8 method-reference gate requires javac on PATH");
    let jar: PathBuf = baseline_jar();
    assert!(
        jar.is_file(),
        "the javac applicability check needs the real baseline jar at {}",
        jar.display()
    );
    let scratch: ScratchDir = ScratchDir::create("d8-method-reference").expect("create scratch");

    let mut against_baseline: String = String::from("final class ProbeA {\n");
    let mut standalone: String = String::from(
        "final class EdgeCases {\n    static final java.util.concurrent.atomic.AtomicInteger CTR \
         = new java.util.concurrent.atomic.AtomicInteger();\n}\nfinal class ProbeB {\n",
    );
    for (index, expected) in EXPECTED.iter().enumerate() {
        let body: &String = recovered_bodies
            .get(expected.method)
            .expect("recovered method body");
        let emitted: String = reference_tokens(body)
            .into_iter()
            .find(|token: &String| simple_token(token) == expected.token)
            .expect("the emitted reference text");
        let declaration: String = format!("    static {} p{index} = {emitted};\n", expected.probe);
        if expected.needs_baseline {
            against_baseline.push_str(&declaration);
        } else {
            standalone.push_str(&declaration);
        }
    }
    against_baseline.push_str("}\n");
    standalone.push_str("}\n");
    compile(
        &javac,
        scratch.path(),
        "ProbeA",
        &against_baseline,
        Some(&jar),
    );
    compile(&javac, scratch.path(), "ProbeB", &standalone, None);

    let residual: Vec<&(String, String)> = original_pairs
        .iter()
        .filter(|pair: &&(String, String)| !recovered_pairs.contains(*pair))
        .collect();
    eprintln!(
        "d8 method-reference recovery: {}/{} (method, reference) pairs recovered from the real D8 \
         artifact, graded against the original corpus/jvm/megafile/EdgeCases.java; {} synthetic \
         classes elided; still unrecovered: {residual:?}",
        recovered_pairs.len(),
        original_pairs.len(),
        ELIDED_SYNTHETICS.len()
    );
}
