#![allow(clippy::expect_used, clippy::panic)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::process::{Command, Output};

use disrobe_core::scratch::ScratchDir;
use disrobe_pass_jvm::dex::{FieldId, MethodId};
use disrobe_pass_jvm::{DecompiledDex, DexFile, decompile_dex, parse_dex};
use sha2::{Digest, Sha256};

pub mod common;

const RELEASE_DEX: &[u8] = include_bytes!("fixtures/d8_lambda_shapes/DesugarShapeProbe-min21.dex");
const DEBUG_DEX: &[u8] =
    include_bytes!("fixtures/d8_lambda_shapes/DesugarShapeProbe-min21-debug.dex");
const AUTHORED: &str = include_str!("fixtures/d8_lambda_shapes/DesugarShapeProbe.java");
const HARNESS: &str = include_str!("fixtures/d8_lambda_shapes/DesugarShapeHarness.java.in");
const PROVENANCE: &str = include_str!("fixtures/d8_lambda_shapes/provenance.toml");
const EDGECASES_DEX: &[u8] = include_bytes!("../../../corpus/jvm/dex/EdgeCases.dex");
const EDGECASES_SOURCE: &str = include_str!("../../../corpus/jvm/megafile/EdgeCases.java");
const EDGECASES_UNIT: &str = "EdgeCases.java";
const EDGECASES_RECALL_FLOOR: usize = 13;

const RELEASE_SHA256: &str = "0d0355dceb5de7938eebd0647661ca5ead3436cdc5408b2167730abe97d03b23";
const DEBUG_SHA256: &str = "fc189f089d04b21e35e11074e24b94e0d98fd5dd7244269d770530cd96d1a341";
const AUTHORED_SHA256: &str = "bf5e31121a1b69606486a5d277a467d86bd1f3c5c0d0b322bc3ced0c6519a74a";
const PROGRAM_UNIT: &str = "DesugarShapeProbe.java";
const SYNTHETIC_PREFIX: &str = "DesugarShapeProbe$";
const EXPECTED_STDOUT: &str = "16:160:18:169:81:16:506:a!\n22:217:-11:228:-87:10:696:b!\n";

#[derive(Debug, Clone, Copy)]
struct LambdaSite {
    method: &'static str,
    authored: &'static str,
    arity: usize,
    captures: usize,
    receiver_capture: bool,
    expected: &'static str,
}

const SITES: [LambdaSite; 9] = [
    LambdaSite {
        method: "stateless",
        authored: "value -> value * 3 + 1",
        arity: 1,
        captures: 0,
        receiver_capture: false,
        expected: "p0 -> ((p0 * 3) + 1)",
    },
    LambdaSite {
        method: "oneCapture",
        authored: "value -> mix(offset, value) + 2",
        arity: 1,
        captures: 1,
        receiver_capture: false,
        expected: "p0 -> (DesugarShapeProbe.mix(arg0, p0) + 2)",
    },
    LambdaSite {
        method: "receiverCapture",
        authored: "value -> scale(value) + 3",
        arity: 1,
        captures: 1,
        receiver_capture: true,
        expected: "p0 -> (this.scale(p0) + 3)",
    },
    LambdaSite {
        method: "twoCaptures",
        authored: "(a, b) -> scale(a) + mix(offset, b)",
        arity: 2,
        captures: 2,
        receiver_capture: true,
        expected: "(p0, p1) -> (this.scale(p0) + DesugarShapeProbe.mix(arg0, p1))",
    },
    LambdaSite {
        method: "wideCapture",
        authored: "() -> base * 7L + 4L",
        arity: 0,
        captures: 1,
        receiver_capture: false,
        expected: "() -> ((arg0 * 7L) + 4L)",
    },
    LambdaSite {
        method: "custom",
        authored: "(a, b, c) -> a + b + c + k",
        arity: 3,
        captures: 1,
        receiver_capture: false,
        expected: "(p0, p1, p2) -> (((p0 + p1) + p2) + arg0)",
    },
    LambdaSite {
        method: "nested",
        authored: "outer -> inner -> outer * 100 + inner + k",
        arity: 1,
        captures: 1,
        receiver_capture: false,
        expected: "p0 -> q0 -> (((p0 * 100) + q0) + arg0)",
    },
    LambdaSite {
        method: "lambda$nested$0",
        authored: "inner -> outer * 100 + inner + k",
        arity: 1,
        captures: 2,
        receiver_capture: false,
        expected: "p0 -> (((arg1 * 100) + p0) + arg0)",
    },
    LambdaSite {
        method: "textCapture",
        authored: "() -> prefix + \"!\"",
        arity: 0,
        captures: 1,
        receiver_capture: false,
        expected: "() -> new StringBuilder().append(arg0).append(\"!\").toString()",
    },
];

const LAMBDA_HELPERS: [&str; 9] = [
    "lambda$custom$0",
    "lambda$nested$0",
    "lambda$nested$1",
    "lambda$oneCapture$0",
    "lambda$receiverCapture$0$DesugarShapeProbe",
    "lambda$stateless$0",
    "lambda$textCapture$0",
    "lambda$twoCaptures$0$DesugarShapeProbe",
    "lambda$wideCapture$0",
];

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn declares_method(line: &str, method: &str) -> bool {
    if !line.starts_with("    ") || line.starts_with("     ") || !line.ends_with('{') {
        return false;
    }
    let trimmed: &str = line.trim();
    let Some(open): Option<usize> = trimmed.find('(') else {
        return false;
    };
    let Some(head): Option<&str> = trimmed.get(..open) else {
        return false;
    };
    head.rsplit([' ', '\t']).next() == Some(method)
}

fn method_body(source: &str, method: &str) -> String {
    let mut collecting: bool = false;
    let mut body: Vec<&str> = Vec::new();
    for line in source.lines() {
        if collecting {
            if line == "    }" {
                break;
            }
            body.push(line.trim());
            continue;
        }
        collecting = declares_method(line, method);
    }
    assert!(
        !body.is_empty(),
        "the recovered unit must declare {method}:\n{source}"
    );
    body.join(" ")
}

fn recovered_lambda(source: &str, method: &str) -> String {
    let body: String = method_body(source, method);
    let expression: &str = body
        .strip_prefix("return ")
        .and_then(|text: &str| text.strip_suffix(';'))
        .unwrap_or_else(|| panic!("{method} must recover as a single return statement: {body}"));
    expression.to_owned()
}

fn program_unit(recovered: &DecompiledDex) -> &String {
    recovered
        .sources
        .get(PROGRAM_UNIT)
        .expect("recover the authored compilation unit")
}

fn retained_synthetics(recovered: &DecompiledDex) -> BTreeSet<String> {
    recovered
        .sources
        .keys()
        .filter(|name: &&String| name.starts_with(SYNTHETIC_PREFIX))
        .cloned()
        .collect()
}

fn synthetic_descriptors(dex: &DexFile) -> Vec<&String> {
    dex.class_descriptors
        .iter()
        .filter(|name: &&String| {
            name.starts_with("LDesugarShapeProbe$") && !name.ends_with("$TriInt;")
        })
        .collect()
}

fn expected_head(arity: usize) -> String {
    if arity == 1 {
        return "p0".to_owned();
    }
    let names: Vec<String> = (0..arity)
        .map(|position: usize| format!("p{position}"))
        .collect();
    format!("({})", names.join(", "))
}

fn recovered_sites(bytes: &'static [u8]) -> BTreeMap<&'static str, String> {
    let dex: DexFile = parse_dex(bytes).expect("parse the real D8 artifact");
    let recovered: DecompiledDex = decompile_dex(&dex, bytes);
    let unit: &String = program_unit(&recovered);
    SITES
        .iter()
        .map(|site: &LambdaSite| {
            let expression: String = if is_generated_helper(site.method) {
                helper_hosted_lambda(unit)
            } else {
                recovered_lambda(unit, site.method)
            };
            (site.method, expression)
        })
        .collect()
}

fn is_generated_helper(name: &str) -> bool {
    name.starts_with("lambda$") || name.starts_with("$r8$lambda$")
}

fn helper_hosted_lambda(source: &str) -> String {
    let mut collecting: bool = false;
    let mut found: Vec<String> = Vec::new();
    for line in source.lines() {
        if collecting {
            collecting = false;
            let trimmed: &str = line.trim();
            if let Some(expression) = trimmed
                .strip_prefix("return ")
                .and_then(|text: &str| text.strip_suffix(';'))
                && expression.contains(" -> ")
            {
                found.push(expression.to_owned());
            }
            continue;
        }
        if !line.starts_with("    ") || line.starts_with("     ") || !line.ends_with('{') {
            continue;
        }
        let trimmed: &str = line.trim();
        let Some(open): Option<usize> = trimmed.find('(') else {
            continue;
        };
        let Some(head): Option<&str> = trimmed.get(..open) else {
            continue;
        };
        collecting = head
            .rsplit([' ', '\t'])
            .next()
            .is_some_and(is_generated_helper);
    }
    assert_eq!(
        found.len(),
        1,
        "exactly one toolchain-generated helper must host a recovered lambda, saw {found:?}"
    );
    found.into_iter().next().unwrap_or_default()
}

fn compile_and_run(label: &str, source: &str) -> Vec<u8> {
    let javac: PathBuf =
        common::find_on_path("javac").expect("the D8 lambda-shape gate requires javac on PATH");
    let java: PathBuf =
        common::find_on_path("java").expect("the D8 lambda-shape gate requires java on PATH");
    let scratch: ScratchDir = ScratchDir::create(label).expect("create Java scratch directory");
    let source_path: PathBuf = scratch.path().join("DesugarShapeProbe.java");
    std::fs::write(&source_path, source).expect("write Java program");
    let compiled: Output = Command::new(javac)
        .arg("-d")
        .arg(scratch.path())
        .arg(&source_path)
        .output()
        .expect("run javac");
    assert!(
        compiled.status.success(),
        "javac rejected {label}:\n{}\n----\n{source}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let executed: Output = Command::new(java)
        .arg("-cp")
        .arg(scratch.path())
        .arg("DesugarShapeProbe")
        .output()
        .expect("run the Java program");
    assert!(
        executed.status.success(),
        "java rejected {label}:\n{}",
        String::from_utf8_lossy(&executed.stderr)
    );
    executed.stdout
}

fn fill_harness(sites: &BTreeMap<&'static str, String>) -> String {
    let mut text: String = HARNESS.to_owned();
    for site in SITES {
        let token: String = format!("@@{}@@", site.method);
        assert!(
            text.contains(token.as_str()),
            "the harness template must carry the {token} placeholder"
        );
        let expression: &String = sites
            .get(site.method)
            .unwrap_or_else(|| panic!("a recovered lambda for {}", site.method));
        text = text.replace(token.as_str(), expression);
    }
    assert!(
        !text.contains("@@"),
        "every harness placeholder must be filled:\n{text}"
    );
    text
}

#[test]
fn fixture_carries_the_declared_d8_lambda_shapes() {
    assert_eq!(sha256_hex(RELEASE_DEX), RELEASE_SHA256);
    assert_eq!(sha256_hex(DEBUG_DEX), DEBUG_SHA256);
    assert_eq!(sha256_hex(AUTHORED.as_bytes()), AUTHORED_SHA256);
    assert!(PROVENANCE.contains("version = \"9.1.31\""));
    assert!(PROVENANCE.contains(RELEASE_SHA256));
    assert!(PROVENANCE.contains(DEBUG_SHA256));
    assert!(PROVENANCE.contains(AUTHORED_SHA256));
    assert_eq!(RELEASE_DEX.get(..8), Some(b"dex\n035\0".as_slice()));
    assert_eq!(DEBUG_DEX.get(..8), Some(b"dex\n035\0".as_slice()));

    for site in SITES {
        assert!(
            AUTHORED.contains(site.authored),
            "the authored program must contain the lambda {} so it can grade {}",
            site.authored,
            site.method
        );
    }

    for bytes in [RELEASE_DEX, DEBUG_DEX] {
        let dex: DexFile = parse_dex(bytes).expect("parse the real D8 artifact");
        assert!(
            dex.strings
                .iter()
                .any(|value: &String| value.contains("~~D8{") && value.contains("\"min-api\":21")),
            "the artifact must carry its own D8 marker"
        );
        assert_eq!(
            dex.call_site_ids_size, 0,
            "D8 must have desugared every invokedynamic away"
        );
        assert_eq!(
            synthetic_descriptors(&dex).len(),
            SITES.len(),
            "the artifact must carry one D8 desugaring class per authored lambda"
        );
        let helpers: BTreeSet<&str> = dex
            .method_ids
            .iter()
            .filter(|method: &&MethodId| method.class == "LDesugarShapeProbe;")
            .map(|method: &MethodId| method.name.as_str())
            .filter(|name: &&str| name.starts_with("lambda$"))
            .collect();
        assert_eq!(
            helpers,
            LAMBDA_HELPERS.into_iter().collect::<BTreeSet<&str>>(),
            "the artifact must carry the declared D8 lambda helper set"
        );
    }
}

#[test]
fn real_d8_lambda_shapes_recover_as_lambda_expressions() {
    let dex: DexFile = parse_dex(RELEASE_DEX).expect("parse the real D8 artifact");
    let synthetics: usize = synthetic_descriptors(&dex).len();
    let recovered: DecompiledDex = decompile_dex(&dex, RELEASE_DEX);
    let unit: &String = program_unit(&recovered);

    let mut matched: usize = 0;
    for site in SITES {
        let expression: String = recovered_lambda(unit, site.method);
        let head: String = expected_head(site.arity);
        assert!(
            expression.starts_with(&format!("{head} -> ")),
            "{} must recover as a lambda of arity {}, saw {expression}",
            site.method,
            site.arity
        );
        assert_eq!(
            expression, site.expected,
            "{} must bind its {} capture(s) and {} parameter(s) into the authored body; receiver \
             capture: {}",
            site.method, site.captures, site.arity, site.receiver_capture
        );
        assert!(
            !expression.contains("lambda$"),
            "{} must recover the authored body, not a call to the D8 helper: {expression}",
            site.method
        );
        matched = matched.saturating_add(1);
    }
    assert_eq!(matched, SITES.len());
    assert_eq!(
        unit.matches(" -> ").count(),
        SITES.len().saturating_add(1),
        "the recovered unit must carry one arrow per authored lambda plus the second arrow of the \
         nested lambda that recovers inside its own outer lambda"
    );

    let retained: BTreeSet<String> = retained_synthetics(&recovered);
    assert!(
        retained.is_empty(),
        "every D8 desugaring class must be elided, still emitted: {retained:?}"
    );
    assert!(
        !unit.contains(SYNTHETIC_PREFIX),
        "no recovered source may still name a D8 desugaring class:\n{unit}"
    );

    eprintln!(
        "d8 lambda-shape recovery: {matched}/{} authored lambda sites recovered as lambda \
         expressions and {}/{synthetics} D8 desugaring classes elided, graded against \
         tests/fixtures/d8_lambda_shapes/DesugarShapeProbe.java built by D8 9.1.31 at min-api 21",
        SITES.len(),
        synthetics.saturating_sub(retained.len())
    );
}

#[test]
fn debug_and_release_artifacts_recover_the_same_lambdas() {
    let release: BTreeMap<&str, String> = recovered_sites(RELEASE_DEX);
    let debug: BTreeMap<&str, String> = recovered_sites(DEBUG_DEX);
    assert_eq!(
        release, debug,
        "the debug and release D8 artifacts must recover the same lambda expressions"
    );
}

#[test]
fn recovered_lambdas_recompile_and_preserve_authored_behavior() {
    let reference: Vec<u8> = compile_and_run("d8-lambda-shapes-authored", AUTHORED);
    assert_eq!(
        String::from_utf8_lossy(&reference).replace("\r\n", "\n"),
        EXPECTED_STDOUT,
        "the authored program must produce the behavior the provenance records"
    );
    assert!(PROVENANCE.contains("16:160:18:169:81:16:506:a!"));

    let sites: BTreeMap<&str, String> = recovered_sites(RELEASE_DEX);
    let filled: String = fill_harness(&sites);
    let recovered_stdout: Vec<u8> = compile_and_run("d8-lambda-shapes-recovered", &filled);
    assert_eq!(
        recovered_stdout, reference,
        "the recovered lambda expressions must reproduce the authored behavior"
    );

    let swapped_captures: String = filled.replacen("((p0 * 100) + q0)", "((q0 * 100) + p0)", 1);
    assert_ne!(
        swapped_captures, filled,
        "the nested lambda mutation must apply"
    );
    assert_ne!(
        compile_and_run("d8-lambda-shapes-nested-swap", &swapped_captures),
        reference,
        "swapping the nested lambda operands must change behavior, so the comparison is real"
    );

    let swapped_parameter: String = filled.replacen(
        "(this.scale(p0) + DesugarShapeProbe.mix(arg0, p1))",
        "(this.scale(p1) + DesugarShapeProbe.mix(arg0, p0))",
        1,
    );
    assert_ne!(
        swapped_parameter, filled,
        "the parameter-order mutation must apply"
    );
    assert_ne!(
        compile_and_run("d8-lambda-shapes-parameter-swap", &swapped_parameter),
        reference,
        "swapping the lambda parameters must change behavior, so the comparison is real"
    );
}

#[test]
fn an_unrecognised_functional_interface_keeps_the_desugaring_class() {
    let dex: DexFile = parse_dex(RELEASE_DEX).expect("parse the real D8 artifact");
    let mut mutated: DexFile = dex;
    let interface: &mut String = mutated
        .type_names
        .iter_mut()
        .find(|name: &&mut String| name.as_str() == "Ljava/util/function/IntUnaryOperator;")
        .expect("the artifact declares IntUnaryOperator");
    *interface = "Ljava/io/Serializable;".to_owned();

    let recovered: DecompiledDex = decompile_dex(&mutated, RELEASE_DEX);
    let unit: &String = program_unit(&recovered);
    assert!(
        !retained_synthetics(&recovered).is_empty(),
        "a marker interface has no single abstract method, so its class must stay visible"
    );
    for method in [
        "stateless",
        "oneCapture",
        "receiverCapture",
        "lambda$nested$0",
    ] {
        let body: String = method_body(unit, method);
        assert!(
            body.contains("new DesugarShapeProbe$"),
            "{method} must keep its construction of the D8 class, saw {body}"
        );
    }
}

#[test]
fn a_backported_core_library_functional_interface_still_recovers() {
    let dex: DexFile = parse_dex(RELEASE_DEX).expect("parse the real D8 artifact");
    let mut mutated: DexFile = dex;
    let interface: &mut String = mutated
        .type_names
        .iter_mut()
        .find(|name: &&mut String| name.as_str() == "Ljava/util/function/IntUnaryOperator;")
        .expect("the artifact declares IntUnaryOperator");
    *interface = "Lj$/util/function/IntUnaryOperator;".to_owned();

    let recovered: DecompiledDex = decompile_dex(&mutated, RELEASE_DEX);
    let unit: &String = program_unit(&recovered);
    for site in SITES {
        if !matches!(
            site.method,
            "stateless" | "oneCapture" | "receiverCapture" | "lambda$nested$0"
        ) {
            continue;
        }
        assert_eq!(
            recovered_lambda(unit, site.method),
            site.expected,
            "a core-library relocated functional interface must still recover {}",
            site.method
        );
    }
    let retained: BTreeSet<String> = retained_synthetics(&recovered);
    assert!(
        retained.is_empty(),
        "the relocated interface must not strand a desugaring class: {retained:?}"
    );
}

#[test]
fn a_renamed_helper_keeps_the_desugaring_class() {
    let dex: DexFile = parse_dex(RELEASE_DEX).expect("parse the real D8 artifact");
    let mut mutated: DexFile = dex;
    let helper: &mut MethodId = mutated
        .method_ids
        .iter_mut()
        .find(|method: &&mut MethodId| method.name == "lambda$custom$0")
        .expect("the artifact declares the custom lambda helper");
    helper.name = "helper$custom$0".to_owned();

    let recovered: DecompiledDex = decompile_dex(&mutated, RELEASE_DEX);
    let body: String = method_body(program_unit(&recovered), "custom");
    assert!(
        body.contains("new DesugarShapeProbe$"),
        "a target that is not a D8 lambda helper must not become a lambda, saw {body}"
    );
}

#[test]
fn a_capture_type_that_disagrees_with_the_helper_keeps_the_desugaring_class() {
    let dex: DexFile = parse_dex(RELEASE_DEX).expect("parse the real D8 artifact");
    let mut mutated: DexFile = dex;
    let captured: &mut FieldId = mutated
        .field_ids
        .iter_mut()
        .find(|field: &&mut FieldId| {
            field.class.starts_with("LDesugarShapeProbe$") && field.type_name == "J"
        })
        .expect("the artifact captures one long");
    captured.type_name = "I".to_owned();

    let recovered: DecompiledDex = decompile_dex(&mutated, RELEASE_DEX);
    let body: String = method_body(program_unit(&recovered), "wideCapture");
    assert!(
        body.contains("new DesugarShapeProbe$"),
        "a capture whose type disagrees with the helper must abstain, saw {body}"
    );
}

#[test]
fn a_program_interface_without_the_matching_abstract_method_keeps_the_desugaring_class() {
    let dex: DexFile = parse_dex(RELEASE_DEX).expect("parse the real D8 artifact");
    let mut mutated: DexFile = dex;
    let declared: &mut MethodId = mutated
        .method_ids
        .iter_mut()
        .find(|method: &&mut MethodId| {
            method.class == "LDesugarShapeProbe$TriInt;" && method.name == "apply"
        })
        .expect("the artifact declares the TriInt abstract method");
    declared.name = "applyTriple".to_owned();

    let recovered: DecompiledDex = decompile_dex(&mutated, RELEASE_DEX);
    let body: String = method_body(program_unit(&recovered), "custom");
    assert!(
        body.contains("new DesugarShapeProbe$"),
        "a program interface whose abstract method does not match the implementation must \
         abstain, saw {body}"
    );
}

const R8_DEX: &[u8] = include_bytes!("fixtures/r8_lambda_shapes/DesugarShapeProbe-r8-min21.dex");
const R8_PROVENANCE: &str = include_str!("fixtures/r8_lambda_shapes/provenance.toml");
const R8_DEX_SHA256: &str = "bdd602970ae2df89225260353b923bec0e572c03c4914fa460ca46bd617fd951";
const R8_OUTLINE_STUBS: usize = 6;

#[test]
fn the_r8_artifact_renames_every_lambda_body_out_of_java() {
    assert_eq!(sha256_hex(R8_DEX), R8_DEX_SHA256);
    assert!(R8_PROVENANCE.contains(R8_DEX_SHA256));
    assert!(R8_PROVENANCE.contains(AUTHORED_SHA256));
    assert_eq!(R8_DEX.get(..8), Some(b"dex\n035\0".as_slice()));

    let dex: DexFile = parse_dex(R8_DEX).expect("parse the real R8 artifact");
    assert!(
        dex.strings
            .iter()
            .any(|value: &String| value.contains("~~R8{")),
        "the artifact must carry its own R8 marker"
    );
    let helpers: Vec<&str> = dex
        .method_ids
        .iter()
        .filter(|method: &&MethodId| method.class == "LDesugarShapeProbe;")
        .map(|method: &MethodId| method.name.as_str())
        .filter(|name: &&str| name.starts_with("$r8$lambda$"))
        .collect();
    assert_eq!(
        helpers.len(),
        SITES.len(),
        "R8 must have renamed one body method per authored lambda, saw {helpers:?}"
    );
    assert!(
        helpers.iter().any(|name: &&str| name.contains('-')),
        "at least one R8 body name must be outside the Java identifier grammar, which is why a \
         recovery that forwards to it by name cannot emit compilable source: {helpers:?}"
    );
    assert!(
        !dex.method_ids
            .iter()
            .any(|method: &MethodId| method.name.starts_with("lambda$")),
        "R8 must have renamed every javac lambda body, or this fixture grades the D8 path again"
    );
}

#[test]
fn the_r8_artifact_recovers_the_same_lambdas_as_the_d8_artifact() {
    let from_d8: BTreeMap<&str, String> = recovered_sites(RELEASE_DEX);
    let from_r8: BTreeMap<&str, String> = recovered_sites(R8_DEX);
    assert_eq!(
        from_r8, from_d8,
        "the same authored program compiled through R8 must recover the same lambda expressions \
         it does through D8"
    );
    for (method, expression) in &from_r8 {
        assert!(
            !expression.contains("r8$lambda"),
            "{method} must carry the authored body, not a call to the renamed R8 body: \
             {expression}"
        );
    }
}

#[test]
fn recovered_r8_lambdas_preserve_authored_behavior() {
    let reference: Vec<u8> = compile_and_run("r8-lambda-shapes-authored", AUTHORED);
    assert_eq!(
        String::from_utf8_lossy(&reference).replace("\r\n", "\n"),
        EXPECTED_STDOUT
    );
    let filled: String = fill_harness(&recovered_sites(R8_DEX));
    assert_eq!(
        compile_and_run("r8-lambda-shapes-recovered", &filled),
        reference,
        "the lambda expressions recovered from the R8 artifact must reproduce the authored \
         behavior"
    );
}

#[test]
fn the_r8_call_outline_stubs_are_left_in_place() {
    let dex: DexFile = parse_dex(R8_DEX).expect("parse the real R8 artifact");
    let recovered: DecompiledDex = decompile_dex(&dex, R8_DEX);
    let retained: BTreeSet<String> = retained_synthetics(&recovered);
    assert_eq!(
        retained.len(),
        R8_OUTLINE_STUBS,
        "every R8 lambda class must be elided and only its call outline stubs may remain: \
         {retained:?}"
    );
    for unit in &retained {
        let source: &String = recovered
            .sources
            .get(unit)
            .expect("a retained unit has a source");
        assert!(
            source.contains("public static ") && source.matches("return ").count() == 1,
            "an R8 call outline stub is a single static forwarder, so a lambda class must not be \
             hiding among them:\n{source}"
        );
    }
}

const DUPLICATION_DEX: &[u8] =
    include_bytes!("fixtures/d8_lambda_duplication/DuplicatingLambdaProbe-min21.dex");
const DUPLICATION_SOURCE: &str =
    include_str!("fixtures/d8_lambda_duplication/DuplicatingLambdaProbe.java");
const DUPLICATION_PROVENANCE: &str = include_str!("fixtures/d8_lambda_duplication/provenance.toml");
const DUPLICATION_DEX_SHA256: &str =
    "e74193df95d47030754c51f95fb86501067c038394d7a5ed397281095c765684";
const DUPLICATION_SOURCE_SHA256: &str =
    "592fa64a885e6085c74e4fc80e2cac87d85a6828704ec497b8085bf4fb604702";

#[test]
fn a_helper_whose_result_is_read_twice_is_not_inlined() {
    assert_eq!(sha256_hex(DUPLICATION_DEX), DUPLICATION_DEX_SHA256);
    assert_eq!(
        sha256_hex(DUPLICATION_SOURCE.as_bytes()),
        DUPLICATION_SOURCE_SHA256
    );
    assert!(DUPLICATION_PROVENANCE.contains(DUPLICATION_DEX_SHA256));
    assert!(
        DUPLICATION_SOURCE.contains("int once = step(seed, value);")
            && DUPLICATION_SOURCE.contains("return once + once;"),
        "the authored program must bind the call once and read it twice"
    );
    assert!(
        DUPLICATION_SOURCE.contains("counter += 1;"),
        "the helper must carry an observable effect, or duplicating it would be harmless"
    );

    let dex: DexFile = parse_dex(DUPLICATION_DEX).expect("parse the real D8 artifact");
    let recovered: DecompiledDex = decompile_dex(&dex, DUPLICATION_DEX);
    let unit: &String = recovered
        .sources
        .get("DuplicatingLambdaProbe.java")
        .expect("recover the authored compilation unit");

    let single: String = recovered_lambda(unit, "single");
    assert_eq!(
        single, "p0 -> (DuplicatingLambdaProbe.step(arg0, p0) + 1)",
        "a helper that reads its call once must inline"
    );
    assert_eq!(
        single.matches("step(").count(),
        1,
        "the inlined body must evaluate the call exactly once: {single}"
    );

    let duplicating: String = recovered_lambda(unit, "duplicating");
    assert_eq!(
        duplicating.matches("step(").count(),
        0,
        "inlining a helper whose result is read twice would evaluate its call twice, so the \
         recovery must keep the call to the helper: {duplicating}"
    );
    assert_eq!(
        duplicating, "p0 -> DuplicatingLambdaProbe.lambda$duplicating$0(arg0, p0)",
        "the abstaining form must still be a lambda over the D8 helper"
    );
}

fn declares_any_method(line: &str) -> Option<String> {
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
            .all(|value: char| value.is_ascii_alphanumeric() || value == '_' || value == '$')
    {
        return None;
    }
    Some(name.to_owned())
}

fn top_level_method_bodies(source: &str) -> BTreeMap<String, String> {
    let mut bodies: BTreeMap<String, String> = BTreeMap::new();
    let mut current: Option<(String, String)> = None;
    for line in source.lines() {
        if let Some((name, body)) = current.as_mut() {
            if line == "    }" {
                bodies.entry(name.clone()).or_default().push_str(body);
                current = None;
            } else {
                body.push_str(line);
                body.push('\n');
            }
            continue;
        }
        current = declares_any_method(line).map(|name: String| (name, String::new()));
    }
    bodies
}

fn carries_lambda(body: &str) -> bool {
    body.lines().any(|line: &str| {
        let trimmed: &str = line.trim();
        !trimmed.starts_with("case ")
            && !trimmed.starts_with("default ")
            && trimmed.contains(" -> ")
    })
}

fn lambda_bearing_methods(source: &str) -> BTreeSet<String> {
    top_level_method_bodies(source)
        .into_iter()
        .filter(|(_, body): &(String, String)| carries_lambda(body))
        .map(|(name, _): (String, String)| name)
        .collect()
}

fn authored_owner(method: &str) -> String {
    method.strip_prefix("lambda$").map_or_else(
        || method.to_owned(),
        |rest: &str| rest.split('$').next().unwrap_or(rest).to_owned(),
    )
}

#[test]
fn real_edgecases_lambdas_land_in_the_methods_the_author_wrote_them_in() {
    let authored: BTreeSet<String> = lambda_bearing_methods(EDGECASES_SOURCE);
    assert!(
        authored.len() > 10,
        "corpus/jvm/megafile/EdgeCases.java must carry lambdas to grade against, saw {authored:?}"
    );

    let dex: DexFile = parse_dex(EDGECASES_DEX).expect("parse the real D8 megafile artifact");
    let recovered: DecompiledDex = decompile_dex(&dex, EDGECASES_DEX);
    let unit: &String = recovered
        .sources
        .get(EDGECASES_UNIT)
        .expect("recover the EdgeCases compilation unit");
    let returned: BTreeSet<String> = lambda_bearing_methods(unit)
        .iter()
        .map(|method: &String| authored_owner(method))
        .collect();

    let misplaced: Vec<&String> = returned
        .iter()
        .filter(|method: &&String| !authored.contains(*method))
        .collect();
    assert!(
        misplaced.is_empty(),
        "every recovered lambda must sit in a method the author wrote a lambda in; these did \
         not: {misplaced:?}"
    );
    assert!(
        returned.len() >= EDGECASES_RECALL_FLOOR,
        "recovered lambda methods fell below the recorded floor: {} of {}",
        returned.len(),
        authored.len()
    );
    eprintln!(
        "d8 lambda recovery on the real EdgeCases artifact: {}/{} authored lambda-bearing methods \
         return a lambda expression, graded against corpus/jvm/megafile/EdgeCases.java; still \
         unrecovered: {:?}",
        returned.len(),
        authored.len(),
        authored.difference(&returned).collect::<Vec<&String>>()
    );
}

#[test]
fn a_reflected_desugaring_class_is_kept() {
    let dex: DexFile = parse_dex(RELEASE_DEX).expect("parse the real D8 artifact");
    let descriptor: String = (*synthetic_descriptors(&dex)
        .first()
        .expect("the artifact carries D8 desugaring classes"))
    .clone();
    let binary: String = descriptor
        .trim_start_matches('L')
        .trim_end_matches(';')
        .replace('/', ".");
    let mut mutated: DexFile = dex;
    mutated.strings.push(binary);

    let recovered: DecompiledDex = decompile_dex(&mutated, RELEASE_DEX);
    let retained: BTreeSet<String> = retained_synthetics(&recovered);
    assert!(
        !retained.is_empty(),
        "a desugaring class named by a string constant may be reached by reflection and must \
         stay emitted"
    );
}
