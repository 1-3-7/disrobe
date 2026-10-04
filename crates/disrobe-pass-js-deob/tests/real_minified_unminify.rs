#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use disrobe_pass_js_deob::{AstUnminifyStats, unminify_ast};
use sha2::{Digest, Sha256};

mod common;

const ARRAY_BUFFER_LIMIT: u64 = 64 * 1_024 * 1_024;

const PARITY_FIXTURE: &str = include_str!("../corpus/unminify/parity/min.js");
const PARITY_FIXTURE_SHA256: &str =
    "eea4274c36cf6156a85cf80574b0858706f0a5a91d9337f6987da27de0fee1e8";
const PARITY_REFERENCE_SOURCE: &str = r#"
var built = [0, 1, 2].map(function (item) { return "row " + item + " of 3"; });
var label = { label: "ok" }.label;
var none = undefined;
var joined = ["a", "b", "c"].join(",");
"#;

const TERSER_MINIFIED: &str = "function greet(e,t){if(null!=e){for(var n=\"user \"+e.name+\" has \"+t+\" items\";!(t<=0);)t--;return\"active\"===e.status?n:\"inactive\"}}";
const TERSER_REFERENCE_SOURCE: &str = r#"
function greet(user, count) {
  if (user == null) return undefined;
  if (user.status !== "active") return "inactive";
  return "user " + user.name + " has " + count + " items";
}
"#;

struct AuthoredReference {
    source: &'static str,
    source_sha256: &'static str,
    output: &'static str,
}

const PARITY_REFERENCE: AuthoredReference = AuthoredReference {
    source: PARITY_REFERENCE_SOURCE,
    source_sha256: "5ae207a0b8af4deca80437a171b6e6842935b97830fd99c8140611e2b0754ea5",
    output: "row 0 of 3|row 1 of 3|row 2 of 3\u{1}ok\u{1}undefined\u{1}a,b,c",
};
const TERSER_REFERENCE: AuthoredReference = AuthoredReference {
    source: TERSER_REFERENCE_SOURCE,
    source_sha256: "bb750464d25218a2f98c515621a8b416fc3b0fbf1936c04dac92c1ae9f77dd4a",
    output: "user ann has 3 items\u{1}inactive\u{1}undefined",
};

fn assert_reference_identity(label: &str, reference: &AuthoredReference) {
    assert_eq!(
        format!("{:x}", Sha256::digest(reference.source.as_bytes())),
        reference.source_sha256,
        "{label} authored source changed without revalidating its output"
    );
}

fn eval_capture(program: &str, tail: &str) -> Option<String> {
    let harness: String = format!("{program}\n{tail}");
    let worker: common::BoaWorker = common::BoaWorker::new(std::env::current_exe().ok()?).ok()?;
    let outcome: common::EvalOutcome = worker.evaluate(&harness, &[]).ok()?;
    let common::Terminal::Completed(value) = outcome.terminal else {
        return None;
    };
    (value.kind == "string").then_some(value.value)
}

#[test]
fn the_oracle_rejects_an_array_buffer_above_the_cap() {
    let program: String = format!("new ArrayBuffer({});", ARRAY_BUFFER_LIMIT + 1);
    assert_eq!(eval_capture(&program, "'unreachable';"), None);
    assert_eq!(
        eval_capture("new ArrayBuffer(1024);", "'bounded';"),
        Some("bounded".to_owned())
    );
}

const PROBE: &str = r#"
var probe = [
  built.join("|"),
  String(label),
  String(none),
  joined
].join("");
probe;
"#;

#[test]
fn real_minified_fixture_recovers_and_preserves_behavior() {
    assert_eq!(
        format!("{:x}", Sha256::digest(PARITY_FIXTURE.as_bytes())),
        PARITY_FIXTURE_SHA256,
        "the minified input changed without revalidating its reference"
    );
    assert_reference_identity("parity", &PARITY_REFERENCE);
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(PARITY_FIXTURE);

    assert_eq!(
        stats.indirect_calls_simplified, 0,
        "member indirect calls must retain their unbound receiver; got {}",
        stats.indirect_calls_simplified
    );
    assert!(
        stats.bracket_accesses_dotted >= 2,
        "this[\"total\"] and o[\"label\"] must become dot access; got {}",
        stats.bracket_accesses_dotted
    );
    assert_eq!(stats.template_literals_rebuilt, 0, "{recovered}");
    assert!(
        stats.optional_chains_rebuilt >= 1,
        "the strict null/void guard around o[\"label\"] must become o?.label; got {}",
        stats.optional_chains_rebuilt
    );
    assert_eq!(stats.apply_calls_spread, 0, "{recovered}");

    assert!(
        recovered.contains("(0,mod.render)(items[i])"),
        "member indirect call must remain unbound:\n{recovered}"
    );
    assert!(
        recovered.contains("o?.label"),
        "optional chain expected:\n{recovered}"
    );
    assert!(
        recovered.contains("\"row \"+n+\" of \"+counters.total"),
        "string concatenation must remain intact:\n{recovered}"
    );
    assert!(recovered.contains("joinAll.apply("), "{recovered}");

    let got: String = eval_capture(&recovered, PROBE)
        .unwrap_or_else(|| panic!("recovered must evaluate:\n{recovered}"));
    assert_eq!(
        got, PARITY_REFERENCE.output,
        "recovered diverged from the pinned reference output\n--got--\n{got}\n--src--\n{recovered}"
    );
    let mutated: String = recovered.replacen("row ", "item ", 1);
    assert_ne!(
        mutated, recovered,
        "the output template must remain present"
    );
    assert_ne!(
        eval_capture(&mutated, PROBE),
        Some(PARITY_REFERENCE.output.to_owned()),
        "the grade must detect a changed recovered output template"
    );
}

const TERSER_PROBE: &str = r#"
var probe = [
  String(greet({ name: "ann", status: "active" }, 3)),
  String(greet({ name: "bob", status: "off" }, 1)),
  String(greet(null, 5))
].join("");
probe;
"#;

#[test]
fn real_terser_output_unminifies_equivalently() {
    assert_reference_identity("Terser", &TERSER_REFERENCE);
    let (recovered, _stats): (String, AstUnminifyStats) = unminify_ast(TERSER_MINIFIED);

    let got: String = eval_capture(&recovered, TERSER_PROBE)
        .unwrap_or_else(|| panic!("recovered terser output must evaluate:\n{recovered}"));
    assert_eq!(
        got, TERSER_REFERENCE.output,
        "recovered diverged from the pinned Terser reference output\n--got--\n{got}\n--src--\n{recovered}"
    );
    let mutated: String = recovered.replacen("active", "inactive", 1);
    assert_ne!(mutated, recovered, "the active branch must remain present");
    assert_ne!(
        eval_capture(&mutated, TERSER_PROBE),
        Some(TERSER_REFERENCE.output.to_owned()),
        "the grade must detect a changed recovered branch"
    );
    assert!(
        reparses(&recovered),
        "recovered terser output must re-parse:\n{recovered}"
    );
}

fn reparses(source: &str) -> bool {
    use oxc_allocator::Allocator;
    use oxc_parser::Parser;
    use oxc_span::SourceType;
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path("check.js").unwrap_or_default();
    let parsed: oxc_parser::ParserReturn<'_> = Parser::new(&allocator, source, source_type).parse();
    parsed.errors.is_empty() && !parsed.panicked
}
