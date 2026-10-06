#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use disrobe_pass_js_deob::{ObfuscatorIoOptions, ObfuscatorIoOutput, obfuscator_io_deobfuscate};
use sha2::{Digest, Sha256};

#[path = "common/mod.rs"]
mod common;

const CFF: &str = include_str!(
    "../../../corpus/src/javascript/obfuscator-io-samples/controls/controlFlowFlattening.js"
);
const CFF_SHA256: &str = "7efcf2ec6c1ac802cb329b76e9a0ba48d69569aab9f5dcaf70f609c95e913963";
const AUTHORED_SOURCE: &str = include_str!("../../../corpus/src/javascript/obfuscator-io-high.js");

struct AuthoredReference {
    source_sha256: &'static str,
    stdout: &'static str,
}

const AUTHORED_REFERENCE: AuthoredReference = AuthoredReference {
    source_sha256: "e29f6f162e5297b68f8dca7037e9b1cb343f2fec65a0e436ca27905f2d049887",
    stdout: "calculator ready :: hello, disrobe\nadd(10,5) = 15\nsub(10,5) = 5\nmul(10,5) = 50\ndiv(10,5) = 2\nprobe:15;5;50;2;calculator ready :: hello, disrobe;add(10,5) = 15|sub(10,5) = 5|mul(10,5) = 50|div(10,5) = 2\n",
};

const PROBE: &str = "console.log('probe:' + [calculate('add', 10, 5), calculate('sub', 10, 5), calculate('mul', 10, 5), calculate('div', 10, 5), greet('disrobe'), runSamples().join('|')].join(';'));";

fn reparses(source: &str) -> bool {
    use oxc_allocator::Allocator;
    use oxc_parser::Parser;
    use oxc_span::SourceType;
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path("check.js").unwrap_or_default();
    let parsed: oxc_parser::ParserReturn<'_> = Parser::new(&allocator, source, source_type).parse();
    parsed.errors.is_empty() && !parsed.panicked
}

fn sha256(source: &str) -> String {
    format!("{:x}", Sha256::digest(source.as_bytes()))
}

fn mutate_add_case(source: &str) -> String {
    for (from, to) in [
        ("case 'add':return add(", "case 'add':return subtract("),
        ("case 'add': return add(", "case 'add': return subtract("),
    ] {
        let mutated: String = source.replacen(from, to, 1);
        if mutated != source {
            return mutated;
        }
    }
    panic!("recovered add case is unavailable for the behavior mutation");
}

#[test]
fn control_flow_object_proxy_declaration_is_removed_after_full_inline() {
    assert_eq!(
        sha256(CFF),
        CFF_SHA256,
        "protected control-flow fixture drifted"
    );
    assert_eq!(
        sha256(AUTHORED_SOURCE),
        AUTHORED_REFERENCE.source_sha256,
        "authored obfuscator.io reference drifted"
    );
    let want: &str = AUTHORED_REFERENCE.stdout;

    let opts: ObfuscatorIoOptions = ObfuscatorIoOptions::all();
    let out: ObfuscatorIoOutput = obfuscator_io_deobfuscate(CFF, &opts).expect("deob ok");

    for proxy_marker in [
        "poLyL", "FatOg", "xvNoh", "TZuPv", "lVzeW", "pgsOS", "mOEWM",
    ] {
        assert!(
            !out.source.contains(proxy_marker),
            "control-flow proxy member `{proxy_marker}` must be inlined and its object removed, not left as a dead declaration:\n{}",
            out.source
        );
    }
    assert!(
        out.source.contains("case 'add':return add(")
            || out.source.contains("case 'add': return add("),
        "the switch body must recover direct calls after the proxy object is dissolved:\n{}",
        out.source
    );
    assert!(
        !out.source.contains("={'"),
        "no residual five-character-key proxy object literal should survive:\n{}",
        out.source
    );

    assert!(
        reparses(&out.source),
        "recovered source must re-parse as valid javascript:\n{}",
        out.source
    );

    let recovered_program: String = format!("{}\n{PROBE}", out.source);
    let worker: common::BoaWorker = common::BoaWorker::new(
        std::env::current_exe().expect("the behavior grader executable must resolve"),
    )
    .expect("the behavior grader worker must initialize");
    let got: String = worker
        .eval_stdout(&recovered_program, &[])
        .unwrap_or_else(|error| {
            panic!("recovered source must evaluate: {error:?}\n{}", out.source)
        });
    assert_eq!(
        want, got,
        "recovered behavior diverged from the authored obfuscator.io source\n--want--\n{want}\n--got--\n{got}\n--src--\n{}",
        out.source
    );

    let mutated: String = mutate_add_case(&out.source);
    let mutated_program: String = format!("{mutated}\n{PROBE}");
    let mutated_output: String = worker
        .eval_stdout(&mutated_program, &[])
        .unwrap_or_else(|error| panic!("behavior mutant must evaluate: {error:?}\n{mutated}"));
    assert_ne!(
        want, mutated_output,
        "changing the recovered add dispatch must make the behavior predicate fail"
    );
}
