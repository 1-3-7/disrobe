#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::collections::BTreeSet;
use std::time::Duration;

use disrobe_pass_js_deob::{
    JscramblerOptions, JscramblerOutput, JscramblerTransform, deobfuscate_jscrambler,
};
use disrobe_testkit::{CommandSpec, ToolOutput, tool_output};

const NODE_TIMEOUT: Duration = Duration::from_secs(30);
const NODE_CAPTURE_BYTES: usize = 1024;

const AUTHORED: &str = r"
process.stdout.write(String('\uD800'.charCodeAt(0)) + ':ok');
";

const DUPLICATE_LITERAL_TABLE: &str = r"
var values = ['\uD800', 'ok'];
process.stdout.write(String(values[0].charCodeAt(0)) + ':' + values[1]);
";

fn node_output(source: &str) -> String {
    let output: ToolOutput = tool_output(
        CommandSpec::new("node", NODE_TIMEOUT)
            .arg("-e")
            .arg(source)
            .capture_limits(NODE_CAPTURE_BYTES, NODE_CAPTURE_BYTES)
            .reap_descendants_on_exit(),
    )
    .expect("Node is required for the UTF-16 surrogate runtime oracle");
    assert!(
        output.success,
        "Node rejected the authored or recovered source; stdout={} stderr={}",
        output.stdout_text(),
        output.stderr_text()
    );
    output.stdout_text()
}

#[test]
fn lone_utf16_surrogate_is_preserved_by_the_public_literal_rewriter() {
    let expected: String = node_output(AUTHORED);
    assert_eq!(expected, "55296:ok");
    assert_eq!(node_output(DUPLICATE_LITERAL_TABLE), expected);

    let mut transforms: BTreeSet<JscramblerTransform> = BTreeSet::new();
    transforms.insert(JscramblerTransform::DuplicateLiteralsRemoval);
    let options: JscramblerOptions = JscramblerOptions {
        i_have_authorization: false,
        transforms,
    };
    let scalar_table: String = DUPLICATE_LITERAL_TABLE.replace(r"\uD800", "A");
    let scalar_output: JscramblerOutput = deobfuscate_jscrambler(&scalar_table, &options)
        .expect("the scalar literal-table control must be recoverable");
    assert!(
        scalar_output
            .per_transform
            .iter()
            .any(|(transform, stats)| {
                *transform == JscramblerTransform::DuplicateLiteralsRemoval
                    && stats.matched == 1
                    && stats.reversed == 2
            })
    );
    assert_eq!(node_output(&scalar_output.source), "65:ok");
    let recovered: JscramblerOutput = deobfuscate_jscrambler(DUPLICATE_LITERAL_TABLE, &options)
        .expect("the public literal-table rewriter must accept valid JavaScript");
    assert_eq!(node_output(&recovered.source), expected);

    assert!(
        recovered.per_transform.iter().any(|(transform, stats)| {
            *transform == JscramblerTransform::DuplicateLiteralsRemoval && stats.reversed == 0
        }),
        "the shared literal decoder must inspect the table and refuse its lone surrogate: {:?}",
        recovered.per_transform
    );
    assert!(
        recovered.source.contains(r"\uD800"),
        "a lone UTF-16 surrogate cannot become a Rust scalar and must remain escaped:\n{}",
        recovered.source
    );
    let mutant_source: String = recovered.source.replace(r"\uD800", "");
    assert_ne!(mutant_source, recovered.source);
    let mutated: String = node_output(&mutant_source);
    assert_ne!(
        mutated, expected,
        "the independent Node oracle must reject a mutation that drops the lone surrogate"
    );
}
