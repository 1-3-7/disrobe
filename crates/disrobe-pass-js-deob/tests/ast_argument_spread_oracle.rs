#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::ffi::OsStr;
use std::path::Path;
use std::time::Duration;

use disrobe_core::subprocess::{CapturedOutput, run_captured};
use disrobe_pass_js_deob::{AstUnminifyStats, unminify_ast};

const NODE_TIMEOUT: Duration = Duration::from_secs(30);
const NODE_CAPTURE: usize = 1usize << 18;

fn node_output(source: &str) -> String {
    let args: [&OsStr; 2] = [OsStr::new("-e"), OsStr::new(source)];
    let output: CapturedOutput = run_captured(Path::new("node"), &args, NODE_TIMEOUT, NODE_CAPTURE)
        .expect("node is required for the argument spread semantic reference")
        .expect("argument spread semantic reference must finish within the timeout");
    assert_eq!(
        output.exit_code,
        Some(0),
        "node must execute source\nstderr: {}\nsource:\n{source}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("Node output is utf-8")
        .trim()
        .to_owned()
}

const OWN_APPLY_OVERRIDE: &str = r#"
function target() { return "target:" + arguments.length; }
target.apply = function(_this, values) { return "override:" + values.join(","); };
var args = ["a", "b"];
process.stdout.write(target.apply(void 0, args));
"#;

#[test]
fn own_apply_override_remains_apply_and_matches_node() {
    let expected: String = node_output(OWN_APPLY_OVERRIDE);
    assert_eq!(expected, "override:a,b");
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(OWN_APPLY_OVERRIDE);
    assert_eq!(
        stats.apply_calls_spread, 0usize,
        "an own apply override must not become a spread call\n{recovered}"
    );
    assert!(
        recovered.contains("target.apply"),
        "the overridden apply call must remain visible\n{recovered}"
    );
    assert_eq!(node_output(&recovered), expected, "{recovered}");
}
