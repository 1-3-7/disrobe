#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::ffi::OsStr;
use std::path::Path;
use std::time::Duration;

use disrobe_core::subprocess::{CapturedOutput, run_captured};
use disrobe_pass_js_deob::{AstUnminifyStats, unminify_ast};

const NODE_TIMEOUT: Duration = Duration::from_secs(30);
const NODE_CAPTURE: usize = 1usize << 18;

const ASI_TAG_BOUNDARY: &str = r#"
let calls = 0;
function factory() { return function () { calls++; }; }
factory()
"x" + 1;
process.stdout.write(String(calls));
"#;

fn node_capture(source: &str) -> String {
    let args: [&OsStr; 2] = [OsStr::new("-e"), OsStr::new(source)];
    let output: CapturedOutput = run_captured(Path::new("node"), &args, NODE_TIMEOUT, NODE_CAPTURE)
        .expect("node is required for the template semantic reference")
        .expect("template semantic reference must finish within the timeout");
    assert_eq!(
        output.exit_code,
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("Node output is utf-8")
        .trim()
        .to_owned()
}

#[test]
fn template_recovery_preserves_asi_statement_boundaries() {
    let expected: String = node_capture(ASI_TAG_BOUNDARY);
    assert_eq!(expected, "0");
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(ASI_TAG_BOUNDARY);
    assert_eq!(
        node_capture(&recovered),
        expected,
        "template conversion must not turn a following statement into a tag call:\n{recovered}"
    );
    assert_eq!(stats.template_literals_rebuilt, 0, "{recovered}");
    assert_eq!(recovered, ASI_TAG_BOUNDARY, "{recovered}");
}
