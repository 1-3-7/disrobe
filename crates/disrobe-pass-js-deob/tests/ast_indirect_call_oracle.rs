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
        .expect("node is required for the indirect call semantic reference")
        .expect("indirect call semantic reference must finish within the timeout");
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

fn assert_node_equivalent(label: &str, input: &str, recovered: &str) {
    let want: String = node_output(input);
    let got: String = node_output(recovered);
    assert_eq!(
        want, got,
        "{label}: recovered source diverged\n--input--\n{input}\n--recovered--\n{recovered}"
    );
}

fn assert_identifier_call_rewrites(label: &str, input: &str) {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(input);
    assert_eq!(
        stats.indirect_calls_simplified, 1usize,
        "{label}: exactly one identifier indirect call must simplify\n{recovered}"
    );
    assert!(
        recovered.contains("receiver()") && !recovered.contains("(0, receiver)"),
        "{label}: identifier indirect call must collapse\n{recovered}"
    );
    assert_node_equivalent(label, input, &recovered);
}

fn assert_indirect_call_is_preserved(label: &str, input: &str, expected: &str) {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(input);
    assert_eq!(
        stats.indirect_calls_simplified, 0usize,
        "{label}: unsafe indirect call must remain untouched\n{recovered}"
    );
    assert!(
        recovered.contains(expected),
        "{label}: unsafe call form must be preserved\n{recovered}"
    );
    assert_node_equivalent(label, input, &recovered);
}

const SLOPPY_IDENTIFIER: &str = r#"
function receiver() { return this === globalThis ? "global" : "other"; }
console.log((0, receiver)());
"#;

const STRICT_IDENTIFIER: &str = r#"
function receiver() { "use strict"; return this === undefined ? "undefined" : "other"; }
console.log((0, receiver)());
"#;

const MEMBER_RECEIVER: &str = r#"
var holder = { receiver: function() { console.log(this === holder ? "member" : "other"); } };
(0, holder.receiver)();
"#;

const INDIRECT_EVAL: &str = r#"
globalThis.marker = "outer";
function read() { var marker = "inner"; return (0, eval)("marker"); }
console.log(read());
"#;

const WITH_SCOPE: &str = r#"
var holder = { receiver: function() { console.log(this === holder ? "member" : "other"); } };
with (holder) { (0, receiver)(); }
"#;

const OPTIONAL_CALL: &str = r#"
function receiver() { console.log("optional"); }
(0, receiver)?.();
"#;

const NONZERO_HEAD: &str = r#"
function receiver() { console.log("nonzero"); }
(1, receiver)();
"#;

const COMMENT_BEARING_IDENTIFIER: &str = r#"
function receiver() { return this === globalThis ? "global" : "other"; }
console.log((0, /* retain */ receiver)());
"#;

#[test]
fn strict_and_sloppy_identifier_calls_simplify_with_node_equivalence() {
    for (label, input) in [
        ("sloppy identifier", SLOPPY_IDENTIFIER),
        ("strict identifier", STRICT_IDENTIFIER),
    ] {
        assert_identifier_call_rewrites(label, input);
    }
}

#[test]
fn member_receivers_remain_indirect() {
    assert_indirect_call_is_preserved("member receiver", MEMBER_RECEIVER, "(0, holder.receiver)()");
}

#[test]
fn indirect_eval_remains_indirect() {
    assert_indirect_call_is_preserved("indirect eval", INDIRECT_EVAL, "(0, eval)(\"marker\")");
}

#[test]
fn module_rejected_with_input_remains_byte_identical() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(WITH_SCOPE);
    assert_eq!(stats.indirect_calls_simplified, 0usize, "{recovered}");
    assert_eq!(recovered, WITH_SCOPE, "{recovered}");
}

#[test]
fn optional_indirect_call_remains_unchanged() {
    assert_indirect_call_is_preserved("optional call", OPTIONAL_CALL, "(0, receiver)?.()");
}

#[test]
fn nonzero_sequence_head_remains_unchanged() {
    assert_indirect_call_is_preserved("nonzero head", NONZERO_HEAD, "(1, receiver)()");
}

#[test]
fn comment_bearing_identifier_call_remains_unchanged() {
    assert_indirect_call_is_preserved(
        "comment bearing identifier",
        COMMENT_BEARING_IDENTIFIER,
        "/* retain */",
    );
}
