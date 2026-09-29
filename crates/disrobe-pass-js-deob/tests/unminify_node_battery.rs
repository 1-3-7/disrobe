#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use disrobe_pass_js_deob::{UnminifyStats, unminify};
use std::process::{Command, Output};

const BATTERY: &str = r"
const inputs = [0, 1, -1, 2, 7, '', 'a', null, undefined, true, false, [], {}, { name: 'n' }, [1, 2]];
const lines = [];
for (const a of inputs) {
  for (const b of inputs) {
    let value;
    try { value = subject(a, b); } catch (error) { value = 'throws ' + error.constructor.name; }
    lines.push(JSON.stringify([typeof value, String(value)]));
  }
}
console.log(lines.join('\n'));
";

fn run_node(program: &str) -> String {
    let output: Output = Command::new("node")
        .env_remove("FORCE_COLOR")
        .args(["-e", program])
        .output()
        .expect("node is required: install Node and put it on PATH");
    assert!(
        output.status.success(),
        "node rejected the program: {}\n{program}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("node prints UTF-8")
}

fn assert_same_behaviour(label: &str, authored: &str) {
    let (unminified, _stats): (String, UnminifyStats) = unminify(authored);
    let before: String = run_node(&format!("{authored}\n{BATTERY}"));
    let after: String = run_node(&format!("{unminified}\n{BATTERY}"));
    assert_eq!(
        before, after,
        "{label}: unminify changed behaviour\n--- authored\n{authored}\n--- unminified\n{unminified}"
    );
}

#[test]
fn double_negation_keeps_boolean_results() {
    assert_same_behaviour(
        "double negation",
        "function subject(ok, ready) { return !!ok && !!ready; }",
    );
}

#[test]
fn de_morgan_keeps_the_parent_precedence() {
    assert_same_behaviour(
        "de morgan under &&",
        "function subject(x, y) { const z = x === y; if (!(x && y) && z) { return 1; } return 2; }",
    );
}

#[test]
fn a_fold_after_a_unary_operator_is_not_reassociated() {
    assert_same_behaviour(
        "fold after unary",
        "function subject(a, b) { return typeof a + 'x' + (-b + 1); }",
    );
}

#[test]
fn a_call_through_call_keeps_its_receiver() {
    assert_same_behaviour(
        "receiver of .call",
        "var base = { tag: 'base', read: function (p) { return this.tag + String(p); } };\n\
         function subject(a, b) { var self = { tag: 'self' }; return base.read.call(self, a); }",
    );
}

#[test]
fn optional_chaining_restoration_keeps_nullish_results() {
    assert_same_behaviour(
        "babel optional chain",
        "function subject(o, b) { var t; return (t = o) === null || t === void 0 ? void 0 : t.name; }",
    );
}

#[test]
fn nullish_restoration_keeps_falsy_values() {
    assert_same_behaviour(
        "babel nullish coalescing",
        "function subject(a, b) { var t; return (t = a) !== null && t !== void 0 ? t : b; }",
    );
}

#[test]
fn two_iife_scripts_keep_their_own_helpers() {
    assert_same_behaviour(
        "concatenated iife scripts",
        "var out = [];\n(function () { function helper() { return 'first'; } out.push(helper()); })();\n\
         (function () { function helper() { return 'second'; } out.push(helper()); })();\n\
         function subject(a, b) { return out.join(','); }",
    );
}
