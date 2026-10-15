#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::collections::BTreeSet;
use std::process::{Command, Output};

use disrobe_pass_js_deob::{
    IntegrityStripStats, JscramblerOptions, JscramblerTransform, deobfuscate_jscrambler,
    peel_eval_indirection, strip_integrity_loops,
};

const BATTERY: &str = r"
const inputs = [0, 1, -1, 2, 7, '', 'a', null, undefined, true, false, [], {}, { name: 'n' }, [1, 2]];
const rows = [];
for (const input of inputs) {
  try {
    const value = subject.call({ base: 11 }, input);
    rows.push(['return', typeof value, String(value)]);
  } catch (error) {
    rows.push(['throw', error.constructor.name, String(error.message)]);
  }
}
console.log(JSON.stringify(rows));
";

fn run_node(program: &str) -> Output {
    Command::new("node")
        .env_remove("FORCE_COLOR")
        .args(["-e", program])
        .output()
        .expect("node is required: install Node and put it on PATH")
}

fn node_stdout(program: &str) -> String {
    let output: Output = run_node(program);
    assert!(
        output.status.success(),
        "node rejected the program: {}\n{program}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("node prints UTF-8")
}

fn assert_same_battery(label: &str, authored: &str, recovered: &str) {
    let before: String = node_stdout(&format!("{authored}\n{BATTERY}"));
    let after: String = node_stdout(&format!("{recovered}\n{BATTERY}"));
    assert_eq!(
        before, after,
        "{label}: recovered program changed behaviour\n--- authored\n{authored}\n--- recovered\n{recovered}"
    );
}

fn variable_masking_output(source: &str) -> String {
    let transforms: BTreeSet<JscramblerTransform> =
        BTreeSet::from([JscramblerTransform::VariableMasking]);
    let options: JscramblerOptions = JscramblerOptions {
        i_have_authorization: false,
        transforms,
    };
    deobfuscate_jscrambler(source, &options)
        .expect("variable masking route must accept the authored program")
        .source
}

#[test]
fn lodash_global_probe_is_detect_only_and_keeps_its_node_result() {
    let authored: &str = "var freeGlobal = typeof global == 'object' && global && global.Object === Object && global;\nvar root = freeGlobal || Function('return this')();\nfunction subject() { return root === globalThis ? 'global' : 'other'; }";
    let recovered: String = peel_eval_indirection(authored).rewritten;
    assert_eq!(recovered, authored);
    assert_same_battery("lodash global probe", authored, &recovered);
}

#[test]
fn eval_inside_a_binary_expression_is_refused_and_keeps_its_node_result() {
    let authored: &str = "var value = 2 * eval('1 + 2');\nfunction subject() { return value; }";
    let recovered: String = peel_eval_indirection(authored).rewritten;
    assert_eq!(recovered, authored);
    assert_same_battery("eval inside binary expression", authored, &recovered);
}

#[test]
fn library_iife_with_for_array_and_tostring_is_not_an_integrity_loop() {
    let authored: &str = "var values = ['a', 'b'];\nvar observed = [];\n(function () { for (var index = 0; index < values.length; index++) { observed.push([].concat(values[index]).toString()); } })();\nfunction subject() { return observed.join('|'); }";
    let (recovered, stats): (String, IntegrityStripStats) = strip_integrity_loops(authored);
    assert_eq!(stats.iifes_stripped, 0);
    assert_eq!(recovered, authored);
    assert_same_battery("library iife", authored, &recovered);
}

#[test]
fn self_alias_used_by_a_callback_keeps_its_lexical_this() {
    let authored: &str = "function subject(value) { var self = this; return [value].map(function (item) { return self.base + item; })[0]; }";
    let recovered: String = variable_masking_output(authored);
    assert_eq!(recovered, authored);
    assert_same_battery("self alias in callback", authored, &recovered);
}

#[test]
fn decrementing_counter_alias_is_not_rewritten() {
    let authored: &str = "function subject(n) { var i = n; var total = 0; while (i-- > 0 && total < 32) { total += i; } return String(n) + ':' + String(total); }";
    let recovered: String = variable_masking_output(authored);
    assert_eq!(recovered, authored);
    assert_same_battery("decrementing counter alias", authored, &recovered);
}

#[test]
fn disabling_the_eval_reparse_gate_turns_the_eval_grade_red() {
    let authored: &str =
        "console.log('before eval');\neval('var = ;');\nfunction subject() { return 7; }";
    let recovered: String = peel_eval_indirection(authored).rewritten;
    assert_eq!(recovered, authored);
    let original: Output = run_node(&format!("{authored}\n{BATTERY}"));
    let refused: Output = run_node(&format!("{recovered}\n{BATTERY}"));
    assert_eq!(refused.status.code(), original.status.code());
    assert_eq!(refused.stdout, original.stdout);
    assert_eq!(refused.stderr, original.stderr);
    assert_eq!(original.stdout, b"before eval\n");

    let ungated: &str = "console.log('before eval');\n/* dr-eval-folded */\nvar = ;\nfunction subject() { return 7; }";
    let output: Output = run_node(&format!("{ungated}\n{BATTERY}"));
    assert_ne!(output.stdout, original.stdout);
}
