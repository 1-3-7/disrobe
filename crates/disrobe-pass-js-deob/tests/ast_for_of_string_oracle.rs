#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use boa_engine::{Context, Source};
use disrobe_pass_js_deob::{AstUnminifyStats, unminify_ast};

const LOOP_LIMIT: u64 = 2_000_000;
const RECURSION_LIMIT: usize = 1_500;
const STACK_LIMIT: usize = 50_000;

fn eval_capture(program: &str) -> Option<String> {
    let mut context: Context = Context::default();
    {
        let runtime: &mut boa_engine::vm::RuntimeLimits = context.runtime_limits_mut();
        runtime.set_loop_iteration_limit(LOOP_LIMIT);
        runtime.set_recursion_limit(RECURSION_LIMIT);
        runtime.set_stack_size_limit(STACK_LIMIT);
    }
    let harness: String = format!(
        "var __out = []; var print = function(v){{ __out.push(String(v)); }};\n{program}\n__out.join('\\u0001');"
    );
    let value: boa_engine::JsValue = context.eval(Source::from_bytes(harness.as_bytes())).ok()?;
    value
        .as_string()
        .map(boa_engine::JsString::to_std_string_escaped)
}

fn assert_recovered_equivalent(label: &str, original: &str, recovered: &str) {
    let want: String = eval_capture(original).expect("original evaluates");
    let got: String = eval_capture(recovered)
        .unwrap_or_else(|| panic!("{label}: recovered must evaluate; src=\n{recovered}"));
    assert_eq!(
        want, got,
        "{label}: recovered diverged\n--want--\n{want}\n--got--\n{got}\n--src--\n{recovered}"
    );
}

const ASTRAL_LITERAL_SUBJECT: &str = r#"
var out = [];
for (var _i = 0, _s = "a\u{1F600}b"; _i < _s.length; _i++) {
  var ch = _s[_i];
  out.push(ch.codePointAt(0).toString(16));
}
print(out.length + ':' + out.join(','));
"#;

const ASTRAL_BINDING_SUBJECT: &str = r#"
var s = "a\u{1F600}b";
var out = [];
for (var _i = 0; _i < s.length; _i++) {
  var ch = s[_i];
  out.push(ch.codePointAt(0).toString(16));
}
print(out.length + ':' + out.join(','));
"#;

const ASTRAL_TEMPLATE_SUBJECT: &str = r"
var s = `a\u{1F600}b`;
var out = [];
for (var _i = 0; _i < s.length; _i++) {
  var ch = s[_i];
  out.push(ch.codePointAt(0).toString(16));
}
print(out.length + ':' + out.join(','));
";

const BMP_LITERAL_SUBJECT: &str = r#"
var out = [];
for (var _i = 0, _s = "abc"; _i < _s.length; _i++) {
  var ch = _s[_i];
  out.push(ch);
}
print(out.join(','));
"#;

const ARRAY_SUBJECT: &str = r"
var items = ['a', 'b', 'c'];
var out = [];
for (var _i = 0; _i < items.length; _i++) {
  var item = items[_i];
  out.push(item.toUpperCase());
}
print(out.join(','));
";

const UNKNOWN_PARAMETER_SUBJECT: &str = r#"
function consume(items) {
  var out = [];
  for (var _i = 0; _i < items.length; _i++) {
    var item = items[_i];
    out.push(item.codePointAt(0).toString(16));
  }
  print(out.length + ':' + out.join(','));
}
consume("a\u{1F600}b");
"#;

const PROVABLE_ARRAY_SUBJECTS: &str = r"
var source = ['a', 'b'];
var from = Array.from(source);
for (var i = 0; i < from.length; i++) { var fromItem = from[i]; print(fromItem); }
var split = 'a.b'.split('.');
for (var j = 0; j < split.length; j++) { var splitItem = split[j]; print(splitItem); }
var made = new Array('a', 'b');
for (var k = 0; k < made.length; k++) { var madeItem = made[k]; print(madeItem); }
";

fn assert_astral_string_subject_is_not_resugared(label: &str, original: &str) {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(original);
    assert_recovered_equivalent(label, original, &recovered);
    assert_eq!(
        stats.index_loops_to_for_of, 0,
        "{label}: an index loop over a string that holds an astral code point must not become for...of, because the loop walks utf-16 code units and for...of walks code points:\n{recovered}"
    );
}

#[test]
fn an_index_loop_over_an_astral_string_literal_is_not_resugared() {
    assert_astral_string_subject_is_not_resugared("astral literal subject", ASTRAL_LITERAL_SUBJECT);
}

#[test]
fn an_index_loop_over_an_astral_string_binding_is_not_resugared() {
    assert_astral_string_subject_is_not_resugared("astral binding subject", ASTRAL_BINDING_SUBJECT);
}

#[test]
fn an_index_loop_over_an_astral_template_literal_is_not_resugared() {
    assert_astral_string_subject_is_not_resugared(
        "astral template subject",
        ASTRAL_TEMPLATE_SUBJECT,
    );
}

#[test]
fn an_index_loop_over_a_basic_plane_string_literal_keeps_its_behaviour() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(BMP_LITERAL_SUBJECT);
    assert_recovered_equivalent(
        "basic plane literal subject",
        BMP_LITERAL_SUBJECT,
        &recovered,
    );
    assert_eq!(
        stats.index_loops_to_for_of, 1,
        "a string literal with no astral code point iterates identically both ways, so refusing it would cost recovery for no correctness gain:
{recovered}"
    );
}

#[test]
fn an_index_loop_over_an_array_still_becomes_for_of() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(ARRAY_SUBJECT);
    assert_eq!(
        stats.index_loops_to_for_of, 1,
        "an array subject must still be recovered:\n{recovered}"
    );
    assert!(
        recovered.contains(" of items)"),
        "the for...of head must reference the original iterable:\n{recovered}"
    );
    assert_recovered_equivalent("array subject", ARRAY_SUBJECT, &recovered);
}

#[test]
fn an_index_loop_over_an_unknown_parameter_is_not_resugared() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(UNKNOWN_PARAMETER_SUBJECT);
    assert_recovered_equivalent(
        "unknown parameter subject",
        UNKNOWN_PARAMETER_SUBJECT,
        &recovered,
    );
    assert_eq!(
        stats.index_loops_to_for_of, 0,
        "a parameter can hold a string at runtime, so its index loop must remain unchanged:\n{recovered}"
    );
}

#[test]
fn unknown_expression_subjects_are_not_resugared() {
    let source: &str = r"
var property = holder.items;
for (var i = 0; i < property.length; i++) { var a = property[i]; sink(a); }
var called = loadItems();
for (var j = 0; j < called.length; j++) { var b = called[j]; sink(b); }
var branched;
if (condition) { branched = ['a']; }
for (var k = 0; k < branched.length; k++) { var c = branched[k]; sink(c); }
if (condition) { var branchDeclared = ['b']; }
for (var l = 0; l < branchDeclared.length; l++) { var d = branchDeclared[l]; sink(d); }
";
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(source);
    assert_eq!(
        stats.index_loops_to_for_of, 0,
        "property reads, unresolved calls, and branch-defined bindings have unknown runtime types:\n{recovered}"
    );
}

#[test]
fn an_imported_subject_is_refused_while_a_proven_array_still_converts() {
    let source: &str = r"
import { values } from './values.js';
for (var i = 0; i < values.length; i++) { var value = values[i]; sink(value); }
var local = ['a'];
for (var j = 0; j < local.length; j++) { var item = local[j]; sink(item); }
";
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(source);
    assert_eq!(
        stats.index_loops_to_for_of, 1,
        "the imported binding must refuse while the local array proves the pass ran:\n{recovered}"
    );
    assert!(recovered.contains("i < values.length"), "{recovered}");
    assert!(recovered.contains(" of local)"), "{recovered}");
}

#[test]
fn every_provable_array_form_keeps_converting() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(PROVABLE_ARRAY_SUBJECTS);
    assert_eq!(
        stats.index_loops_to_for_of, 3,
        "Array.from, split, and new Array subjects must remain recoverable:\n{recovered}"
    );
    assert_recovered_equivalent(
        "provable array subjects",
        PROVABLE_ARRAY_SUBJECTS,
        &recovered,
    );
}

#[test]
fn subject_evidence_is_bound_to_the_lexical_symbol() {
    let source: &str = r#"
var items = "a\u{1F600}b";
function consume() {
  var items = ['a', 'b'];
  for (var i = 0; i < items.length; i++) {
    var item = items[i];
    function alter(items) { items = ['c']; return items; }
    print(item + ':' + alter(['d'])[0]);
  }
}
consume();
"#;
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(source);
    assert_eq!(
        stats.index_loops_to_for_of, 1,
        "an outer string binding must not taint a shadowing inner array binding:\n{recovered}"
    );
    assert_recovered_equivalent("shadowed array subject", source, &recovered);
}

#[test]
fn a_defaulted_parameter_and_a_loop_reassignment_are_refused() {
    let source: &str = r"
function defaulted(items = 'abc') {
  for (var i = 0; i < items.length; i++) { var item = items[i]; sink(item); }
}
var values = ['a', 'b'];
for (var j = 0; j < values.length; j++) {
  var value = values[j];
  values = ['c'];
  sink(value);
}
";
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(source);
    assert_eq!(
        stats.index_loops_to_for_of, 0,
        "defaulted parameters and subjects rebound during iteration must refuse:\n{recovered}"
    );
}

#[test]
fn conditional_and_compound_array_assignments_do_not_prove_a_subject() {
    let source: &str = r"
var shortCircuited;
condition && (shortCircuited = ['a']);
for (var i = 0; i < shortCircuited.length; i++) { var a = shortCircuited[i]; sink(a); }
var logicalAssignment;
logicalAssignment ||= ['b'];
for (var j = 0; j < logicalAssignment.length; j++) { var b = logicalAssignment[j]; sink(b); }
var loopAssigned;
for (var key in source) { loopAssigned = ['c']; }
for (var k = 0; k < loopAssigned.length; k++) { var c = loopAssigned[k]; sink(c); }
var maybeString;
while (condition) { maybeString = 'abc'; }
for (var l = 0; l < maybeString.length; l++) { var d = maybeString[l]; sink(d); }
";
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(source);
    assert_eq!(
        stats.index_loops_to_for_of, 0,
        "short-circuit, logical-assignment and conditional loop writes do not prove an array:\n{recovered}"
    );
}

#[test]
fn unresolved_reassignment_and_captured_state_do_not_prove_a_subject() {
    let source: &str = r"
var reassigned = 'abc';
reassigned = loadItems();
for (var i = 0; i < reassigned.length; i++) { var a = reassigned[i]; sink(a); }
var captured = ['a'];
function consume() {
  for (var j = 0; j < captured.length; j++) { var b = captured[j]; sink(b); }
}
captured = loadItems();
consume();
";
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(source);
    assert_eq!(
        stats.index_loops_to_for_of, 0,
        "unresolved writes and captured mutable state must remain index loops:\n{recovered}"
    );
}

#[test]
fn custom_split_and_destructuring_writes_do_not_prove_a_subject() {
    let source: &str = r#"
var custom = ({ split() { return "a\u{1F600}b"; } }).split();
for (var i = 0; i < custom.length; i++) { var a = custom[i]; sink(a); }
var destructured = ['a'];
[destructured] = [loadItems()];
for (var j = 0; j < destructured.length; j++) { var b = destructured[j]; sink(b); }
var updated = ['a'];
updated++;
for (var k = 0; k < updated.length; k++) { var c = updated[k]; sink(c); }
"#;
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(source);
    assert_eq!(
        stats.index_loops_to_for_of, 0,
        "custom split methods, destructuring writes and updates do not prove arrays:\n{recovered}"
    );
}
