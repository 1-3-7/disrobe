#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod common;

use common::{assert_equivalent, eval_capture};
use disrobe_pass_js_deob::{
    DeobOptions, JsObfuRewriteStats, JscramblerOptions, ObfuscatorIoOptions, ObfuscatorIoOutput,
    OpaqueReversalResult, RgfReversalResult, deobfuscate_all as jsconfuser_deobfuscate_all,
    deobfuscate_jscrambler, obfuscator_io_deobfuscate, reverse_flatten, reverse_opaque_predicates,
    reverse_rgf, reverse_string_encoding, rewrite_bracket_access, strip_integrity_loops,
};

const ORIGINAL_STRING_ARRAY: &str = r"
function greet(name) { return 'hello, ' + name; }
function pick(flag) { return flag ? 'yes' : 'no'; }
print(greet('world'));
print(pick(true));
print(pick(false));
print('divide by zero');
";

const OBF_STRING_ARRAY: &str = r"
var _0xarr = ['hello, ', 'yes', 'no', 'divide by zero', 'world'];
var _0xdec = function(_0xi){ return _0xarr[_0xi - 0x0]; };
function greet(name) { return _0xdec(0x0) + name; }
function pick(flag) { return flag ? _0xdec(0x1) : _0xdec(0x2); }
print(greet(_0xdec(0x4)));
print(pick(true));
print(pick(false));
print(_0xdec(0x3));
";

#[test]
fn obfuscator_io_string_array_fixture_is_faithful() {
    let want: String = eval_capture(ORIGINAL_STRING_ARRAY).expect("original evaluates");
    let obf: String = eval_capture(OBF_STRING_ARRAY).expect("obfuscated evaluates");
    assert_eq!(
        want, obf,
        "hand-built wire-shape fixture must be behaviorally identical to the original before deob"
    );
}

#[test]
fn obfuscator_io_string_array_reeval_equivalent() {
    let opts: ObfuscatorIoOptions = ObfuscatorIoOptions::all();
    let out: ObfuscatorIoOutput =
        obfuscator_io_deobfuscate(OBF_STRING_ARRAY, &opts).expect("deob ok");
    assert!(
        out.string_array_call_sites_inlined >= 5,
        "expected the decoder call sites inlined; got {}",
        out.string_array_call_sites_inlined
    );
    assert!(
        !out.source.contains("_0xdec(0x0)") && !out.source.contains("_0xdec(0x4)"),
        "decoder indirection must be gone from recovered source:\n{}",
        out.source
    );
    assert_equivalent(
        "obfuscator.io/string-array",
        ORIGINAL_STRING_ARRAY,
        &out.source,
    );
}

#[test]
fn obfuscator_io_wrong_rotation_is_not_silently_accepted() {
    let wrong_obf: &str = r"
var _0xarr = ['hello, ', 'yes', 'no', 'divide by zero', 'world'];
var _0xdec = function(_0xi){ return _0xarr[_0xi]; };
function greet(name) { return _0xdec(0x0) + name; }
print(greet(_0xdec(0x4)));
";
    let original_for_wrong: &str = r"
function greet(name) { return 'hello, ' + name; }
print(greet('world'));
";
    let opts: ObfuscatorIoOptions = ObfuscatorIoOptions::all();
    let out: ObfuscatorIoOutput = obfuscator_io_deobfuscate(wrong_obf, &opts).expect("deob ok");
    let want: String = eval_capture(original_for_wrong).expect("orig evaluates");
    let got: String = eval_capture(&out.source).expect("recovered evaluates");
    assert_eq!(
        want, got,
        "with no rotation, the literal mapping must still round-trip exactly"
    );
    let mis_mapped: &str = r"
var _0xarr = ['hello, ', 'yes', 'no', 'divide by zero', 'world'];
var _0xdec = function(_0xi){ return _0xarr[_0xi]; };
function greet(name) { return _0xdec(0x1) + name; }
print(greet(_0xdec(0x2)));
";
    let mis_out: ObfuscatorIoOutput =
        obfuscator_io_deobfuscate(mis_mapped, &opts).expect("deob ok");
    let mis_got: String = eval_capture(&mis_out.source).expect("evaluates");
    assert_ne!(
        want, mis_got,
        "a deliberately wrong index mapping must NOT recover the original behavior (proves the reverser is faithful to indices, not a no-op)"
    );
}

const ORIGINAL_ROTATED: &str = r"
function greet(name) { return 'hello, ' + name; }
function pick(flag) { return flag ? 'yes' : 'no'; }
print(greet('world'));
print(pick(true));
print(pick(false));
print('divide by zero');
";

const OBF_ROTATED: &str = r"
var _0xarr = ['no', 'divide by zero', 'world', '331', 'hello, ', 'yes'];
(function(_0xa, _0xb){
  while(!![]){
    try {
      var _0xchk = parseInt(_0xa[0x0], 0xa);
      if (_0xchk === _0xb) { break; }
      _0xa['push'](_0xa['shift']());
    } catch(_0xe) { _0xa['push'](_0xa['shift']()); }
  }
}(_0xarr, 0x14b));
var _0xdec = function(_0xi){ return _0xarr[_0xi - 0x0]; };
function greet(name) { return _0xdec(0x1) + name; }
function pick(flag) { return flag ? _0xdec(0x2) : _0xdec(0x3); }
print(greet(_0xdec(0x5)));
print(pick(true));
print(pick(false));
print(_0xdec(0x4));
";

#[test]
fn obfuscator_io_rotated_string_array_fixture_is_faithful() {
    let want: String = eval_capture(ORIGINAL_ROTATED).expect("orig evaluates");
    let obf: String = eval_capture(OBF_ROTATED).expect("rotated fixture evaluates");
    assert_eq!(
        want, obf,
        "the parseInt-pivot rotator fixture must be behaviorally identical to the original before deob"
    );
}

#[test]
fn obfuscator_io_rotated_string_array_reeval_equivalent() {
    let opts: ObfuscatorIoOptions = ObfuscatorIoOptions::all();
    let out: ObfuscatorIoOutput = obfuscator_io_deobfuscate(OBF_ROTATED, &opts).expect("deob ok");
    assert!(
        out.string_array_rotation_count > 0,
        "the rotator must be simulated; got rotation_count {}",
        out.string_array_rotation_count
    );
    assert!(
        !out.source.contains("_0xdec(0x5)") && !out.source.contains("parseInt(_0xa"),
        "rotator IIFE and decoder indirection must be gone:\n{}",
        out.source
    );
    assert_equivalent(
        "obfuscator.io/rotated-string-array",
        ORIGINAL_ROTATED,
        &out.source,
    );
}

const ORIGINAL_OPAQUE: &str = r"
var ready = true;
function run() { print('ran'); }
function skip() { print('skipped'); }
if (ready) { run(); } else { skip(); }
if (0x19 > 0xa) { print('big'); }
";

const OBF_OPAQUE: &str = r"
var ready = true;
function run() { print('ran'); }
function skip() { print('skipped'); }
if (!![] && ready) { run(); } else { skip(); }
if (0x19 > 0xa) { print('big'); }
";

#[test]
fn jsconfuser_opaque_predicate_reeval_equivalent() {
    let want: String = eval_capture(ORIGINAL_OPAQUE).expect("orig evaluates");
    let obf: String = eval_capture(OBF_OPAQUE).expect("obf evaluates");
    assert_eq!(want, obf, "opaque fixture must be behaviorally faithful");
    let folded: String = reverse_opaque_predicates(OBF_OPAQUE).rewritten_source;
    assert_equivalent("jsconfuser/opaque", ORIGINAL_OPAQUE, &folded);
}

const ORIGINAL_ALGEBRAIC: &str = r"
function classify(n) {
  var r = 0;
  if (n > 5) { r = r + 100; } else { r = r + 1; }
  r = r + n * 2;
  return r;
}
print(classify(3));
print(classify(9));
print(classify(0));
";

const OBF_ALGEBRAIC: &str = r"
function classify(n) {
  var r = 0;
  if (((n | 0) ^ (n | 0)) === 0) {
    if (n > 5) { r = r + 100; } else { r = r + 1; }
  } else {
    r = r + 123456;
  }
  if ((n & 1) === 0 || (n & 1) === 1) {
    r = r + n * 2;
  } else {
    r = r - 777;
  }
  return r;
}
print(classify(3));
print(classify(9));
print(classify(0));
";

#[test]
fn jsconfuser_algebraic_opaque_true_guards_reeval_equivalent() {
    let want: String = eval_capture(ORIGINAL_ALGEBRAIC).expect("orig evaluates");
    let obf: String = eval_capture(OBF_ALGEBRAIC).expect("obf evaluates");
    assert_eq!(
        want, obf,
        "the algebraic opaque guards are input-independent, so the fixture must match the original before deob"
    );
    let result: OpaqueReversalResult = reverse_opaque_predicates(OBF_ALGEBRAIC);
    assert!(
        result.predicates_folded >= 2,
        "both the xor-self and parity-disjunction tautologies must fold; got {}",
        result.predicates_folded
    );
    assert!(
        !result.rewritten_source.contains("123456") && !result.rewritten_source.contains("777"),
        "dead branches guarded by proven tautologies must be gone:\n{}",
        result.rewritten_source
    );
    assert!(
        result.rewritten_source.contains("n > 5"),
        "the genuinely data-dependent inner branch must be preserved:\n{}",
        result.rewritten_source
    );
    assert_equivalent(
        "jsconfuser/algebraic-opaque-true",
        ORIGINAL_ALGEBRAIC,
        &result.rewritten_source,
    );
}

const ORIGINAL_ALGEBRAIC_FALSE: &str = r"
function step(x) {
  var acc = x;
  if (x < 100) { acc = acc + 3; }
  return acc;
}
print(step(4));
print(step(250));
print(step(99));
";

const OBF_ALGEBRAIC_FALSE: &str = r"
function step(x) {
  var acc = x;
  if (((x | 0) & (~(x | 0))) !== 0) {
    acc = acc + 55555;
  } else {
    if (x < 100) { acc = acc + 3; }
  }
  if ((((x | 0) * 2) | 0) === (x << 1)) {
    return acc;
  } else {
    return -1;
  }
}
print(step(4));
print(step(250));
print(step(99));
";

#[test]
fn jsconfuser_algebraic_opaque_false_and_shift_reeval_equivalent() {
    let want: String = eval_capture(ORIGINAL_ALGEBRAIC_FALSE).expect("orig evaluates");
    let obf: String = eval_capture(OBF_ALGEBRAIC_FALSE).expect("obf evaluates");
    assert_eq!(
        want, obf,
        "the always-false and shift-equivalence guards are input-independent; fixture must match original before deob"
    );
    let result: OpaqueReversalResult = reverse_opaque_predicates(OBF_ALGEBRAIC_FALSE);
    assert!(
        result.predicates_folded >= 2,
        "the x&~x contradiction and the 2*x==x<<1 tautology must fold; got {}",
        result.predicates_folded
    );
    assert!(
        !result.rewritten_source.contains("55555") && !result.rewritten_source.contains("-1"),
        "dead branches must be gone:\n{}",
        result.rewritten_source
    );
    assert_equivalent(
        "jsconfuser/algebraic-opaque-false",
        ORIGINAL_ALGEBRAIC_FALSE,
        &result.rewritten_source,
    );
}

#[test]
fn jsconfuser_algebraic_opaque_pipeline_preserves_behavior() {
    let opts: DeobOptions = DeobOptions::all();
    let out = jsconfuser_deobfuscate_all(OBF_ALGEBRAIC, &opts);
    assert_equivalent(
        "jsconfuser/algebraic-opaque/pipeline",
        ORIGINAL_ALGEBRAIC,
        &out.source,
    );
}

const OBF_ALGEBRAIC_DATA_DEPENDENT: &str = r"
function pick(a, b) {
  if (((a | 0) - (b | 0)) === 0) { return 'equal'; }
  return 'different';
}
print(pick(3, 3));
print(pick(3, 4));
print(pick(0, 0));
";

#[test]
fn jsconfuser_algebraic_opaque_refuses_data_dependent_predicate() {
    let want: String = eval_capture(OBF_ALGEBRAIC_DATA_DEPENDENT).expect("obf evaluates");
    let result: OpaqueReversalResult = reverse_opaque_predicates(OBF_ALGEBRAIC_DATA_DEPENDENT);
    assert_eq!(
        result.predicates_folded, 0,
        "a genuinely input-dependent equality must never be folded:\n{}",
        result.rewritten_source
    );
    let got: String = eval_capture(&result.rewritten_source).expect("recovered evaluates");
    assert_eq!(want, got, "refusing to fold must leave behavior untouched");
}

const ORIGINAL_STRING_ENCODING: &str = r"
function label() { return 'hi'; }
print(label());
";

const OBF_STRING_ENCODING: &str = r"
function label() { return '\x68\x69'; }
print(label());
";

#[test]
fn jsconfuser_string_encoding_reeval_equivalent() {
    let want: String = eval_capture(ORIGINAL_STRING_ENCODING).expect("orig evaluates");
    let obf: String = eval_capture(OBF_STRING_ENCODING).expect("obf evaluates");
    assert_eq!(want, obf, "string-encoding fixture must be faithful");
    let decoded: String = reverse_string_encoding(OBF_STRING_ENCODING).rewritten_source;
    assert!(
        decoded.contains("'hi'") || decoded.contains("\"hi\""),
        "hex escapes must be decoded to a plain literal:\n{decoded}"
    );
    assert_equivalent(
        "jsconfuser/string-encoding",
        ORIGINAL_STRING_ENCODING,
        &decoded,
    );
}

#[test]
fn jsconfuser_deobfuscate_all_preserves_behavior() {
    let opts: DeobOptions = DeobOptions::all();
    let out = jsconfuser_deobfuscate_all(OBF_OPAQUE, &opts);
    assert_equivalent("jsconfuser/all", ORIGINAL_OPAQUE, &out.source);
}

const ORIGINAL_NONASCII_ESCAPE: &str = "print('caf\u{e9}\\x41');\nprint('\u{20ac}\\x39\u{1f600}');";

#[test]
fn jsconfuser_string_encoding_preserves_non_ascii_adjacent_to_escape() {
    let want: String = eval_capture(ORIGINAL_NONASCII_ESCAPE).expect("orig evaluates");
    let decoded: String = reverse_string_encoding(ORIGINAL_NONASCII_ESCAPE).rewritten_source;
    let got: String = eval_capture(&decoded).expect("recovered evaluates");
    assert_eq!(
        want, got,
        "a literal multi-byte code point next to an \\x escape must survive decoding byte-identical, not be split into Latin-1 units:\n--recovered--\n{decoded}"
    );
    assert_equivalent(
        "jsconfuser/string-encoding/non-ascii",
        ORIGINAL_NONASCII_ESCAPE,
        &decoded,
    );
}

const ORIGINAL_JSCRAMBLER: &str = r"
function build() { return 'foo' + 'bar' + 'baz'; }
print(build());
";

const OBF_JSCRAMBLER_SPLIT: &str = r"
function build() { var a = 'fo'; var b = 'o'; var c = 'ba'; var d = 'r'; return a + b + 'bar' + 'baz'.slice(0); }
print(build());
";

#[test]
fn jscrambler_static_layers_preserve_behavior() {
    let want: String = eval_capture(ORIGINAL_JSCRAMBLER).expect("orig evaluates");
    let obf: String = eval_capture(OBF_JSCRAMBLER_SPLIT).expect("obf evaluates");
    assert_eq!(
        want, obf,
        "jscrambler split fixture must be behaviorally faithful to the original"
    );
    let opts: JscramblerOptions = JscramblerOptions::all_obfuscation();
    let out = deobfuscate_jscrambler(OBF_JSCRAMBLER_SPLIT, &opts).expect("deob ok");
    assert_equivalent("jscrambler/static-layers", ORIGINAL_JSCRAMBLER, &out.source);
}

const ORIGINAL_CFF: &str = r"
function compute() {
  var acc = 0;
  acc = acc + 5;
  acc = acc * 3;
  acc = acc - 2;
  return acc;
}
print(compute());
";

const OBF_CFF: &str = r"
function compute() {
  var acc = 0;
  var order = '0|1|2'['split']('|');
  var ptr = 0;
  while (true) {
    switch (order[ptr++]) {
      case '0': acc = acc + 5; continue;
      case '1': acc = acc * 3; continue;
      case '2': acc = acc - 2; continue;
    }
    break;
  }
  return acc;
}
print(compute());
";

#[test]
fn obfuscator_io_control_flow_flattening_reeval_equivalent() {
    let want: String = eval_capture(ORIGINAL_CFF).expect("orig evaluates");
    let obf: String = eval_capture(OBF_CFF).expect("cff fixture evaluates");
    assert_eq!(
        want, obf,
        "switch-dispatch CFF fixture must be behaviorally faithful before deob"
    );
    let opts: ObfuscatorIoOptions = ObfuscatorIoOptions::all();
    let out: ObfuscatorIoOutput = obfuscator_io_deobfuscate(OBF_CFF, &opts).expect("deob ok");
    assert!(
        out.control_flow_switches_unflattened > 0,
        "the switch dispatcher must be unflattened; got {}",
        out.control_flow_switches_unflattened
    );
    assert!(
        !out.source.contains("['split']") && !out.source.contains("switch ("),
        "the dispatcher scaffolding must be gone:\n{}",
        out.source
    );
    assert_equivalent(
        "obfuscator.io/control-flow-flattening",
        ORIGINAL_CFF,
        &out.source,
    );
}

const ORIGINAL_FLATTEN: &str = r"
function run() {
  var acc = 1;
  acc = acc + 10;
  acc = acc * 2;
  print(acc);
}
run();
";

const OBF_FLATTEN: &str = r"
function run() {
  var acc = 1;
  var state = 0;
  while (true) {
    switch (state) {
      case 0:
        acc = acc + 10;
        state = 1;
        break;
      case 1:
        acc = acc * 2;
        state = 2;
        break;
      case 2:
        print(acc);
        return;
    }
  }
}
run();
";

#[test]
fn jsconfuser_flatten_reeval_equivalent() {
    let want: String = eval_capture(ORIGINAL_FLATTEN).expect("orig evaluates");
    let obf: String = eval_capture(OBF_FLATTEN).expect("flatten fixture evaluates");
    assert_eq!(
        want, obf,
        "numeric-state flatten fixture must be behaviorally faithful before deob"
    );
    let collapsed: String = reverse_flatten(OBF_FLATTEN).rewritten_source;
    assert!(
        !collapsed.contains("switch (state)") && !collapsed.contains("state ="),
        "the state machine must be unrolled to straight-line code:\n{collapsed}"
    );
    assert_equivalent("jsconfuser/flatten", ORIGINAL_FLATTEN, &collapsed);
}

const RGF_RUNTIME_DERIVED: &str = r"
var _rgf = [Function('a', 'b', atob(window.__k))];
function compute(x, y) { return _rgf[0](x, y); }
print(compute(2, 3));
";

#[test]
fn jsconfuser_rgf_runtime_derived_body_is_an_honest_wall() {
    let result: RgfReversalResult = reverse_rgf(RGF_RUNTIME_DERIVED);
    assert_eq!(
        result.call_sites_inlined, 0,
        "an RGF entry whose body is produced by a runtime atob/Function payload is not statically present; the reverser must NOT fabricate a body. call_sites_inlined must stay 0, got {}",
        result.call_sites_inlined
    );
    assert_eq!(
        result.entries_extracted, 0,
        "no validatable function body is statically present for a runtime-derived RGF entry"
    );
}

const ORIGINAL_SELF_DEFENDING: &str = r"
function area(w, h) { return w * h; }
print(area(4, 5));
";

const OBF_SELF_DEFENDING: &str = r"
function area(w, h) { return w * h; }
if (true) { var __keep = 1; }
if (false) { var __drop = 2; }
setInterval(function(){debugger;}, 4000);
(function(){debugger;})();
print(area(4, 5));
";

#[test]
fn obfuscator_io_self_defending_strip_preserves_behavior() {
    let want: String = eval_capture(ORIGINAL_SELF_DEFENDING).expect("orig evaluates");
    let obf: String = eval_capture(OBF_SELF_DEFENDING).expect("self-defending fixture evaluates");
    assert_eq!(
        want, obf,
        "the debug-protection stubs are runtime no-ops, so the fixture must match the original before deob"
    );
    let opts: ObfuscatorIoOptions = ObfuscatorIoOptions::all();
    let out: ObfuscatorIoOutput =
        obfuscator_io_deobfuscate(OBF_SELF_DEFENDING, &opts).expect("deob ok");
    assert!(
        !out.source.contains("debugger") && !out.source.contains("setInterval"),
        "debug-protection stubs must be stripped:\n{}",
        out.source
    );
    assert!(
        !out.source.contains("__drop"),
        "dead if(false) branch must be eliminated:\n{}",
        out.source
    );
    assert_equivalent(
        "obfuscator.io/self-defending",
        ORIGINAL_SELF_DEFENDING,
        &out.source,
    );
}

const ORIGINAL_BRACKET: &str = r"
function biggest(a, b) { return Math.max(a, b); }
print(biggest(7, 3));
";

const OBF_BRACKET: &str = r"
function biggest(a, b) { return Math['max'](a, b); }
print(biggest(7, 3));
";

#[test]
fn obfuscator_io_bracket_to_dot_preserves_behavior() {
    let want: String = eval_capture(ORIGINAL_BRACKET).expect("orig evaluates");
    let obf: String = eval_capture(OBF_BRACKET).expect("bracket fixture evaluates");
    assert_eq!(
        want, obf,
        "bracket member access is behaviorally identical to dot access"
    );
    let (rewritten, stats): (String, JsObfuRewriteStats) = rewrite_bracket_access(OBF_BRACKET);
    assert!(
        stats.bracket_to_dot_rewrites > 0,
        "the Math['max'] bracket access must be normalized to Math.max"
    );
    assert!(
        rewritten.contains("Math.max") && !rewritten.contains("Math['max']"),
        "normalized output must use dot access:\n{rewritten}"
    );
    assert_equivalent("obfuscator.io/bracket-to-dot", ORIGINAL_BRACKET, &rewritten);
}

const ORIGINAL_JSCRAMBLER_INTEGRITY: &str = r"
function checksum(n) { return n + 1; }
print(checksum(41));
";

const OBF_JSCRAMBLER_INTEGRITY: &str = r"
function checksum(n) { return n + 1; }
(function(){ while(!![]){ var _t = [][('constructor')]; } })();
print(checksum(41));
";

#[test]
fn jscrambler_integrity_loop_strip_is_honest() {
    let want: String = eval_capture(ORIGINAL_JSCRAMBLER_INTEGRITY).expect("orig evaluates");
    let (stripped, stats): (String, _) = strip_integrity_loops(OBF_JSCRAMBLER_INTEGRITY);
    assert!(
        stats.iifes_stripped > 0,
        "the static anti-tamper integrity IIFE must be matched and removed"
    );
    assert!(
        !stripped.contains("while(!![])") && !stripped.contains("constructor"),
        "the integrity self-reference loop must be gone:\n{stripped}"
    );
    assert!(
        stripped.contains("checksum"),
        "real code must survive the integrity strip"
    );
    let got: String = eval_capture(&stripped).expect("stripped output evaluates and terminates");
    assert_eq!(
        want, got,
        "stripping the static integrity loop must not change the real function behavior"
    );
    let opts: JscramblerOptions = JscramblerOptions::all_obfuscation();
    let pipeline = deobfuscate_jscrambler(OBF_JSCRAMBLER_INTEGRITY, &opts).expect("deob ok");
    assert!(
        pipeline.integrity_strip.iifes_stripped > 0
            || pipeline.integrity_strip.bare_loops_stripped > 0,
        "the default all_obfuscation pipeline must run the integrity-loop stripper: {:?}",
        pipeline.integrity_strip
    );
    assert!(
        !pipeline.source.contains("while(!![])") && !pipeline.source.contains("constructor"),
        "default pipeline must remove the polymorphic self-reference integrity loop:\n{}",
        pipeline.source
    );
    assert!(
        pipeline.source.contains("checksum"),
        "real code must survive the default pipeline integrity strip:\n{}",
        pipeline.source
    );
    let pipeline_got: String =
        eval_capture(&pipeline.source).expect("default-pipeline output evaluates and terminates");
    assert_eq!(
        want, pipeline_got,
        "the default pipeline integrity strip must not change real function behavior"
    );
}
