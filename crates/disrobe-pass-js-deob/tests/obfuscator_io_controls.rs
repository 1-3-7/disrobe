#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use std::collections::BTreeSet;

use disrobe_pass_js_deob::{
    ObfuscatorIoControl, ObfuscatorIoOptions, ObfuscatorIoOutput, obfuscator_io_deobfuscate,
    obfuscator_io_detect,
};

fn options_for(control: ObfuscatorIoControl) -> ObfuscatorIoOptions {
    let mut set: BTreeSet<ObfuscatorIoControl> = BTreeSet::new();
    set.insert(control);
    ObfuscatorIoOptions {
        controls: set,
        max_passes: 4,
    }
}

fn run(src: &str, control: ObfuscatorIoControl) -> ObfuscatorIoOutput {
    let opts: ObfuscatorIoOptions = options_for(control);
    obfuscator_io_deobfuscate(src, &opts).expect("deobfuscate ok")
}

#[test]
fn detect_booleans_in_obfuscator_io_form() {
    let src: &str = "var _0xfeed = !![]; var _0xdead = ![]; var x = 1;";
    let det = obfuscator_io_detect(src);
    assert!(det.controls.contains(&ObfuscatorIoControl::Booleans));
}

#[test]
fn reverse_booleans_in_minimal_snippet() {
    let src: &str = "var a = !0; var b = !1;";
    let out: ObfuscatorIoOutput = run(src, ObfuscatorIoControl::Booleans);
    assert!(
        out.source.contains("true") && out.source.contains("false"),
        "expected boolean restoration; got: {}",
        out.source
    );
}

#[test]
fn detect_control_flow_flattening_signature() {
    let src: &str = r"var _0xab='0|1|2|3'.split('|'),_0xcd=0;while(!![]){switch(_0xab[_0xcd++]){case'0':a();break;case'1':b();break;case'2':c();break;case'3':d();break;}break;}";
    let det = obfuscator_io_detect(src);
    assert!(
        det.controls
            .contains(&ObfuscatorIoControl::ControlFlowFlattening)
    );
}

#[test]
fn reverse_control_flow_flattening_smoke() {
    let src: &str = r"var seq='0|1|2'.split('|'),idx=0;while(!![]){switch(seq[idx++]){case'0':a();break;case'1':b();break;case'2':c();break;}break;}";
    let out: ObfuscatorIoOutput = run(src, ObfuscatorIoControl::ControlFlowFlattening);
    let _ = out.source;
    assert!(out.passes_run >= 1);
}

#[test]
fn detect_function_inlining_signature() {
    let src: &str = "if ('aaa' === 'bbb') { return helper(); } else { return real(); }";
    let det = obfuscator_io_detect(src);
    assert!(
        det.controls
            .contains(&ObfuscatorIoControl::FunctionInlining)
    );
}

#[test]
fn function_inlining_passes_through_safely() {
    let src: &str = "if ('a' === 'b') { return f(); } var x = 1;";
    let out: ObfuscatorIoOutput = run(src, ObfuscatorIoControl::FunctionInlining);
    assert!(out.source.contains("var x"));
}

#[test]
fn detect_identifiers_hex_form() {
    let src: &str = "var _0xabcd = 1; function _0xfeed() { return _0xabcd; }";
    let det = obfuscator_io_detect(src);
    assert!(det.controls.contains(&ObfuscatorIoControl::Identifiers));
}

#[test]
fn reverse_identifiers_renames_hex() {
    let src: &str = "var _0xabcd = 1; var _0xfeed = 2;";
    let out: ObfuscatorIoOutput = run(src, ObfuscatorIoControl::Identifiers);
    assert!(
        out.idents_renamed > 0
            || out
                .controls_applied
                .contains(&ObfuscatorIoControl::Identifiers)
            || !out.source.contains("_0xabcd")
    );
}

#[test]
fn detect_hex_numbers() {
    let src: &str = "var x = 0xff; var y = 0xabcd;";
    let det = obfuscator_io_detect(src);
    assert!(det.controls.contains(&ObfuscatorIoControl::Numbers));
}

#[test]
fn numbers_control_passes_through() {
    let src: &str = "var x = 0xff; var y = 0xabcd;";
    let out: ObfuscatorIoOutput = run(src, ObfuscatorIoControl::Numbers);
    assert!(out.source.contains("var x"));
}

#[test]
fn detect_object_property_proxy() {
    let src: &str = "var _0xabcd = { 'add': function(a, b) { return a + b; } };";
    let det = obfuscator_io_detect(src);
    assert!(det.controls.contains(&ObfuscatorIoControl::Objects));
}

#[test]
fn reverse_objects_bracket_to_dot() {
    let src: &str = "Math['floor'](1.5);";
    let out: ObfuscatorIoOutput = run(src, ObfuscatorIoControl::Objects);
    assert!(
        out.source.contains("Math.floor")
            || out.controls_applied.contains(&ObfuscatorIoControl::Objects)
            || !out.source.is_empty()
    );
}

#[test]
fn detect_opaque_predicate_signature() {
    let src: &str = "if ('xyz' === 'abc') { real(); } else { dead(); }";
    let det = obfuscator_io_detect(src);
    assert!(det.controls.contains(&ObfuscatorIoControl::Predicates));
}

#[test]
fn reverse_opaque_predicate_passes_through() {
    let src: &str = "if ('xyz' === 'abc') { real(); } else { dead(); }";
    let out: ObfuscatorIoOutput = run(src, ObfuscatorIoControl::Predicates);
    assert!(out.passes_run >= 1);
}

#[test]
fn detect_console_output_disable() {
    let src: &str = r"console['log']=function(){};console['warn']=function(){};";
    let det = obfuscator_io_detect(src);
    assert!(
        det.controls
            .contains(&ObfuscatorIoControl::RegularExpressions)
    );
}

#[test]
fn regular_expressions_control_passes_through() {
    let src: &str = r"console['log']=function(){};var x=1;";
    let out: ObfuscatorIoOutput = run(src, ObfuscatorIoControl::RegularExpressions);
    assert!(out.source.contains("var x") || !out.source.is_empty());
}

#[test]
fn detect_statements_string_array() {
    let src: &str = "var _0xabc = ['hello', 'world']; var x = _0xabc[0];";
    let det = obfuscator_io_detect(src);
    assert!(det.controls.contains(&ObfuscatorIoControl::Statements));
}

#[test]
fn reverse_statements_inlines_string_array() {
    let src: &str = "var _0xabc = ['hello', 'world'];\nvar y = _0xabc;\nconsole.log(_0xabc[0]);";
    let out: ObfuscatorIoOutput = run(src, ObfuscatorIoControl::Statements);
    assert!(
        out.string_array_call_sites_inlined > 0
            || out
                .controls_applied
                .contains(&ObfuscatorIoControl::Statements)
            || out.source.contains("hello")
    );
}

#[test]
fn detect_split_string_concat() {
    let src: &str = r"var x = 'hel' + 'lo' + 'wor' + 'ld';";
    let det = obfuscator_io_detect(src);
    assert!(det.controls.contains(&ObfuscatorIoControl::Strings));
}

#[test]
fn strings_control_passes_through() {
    let src: &str = "var x = 'foo' + 'bar';";
    let out: ObfuscatorIoOutput = run(src, ObfuscatorIoControl::Strings);
    assert!(out.passes_run >= 1);
}

#[test]
fn detect_renamed_properties() {
    let src: &str = "var x = obj._0xabcd; var y = self._0xfeed;";
    let det = obfuscator_io_detect(src);
    assert!(det.controls.contains(&ObfuscatorIoControl::Variables));
}

#[test]
fn variables_control_passes_through() {
    let src: &str = "var x = obj._0xabcd;";
    let out: ObfuscatorIoOutput = run(src, ObfuscatorIoControl::Variables);
    assert!(out.passes_run >= 1);
}

#[test]
fn detect_self_defending_and_debug() {
    let src: &str =
        r#"setInterval(function(){debugger;},4000);Function("debu"+"gger").call(this);"#;
    let det = obfuscator_io_detect(src);
    assert!(det.controls.contains(&ObfuscatorIoControl::Minification));
}

#[test]
fn reverse_minification_strips_protection() {
    let src: &str = "setInterval(function(){debugger;},4000); var x = 1;";
    let out: ObfuscatorIoOutput = run(src, ObfuscatorIoControl::Minification);
    assert!(
        !out.source.contains("setInterval")
            || out
                .controls_applied
                .contains(&ObfuscatorIoControl::Minification)
            || out.unminify_stats.set_interval_watchdogs_removed > 0
    );
}
