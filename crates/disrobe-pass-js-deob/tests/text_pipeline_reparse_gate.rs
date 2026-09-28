#![cfg(not(target_arch = "wasm32"))]
#![allow(clippy::panic)]

use std::collections::BTreeSet;

use disrobe_pass_js_deob::{
    DeobOptions, Error, JscramblerOptions, JscramblerTransform, deobfuscate_all,
    deobfuscate_jscrambler,
};

fn parses(source: &str) -> bool {
    let allocator: oxc_allocator::Allocator = oxc_allocator::Allocator::default();
    let source_type: oxc_span::SourceType =
        oxc_span::SourceType::from_path("probe.js").unwrap_or_default();
    let parsed: oxc_parser::ParserReturn<'_> =
        oxc_parser::Parser::new(&allocator, source, source_type).parse();
    !parsed.panicked && parsed.errors.is_empty()
}

const JSCRAMBLER_MACHINE_WITH_REGEX_BRACE: &str = "function f(s){var H=2;for(;H!==9;){switch(H){case 2:s=s+'!';H=1;break;case 1:return s.replace(/\\}/g,'');}}}console.log(f('a}'));";

const JSCONFUSER_FLATTEN_WITH_REGEX_BRACES: &str = "function f(s){var S=1;while(!![]){switch(S){case 1:s=s+'!';S=2;break;case 2:return s['replace'](/\\}}/g,'');}}}console['log'](f('a}}'));";

#[test]
fn jscrambler_refuses_a_state_machine_truncated_at_a_regex_brace() {
    assert!(
        parses(JSCRAMBLER_MACHINE_WITH_REGEX_BRACE),
        "the probe input itself must be valid JavaScript"
    );
    let opts: JscramblerOptions = JscramblerOptions {
        i_have_authorization: false,
        transforms: BTreeSet::from([JscramblerTransform::ControlFlowFlattening]),
    };
    match deobfuscate_jscrambler(JSCRAMBLER_MACHINE_WITH_REGEX_BRACE, &opts) {
        Err(Error::CorruptedByTransform { transform }) => {
            assert_eq!(transform, "ControlFlowFlattening");
        }
        Err(other) => panic!("unexpected refusal: {other}"),
        Ok(output) => panic!(
            "jscrambler reported success (parses: {}) on:\n{}",
            parses(&output.source),
            output.source
        ),
    }
}

#[test]
fn jsconfuser_refuses_a_flattened_switch_truncated_at_a_regex_brace() {
    assert!(
        parses(JSCONFUSER_FLATTEN_WITH_REGEX_BRACES),
        "the probe input itself must be valid JavaScript"
    );
    match deobfuscate_all(JSCONFUSER_FLATTEN_WITH_REGEX_BRACES, &DeobOptions::all()) {
        Err(Error::CorruptedByTransform { transform }) => assert_eq!(transform, "flatten"),
        Err(other) => panic!("unexpected refusal: {other}"),
        Ok(output) => panic!(
            "js-confuser reported success (parses: {}) on:\n{}",
            parses(&output.source),
            output.source
        ),
    }
}
