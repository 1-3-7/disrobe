#![cfg(not(target_arch = "wasm32"))]
#![allow(clippy::panic)]

use disrobe_pass_js_deob::{Error, ObfuscatorIoOptions, obfuscator_io_deobfuscate};

fn parses(source: &str) -> bool {
    let allocator: oxc_allocator::Allocator = oxc_allocator::Allocator::default();
    let source_type: oxc_span::SourceType =
        oxc_span::SourceType::from_path("probe.js").unwrap_or_default();
    let parsed: oxc_parser::ParserReturn<'_> =
        oxc_parser::Parser::new(&allocator, source, source_type).parse();
    !parsed.panicked && parsed.errors.is_empty()
}

const FLATTENED_WITH_REGEX_BRACE: &str = "function f(s){var _0x1a2b='1|0'['split']('|'),_0x3c4d=0x0;while(!![]){switch(_0x1a2b[_0x3c4d++]){case'0':return s['replace'](/\\}/g,'');case'1':s=s+`${`${s}`}`;continue;}break;}}console['log'](f('a}'));";

#[test]
fn a_stage_never_reports_success_on_output_that_no_longer_parses() {
    assert!(
        parses(FLATTENED_WITH_REGEX_BRACE),
        "the probe input itself must be valid JavaScript"
    );
    match obfuscator_io_deobfuscate(FLATTENED_WITH_REGEX_BRACE, &ObfuscatorIoOptions::all()) {
        Ok(output) => assert!(
            parses(&output.source),
            "obfuscator.io reported success on output that does not parse:\n{}",
            output.source
        ),
        Err(Error::CorruptedByTransform { transform }) => assert!(!transform.is_empty()),
        Err(other) => panic!("unexpected refusal: {other}"),
    }
}
