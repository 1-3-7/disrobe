#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use disrobe_pass_js_deob::{RecoverOptions, RecoveryReport, recover_source_map_json};
use oxc_allocator::Allocator;
use oxc_parser::{Parser, ParserReturn};
use oxc_span::SourceType;

const FORMAT_CONTROLS: [char; 11] = [
    '\u{202a}', '\u{202b}', '\u{202c}', '\u{202d}', '\u{202e}', '\u{2066}', '\u{2067}', '\u{2068}',
    '\u{2069}', '\u{2028}', '\u{2029}',
];

fn hostile_map() -> String {
    serde_json::to_string(&serde_json::json!({
        "version": 3,
        "file": "bundle.js",
        "sources": ["src/app\nalert(document.cookie)\u{202e}.js"],
        "names": ["ok", "evil\nfetch('//x.invalid')\u{2066}"],
        "mappings": "AAAAA;AAAAC"
    }))
    .expect("serialize map")
}

#[test]
fn stub_comments_escape_names_and_sources_so_nothing_becomes_code() {
    let report: RecoveryReport =
        recover_source_map_json(&hostile_map(), RecoverOptions { emit_stubs: true })
            .expect("the map recovers to a stub");
    assert_eq!(report.files.len(), 1, "one stub for the one source");
    let stub: String = String::from_utf8(report.files[0].bytes.clone()).expect("utf-8 stub");
    assert!(
        report.files[0].reconstructed,
        "the source has no content, so it is a stub"
    );
    for line in stub.lines() {
        assert!(
            line.starts_with("//"),
            "every stub line stays a comment; a name or source broke out:\n{stub}"
        );
    }
    assert!(
        !stub
            .chars()
            .any(|c: char| FORMAT_CONTROLS.contains(&c) || (c.is_control() && c != '\n')),
        "no raw control or bidi/format character may reach the stub:\n{stub:?}"
    );
    assert!(
        stub.contains("fetch('//x.invalid')") && stub.contains("alert(document.cookie)"),
        "the hostile text is kept, escaped, inside the comments:\n{stub}"
    );
    let allocator: Allocator = Allocator::default();
    let parsed: ParserReturn<'_> = Parser::new(&allocator, &stub, SourceType::default()).parse();
    assert!(
        parsed.errors.is_empty(),
        "the stub parses: {:?}",
        parsed.errors
    );
    assert!(
        parsed.program.body.is_empty(),
        "the stub holds no statements, only comments"
    );
}
