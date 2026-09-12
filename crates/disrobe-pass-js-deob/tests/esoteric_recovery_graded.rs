#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use std::fs;
use std::path::PathBuf;

use disrobe_pass_js_deob::{
    AaEncodeDecode, JjEncodeDecode, PackerDecode, decode_aaencode, decode_jjencode, unpack_packer,
};

fn corpus(rel: &str) -> Option<String> {
    let p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("corpus")
        .join("js")
        .join(rel);
    if p.exists() {
        fs::read_to_string(&p).ok()
    } else {
        None
    }
}

fn reparses(source: &str) -> bool {
    use oxc_allocator::Allocator;
    use oxc_parser::Parser;
    use oxc_span::SourceType;
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path("check.js").unwrap_or_default();
    let parsed: oxc_parser::ParserReturn<'_> = Parser::new(&allocator, source, source_type).parse();
    parsed.errors.is_empty() && !parsed.panicked
}

const CANONICAL_TOKENS: [&str; 8] = [
    "use strict",
    "legacyVar",
    "blockConst",
    "destructured",
    "deepValue",
    "Animal",
    "greeter",
    "addAll",
];

fn assert_recovers_canonical_source(recovered: &str, family: &str) {
    assert!(
        reparses(recovered),
        "{family}: recovered source must re-parse with an independent parser (oxc), not just boa"
    );
    for token in CANONICAL_TOKENS {
        assert!(
            recovered.contains(token),
            "{family}: recovered source must contain canonical original identifier {token:?}; \
             a wrong decode cannot fabricate these. head:\n{}",
            &recovered[..recovered.len().min(200)]
        );
    }
}

#[test]
fn aaencode_real_sample_recovers_original_source() {
    let Some(src): Option<String> = corpus("aaencode/obfuscated.megafile.js") else {
        return;
    };
    let decoded: AaEncodeDecode = decode_aaencode(&src);
    assert!(decoded.detection.matched, "aaencode detection precondition");
    let Some(recovered): Option<String> = decoded.recovered else {
        panic!("aaencode real sample must recover source, got None");
    };
    assert_recovers_canonical_source(&recovered, "aaencode");
}

#[test]
fn jjencode_real_sample_recovers_original_source() {
    let Some(src): Option<String> = corpus("jjencode/obfuscated.megafile.js") else {
        return;
    };
    let decoded: JjEncodeDecode = decode_jjencode(&src);
    assert!(decoded.detection.matched, "jjencode detection precondition");
    let Some(recovered): Option<String> = decoded.recovered else {
        panic!("jjencode real sample must recover source, got None");
    };
    assert_recovers_canonical_source(&recovered, "jjencode");
}

#[test]
fn packer_real_sample_recovers_original_source() {
    let Some(src): Option<String> = corpus("packer/obfuscated.megafile.js") else {
        return;
    };
    let decoded: PackerDecode = unpack_packer(&src);
    assert!(decoded.detection.matched, "packer detection precondition");
    let Some(recovered): Option<String> = decoded.recovered else {
        panic!("packer real sample must recover source, got None");
    };
    assert!(
        reparses(&recovered),
        "packer: recovered source must re-parse with oxc:\n{}",
        &recovered[..recovered.len().min(200)]
    );
    for token in ["use strict", "legacyVar", "blockConst", "identity"] {
        assert!(
            recovered.contains(token),
            "packer: recovered must contain {token:?}"
        );
    }
}
